use device_development_mesh::network_processes::{Request, Response, RunRequest};
use device_development_mesh::registry_runtime::{
    RegistryRecoveryPolicy, RegistryRuntime, RegistryRuntimeConfig, RegistryRuntimeState,
};
use device_development_mesh::secure_transport::SecureTransport;
use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

#[test]
fn shutdown_closes_idle_partial_tls_and_partial_authenticated_request() {
    subprocess_fixture("shutdown");
}

#[test]
fn state_writer_exclusion_preserves_owner_and_allows_successor() {
    subprocess_fixture("writer");
}

#[test]
fn shutdown_interrupts_waiting_legacy_run_and_preserves_pending_restart_state() {
    subprocess_fixture("waiting-run");
}

#[test]
fn admission_rejects_overflow_after_sixty_four_live_authenticated_connections() {
    subprocess_fixture("admission");
}

// Execute shutdown assertions in our own killable test process. A lifecycle bug
// must not strand the parent test runner in Drop or a worker join.
#[test]
#[ignore = "subprocess fixture invoked by the bounded parent tests"]
fn registry_runtime_fixture() {
    let mode = std::env::var("DEVICELANE_RUNTIME_FIXTURE_MODE").expect("fixture mode");
    let root =
        PathBuf::from(std::env::var_os("DEVICELANE_RUNTIME_FIXTURE_ROOT").expect("fixture root"));
    let (authority, client) = identities(&root);
    match mode.as_str() {
        "shutdown" => shutdown_fixture(&root, authority, client),
        "writer" => writer_fixture(&root, authority, client),
        "waiting-run" => waiting_run_fixture(&root, authority, client),
        "admission" => admission_fixture(&root, authority, client),
        _ => panic!("unknown fixture mode"),
    }
    std::fs::write(root.join("fixture-completed"), &mode).unwrap();
}

fn identities(root: &Path) -> (Arc<SecureTransport>, SecureTransport) {
    let mut authority =
        SecureTransport::load_or_create(root.join("identity"), "controller-fixture").unwrap();
    let mut client =
        SecureTransport::load_or_create(root.join("client"), "fixture-client").unwrap();
    authority
        .trust("fixture-client", client.certificate_der())
        .unwrap();
    client
        .trust("controller-fixture", authority.certificate_der())
        .unwrap();
    (Arc::new(authority), client)
}

fn config(
    listener: TcpListener,
    authority: Arc<SecureTransport>,
    root: &Path,
) -> RegistryRuntimeConfig {
    RegistryRuntimeConfig {
        listener,
        transport: authority,
        state_root: root.join("state"),
        offline_after: Duration::from_secs(10),
        agent_peers: Default::default(),
        recovery_policy: RegistryRecoveryPolicy::Reject,
    }
}

fn connect(address: SocketAddr) -> TcpStream {
    let socket = TcpStream::connect_timeout(&address, Duration::from_secs(1)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    socket
}

fn shutdown_fixture(root: &Path, authority: Arc<SecureTransport>, client: SecureTransport) {
    let mut runtime = RegistryRuntime::start(config(
        TcpListener::bind("127.0.0.1:0").unwrap(),
        authority,
        root,
    ))
    .unwrap();
    let address = runtime.local_addr();
    let status = runtime.status();
    let idle = connect(address);
    let mut partial_tls = connect(address);
    partial_tls.write_all(&[0x16, 0x03, 0x03, 0x00]).unwrap();
    // The completed handshake on the next queued connection is an accept-loop
    // fence: this proves progress past the already-connected idle/partial peers.
    let mut authenticated = client
        .connect_tls(connect(address), "controller-fixture")
        .unwrap();
    let request = serde_json::to_vec(&Request::List).unwrap();
    assert!(request.len() > 1);
    authenticated
        .write_all(&request[..request.len() - 1])
        .unwrap();
    authenticated.flush().unwrap();
    let authenticated_socket = authenticated.sock.try_clone().unwrap();
    assert_eq!(status.snapshot(), RegistryRuntimeState::Running);
    let started = Instant::now();
    runtime.shutdown().unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "shutdown waited for a long RPC deadline"
    );
    assert_eq!(status.snapshot(), RegistryRuntimeState::Stopped);
    assert_closed(idle);
    assert_closed(partial_tls);
    assert_closed(authenticated_socket);
    let rebound = TcpListener::bind(address).expect("shutdown did not release the registry port");
    assert_eq!(rebound.local_addr().unwrap(), address);
}

fn assert_closed(mut socket: TcpStream) {
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut bytes = [0; 1024];
    loop {
        match socket.read(&mut bytes) {
            Ok(0) => return,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset
                        | io::ErrorKind::ConnectionAborted
                        | io::ErrorKind::BrokenPipe
                ) =>
            {
                return;
            }
            Ok(_) => assert!(
                Instant::now() < deadline,
                "closed socket kept producing data"
            ),
            Err(error) => panic!("socket was not closed by runtime shutdown: {error}"),
        }
    }
}

fn writer_fixture(root: &Path, authority: Arc<SecureTransport>, client: SecureTransport) {
    let mut first = RegistryRuntime::start(config(
        TcpListener::bind("127.0.0.1:0").unwrap(),
        Arc::clone(&authority),
        root,
    ))
    .unwrap();
    inventory(first.local_addr(), &client);
    // Snapshot the exact durable store bytes; read requests do not rewrite them.
    let before = files(&root.join("state"));
    let loser_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let loser_address = loser_listener.local_addr().unwrap();
    let result = RegistryRuntime::start(config(loser_listener, Arc::clone(&authority), root));
    let error = match result {
        Err(error) => error,
        Ok(_) => panic!("second state writer was admitted"),
    };
    assert_eq!(
        error.kind(),
        fs2::lock_contended_error().kind(),
        "unrelated startup failure: {error}"
    );
    assert_eq!(
        error.raw_os_error(),
        fs2::lock_contended_error().raw_os_error()
    );
    assert_eq!(
        files(&root.join("state")),
        before,
        "losing writer changed durable files"
    );
    let _released_loser =
        TcpListener::bind(loser_address).expect("rejected runtime leaked its reserved listener");
    inventory(first.local_addr(), &client);
    assert_eq!(first.status().snapshot(), RegistryRuntimeState::Running);
    let identity_before = files(&root.join("identity"));
    let started = Instant::now();
    first.shutdown().unwrap();
    assert!(started.elapsed() < Duration::from_secs(5));
    let mut successor = RegistryRuntime::start(config(
        TcpListener::bind("127.0.0.1:0").unwrap(),
        authority,
        root,
    ))
    .expect("state lock was not released for successor");
    assert_eq!(successor.identity_id(), "controller-fixture");
    inventory(successor.local_addr(), &client);
    successor.shutdown().unwrap();
    assert_eq!(files(&root.join("identity")), identity_before);
}

fn waiting_run_fixture(root: &Path, authority: Arc<SecureTransport>, client: SecureTransport) {
    let identity_before = files(&root.join("identity"));
    let mut runtime = RegistryRuntime::start(config(
        TcpListener::bind("127.0.0.1:0").unwrap(),
        Arc::clone(&authority),
        root,
    ))
    .unwrap();
    let operation = RunRequest {
        principal_id: "fixture-client".into(),
        host_id: "missing-agent".into(),
        device_id: "fixture-device".into(),
        workspace_id: "fixture-workspace".into(),
        request_id: "waiting-run-request".into(),
        manifest: vec![],
    };
    let request = Request::Run {
        operation: operation.clone(),
    };
    let mut tls = client
        .connect_tls(connect(runtime.local_addr()), "controller-fixture")
        .unwrap();
    // This read timeout deliberately exceeds the five-second shutdown assertion.
    // A client-side one-second timeout must not look like server cancellation.
    tls.sock
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let socket = tls.sock.try_clone().unwrap();
    let mut frame = serde_json::to_vec(&request).unwrap();
    frame.push(b'\n');
    tls.write_all(&frame).unwrap();
    tls.flush().unwrap();
    let (entered_sender, entered) = std::sync::mpsc::channel();
    let (finished_sender, finished) = std::sync::mpsc::channel();
    let reader = thread::spawn(move || {
        entered_sender.send(()).unwrap();
        let result = tls.read(&mut [0; 1]);
        let _ = finished_sender.send(result);
    });
    entered.recv_timeout(Duration::from_secs(1)).unwrap();
    let state_path = root.join("state").join("vertical-slice.json");
    let pending_deadline = Instant::now() + Duration::from_secs(2);
    let (state_bytes, persisted, job_id) = loop {
        if let Ok(bytes) = std::fs::read(&state_path)
            && let Ok(envelope) = serde_json::from_slice::<serde_json::Value>(&bytes)
            && let Some(job_id) = envelope["payload"]["requests"][&operation.request_id].as_str()
            && envelope["payload"]["pending"].get(job_id).is_some()
        {
            break (bytes, envelope["payload"].clone(), job_id.to_owned());
        }
        assert!(
            Instant::now() < pending_deadline,
            "real Run request was not durably pending"
        );
        thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(
        persisted["pending"][&job_id],
        serde_json::to_value(&operation).unwrap()
    );
    assert!(
        matches!(
            finished.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ),
        "client stopped waiting before runtime shutdown"
    );
    let started = Instant::now();
    runtime.shutdown().unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "shutdown waited for the legacy fifteen-second agent deadline"
    );
    assert_eq!(runtime.status().snapshot(), RegistryRuntimeState::Stopped);
    let _read_result = finished
        .recv_timeout(Duration::from_secs(1))
        .expect("client read was not released by shutdown");
    reader.join().unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    assert_closed(socket);
    assert_eq!(std::fs::read(&state_path).unwrap(), state_bytes);
    assert_eq!(files(&root.join("identity")), identity_before);

    let mut successor = RegistryRuntime::start(config(
        TcpListener::bind("127.0.0.1:0").unwrap(),
        authority,
        root,
    ))
    .unwrap();
    inventory(successor.local_addr(), &client);
    let restored: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
    assert_eq!(restored["payload"], persisted);
    // Replay proves the live successor loaded the durable idempotency mapping.
    // It does not assert a terminal cancellation or successful job execution.
    let replay = rpc(successor.local_addr(), &client, &request);
    assert!(replay.accepted);
    assert_eq!(replay.job_id.as_deref(), Some(job_id.as_str()));
    successor.shutdown().unwrap();
    assert_eq!(std::fs::read(&state_path).unwrap(), state_bytes);
    assert_eq!(files(&root.join("identity")), identity_before);
}

fn admission_fixture(root: &Path, authority: Arc<SecureTransport>, client: SecureTransport) {
    use std::sync::atomic::{AtomicBool, Ordering};
    let mut runtime = RegistryRuntime::start(config(
        TcpListener::bind("127.0.0.1:0").unwrap(),
        authority,
        root,
    ))
    .unwrap();
    let address = runtime.local_addr();
    let client = Arc::new(client);
    let release = Arc::new(AtomicBool::new(false));
    let (ready_sender, ready) = std::sync::mpsc::channel();
    let mut holders = Vec::new();
    let ready_deadline = Instant::now() + Duration::from_secs(8);
    for _ in 0..64 {
        let client = Arc::clone(&client);
        let release = Arc::clone(&release);
        let ready_sender = ready_sender.clone();
        holders.push(thread::spawn(move || {
            let mut tls = client
                .connect_tls(connect(address), "controller-fixture")
                .unwrap();
            let mut first = true;
            loop {
                let response = exchange(&mut tls, &Request::List);
                assert!(response.accepted, "admitted holder lost inventory access");
                if first {
                    ready_sender.send(()).unwrap();
                    first = false;
                }
                if release.load(Ordering::Acquire) {
                    break;
                }
                // Keep the connection active below the server's two-second I/O
                // timeout. Readiness is established by RPC, never by this sleep.
                thread::sleep(Duration::from_millis(200));
            }
        }));
    }
    drop(ready_sender);
    for _ in 0..64 {
        ready
            .recv_timeout(ready_deadline.saturating_duration_since(Instant::now()))
            .expect("all sixty-four holders must complete real TLS and accepted inventory");
    }
    assert!(
        holders.iter().all(|worker| !worker.is_finished()),
        "holder ended before overflow probe"
    );
    for _ in 0..2 {
        let mut overflow = connect(address);
        overflow
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        // An admitted idle socket would wait for TLS input for two seconds.
        // Only EOF/reset counts as rejection; a client read timeout must fail.
        match overflow.read(&mut [0; 1]) {
            Ok(0) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
                ) => {}
            result => panic!("overflow socket was not promptly rejected: {result:?}"),
        }
    }
    assert!(
        holders.iter().all(|worker| !worker.is_finished()),
        "admitted holder expired during overflow probes"
    );
    assert_eq!(runtime.status().snapshot(), RegistryRuntimeState::Running);
    release.store(true, Ordering::Release);
    for holder in holders {
        holder.join().expect("admitted holder failed");
    }
    let recovery_deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match recovery_inventory(address, &client, recovery_deadline) {
            Ok(()) => break,
            Err(error) => {
                assert!(
                    Instant::now() < recovery_deadline,
                    "registry did not recover admission before its deadline: {error}"
                );
                thread::sleep(Duration::from_millis(10));
            }
        }
    }
    let started = Instant::now();
    runtime.shutdown().unwrap();
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(runtime.status().snapshot(), RegistryRuntimeState::Stopped);
}

fn recovery_inventory(
    address: SocketAddr,
    client: &SecureTransport,
    deadline: Instant,
) -> Result<(), String> {
    let remaining = || {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            Err("admission recovery deadline expired".to_owned())
        } else {
            Ok(remaining.min(Duration::from_secs(1)))
        }
    };
    let socket =
        TcpStream::connect_timeout(&address, remaining()?).map_err(|error| error.to_string())?;
    socket
        .set_read_timeout(Some(remaining()?))
        .map_err(|error| error.to_string())?;
    socket
        .set_write_timeout(Some(remaining()?))
        .map_err(|error| error.to_string())?;
    let mut tls = client
        .connect_tls(socket, "controller-fixture")
        .map_err(|error| format!("recovery TLS failed: {error:?}"))?;
    tls.sock
        .set_write_timeout(Some(remaining()?))
        .map_err(|error| error.to_string())?;
    let mut request = serde_json::to_vec(&Request::List).map_err(|error| error.to_string())?;
    request.push(b'\n');
    tls.write_all(&request).map_err(|error| error.to_string())?;
    tls.flush().map_err(|error| error.to_string())?;
    let mut frame = Vec::new();
    loop {
        tls.sock
            .set_read_timeout(Some(remaining()?))
            .map_err(|error| error.to_string())?;
        let mut byte = [0; 1];
        tls.read_exact(&mut byte)
            .map_err(|error| error.to_string())?;
        if byte[0] == b'\n' {
            break;
        }
        if frame.len() >= 1024 * 1024 {
            return Err("recovery inventory frame exceeded bound".into());
        }
        frame.push(byte[0]);
    }
    let response: Response = serde_json::from_slice(&frame).map_err(|error| error.to_string())?;
    remaining()?;
    if response.accepted {
        Ok(())
    } else {
        Err(format!("recovery inventory rejected: {:?}", response.error))
    }
}

fn inventory(address: SocketAddr, client: &SecureTransport) {
    let response = rpc(address, client, &Request::List);
    assert!(response.accepted, "inventory failed: {:?}", response.error);
}

fn rpc(address: SocketAddr, client: &SecureTransport, request: &Request) -> Response {
    let mut tls = client
        .connect_tls(connect(address), "controller-fixture")
        .unwrap();
    exchange(&mut tls, request)
}

fn exchange(stream: &mut (impl Read + Write), request: &Request) -> Response {
    let mut request = serde_json::to_vec(request).unwrap();
    request.push(b'\n');
    stream.write_all(&request).unwrap();
    stream.flush().unwrap();
    let mut frame = Vec::new();
    loop {
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        if byte[0] == b'\n' {
            break;
        }
        assert!(
            frame.len() < 1024 * 1024,
            "inventory response exceeded fixture bound"
        );
        frame.push(byte[0]);
    }
    serde_json::from_slice(&frame).unwrap()
}

fn files(root: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    fn visit(root: &Path, directory: &Path, entries: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
        for entry in std::fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            let relative = path.strip_prefix(root).unwrap().to_owned();
            if path.file_name().is_some_and(|name| name == "registry.lock") {
                // Windows mandatory file locking prohibits reading the held lock
                // itself. Its presence is checked; it is not a durable data store.
                assert!(path.is_file());
                entries.insert(relative, None);
                continue;
            }
            if path.is_dir() {
                entries.insert(relative, None);
                visit(root, &path, entries);
            } else {
                entries.insert(relative, Some(std::fs::read(path).unwrap()));
            }
        }
    }
    let mut entries = BTreeMap::new();
    visit(root, root, &mut entries);
    entries
}

fn subprocess_fixture(mode: &str) {
    let root = tempfile::tempdir().unwrap();
    let command = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "registry_runtime_fixture",
            "--ignored",
            "--nocapture",
        ])
        .env("DEVICELANE_RUNTIME_FIXTURE_MODE", mode)
        .env("DEVICELANE_RUNTIME_FIXTURE_ROOT", root.path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut process = FixtureProcess {
        child: command,
        readers: Vec::new(),
    };
    process
        .readers
        .push(drain(process.child.stdout.take().unwrap()));
    process
        .readers
        .push(drain(process.child.stderr.take().unwrap()));
    let deadline = Instant::now() + Duration::from_secs(15);
    let status = loop {
        if let Some(status) = process.child.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "{mode} runtime fixture exceeded its process deadline"
        );
        thread::sleep(Duration::from_millis(20));
    };
    let mut diagnostics = String::new();
    for reader in process.readers.drain(..) {
        diagnostics.push_str(&String::from_utf8_lossy(&reader.join().unwrap()));
    }
    assert!(
        status.success(),
        "{mode} runtime fixture failed: {diagnostics}"
    );
    assert_eq!(
        std::fs::read(root.path().join("fixture-completed"))
            .expect("runtime fixture exited successfully without completing its assertions"),
        mode.as_bytes(),
        "runtime fixture completed the wrong scenario"
    );
}

struct FixtureProcess {
    child: Child,
    readers: Vec<JoinHandle<Vec<u8>>>,
}
impl Drop for FixtureProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        for reader in self.readers.drain(..) {
            if let Ok(bytes) = reader.join() {
                if thread::panicking() {
                    eprintln!("runtime fixture: {}", String::from_utf8_lossy(&bytes));
                }
            }
        }
    }
}

fn drain(mut stream: impl Read + Send + 'static) -> JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut captured = Vec::new();
        let mut bytes = [0; 4096];
        loop {
            match stream.read(&mut bytes) {
                Ok(0) => break,
                Ok(count) => {
                    let keep = count.min((64 * 1024usize).saturating_sub(captured.len()));
                    captured.extend_from_slice(&bytes[..keep]);
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        captured
    })
}
