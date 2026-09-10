use super::*;
use std::process::{Command, Stdio};
use std::sync::mpsc;

#[test]
fn registry_worker_panic_stops_admission() {
    bounded_fixture("registry_worker_panic_stops_admission", |root| {
        let (mut runtime, _) = runtime(root, panic_hook());
        let address = runtime.local_addr();
        connect(address).write_all(b"!").unwrap();
        await_failure(&runtime.status());
        assert!(
            runtime.stopping.load(Ordering::Acquire),
            "failed registry did not stop admission"
        );
        assert!(
            TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_err(),
            "failed registry admitted a socket after publishing failure"
        );
        let deadline = Instant::now() + Duration::from_secs(2);
        while TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_ok() {
            assert!(
                Instant::now() < deadline,
                "failed registry still admits sockets"
            );
            thread::sleep(Duration::from_millis(10));
        }
        assert!(runtime.stopping.load(Ordering::Acquire));
        assert!(runtime.shutdown().is_err());
        await_failure(&runtime.status());
    });
}

#[test]
fn registry_worker_panic_joins_cleanup() {
    bounded_fixture("registry_worker_panic_joins_cleanup", |root| {
        for during_shutdown in [false, true] {
            let root = root.join(if during_shutdown {
                "shutdown"
            } else {
                "running"
            });
            let (entered_tx, entered) = mpsc::channel();
            let (release, released) = mpsc::channel();
            let released = Mutex::new(released);
            let (panic_entered_tx, panic_entered) = mpsc::channel();
            let (trigger, triggered) = mpsc::channel();
            let triggered = Mutex::new(triggered);
            let joined = Arc::new(AtomicBool::new(false));
            let worker_joined = joined.clone();
            let hook = Arc::new(move |mut socket: &TcpStream, state: &Mutex<DurableState>| {
                socket
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut byte = [0];
                if socket.peek(&mut byte).unwrap_or(0) == 0 {
                    return;
                }
                match byte[0] {
                    b'!' => {
                        panic_entered_tx.send(()).unwrap();
                        triggered.lock().unwrap().recv().unwrap();
                        let _state = state.lock().unwrap();
                        panic!("private dispatcher fault");
                    }
                    b'~' => {
                        socket.read_exact(&mut byte).unwrap();
                        entered_tx.send(()).unwrap();
                        released.lock().unwrap().recv().unwrap();
                        worker_joined.store(true, Ordering::Release);
                    }
                    _ => {}
                }
            });
            let (mut runtime, client) = runtime(&root, hook);
            let address = runtime.local_addr();
            let status = runtime.status();
            let idle = connect(address);
            let mut held = connect(address);
            held.write_all(b"~").unwrap();
            entered.recv_timeout(Duration::from_secs(2)).unwrap();
            let mut partial_tls = connect(address);
            partial_tls.write_all(&[0x16, 0x03, 0x03, 0]).unwrap();
            let mut authenticated = client
                .connect_tls(connect(address), "controller-fixture")
                .unwrap();
            authenticated.write_all(b"{").unwrap();
            authenticated.flush().unwrap();
            let authenticated_socket = authenticated.sock.try_clone().unwrap();
            connect(address).write_all(b"!").unwrap();
            panic_entered.recv_timeout(Duration::from_secs(2)).unwrap();
            if during_shutdown {
                runtime.stopping.store(true, Ordering::Release);
                assert_closed(held.try_clone().unwrap());
            }
            trigger.send(()).unwrap();
            await_failure(&status);
            if !during_shutdown {
                assert_closed(held.try_clone().unwrap());
            }
            assert_closed(idle);
            assert_closed(partial_tls);
            assert_closed(authenticated_socket);
            assert!(!joined.load(Ordering::Acquire));
            assert!(!runtime.worker.as_ref().unwrap().is_finished());
            let lock = open_state_lock(&root.join("state/registry.lock")).unwrap();
            let error = fs2::FileExt::try_lock_exclusive(&lock).unwrap_err();
            assert_eq!(
                error.raw_os_error(),
                fs2::lock_contended_error().raw_os_error()
            );
            release.send(()).unwrap();
            assert!(runtime.shutdown().is_err());
            assert!(joined.load(Ordering::Acquire));
            fs2::FileExt::try_lock_exclusive(&lock)
                .expect("writer lock leaked after joined shutdown");
            await_failure(&status);
        }
    });
}

#[test]
fn registry_worker_panic_degrades_ipc() {
    bounded_fixture("registry_worker_panic_degrades_ipc", |root| {
        let (mut runtime, client) = runtime(root, panic_hook());
        let mut daemon = super::terminal_status_tests::daemon();
        daemon.attach_registry_status(runtime.status());
        let request: Request = serde_json::from_value(serde_json::json!({
            "request": "run",
            "operation": {
                "principal_id": "fixture-client", "host_id": "host", "device_id": "device",
                "workspace_id": "workspace", "request_id": "invalid-manifest",
                "manifest": [{"path": "../escape", "contents": "fixture"}]
            }
        }))
        .unwrap();
        let rejected = rpc(runtime.local_addr(), &client, &request);
        assert!(!rejected.accepted);
        assert_eq!(rejected.error.as_deref(), Some("invalid_manifest_path"));
        assert!(rpc(runtime.local_addr(), &client, &Request::List).accepted);
        assert_eq!(runtime.status().snapshot(), RegistryRuntimeState::Running);
        use crate::local_ipc::{
            ConnectionState, LocalProtocolVersion, LocalRequest, LocalResponse,
        };
        let LocalResponse::Snapshot(snapshot) = daemon
            .handle(LocalRequest::Status {
                version: LocalProtocolVersion::CURRENT,
            })
            .unwrap()
        else {
            panic!("expected snapshot")
        };
        assert_ne!(snapshot.connection, ConnectionState::Degraded);
        connect(runtime.local_addr()).write_all(b"!").unwrap();
        await_failure(&runtime.status());
        super::terminal_status_tests::assert_degraded(&mut daemon, "registry_worker_panicked");
        assert!(runtime.shutdown().is_err());
    });
}

fn panic_hook() -> DispatchHook {
    Arc::new(|socket, state| {
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut byte = [0];
        if socket.peek(&mut byte).unwrap_or(0) == 1 && byte[0] == b'!' {
            let _state = state.lock().unwrap();
            panic!("private dispatcher fault");
        }
    })
}

fn runtime(root: &Path, hook: DispatchHook) -> (RegistryRuntime, SecureTransport) {
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
    let runtime = RegistryRuntime::start_inner(
        RegistryRuntimeConfig {
            listener: TcpListener::bind("127.0.0.1:0").unwrap(),
            transport: Arc::new(authority),
            state_root: root.join("state"),
            offline_after: Duration::from_secs(10),
            agent_peers: HashSet::new(),
            recovery_policy: RegistryRecoveryPolicy::Reject,
        },
        Some(hook),
    )
    .unwrap();
    (runtime, client)
}

fn connect(address: SocketAddr) -> TcpStream {
    let socket = TcpStream::connect_timeout(&address, Duration::from_secs(2)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    socket
}

fn await_failure(status: &RegistryStatus) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while status.snapshot()
        != (RegistryRuntimeState::Failed {
            code: "registry_worker_panicked",
        })
    {
        assert!(
            Instant::now() < deadline,
            "worker panic left status {:?}",
            status.snapshot()
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn assert_closed(mut socket: TcpStream) {
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut bytes = [0; 1024];
    loop {
        match socket.read(&mut bytes) {
            Ok(0) => return,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::BrokenPipe
                ) =>
            {
                return;
            }
            Ok(_) => assert!(Instant::now() < deadline, "socket kept producing data"),
            Err(error) => panic!("tracked socket was not closed: {error}"),
        }
    }
}

fn rpc(address: SocketAddr, client: &SecureTransport, request: &Request) -> Response {
    let mut tls = client
        .connect_tls(connect(address), "controller-fixture")
        .unwrap();
    serde_json::to_writer(&mut tls, request).unwrap();
    tls.write_all(b"\n").unwrap();
    tls.flush().unwrap();
    let mut line = String::new();
    BufReader::new(tls).read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap()
}

fn bounded_fixture(name: &str, fixture: impl FnOnce(&Path)) {
    const CHILD: &str = "DEVICELANE_WORKER_PANIC_FIXTURE";
    if std::env::var(CHILD).as_deref() == Ok(name) {
        let root = PathBuf::from(std::env::var_os("DEVICELANE_WORKER_PANIC_ROOT").unwrap());
        fixture(&root);
        fs::write(root.join("completed"), name).unwrap();
        return;
    }
    let root = test_tempdir();
    let fixture_root = root.path().join("fixture");
    crate::dashboard::audit::create_private_dir(&fixture_root).unwrap();
    let output = fs::File::create(root.path().join("output")).unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            &format!("registry_runtime::lifecycle::worker_failure_tests::{name}"),
            "--nocapture",
        ])
        .env(CHILD, name)
        .env("DEVICELANE_WORKER_PANIC_ROOT", &fixture_root)
        .stdin(Stdio::null())
        .stdout(output.try_clone().unwrap())
        .stderr(output)
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!(
                "{name} stranded cleanup: {}",
                fs::read_to_string(root.path().join("output")).unwrap()
            );
        }
        thread::sleep(Duration::from_millis(20));
    };
    assert!(
        status.success(),
        "{name} failed: {}",
        fs::read_to_string(root.path().join("output")).unwrap()
    );
    assert_eq!(
        fs::read_to_string(fixture_root.join("completed")).unwrap(),
        name
    );
}

fn test_tempdir() -> tempfile::TempDir {
    #[cfg(windows)]
    if let Some(parent) = std::env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .map(|profile| profile.join("AppData/Local"))
        .filter(|parent| parent.is_dir())
    {
        let root = tempfile::tempdir_in(parent).unwrap();
        return root;
    }
    tempfile::tempdir().unwrap()
}
