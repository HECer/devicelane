use device_development_mesh::network_processes::{Request, Response};
use device_development_mesh::secure_transport::SecureTransport;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

fn prepare_service_state_directory(path: &Path) {
    #[cfg(windows)]
    device_development_mesh::state_paths::prepare_private_state_directory(path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir_all(path).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
}

#[test]
fn daemon_controller_serves_inventory_with_its_existing_certificate() {
    // macOS's default temporary directory can exceed the Unix socket path limit.
    #[cfg(unix)]
    let root = tempfile::Builder::new()
        .prefix("dl-")
        .tempdir_in("/tmp")
        .unwrap();
    #[cfg(not(unix))]
    let root = tempfile::tempdir().unwrap();
    let absolute_root = root.path().canonicalize().unwrap();
    let identity = absolute_root.join("identity");
    prepare_service_state_directory(&identity);
    let mut daemon = SecureTransport::load_or_create(&identity, "controller-fixture").unwrap();
    let mut client =
        SecureTransport::load_or_create(absolute_root.join("client"), "fixture-client").unwrap();
    // Fixture-only mutual trust; this test does not establish product pairing support.
    let code = daemon.issue_pairing_code(Duration::from_secs(10));
    daemon
        .accept_pairing(&code, client.certificate_der(), Duration::ZERO)
        .unwrap();
    client
        .trust("controller-fixture", daemon.certificate_der())
        .unwrap();
    let certificate = std::fs::read(identity.join("certificate.der")).unwrap();
    let key = std::fs::read(identity.join("private-key.der")).unwrap();
    assert_eq!(daemon.certificate_der(), certificate);
    assert_ne!(client.certificate_der(), certificate);

    let runtime = absolute_root.join("runtime");
    let logs = absolute_root.join("logs");
    for directory in [&runtime, &logs] {
        prepare_service_state_directory(directory);
    }
    #[cfg(unix)]
    let local_endpoint = runtime.join("controller.sock").to_str().unwrap().to_owned();
    #[cfg(windows)]
    let local_endpoint = format!(
        r"\\.\pipe\devicelane-controller-{}-{}",
        std::process::id(),
        root.path().file_name().unwrap().to_str().unwrap()
    );
    device_development_mesh::local_ipc::local_endpoint(&runtime, &local_endpoint)
        .expect("fixture must provide a valid private local IPC endpoint");

    let reservation = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reservation.local_addr().unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_devicelane-service"));
    command
        .arg("--identity")
        .arg(&identity)
        .arg("--runtime-dir")
        .arg(&runtime)
        .arg("--log-dir")
        .arg(&logs)
        .args([
            "--role",
            "registry",
            "--registry-listen",
            &address.to_string(),
            "--agent-peer",
            "fixture-agent",
            "--listen",
            &local_endpoint,
            "--foreground",
        ]);
    // A competing bind is reported as a startup failure. Only our child is ever killed.
    drop(reservation);
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut process = Process::spawn(&mut command);
    let socket = loop {
        process.assert_running();
        let timeout = match remaining(deadline) {
            Ok(timeout) => timeout,
            Err(error) => panic!("controller did not start at {address}: {error}"),
        };
        match TcpStream::connect_timeout(&address, timeout) {
            Ok(socket) => break socket,
            Err(error) => {
                process.assert_running();
                assert!(
                    Instant::now() < deadline,
                    "controller did not listen at {address}: {error}"
                );
                thread::sleep(
                    Duration::from_millis(20)
                        .min(deadline.saturating_duration_since(Instant::now())),
                );
            }
        }
    };
    process.assert_running();
    socket
        .set_read_timeout(Some(remaining(deadline).unwrap()))
        .unwrap();
    socket
        .set_write_timeout(Some(remaining(deadline).unwrap()))
        .unwrap();
    // Also interrupt a peer that trickles TLS records indefinitely between socket timeouts.
    let _socket_deadline = SocketDeadline::new(&socket, deadline);
    let mut tls = client
        .connect_tls(socket, "controller-fixture")
        .expect("controller must complete normal mutual TLS with the trusted inventory client");
    let peer = tls.conn.peer_certificates().unwrap().first().unwrap();
    assert_eq!(
        peer.as_ref(),
        certificate,
        "controller served a different identity"
    );
    let tls_identity = client.peer_id(peer.as_ref()).unwrap();
    tls.sock
        .set_write_timeout(Some(remaining(deadline).unwrap()))
        .unwrap();
    let mut request = serde_json::to_vec(&Request::List).unwrap();
    request.push(b'\n');
    tls.write_all(&request).unwrap();
    tls.flush().unwrap();
    let mut frame = Vec::new();
    loop {
        tls.sock
            .set_read_timeout(Some(remaining(deadline).unwrap()))
            .unwrap();
        let mut byte = [0];
        tls.read_exact(&mut byte)
            .expect("controller must return an inventory response");
        if byte[0] == b'\n' {
            break;
        }
        assert!(
            frame.len() < 1024 * 1024,
            "inventory response exceeded fixture bound"
        );
        frame.push(byte[0]);
    }
    let response: Response = serde_json::from_slice(&frame).expect("typed inventory response");
    assert!(
        response.accepted,
        "inventory rejected: {:?}",
        response.error
    );
    process.assert_running();
    drop(tls);
    drop(_socket_deadline);
    let endpoint =
        device_development_mesh::local_ipc::local_endpoint(&runtime, &local_endpoint).unwrap();
    let (sender, receiver) = mpsc::channel();
    let ipc_worker = thread::spawn(move || {
        let request = device_development_mesh::local_ipc::LocalRequest::Status {
            version: device_development_mesh::local_ipc::LocalProtocolVersion::CURRENT,
        };
        let response = loop {
            let response =
                device_development_mesh::local_ipc::send_local_request(&endpoint, &request);
            if response.is_ok() || Instant::now() >= deadline {
                break response;
            }
            thread::sleep(Duration::from_millis(20));
        };
        let _ = sender.send(response);
    });
    // The public native IPC client has no caller-supplied deadline. On timeout,
    // stop our child to close its pipe/socket before joining the bounded fixture worker.
    let local_response = receiver.recv_timeout(deadline.saturating_duration_since(Instant::now()));
    if local_response.is_err() {
        let _ = process.child.kill();
        let _ = process.child.wait();
    }
    ipc_worker.join().unwrap();
    let device_development_mesh::local_ipc::LocalResponse::Snapshot(snapshot) = local_response
        .expect("native local IPC status exceeded controller startup deadline")
        .expect("native local IPC status failed")
    else {
        panic!("expected typed daemon snapshot");
    };
    assert_eq!(snapshot.public_identity, "controller-fixture");
    assert_eq!(snapshot.public_identity, tls_identity);
    assert_ne!(
        snapshot.public_identity,
        identity.file_name().unwrap().to_str().unwrap()
    );
    process.assert_running();
    drop(process); // Reap and join pipe readers before reading final files or removing the root.
    assert_eq!(
        std::fs::read(identity.join("certificate.der")).unwrap(),
        certificate
    );
    assert_eq!(
        std::fs::read(identity.join("private-key.der")).unwrap(),
        key
    );
}

#[test]
fn daemon_controller_rejects_corrupt_state_before_becoming_ready() {
    #[cfg(unix)]
    let root = tempfile::Builder::new()
        .prefix("dl-")
        .tempdir_in("/tmp")
        .unwrap();
    #[cfg(not(unix))]
    let root = tempfile::tempdir().unwrap();
    let absolute_root = root.path().canonicalize().unwrap();
    let identity = absolute_root.join("identity");
    prepare_service_state_directory(&identity);
    let mut daemon = SecureTransport::load_or_create(&identity, "controller-fixture").unwrap();
    let peer = SecureTransport::load_or_create(absolute_root.join("peer"), "fixture-peer").unwrap();
    daemon
        .trust("fixture-peer", peer.certificate_der())
        .unwrap();
    let registry_state = identity.join("registry-state");
    let runtime = absolute_root.join("runtime");
    let logs = absolute_root.join("logs");
    for directory in [&registry_state, &runtime, &logs] {
        prepare_service_state_directory(directory);
    }
    let corrupt_state = registry_state.join("vertical-slice.json");
    std::fs::write(&corrupt_state, b"{interrupted durable registry state").unwrap();
    let preserved: Vec<_> = [
        identity.join("certificate.der"),
        identity.join("private-key.der"),
        identity.join("trust").join("fixture-peer.der"),
        corrupt_state,
    ]
    .into_iter()
    .map(|path| {
        let bytes = std::fs::read(&path).unwrap();
        (path, bytes)
    })
    .collect();
    #[cfg(unix)]
    let local_endpoint = runtime.join("controller.sock").to_str().unwrap().to_owned();
    #[cfg(windows)]
    let local_endpoint = format!(
        r"\\.\pipe\devicelane-corrupt-controller-{}-{}",
        std::process::id(),
        root.path().file_name().unwrap().to_str().unwrap()
    );
    device_development_mesh::local_ipc::local_endpoint(&runtime, &local_endpoint)
        .expect("fixture must provide a valid private local IPC endpoint");
    let mut command = Command::new(env!("CARGO_BIN_EXE_devicelane-service"));
    command
        .arg("--identity")
        .arg(&identity)
        .arg("--runtime-dir")
        .arg(&runtime)
        .arg("--log-dir")
        .arg(&logs)
        .args([
            "--role",
            "registry",
            "--registry-listen",
            "127.0.0.1:0",
            "--agent-peer",
            "fixture-agent",
            "--listen",
            &local_endpoint,
            "--foreground",
        ]);
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut process = Process::spawn(&mut command);
    let status = loop {
        if let Some(status) = process.child.try_wait().expect("poll controller startup") {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "controller with corrupt durable state remained alive instead of rejecting startup"
        );
        thread::sleep(Duration::from_millis(20));
    };
    let mut diagnostics = String::new();
    for (_, reader) in process.readers.drain(..) {
        diagnostics.push_str(&String::from_utf8_lossy(&reader.join().unwrap()));
    }
    drop(process);
    assert!(
        !status.success(),
        "corrupt-state startup unexpectedly succeeded"
    );
    assert!(
        diagnostics.contains("recovery_state_corrupt"),
        "startup failed for an unrelated reason: {diagnostics}"
    );
    assert!(
        !diagnostics.contains("devicelane-service: listening on"),
        "controller advertised local readiness before rejecting corrupt state: {diagnostics}"
    );
    for (path, bytes) in preserved {
        assert_eq!(
            std::fs::read(&path).unwrap(),
            bytes,
            "modified {}",
            path.display()
        );
    }
    assert!(!registry_state.join("artifacts").exists());
    assert!(!registry_state.join("device-leases.json").exists());
}

#[test]
fn daemon_controller_rejects_invalid_manifest_without_poisoning_state() {
    use device_development_mesh::local_ipc::{LocalProtocolVersion, LocalRequest, LocalResponse};
    use device_development_mesh::network_processes::{ManifestUpload, RunRequest};
    #[cfg(unix)]
    let root = tempfile::Builder::new()
        .prefix("dl-")
        .tempdir_in("/tmp")
        .unwrap();
    #[cfg(not(unix))]
    let root = tempfile::tempdir().unwrap();
    let absolute_root = root.path().canonicalize().unwrap();
    let identity = absolute_root.join("identity");
    prepare_service_state_directory(&identity);
    let mut authority = SecureTransport::load_or_create(&identity, "controller-fixture").unwrap();
    let mut client =
        SecureTransport::load_or_create(absolute_root.join("client"), "fixture-client").unwrap();
    authority
        .trust("fixture-client", client.certificate_der())
        .unwrap();
    client
        .trust("controller-fixture", authority.certificate_der())
        .unwrap();
    let runtime = absolute_root.join("runtime");
    let logs = absolute_root.join("logs");
    for directory in [&runtime, &logs] {
        prepare_service_state_directory(directory);
    }
    #[cfg(unix)]
    let local_endpoint = runtime.join("controller.sock").to_str().unwrap().to_owned();
    #[cfg(windows)]
    let local_endpoint = format!(
        r"\\.\pipe\devicelane-malformed-run-{}-{}",
        std::process::id(),
        root.path().file_name().unwrap().to_str().unwrap()
    );
    let endpoint =
        device_development_mesh::local_ipc::local_endpoint(&runtime, &local_endpoint).unwrap();
    let reservation = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reservation.local_addr().unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_devicelane-service"));
    command
        .arg("--identity")
        .arg(&identity)
        .arg("--runtime-dir")
        .arg(&runtime)
        .arg("--log-dir")
        .arg(&logs)
        .args([
            "--role",
            "registry",
            "--registry-listen",
            &address.to_string(),
            "--listen",
            &local_endpoint,
            "--foreground",
        ]);
    drop(reservation);
    let mut process = Process::spawn(&mut command);
    let startup_deadline = Instant::now() + Duration::from_secs(10);
    loop {
        process.assert_running();
        match controller_request(address, &client, &Request::List, startup_deadline) {
            Ok(response) => {
                assert!(response.accepted, "initial inventory rejected");
                break;
            }
            Err(error) => {
                assert!(
                    Instant::now() < startup_deadline,
                    "initial inventory failed: {error}"
                );
                thread::sleep(Duration::from_millis(20));
            }
        }
    }
    // Registry TCP starts before dashboard initialization and native IPC serving.
    // Establish both readiness boundaries before exercising malformed input.
    let ready_endpoint = endpoint.clone();
    let (ready_sender, ready_receiver) = mpsc::channel();
    let ready_worker = thread::spawn(move || {
        loop {
            let result = device_development_mesh::local_ipc::send_local_request(
                &ready_endpoint,
                &LocalRequest::Status {
                    version: LocalProtocolVersion::CURRENT,
                },
            );
            if result.is_ok() || Instant::now() >= startup_deadline {
                let _ = ready_sender.send(result);
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
    });
    let ready =
        ready_receiver.recv_timeout(startup_deadline.saturating_duration_since(Instant::now()));
    if ready.is_err() {
        let _ = process.child.kill();
        let _ = process.child.wait();
    }
    ready_worker.join().unwrap();
    assert!(
        matches!(ready, Ok(Ok(LocalResponse::Snapshot(_)))),
        "initial native IPC readiness failed: {ready:?}"
    );
    let before = fixture_tree_excluding(
        &identity,
        Some(std::path::Path::new("registry-state/registry.lock")),
    );
    let request = Request::Run {
        operation: RunRequest {
            principal_id: "fixture-client".into(),
            host_id: "fixture-host".into(),
            device_id: "fixture-device".into(),
            workspace_id: "fixture-workspace".into(),
            request_id: "malformed-manifest".into(),
            manifest: vec![ManifestUpload {
                path: "../escape".into(),
                contents: "must not persist".into(),
            }],
        },
    };
    // Gather all downstream evidence before any malformed-request assertions.
    let malformed = controller_request(
        address,
        &client,
        &request,
        Instant::now() + Duration::from_secs(3),
    );
    let following = controller_request(
        address,
        &client,
        &Request::List,
        Instant::now() + Duration::from_secs(3),
    );
    // List uses inventory state; Events independently acquires the durable-state mutex.
    let durable_read = controller_request(
        address,
        &client,
        &Request::Events {
            job_id: "missing-regression-job".into(),
            after: 0,
        },
        Instant::now() + Duration::from_secs(3),
    );
    let ipc_deadline = Instant::now() + Duration::from_secs(3);
    let (sender, receiver) = mpsc::channel();
    let ipc_worker = thread::spawn(move || {
        let status = device_development_mesh::local_ipc::send_local_request(
            &endpoint,
            &LocalRequest::Status {
                version: LocalProtocolVersion::CURRENT,
            },
        );
        let diagnostics = device_development_mesh::local_ipc::send_local_request(
            &endpoint,
            &LocalRequest::Diagnostics {
                version: LocalProtocolVersion::CURRENT,
            },
        );
        let _ = sender.send((status, diagnostics));
    });
    let ipc = receiver.recv_timeout(ipc_deadline.saturating_duration_since(Instant::now()));
    let alive = process.child.try_wait().unwrap().is_none();
    if ipc.is_err() {
        let _ = process.child.kill();
        let _ = process.child.wait();
    }
    ipc_worker.join().unwrap();
    drop(process);
    let after = fixture_tree_excluding(
        &identity,
        Some(std::path::Path::new("registry-state/registry.lock")),
    );
    let describe = |response: &io::Result<Response>| match response {
        Ok(response) => serde_json::to_string(response).unwrap(),
        Err(error) => format!("transport_error: {error}"),
    };
    let evidence = format!(
        "malformed={}, following={}, durable_read={}, ipc={ipc:?}, alive={alive}, state_changed={}",
        describe(&malformed),
        describe(&following),
        describe(&durable_read),
        before != after
    );
    assert!(
        malformed.is_ok(),
        "malformed request did not receive typed rejection: {evidence}"
    );
    let malformed = malformed.unwrap();
    assert!(!malformed.accepted, "{evidence}");
    assert_eq!(
        malformed.error.as_deref(),
        Some("invalid_manifest_path"),
        "{evidence}"
    );
    assert!(malformed.job_id.is_none(), "{evidence}");
    assert!(
        following.as_ref().is_ok_and(|response| response.accepted),
        "subsequent inventory failed: {evidence}"
    );
    assert!(
        durable_read.as_ref().is_ok_and(|response| response.accepted
            && response.error.is_none()
            && response.job_id.as_deref() == Some("missing-regression-job")
            && response.events.is_empty()),
        "durable state unavailable after malformed request: {evidence}"
    );
    assert!(alive, "{evidence}");
    let (status, diagnostics) = ipc.expect("bounded native IPC responses");
    let LocalResponse::Snapshot(snapshot) =
        status.unwrap_or_else(|error| panic!("native Status: {error:?}; {evidence}"))
    else {
        panic!("expected snapshot: {evidence}")
    };
    assert_eq!(snapshot.public_identity, "controller-fixture", "{evidence}");
    assert!(
        !snapshot
            .warnings
            .iter()
            .any(|code| code.starts_with("registry_")),
        "{evidence}"
    );
    let LocalResponse::Diagnostics(diagnostics) =
        diagnostics.unwrap_or_else(|error| panic!("native Diagnostics: {error:?}; {evidence}"))
    else {
        panic!("expected diagnostics: {evidence}")
    };
    assert!(diagnostics.iter().all(|item| item.healthy), "{evidence}");
    assert!(
        diagnostics
            .iter()
            .any(|item| item.code == "ready" && item.healthy),
        "{evidence}"
    );
    assert_eq!(
        after, before,
        "malformed request changed credentials or durable state: {evidence}"
    );
}

fn controller_request(
    address: std::net::SocketAddr,
    client: &SecureTransport,
    request: &Request,
    deadline: Instant,
) -> io::Result<Response> {
    let socket = TcpStream::connect_timeout(&address, remaining(deadline)?)?;
    socket.set_read_timeout(Some(remaining(deadline)?))?;
    socket.set_write_timeout(Some(remaining(deadline)?))?;
    let _socket_deadline = SocketDeadline::new(&socket, deadline);
    let mut tls = client
        .connect_tls(socket, "controller-fixture")
        .map_err(|error| io::Error::other(format!("mutual TLS: {error:?}")))?;
    let mut frame = serde_json::to_vec(request)?;
    frame.push(b'\n');
    tls.sock.set_write_timeout(Some(remaining(deadline)?))?;
    tls.write_all(&frame)?;
    tls.flush()?;
    frame.clear();
    loop {
        tls.sock.set_read_timeout(Some(remaining(deadline)?))?;
        let mut byte = [0];
        tls.read_exact(&mut byte)?;
        if byte[0] == b'\n' {
            break;
        }
        if frame.len() >= 1024 * 1024 {
            return Err(io::Error::other(
                "controller response exceeded fixture bound",
            ));
        }
        frame.push(byte[0]);
    }
    serde_json::from_slice(&frame).map_err(io::Error::other)
}

#[test]
fn occupied_registry_port_preserves_existing_identity_configuration_and_state() {
    #[cfg(unix)]
    let root = tempfile::Builder::new()
        .prefix("dl-")
        .tempdir_in("/tmp")
        .unwrap();
    #[cfg(not(unix))]
    let root = tempfile::tempdir().unwrap();
    let absolute_root = root.path().canonicalize().unwrap();
    let identity = absolute_root.join("identity");
    prepare_service_state_directory(&identity);
    let mut daemon = SecureTransport::load_or_create(&identity, "controller-fixture").unwrap();
    let peer = SecureTransport::load_or_create(absolute_root.join("peer"), "fixture-peer").unwrap();
    daemon
        .trust("fixture-peer", peer.certificate_der())
        .unwrap();
    device_development_mesh::connection_config::ConnectionConfig::new(
        "127.0.0.1:7443",
        "fixture-peer",
    )
    .unwrap()
    .save(&identity)
    .unwrap();
    let registry_state = identity.join("registry-state");
    let runtime = absolute_root.join("runtime");
    let logs = absolute_root.join("logs");
    for directory in [&registry_state, &runtime, &logs] {
        prepare_service_state_directory(directory);
    }
    std::fs::write(
        registry_state.join("vertical-slice.json"),
        b"existing state must not be opened or changed",
    )
    .unwrap();
    #[cfg(unix)]
    let local_endpoint = runtime.join("controller.sock").to_str().unwrap().to_owned();
    #[cfg(windows)]
    let local_endpoint = format!(
        r"\\.\pipe\devicelane-occupied-controller-{}-{}",
        std::process::id(),
        root.path().file_name().unwrap().to_str().unwrap()
    );
    device_development_mesh::local_ipc::local_endpoint(&runtime, &local_endpoint).unwrap();
    let before = fixture_tree(&absolute_root);
    // Keep this real listener alive through startup and the final usability check.
    let held_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = held_listener.local_addr().unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_devicelane-service"));
    command
        .arg("--identity")
        .arg(&identity)
        .arg("--runtime-dir")
        .arg(&runtime)
        .arg("--log-dir")
        .arg(&logs)
        .args([
            "--role",
            "registry",
            "--registry-listen",
            &address.to_string(),
            "--agent-peer",
            "fixture-agent",
            "--listen",
            &local_endpoint,
            "--foreground",
        ]);
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut process = Process::spawn(&mut command);
    let status = loop {
        if let Some(status) = process.child.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "controller did not reject its occupied registry port"
        );
        thread::sleep(Duration::from_millis(20));
    };
    let mut diagnostics = String::new();
    for (_, reader) in process.readers.drain(..) {
        diagnostics.push_str(&String::from_utf8_lossy(&reader.join().unwrap()));
    }
    drop(process);
    assert!(!status.success());
    assert!(
        diagnostics.contains("cannot bind registry listener:"),
        "unexpected startup failure: {diagnostics}"
    );
    assert!(
        !diagnostics.contains("devicelane-service: listening on"),
        "advertised readiness: {diagnostics}"
    );
    assert_eq!(
        fixture_tree(&absolute_root),
        before,
        "occupied-port startup changed files or created stores/identities"
    );
    held_listener.set_nonblocking(true).unwrap();
    let mut connector = TcpStream::connect_timeout(&address, Duration::from_secs(1)).unwrap();
    connector
        .set_write_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    connector.write_all(b"held-listener").unwrap();
    let accept_deadline = Instant::now() + Duration::from_secs(1);
    let mut accepted = loop {
        match held_listener.accept() {
            Ok((socket, _)) => break socket,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < accept_deadline,
                    "held listener became unusable"
                );
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("held listener failed: {error}"),
        }
    };
    accepted.set_nonblocking(false).unwrap();
    accepted
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let mut payload = [0; 13];
    accepted.read_exact(&mut payload).unwrap();
    assert_eq!(&payload, b"held-listener");
}

#[test]
fn daemon_rejects_ancestor_identity_symlink_before_first_run_writes() {
    ancestor_identity_fixture(env!("CARGO_BIN_EXE_devicelane-service"), true);
}

#[test]
fn daemon_rejects_ineligible_log_root_before_any_first_run_writes() {
    #[cfg(unix)]
    let root = tempfile::Builder::new()
        .prefix("dl-")
        .tempdir_in("/tmp")
        .unwrap();
    #[cfg(not(unix))]
    let root = tempfile::tempdir().unwrap();
    let absolute_root = root.path().canonicalize().unwrap();
    let identity = absolute_root.join("identity");
    let runtime = absolute_root.join("runtime");
    // The filesystem root is only a rejected argument, never a fixture mutation target.
    let filesystem_root = absolute_root.ancestors().last().unwrap();
    assert!(filesystem_root.is_absolute());
    assert!(filesystem_root.parent().is_none());
    assert!(filesystem_root.is_dir());
    std::fs::write(
        absolute_root.join("preserve"),
        b"first-run preflight sentinel",
    )
    .unwrap();
    let before = fixture_tree(&absolute_root);
    assert!(!identity.exists());
    assert!(!runtime.exists());
    #[cfg(unix)]
    let local_endpoint = runtime.join("controller.sock").to_str().unwrap().to_owned();
    #[cfg(windows)]
    let local_endpoint = format!(
        r"\\.\pipe\devicelane-ineligible-root-{}-{}",
        std::process::id(),
        root.path().file_name().unwrap().to_str().unwrap()
    );
    // Do not call local_endpoint here: that helper can create the missing runtime directory.
    let mut command = Command::new(env!("CARGO_BIN_EXE_devicelane-service"));
    command
        .arg("--identity")
        .arg(&identity)
        .arg("--runtime-dir")
        .arg(&runtime)
        .arg("--log-dir")
        .arg(filesystem_root)
        .args([
            "--role",
            "registry",
            "--registry-listen",
            "127.0.0.1:0",
            "--listen",
            &local_endpoint,
            "--foreground",
        ]);
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut process = Process::spawn(&mut command);
    let (status, exceeded_deadline) = loop {
        if let Some(status) = process.child.try_wait().expect("poll preflight fixture") {
            break (status, false);
        }
        if Instant::now() >= deadline {
            process.child.kill().expect("stop owned preflight fixture");
            break (process.child.wait().expect("reap preflight fixture"), true);
        }
        thread::sleep(Duration::from_millis(20));
    };
    let mut diagnostics = String::new();
    for (_, reader) in process.readers.drain(..) {
        diagnostics.push_str(&String::from_utf8_lossy(&reader.join().unwrap()));
    }
    drop(process);
    let after = fixture_tree(&absolute_root);
    assert!(
        !exceeded_deadline,
        "ineligible log-root startup stayed alive; fixture_changed={}; {diagnostics}",
        before != after
    );
    assert!(!status.success(), "ineligible log-root startup succeeded");
    assert!(
        diagnostics.contains("state_path_insecure"),
        "unrelated startup failure: {diagnostics}"
    );
    assert!(
        !diagnostics.contains("listening on"),
        "startup advertised readiness: {diagnostics}"
    );
    assert_eq!(
        after, before,
        "ineligible log-root preflight created earlier identity/runtime paths or changed fixture data"
    );
    assert!(!identity.exists());
    assert!(!runtime.exists());
    #[cfg(unix)]
    assert!(!std::path::Path::new(&local_endpoint).exists());
}

#[test]
fn standalone_relative_identity_preserves_certificate_and_serves_inventory() {
    let root = tempfile::tempdir().unwrap();
    let absolute_root = root.path().canonicalize().unwrap();
    let relative_identity = std::path::Path::new("mesh").join("identity");
    let identity = absolute_root.join(&relative_identity);
    prepare_service_state_directory(&identity);
    let mut authority = SecureTransport::load_or_create(&identity, "controller-relative").unwrap();
    let mut client =
        SecureTransport::load_or_create(absolute_root.join("client"), "fixture-client").unwrap();
    authority
        .trust("fixture-client", client.certificate_der())
        .unwrap();
    client
        .trust("controller-relative", authority.certificate_der())
        .unwrap();
    let certificate = authority.certificate_der().to_vec();
    let original_identity = fixture_tree(&identity);
    let reservation = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reservation.local_addr().unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_mesh-registry"));
    command
        .current_dir(&absolute_root)
        .arg("--identity")
        .arg(&relative_identity)
        .args([
            "--listen",
            &address.to_string(),
            "--offline-after-ms",
            "5000",
        ]);
    drop(reservation);
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut process = Process::spawn(&mut command);
    let socket = loop {
        process.assert_running();
        match TcpStream::connect_timeout(&address, remaining(deadline).unwrap()) {
            Ok(socket) => break socket,
            Err(error) => {
                process.assert_running();
                assert!(
                    Instant::now() < deadline,
                    "relative-identity registry did not listen: {error}"
                );
                thread::sleep(Duration::from_millis(20));
            }
        }
    };
    socket
        .set_read_timeout(Some(remaining(deadline).unwrap()))
        .unwrap();
    socket
        .set_write_timeout(Some(remaining(deadline).unwrap()))
        .unwrap();
    let socket_deadline = SocketDeadline::new(&socket, deadline);
    let mut tls = client.connect_tls(socket, "controller-relative").unwrap();
    let peer = tls.conn.peer_certificates().unwrap().first().unwrap();
    assert_eq!(peer.as_ref(), certificate);
    assert_eq!(
        client.peer_id(peer.as_ref()).unwrap(),
        "controller-relative"
    );
    let mut request = serde_json::to_vec(&Request::List).unwrap();
    request.push(b'\n');
    tls.sock
        .set_write_timeout(Some(remaining(deadline).unwrap()))
        .unwrap();
    tls.write_all(&request).unwrap();
    tls.flush().unwrap();
    let mut frame = Vec::new();
    loop {
        tls.sock
            .set_read_timeout(Some(remaining(deadline).unwrap()))
            .unwrap();
        let mut byte = [0; 1];
        tls.read_exact(&mut byte).unwrap();
        if byte[0] == b'\n' {
            break;
        }
        assert!(frame.len() < 1024 * 1024);
        frame.push(byte[0]);
    }
    let response: Response = serde_json::from_slice(&frame).unwrap();
    assert!(
        response.accepted,
        "relative-identity inventory rejected: {:?}",
        response.error
    );
    process.assert_running();
    drop(tls);
    drop(socket_deadline);
    drop(process);
    let persisted_identity = fixture_tree(&identity);
    for (path, bytes) in original_identity {
        assert_eq!(
            persisted_identity.get(&path),
            Some(&bytes),
            "changed existing identity/trust path {}",
            path.display()
        );
    }
    assert!(identity.join("device-leases.json").is_file());
    assert!(identity.join("artifacts").is_dir());
    for path in fixture_tree(&absolute_root).keys() {
        assert!(
            path == std::path::Path::new("mesh")
                || path.starts_with(&relative_identity)
                || path.starts_with("client"),
            "registry wrote outside selected relative identity: {}",
            path.display()
        );
    }
}

#[test]
fn standalone_rejects_ancestor_identity_symlink_before_first_run_writes() {
    ancestor_identity_fixture(env!("CARGO_BIN_EXE_mesh-registry"), false);
}

fn ancestor_identity_fixture(program: &str, service: bool) {
    #[cfg(unix)]
    let root = tempfile::Builder::new()
        .prefix("dl-")
        .tempdir_in("/tmp")
        .unwrap();
    #[cfg(not(unix))]
    let root = tempfile::tempdir().unwrap();
    let absolute_root = root.path().canonicalize().unwrap();
    let target = absolute_root.join("target");
    let runtime = absolute_root.join("runtime");
    let logs = absolute_root.join("logs");
    for directory in [&target, &runtime, &logs] {
        prepare_service_state_directory(directory);
    }
    std::fs::write(target.join("preserve"), b"owned target sentinel").unwrap();
    // Snapshot only the real target subtree. The fixture root itself contains
    // the intentional link and must not be passed to the recursive tree reader.
    let before = fixture_tree(&target);
    let link = absolute_root.join("link");
    #[cfg(windows)]
    std::os::windows::fs::symlink_dir(&target, &link)
        .expect("fixture requires Windows directory symlink permission; setup failed");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&target, &link)
        .expect("fixture requires an actual ancestor directory symlink; setup failed");
    assert!(
        std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(
        std::fs::read_link(&link).unwrap().canonicalize().unwrap(),
        target.canonicalize().unwrap()
    );
    let identity = link.join("nested").join("identity");
    assert!(!target.join("nested").exists());
    #[cfg(unix)]
    let local_endpoint = runtime.join("controller.sock").to_str().unwrap().to_owned();
    #[cfg(windows)]
    let local_endpoint = format!(
        r"\\.\pipe\devicelane-ancestor-{}-{}-{}",
        std::process::id(),
        service,
        root.path().file_name().unwrap().to_str().unwrap()
    );
    device_development_mesh::local_ipc::local_endpoint(&runtime, &local_endpoint).unwrap();
    let mut command = Command::new(program);
    command.arg("--identity").arg(&identity);
    if service {
        command
            .arg("--runtime-dir")
            .arg(&runtime)
            .arg("--log-dir")
            .arg(&logs)
            .args([
                "--role",
                "registry",
                "--registry-listen",
                "127.0.0.1:0",
                "--agent-peer",
                "fixture-agent",
                "--listen",
                &local_endpoint,
                "--foreground",
            ]);
    } else {
        command.args(["--listen", "127.0.0.1:0", "--offline-after-ms", "5000"]);
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut process = Process::spawn(&mut command);
    let (status, exceeded_deadline) = loop {
        if let Some(status) = process
            .child
            .try_wait()
            .expect("poll ancestor fixture process")
        {
            break (status, false);
        }
        if Instant::now() >= deadline {
            process
                .child
                .kill()
                .expect("stop owned ancestor fixture process");
            break (
                process
                    .child
                    .wait()
                    .expect("reap owned ancestor fixture process"),
                true,
            );
        }
        thread::sleep(Duration::from_millis(20));
    };
    let mut diagnostics = String::new();
    for (_, reader) in process.readers.drain(..) {
        diagnostics.push_str(&String::from_utf8_lossy(&reader.join().unwrap()));
    }
    drop(process);
    // Inspect side effects only after the child is reaped, including the RED
    // path where baseline first-run startup creates credentials and stays alive.
    let after = fixture_tree(&target);
    let nested_created = target.join("nested").exists();
    assert!(
        !exceeded_deadline,
        "ancestor identity startup remained alive; target_changed={}, nested_created={nested_created}; {diagnostics}",
        before != after
    );
    assert!(
        !status.success(),
        "ancestor identity startup unexpectedly succeeded"
    );
    assert!(
        diagnostics.contains("state_path_insecure"),
        "unrelated startup failure: {diagnostics}"
    );
    assert!(
        !diagnostics.contains("listening on"),
        "startup advertised readiness: {diagnostics}"
    );
    assert_eq!(
        after, before,
        "startup modified the symlink's owned target subtree"
    );
    assert!(
        !nested_created,
        "startup created missing ancestors/identity through the link"
    );
}

fn fixture_tree(
    root: &std::path::Path,
) -> std::collections::BTreeMap<std::path::PathBuf, Option<Vec<u8>>> {
    fixture_tree_excluding(root, None)
}

fn fixture_tree_excluding(
    root: &std::path::Path,
    excluded: Option<&std::path::Path>,
) -> std::collections::BTreeMap<std::path::PathBuf, Option<Vec<u8>>> {
    fn visit(
        root: &std::path::Path,
        directory: &std::path::Path,
        entries: &mut std::collections::BTreeMap<std::path::PathBuf, Option<Vec<u8>>>,
        excluded: Option<&std::path::Path>,
    ) {
        for entry in std::fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            let relative = path.strip_prefix(root).unwrap().to_owned();
            if excluded == Some(relative.as_path()) {
                continue;
            }
            if path.is_dir() {
                entries.insert(relative, None);
                visit(root, &path, entries, excluded);
            } else {
                entries.insert(relative, Some(std::fs::read(path).unwrap()));
            }
        }
    }
    let mut entries = std::collections::BTreeMap::new();
    visit(root, root, &mut entries, excluded);
    entries
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "controller startup deadline expired",
        ))
    } else {
        Ok(remaining.min(Duration::from_secs(1)))
    }
}

struct SocketDeadline {
    cancel: Option<mpsc::Sender<()>>,
    worker: Option<JoinHandle<()>>,
}

impl SocketDeadline {
    fn new(socket: &TcpStream, deadline: Instant) -> Self {
        let socket = socket.try_clone().unwrap();
        let (cancel, receiver) = mpsc::channel();
        let worker = thread::spawn(move || {
            if receiver.recv_timeout(deadline.saturating_duration_since(Instant::now()))
                == Err(mpsc::RecvTimeoutError::Timeout)
            {
                let _ = socket.shutdown(Shutdown::Both);
            }
        });
        Self {
            cancel: Some(cancel),
            worker: Some(worker),
        }
    }
}

impl Drop for SocketDeadline {
    fn drop(&mut self) {
        self.cancel.take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

struct Process {
    child: Child,
    readers: Vec<(&'static str, JoinHandle<Vec<u8>>)>,
}

impl Process {
    fn spawn(command: &mut Command) -> Self {
        let child = command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn devicelane-service");
        // Install the guard before spawning readers so unwinding still reaps the child.
        let mut process = Self {
            child,
            readers: Vec::new(),
        };
        let stdout = process.child.stdout.take().unwrap();
        process.readers.push(("stdout", drain(stdout)));
        let stderr = process.child.stderr.take().unwrap();
        process.readers.push(("stderr", drain(stderr)));
        process
    }

    fn assert_running(&mut self) {
        if let Some(status) = self.child.try_wait().expect("poll devicelane-service") {
            panic!("devicelane-service exited before serving inventory: {status}");
        }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        for (name, reader) in self.readers.drain(..) {
            if let Ok(bytes) = reader.join() {
                if thread::panicking() {
                    eprintln!(
                        "devicelane-service {name} (first 64 KiB): {}",
                        String::from_utf8_lossy(&bytes)
                    );
                }
            }
        }
    }
}

fn drain(mut pipe: impl Read + Send + 'static) -> JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut captured = Vec::new();
        let mut chunk = [0; 4096];
        loop {
            match pipe.read(&mut chunk) {
                Ok(0) => break,
                Ok(count) => {
                    let keep = count.min((64 * 1024usize).saturating_sub(captured.len()));
                    captured.extend_from_slice(&chunk[..keep]);
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        captured
    })
}
