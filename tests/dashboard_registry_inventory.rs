use device_development_mesh::dashboard::{DashboardScope, Freshness, HostId};
use device_development_mesh::local_ipc::{
    LocalProtocolVersion, LocalRequest, LocalResponse, MeshRpcBoundary, PersistentMeshRpcBoundary,
    RemoteExecutionConfig, local_endpoint, send_local_request,
};
use device_development_mesh::secure_transport::SecureTransport;
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn(binary: &str, args: &[&str]) -> Process {
    Process(
        Command::new(binary)
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    )
}

#[test]
fn local_snapshot_responds_before_blocked_authenticated_inventory_is_released() {
    use std::io::{BufRead, BufReader, Write};
    use std::sync::mpsc;
    let root = tempfile::tempdir().unwrap();
    let identity = root.path().join("workstation");
    let mut registry =
        SecureTransport::load_or_create(root.path().join("registry"), "registry").unwrap();
    let mut client = SecureTransport::load_or_create(&identity, "workstation").unwrap();
    registry
        .trust("workstation", client.certificate_der())
        .unwrap();
    client
        .trust("registry", registry.certificate_der())
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    listener.set_nonblocking(true).unwrap();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let peer = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        let socket = loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "observer never connected");
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("accept failed: {error}"),
            }
        };
        socket.set_nonblocking(false).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut stream = registry.accept_tls(socket).unwrap();
        let mut request = String::new();
        BufReader::new(&mut stream).read_line(&mut request).unwrap();
        assert!(matches!(
            serde_json::from_str::<device_development_mesh::network_processes::Request>(&request)
                .unwrap(),
            device_development_mesh::network_processes::Request::List
        ));
        entered_tx.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match release_rx.recv_timeout(Duration::from_millis(20)) {
                Ok(()) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    assert!(
                        Instant::now() < deadline,
                        "test failed to release inventory gate"
                    );
                    // Keep the real TLS read pending without completing its JSON frame or
                    // allowing the socket inactivity timeout to end the observation early.
                    stream.write_all(b" ").unwrap();
                    stream.flush().unwrap();
                }
                Err(error) => panic!("inventory gate disconnected: {error}"),
            }
        }
        stream
            .write_all(b"{\"accepted\":true,\"hosts\":[]}\n")
            .unwrap();
        stream.flush().unwrap();
    });
    let runtime = root.path().join("runtime");
    let logs = root.path().join("logs");
    std::fs::create_dir_all(&runtime).unwrap();
    std::fs::create_dir_all(&logs).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    #[cfg(windows)]
    let listen = format!(
        r"\\.\pipe\devicelane-blocked-inventory-{}",
        std::process::id()
    );
    #[cfg(unix)]
    let listen = runtime
        .canonicalize()
        .unwrap()
        .join("blocked.sock")
        .display()
        .to_string();
    let endpoint = local_endpoint(&runtime, &listen).unwrap();
    let _service = spawn(
        env!("CARGO_BIN_EXE_devicelane-service"),
        &[
            "--identity",
            identity.to_str().unwrap(),
            "--runtime-dir",
            runtime.to_str().unwrap(),
            "--role",
            "workstation",
            "--registry",
            &address,
            "--listen",
            &listen,
            "--log-dir",
            logs.to_str().unwrap(),
        ],
    );
    entered_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("no authenticated inventory request");
    let (snapshot_tx, snapshot_rx) = mpsc::channel();
    let query = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let response = send_local_request(
                &endpoint,
                &LocalRequest::DashboardSnapshot {
                    version: LocalProtocolVersion::CURRENT,
                    scope: DashboardScope::Local,
                },
            );
            if response.is_ok() || Instant::now() >= deadline {
                let _ = snapshot_tx.send(response);
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    });
    let snapshot = snapshot_rx.recv_timeout(Duration::from_secs(2));
    release_tx.send(()).unwrap();
    peer.join().unwrap();
    query.join().unwrap();
    assert!(
        matches!(snapshot, Ok(Ok(LocalResponse::DashboardSnapshot(_)))),
        "IPC snapshot did not finish while the authenticated List response was blocked"
    );
}

#[test]
fn actual_service_observes_registry_inventory_and_recovers_after_disconnect() {
    let root = tempfile::tempdir().unwrap();
    let registry_path = root.path().join("registry");
    let client_path = root.path().join("workstation");
    let agent_path = root.path().join("agent");
    let hostile_path = root.path().join("hostile-agent");
    let mut registry = SecureTransport::load_or_create(&registry_path, "registry").unwrap();
    for (path, id) in [
        (&client_path, "workstation"),
        (&agent_path, "agent"),
        (&hostile_path, "hostile-agent"),
    ] {
        let mut peer = SecureTransport::load_or_create(path, id).unwrap();
        registry.trust(id, peer.certificate_der()).unwrap();
        peer.trust("registry", registry.certificate_der()).unwrap();
    }
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    drop(listener);
    let registry_args = [
        "--listen",
        &address,
        "--identity",
        registry_path.to_str().unwrap(),
        "--offline-after-ms",
        "5000",
        "--agent-peer",
        "agent",
        "--agent-peer",
        "hostile-agent",
    ];
    let mut registry_process = spawn(env!("CARGO_BIN_EXE_mesh-registry"), &registry_args);
    let mut agent = spawn(
        env!("CARGO_BIN_EXE_mesh-agent"),
        &[
            "--registry",
            &address,
            "--identity",
            agent_path.to_str().unwrap(),
            "--id",
            "mac-inventory",
            "--os",
            "macos",
            "--arch",
            "aarch64",
            "--capability",
            "apple.build@1",
            "--device",
            "iphone-inventory:ios:connected",
            "--heartbeat-ms",
            "100",
        ],
    );
    let runtime = root.path().join("runtime");
    let logs = root.path().join("logs");
    std::fs::create_dir_all(&runtime).unwrap();
    std::fs::create_dir_all(&logs).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    #[cfg(windows)]
    let listen = format!(r"\\.\pipe\devicelane-inventory-{}", std::process::id());
    #[cfg(unix)]
    let listen = runtime
        .canonicalize()
        .unwrap()
        .join("inventory.sock")
        .display()
        .to_string();
    let endpoint = local_endpoint(&runtime, &listen).unwrap();
    let _service = spawn(
        env!("CARGO_BIN_EXE_devicelane-service"),
        &[
            "--identity",
            client_path.to_str().unwrap(),
            "--runtime-dir",
            runtime.to_str().unwrap(),
            "--role",
            "workstation",
            "--registry",
            &address,
            "--listen",
            &listen,
            "--log-dir",
            logs.to_str().unwrap(),
        ],
    );
    let mac_id = HostId::parse("mac-inventory").unwrap();
    let config = RemoteExecutionConfig {
        registry_address: address.clone(),
        registry_peer_id: "registry".into(),
        identity_path: client_path.clone(),
        client_id: "workstation".into(),
    };
    let boundary = PersistentMeshRpcBoundary::default();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(response) = boundary.call(
            &config,
            &device_development_mesh::network_processes::Request::List,
        ) {
            if response.accepted && response.hosts.iter().any(|host| host.id == "mac-inventory") {
                break;
            }
        }
        assert!(
            Instant::now() < deadline,
            "agent never reached authenticated registry"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let wait_for = |live: bool| {
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut last_snapshot = None;
        loop {
            let started = Instant::now();
            if let Ok(LocalResponse::DashboardSnapshot(snapshot)) = send_local_request(
                &endpoint,
                &LocalRequest::DashboardSnapshot {
                    version: LocalProtocolVersion::CURRENT,
                    scope: DashboardScope::Mesh,
                },
            ) {
                assert!(
                    started.elapsed() < Duration::from_secs(2),
                    "registry I/O blocked the local dashboard"
                );
                if let Some(host) = snapshot.hosts.iter().find(|host| host.id == mac_id) {
                    let matches = if live {
                        host.freshness == Freshness::Live
                    } else {
                        matches!(host.freshness, Freshness::Stale { .. })
                    };
                    if matches {
                        assert_eq!(host.platform.as_str(), "macos");
                        assert!(
                            host.capabilities
                                .iter()
                                .any(|code| code.as_str() == "apple.build@1")
                        );
                        assert_eq!(host.devices.len(), 1);
                        return host.clone();
                    }
                }
                last_snapshot = Some(snapshot);
            }
            assert!(
                Instant::now() < deadline,
                "real service never projected registry host with live={live}: {last_snapshot:?}"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    };
    wait_for(true);
    let LocalResponse::DashboardSnapshot(local) = send_local_request(
        &endpoint,
        &LocalRequest::DashboardSnapshot {
            version: LocalProtocolVersion::CURRENT,
            scope: DashboardScope::Local,
        },
    )
    .unwrap() else {
        panic!("missing local snapshot")
    };
    assert_eq!(local.hosts.len(), 1);
    assert_eq!(local.hosts[0].id.as_str(), "workstation");
    registry_process.0.kill().unwrap();
    registry_process.0.wait().unwrap();
    wait_for(false);
    registry_process = spawn(env!("CARGO_BIN_EXE_mesh-registry"), &registry_args);
    wait_for(true);
    assert!(registry_process.0.try_wait().unwrap().is_none());
    agent.0.kill().unwrap();
    agent.0.wait().unwrap();
    let offline = wait_for(false);
    for _ in 0..3 {
        std::thread::sleep(Duration::from_millis(1100));
        assert_eq!(
            wait_for(false).freshness,
            offline.freshness,
            "polling an offline agent must not advance its last-seen timestamp"
        );
    }
    let _reconnected_agent = spawn(
        env!("CARGO_BIN_EXE_mesh-agent"),
        &[
            "--registry",
            &address,
            "--identity",
            agent_path.to_str().unwrap(),
            "--id",
            "mac-inventory",
            "--os",
            "macos",
            "--arch",
            "aarch64",
            "--capability",
            "apple.build@1",
            "--device",
            "iphone-inventory:ios:connected",
            "--heartbeat-ms",
            "100",
        ],
    );
    wait_for(true);
    let hostile_boundary = PersistentMeshRpcBoundary::default();
    let hostile_config = RemoteExecutionConfig {
        registry_address: address.clone(),
        registry_peer_id: "registry".into(),
        identity_path: hostile_path,
        client_id: "hostile-agent".into(),
    };
    for unsafe_id in [
        "forged\x1b[2J",
        "forged\nline",
        "forged\rline",
        "forged\u{009b}2J",
    ] {
        let response = hostile_boundary
            .call(
                &hostile_config,
                &device_development_mesh::network_processes::Request::Heartbeat {
                    host: device_development_mesh::network_processes::HostSnapshot {
                        id: unsafe_id.into(),
                        operating_system: "macos".into(),
                        architecture: "arm64".into(),
                        status: "online".into(),
                        capabilities: vec!["apple.build@1".into()],
                        devices: Vec::new(),
                    },
                },
            )
            .unwrap();
        assert!(
            !response.accepted,
            "registry accepted an unsafe authenticated heartbeat"
        );
        assert_eq!(response.error.as_deref(), Some("invalid_host_inventory"));
    }
    for _ in 0..3 {
        std::thread::sleep(Duration::from_millis(1100));
        assert_eq!(wait_for(true).freshness, Freshness::Live);
        let LocalResponse::DashboardSnapshot(snapshot) = send_local_request(
            &endpoint,
            &LocalRequest::DashboardSnapshot {
                version: LocalProtocolVersion::CURRENT,
                scope: DashboardScope::Mesh,
            },
        )
        .unwrap() else {
            panic!("missing snapshot")
        };
        assert!(
            snapshot
                .hosts
                .iter()
                .all(|host| !host.id.as_str().chars().any(char::is_control)
                    && !host.display_name.chars().any(char::is_control))
        );
    }
}
