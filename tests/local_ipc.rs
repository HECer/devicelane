use device_development_mesh::local_ipc::{
    Authorizer, ConnectionState, DaemonRole, DaemonSnapshot, DaemonState, DiagnosticItem,
    LocalProtocolError, LocalProtocolVersion, LocalRequest, LocalResponse, MAX_FRAME_BYTES,
    PeerCredentials, SameUserAuthorizer, read_frame, send_local_request, send_raw_local_frame,
    validate_state_paths, write_frame,
};
use std::io::{BufReader, Cursor};
use std::path::PathBuf;
use std::process::Command;

fn snapshot() -> DaemonSnapshot {
    DaemonSnapshot {
        public_identity: "sha256:public-fingerprint".into(),
        role: DaemonRole::Workstation,
        endpoint: "local://devicelane".into(),
        connection: ConnectionState::Connected,
        local_protocol: LocalProtocolVersion::CURRENT,
        remote_protocol: "1.0".into(),
        warnings: vec!["certificate expires soon".into()],
        remote_access_paused: false,
        autostart: false,
    }
}

#[test]
fn request_contract_is_strict_and_rejects_incompatible_major_versions() {
    let encoded = serde_json::to_string(&LocalRequest::Status {
        version: LocalProtocolVersion::CURRENT,
    })
    .unwrap();
    assert!(encoded.contains(r#""request":"status""#));
    let unknown = r#"{"request":"status","version":{"major":1,"minor":0},"extra":true}"#;
    assert!(serde_json::from_str::<LocalRequest>(unknown).is_err());

    let request = LocalRequest::Status {
        version: LocalProtocolVersion { major: 2, minor: 0 },
    };
    assert_eq!(
        request.validate(),
        Err(LocalProtocolError::IncompatibleVersion)
    );
}

#[test]
fn status_response_exposes_only_public_operational_fields() {
    let response = LocalResponse::Snapshot(snapshot());
    let json = serde_json::to_string(&response).unwrap();
    for expected in [
        "public_identity",
        "role",
        "endpoint",
        "connection",
        "local_protocol",
        "remote_protocol",
        "warnings",
    ] {
        assert!(json.contains(expected), "missing {expected}: {json}");
    }
    assert!(!json.contains("private_key"));
    assert!(!json.contains("private-key"));
    assert!(!json.contains("key_der"));
}

#[test]
fn daemon_state_supports_status_pause_resume_autostart_and_diagnostics() {
    let mut state = DaemonState::new(
        snapshot(),
        vec![DiagnosticItem {
            code: "ready".into(),
            message: "daemon ready".into(),
            healthy: true,
        }],
    );
    let version = LocalProtocolVersion::CURRENT;

    assert!(matches!(
        state.handle(LocalRequest::Status { version }),
        Ok(LocalResponse::Snapshot(_))
    ));
    assert_eq!(
        state.handle(LocalRequest::PauseRemoteAccess { version }),
        Ok(LocalResponse::Acknowledged)
    );
    assert!(state.snapshot().remote_access_paused);
    assert_eq!(
        state.handle(LocalRequest::ResumeRemoteAccess { version }),
        Ok(LocalResponse::Acknowledged)
    );
    assert!(!state.snapshot().remote_access_paused);
    assert_eq!(
        state.handle(LocalRequest::SetAutostart {
            version,
            enabled: true
        }),
        Ok(LocalResponse::Acknowledged)
    );
    assert!(state.snapshot().autostart);
    assert!(
        matches!(state.handle(LocalRequest::Diagnostics { version }), Ok(LocalResponse::Diagnostics(items)) if items.len() == 1)
    );
}

#[test]
fn newline_frames_round_trip_and_are_bounded() {
    let request = LocalRequest::Status {
        version: LocalProtocolVersion::CURRENT,
    };
    let mut wire = Vec::new();
    write_frame(&mut wire, &request).unwrap();
    assert_eq!(wire.last(), Some(&b'\n'));
    assert_eq!(
        read_frame::<_, LocalRequest>(&mut BufReader::new(Cursor::new(wire))).unwrap(),
        request
    );

    let oversized = vec![b'x'; MAX_FRAME_BYTES + 1];
    let error =
        read_frame::<_, LocalRequest>(&mut BufReader::new(Cursor::new(oversized))).unwrap_err();
    assert_eq!(error, LocalProtocolError::FrameTooLarge);
}

struct SameUser;

impl Authorizer for SameUser {
    fn authorize(&self, peer: &PeerCredentials) -> bool {
        matches!(peer, PeerCredentials::Unix { uid: 42, .. })
    }
}

#[test]
fn authorization_uses_os_peer_credentials() {
    assert!(SameUser.authorize(&PeerCredentials::Unix {
        uid: 42,
        gid: 7,
        pid: Some(9)
    }));
    assert!(!SameUser.authorize(&PeerCredentials::Unix {
        uid: 41,
        gid: 7,
        pid: Some(9)
    }));
}

#[test]
fn platform_authorizer_rejects_unauthenticated_and_different_users() {
    let authorizer = SameUserAuthorizer::unix(42);
    assert!(!authorizer.authorize(&PeerCredentials::Unix {
        uid: 41,
        gid: 7,
        pid: Some(9)
    }));
    assert!(authorizer.authorize(&PeerCredentials::Unix {
        uid: 42,
        gid: 7,
        pid: Some(9)
    }));
    assert!(!authorizer.authorize(&PeerCredentials::Windows {
        process_id: 9,
        user_sid: String::new()
    }));
}

#[test]
fn state_paths_must_be_absolute_before_transport_binding() {
    let absolute = if cfg!(windows) {
        PathBuf::from(r"C:\devicelane")
    } else {
        PathBuf::from("/var/lib/devicelane")
    };
    assert!(validate_state_paths([absolute.as_path()]).is_ok());
    assert_eq!(
        validate_state_paths([std::path::Path::new("relative")]),
        Err(LocalProtocolError::StatePathNotAbsolute)
    );
}

#[test]
#[cfg(windows)]
fn service_rejects_relative_state_paths_before_binding() {
    let service = env!("CARGO_BIN_EXE_devicelane-service");
    let status = Command::new(service)
        .args([
            "--identity",
            "relative",
            "--runtime-dir",
            r"C:\state\run",
            "--role",
            "workstation",
            "--registry",
            "registry.example:7443",
            "--listen",
            r"\\.\pipe\devicelane-test",
            "--agent-peer",
            "mac-agent-1",
            "--log-dir",
            r"C:\state\logs",
        ])
        .status()
        .unwrap();
    assert!(!status.success());
}

#[test]
#[cfg(windows)]
fn production_named_pipe_serves_state_and_recovers_after_bad_frames() {
    let pipe = format!(r"\\.\pipe\devicelane-e2e-{}", std::process::id());
    let temp = tempfile::tempdir().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_devicelane-service"))
        .args([
            "--identity",
            temp.path().join("identity").to_str().unwrap(),
            "--runtime-dir",
            temp.path().to_str().unwrap(),
            "--role",
            "workstation",
            "--registry",
            "registry.example:7443",
            "--listen",
            &pipe,
            "--agent-peer",
            "mac-agent-1",
            "--log-dir",
            temp.path().join("logs").to_str().unwrap(),
        ])
        .spawn()
        .unwrap();

    let endpoint = device_development_mesh::local_ipc::LocalEndpoint::NamedPipe(pipe);
    let request = LocalRequest::Status {
        version: LocalProtocolVersion::CURRENT,
    };
    let first = (0..100)
        .find_map(|_| {
            send_local_request(&endpoint, &request).ok().or_else(|| {
                std::thread::sleep(std::time::Duration::from_millis(20));
                None
            })
        })
        .expect("service did not bind named pipe");
    assert!(matches!(first, LocalResponse::Snapshot(snapshot) if !snapshot.remote_access_paused));

    assert!(matches!(
        send_local_request(
            &endpoint,
            &LocalRequest::PauseRemoteAccess {
                version: LocalProtocolVersion::CURRENT
            }
        )
        .unwrap(),
        LocalResponse::Acknowledged
    ));
    assert!(
        matches!(send_local_request(&endpoint, &request).unwrap(), LocalResponse::Snapshot(snapshot) if snapshot.remote_access_paused)
    );

    assert!(matches!(
        send_raw_local_frame(&endpoint, b"not-json\n").unwrap(),
        LocalResponse::Error { .. }
    ));
    let oversized = vec![b'x'; MAX_FRAME_BYTES + 1];
    assert!(matches!(
        send_raw_local_frame(&endpoint, &oversized).unwrap(),
        LocalResponse::Error { .. }
    ));
    assert!(matches!(
        send_local_request(&endpoint, &request).unwrap(),
        LocalResponse::Snapshot(_)
    ));
    assert!(
        child.try_wait().unwrap().is_none(),
        "service exited instead of remaining available"
    );
    child.kill().unwrap();
    child.wait().unwrap();
}

#[test]
#[cfg(unix)]
fn production_unix_socket_serves_state_and_recovers_after_bad_frames() {
    let temp = tempfile::tempdir().unwrap();
    let socket = temp.path().join("devicelane.sock");
    let identity = temp.path().join("identity");
    let logs = temp.path().join("logs");
    let mut child = Command::new(env!("CARGO_BIN_EXE_devicelane-service"))
        .args([
            "--identity",
            identity.to_str().unwrap(),
            "--runtime-dir",
            temp.path().to_str().unwrap(),
            "--role",
            "workstation",
            "--registry",
            "registry.example:7443",
            "--listen",
            socket.to_str().unwrap(),
            "--agent-peer",
            "mac-agent-1",
            "--log-dir",
            logs.to_str().unwrap(),
        ])
        .spawn()
        .unwrap();
    let endpoint = device_development_mesh::local_ipc::LocalEndpoint::UnixSocket(socket);
    let request = LocalRequest::Status {
        version: LocalProtocolVersion::CURRENT,
    };
    let first = (0..100)
        .find_map(|_| {
            send_local_request(&endpoint, &request).ok().or_else(|| {
                std::thread::sleep(std::time::Duration::from_millis(20));
                None
            })
        })
        .expect("service did not bind Unix socket");
    assert!(matches!(first, LocalResponse::Snapshot(snapshot) if !snapshot.remote_access_paused));
    assert!(matches!(
        send_local_request(
            &endpoint,
            &LocalRequest::PauseRemoteAccess {
                version: LocalProtocolVersion::CURRENT
            }
        )
        .unwrap(),
        LocalResponse::Acknowledged
    ));
    assert!(
        matches!(send_local_request(&endpoint, &request).unwrap(), LocalResponse::Snapshot(snapshot) if snapshot.remote_access_paused)
    );
    assert!(matches!(
        send_raw_local_frame(&endpoint, b"not-json\n").unwrap(),
        LocalResponse::Error { .. }
    ));
    let oversized = vec![b'x'; MAX_FRAME_BYTES + 1];
    assert!(matches!(
        send_raw_local_frame(&endpoint, &oversized).unwrap(),
        LocalResponse::Error { .. }
    ));
    assert!(matches!(
        send_local_request(&endpoint, &request).unwrap(),
        LocalResponse::Snapshot(_)
    ));
    assert!(child.try_wait().unwrap().is_none());
    child.kill().unwrap();
    child.wait().unwrap();
}
