use device_development_mesh::local_ipc::{
    Authorizer, ConnectionState, DaemonRole, DaemonSnapshot, DaemonState, DiagnosticItem,
    LocalProtocolError, LocalProtocolVersion, LocalRequest, LocalResponse, MAX_FRAME_BYTES,
    PeerCredentials, SameUserAuthorizer, read_frame, validate_state_paths, write_frame,
};
use std::io::{BufReader, Cursor};
use std::path::PathBuf;
#[cfg(windows)]
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
fn service_accepts_endpoint_and_peer_values_but_rejects_relative_state_paths() {
    let service = env!("CARGO_BIN_EXE_devicelane-service");
    let status = Command::new(service)
        .args([
            "--identity",
            r"C:\state\identity",
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
    assert!(status.success());

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
