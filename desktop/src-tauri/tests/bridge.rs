use device_development_mesh::local_ipc::{
    ConnectionState, DaemonRole, DaemonSnapshot, LocalProtocolVersion, LocalRequest, LocalResponse,
};
use devicelane_desktop::{DaemonTransport, DesktopBridge};
use std::sync::{Arc, Mutex};

struct FakeTransport {
    requests: Arc<Mutex<Vec<LocalRequest>>>,
    response: LocalResponse,
}

impl DaemonTransport for FakeTransport {
    fn send(&self, request: LocalRequest) -> Result<LocalResponse, String> {
        self.requests.lock().unwrap().push(request);
        Ok(self.response.clone())
    }
}

fn snapshot() -> DaemonSnapshot {
    DaemonSnapshot {
        public_identity: "mac-agent".into(),
        role: DaemonRole::Agent,
        endpoint: "local".into(),
        connection: ConnectionState::Connected,
        local_protocol: LocalProtocolVersion::CURRENT,
        remote_protocol: "mesh/1".into(),
        warnings: vec!["warning".into()],
        remote_access_paused: false,
        autostart: true,
    }
}

#[test]
fn status_maps_the_wire_snapshot_to_the_typed_desktop_contract() {
    let transport = FakeTransport {
        requests: Arc::new(Mutex::new(vec![])),
        response: LocalResponse::Snapshot(snapshot()),
    };
    let bridge = DesktopBridge::new(transport, "macOS", "arm64", "/logs/service.log");

    let status = bridge.status().unwrap();

    assert_eq!(status.os, "macOS");
    assert_eq!(status.architecture, "arm64");
    assert_eq!(status.role, DaemonRole::Agent);
    assert_eq!(status.connection, ConnectionState::Connected);
    assert!(status.autostart_enabled);
    assert_eq!(status.log_location, "/logs/service.log");
}

#[test]
fn controls_send_only_versioned_local_ipc_requests() {
    let requests = Arc::new(Mutex::new(vec![]));
    let transport = FakeTransport {
        requests: Arc::clone(&requests),
        response: LocalResponse::Acknowledged,
    };
    let bridge = DesktopBridge::new(transport, "Windows", "x86_64", "logs");

    bridge.pause().unwrap();
    bridge.resume().unwrap();
    bridge.set_autostart(false).unwrap();

    assert_eq!(
        *requests.lock().unwrap(),
        vec![
            LocalRequest::PauseRemoteAccess {
                version: LocalProtocolVersion::CURRENT
            },
            LocalRequest::ResumeRemoteAccess {
                version: LocalProtocolVersion::CURRENT
            },
            LocalRequest::SetAutostart {
                version: LocalProtocolVersion::CURRENT,
                enabled: false
            },
        ]
    );
}

#[test]
fn daemon_errors_remain_errors_at_the_command_boundary() {
    let transport = FakeTransport {
        requests: Arc::new(Mutex::new(vec![])),
        response: LocalResponse::Error {
            code: "unauthorized".into(),
            message: "wrong user".into(),
        },
    };
    let bridge = DesktopBridge::new(transport, "Linux", "x86_64", "logs");

    assert_eq!(
        bridge.pause().unwrap_err(),
        "daemon error (unauthorized): wrong user"
    );
}
