use device_development_mesh::local_ipc::{
    ConnectionState, DaemonRole, DaemonSnapshot, LocalProtocolVersion, LocalRequest, LocalResponse,
};
use devicelane_desktop::{DaemonTransport, DesktopBridge, RepairProcess, repair_spec};
use std::ffi::OsString;
use std::path::Path;
use std::sync::{Arc, Mutex};

struct FakeTransport {
    requests: Arc<Mutex<Vec<LocalRequest>>>,
    response: LocalResponse,
}

struct FakeRepairProcess {
    calls: Mutex<usize>,
}

impl RepairProcess for FakeRepairProcess {
    fn execute(&self, _spec: &devicelane_desktop::RepairSpec) -> Result<(), String> {
        *self.calls.lock().unwrap() += 1;
        Ok(())
    }
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
        daemon_version: "0.1.0-service".into(),
        os: "macOS".into(),
        architecture: "arm64".into(),
        role: DaemonRole::Agent,
        endpoint: "local".into(),
        connection: ConnectionState::Connected,
        local_protocol: LocalProtocolVersion::CURRENT,
        remote_protocol: "mesh/1".into(),
        warnings: vec!["warning".into()],
        remote_access_paused: false,
        autostart: true,
        log_location: "/logs/service.log".into(),
    }
}

#[test]
fn status_maps_the_wire_snapshot_to_the_typed_desktop_contract() {
    let transport = FakeTransport {
        requests: Arc::new(Mutex::new(vec![])),
        response: LocalResponse::Snapshot(snapshot()),
    };
    let bridge = DesktopBridge::new(transport);

    let status = bridge.status().unwrap();

    assert_eq!(status, snapshot());
    assert_eq!(status.public_identity, "mac-agent");
    assert_eq!(status.endpoint, "local");
    assert_eq!(status.remote_protocol, "mesh/1");
    assert_eq!(status.daemon_version, "0.1.0-service");
}

#[test]
fn controls_send_only_versioned_local_ipc_requests() {
    let requests = Arc::new(Mutex::new(vec![]));
    let transport = FakeTransport {
        requests: Arc::clone(&requests),
        response: LocalResponse::Acknowledged,
    };
    let bridge = DesktopBridge::new(transport);

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
    let bridge = DesktopBridge::new(transport);

    assert_eq!(
        bridge.pause().unwrap_err(),
        "daemon error (unauthorized): wrong user"
    );
}

#[test]
fn repair_uses_only_fixed_platform_programs_and_arguments() {
    let root = Path::new("/trusted/resources");
    let linux_binary = Path::new("/trusted/bin/devicelane-service");
    let linux = repair_spec("linux", root, linux_binary).unwrap();
    assert_eq!(linux.program, Path::new("/bin/sh"));
    assert_eq!(
        linux.arguments,
        [root.join("scripts/setup-linux.sh"), "--repair".into()]
    );

    assert_eq!(linux.service_binary, linux_binary);

    let windows_binary = Path::new(r"C:\trusted\bin\devicelane-service.exe");
    let windows = repair_spec("windows", root, windows_binary).unwrap();
    assert_eq!(
        windows.program,
        Path::new(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
    );
    let expected: Vec<OsString> = vec![
        "-NoProfile".into(),
        "-NonInteractive".into(),
        "-ExecutionPolicy".into(),
        "Bypass".into(),
        "-File".into(),
        root.join("scripts").join("setup-windows.ps1").into(),
        "--service-repair".into(),
    ];
    assert_eq!(windows.arguments, expected);
    assert_eq!(windows.service_binary, windows_binary);
}

#[test]
fn fake_process_executes_a_validated_repair_spec_once() {
    let process = FakeRepairProcess {
        calls: Mutex::new(0),
    };
    let spec = devicelane_desktop::RepairSpec {
        program: "/bin/sh".into(),
        arguments: vec!["setup-linux.sh".into(), "--repair".into()],
        service_binary: "/trusted/devicelane-service".into(),
    };

    process.execute(&spec).unwrap();

    assert_eq!(*process.calls.lock().unwrap(), 1);
}
