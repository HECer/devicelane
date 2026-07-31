use device_development_mesh::remote_apple_protocol::{
    AppleOperation, AppleRequest, RemoteProtocolVersion,
};
use device_development_mesh::secure_transport::SecureTransport;
use std::net::TcpListener;
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[test]
fn public_processes_dispatch_apple_job_once_with_progress_cancel_and_reconnect() {
    let address = free_address();
    let temp = tempfile::tempdir().unwrap();
    let registry_identity = temp.path().join("registry");
    let agent_identity = temp.path().join("agent");
    let cli_identity = temp.path().join("cli");
    pair(&registry_identity, "registry", &agent_identity, "agent");
    pair(&registry_identity, "registry", &cli_identity, "cli");
    let workspace = temp.path().join("workspace");
    std::fs::create_dir_all(workspace.join("mac-1/project")).unwrap();
    let marker = workspace.join("mac-1/project/executions");
    let tool = fake_xcodebuild(temp.path());

    let mut registry = spawn(
        env!("CARGO_BIN_EXE_mesh-registry"),
        &[
            "--listen",
            &address,
            "--identity",
            registry_identity.to_str().unwrap(),
            "--offline-after-ms",
            "500",
        ],
    );
    let mut agent = spawn(
        env!("CARGO_BIN_EXE_mesh-agent"),
        &[
            "--registry",
            &address,
            "--identity",
            agent_identity.to_str().unwrap(),
            "--id",
            "mac-1",
            "--os",
            "macos",
            "--arch",
            "aarch64",
            "--workspace-root",
            workspace.to_str().unwrap(),
            "--xcodebuild",
            tool.to_str().unwrap(),
            "--heartbeat-ms",
            "25",
        ],
    );

    let request = AppleRequest {
        version: RemoteProtocolVersion { major: 1, minor: 0 },
        request_id: "apple-request-1".into(),
        idempotency_key: "apple-idempotency-1".into(),
        capability: "apple.build@1".into(),
        workspace_path: "project".into(),
        device_id: None,
        lease_id: None,
        operation: AppleOperation::BuildApp {
            container: "MeshApp.xcodeproj".into(),
            scheme: "MeshApp".into(),
            destination: "platform=iOS Simulator,id=sim-1".into(),
        },
    };
    wait_for_host(&address, &cli_identity);

    let mut invalid_version = request.clone();
    invalid_version.version.major = 2;
    invalid_version.request_id = "invalid-version".into();
    invalid_version.idempotency_key = "invalid-version".into();
    let denied = cli(&address, &cli_identity, "apple-run", &invalid_version);
    let denied: serde_json::Value = serde_json::from_slice(&denied.stdout).unwrap();
    assert_eq!(denied["accepted"], false);
    assert_eq!(denied["error"], "unsupported_version");

    let mut escaped_workspace = request.clone();
    escaped_workspace.workspace_path = "../outside".into();
    escaped_workspace.request_id = "escaped-workspace".into();
    escaped_workspace.idempotency_key = "escaped-workspace".into();
    let denied = cli(&address, &cli_identity, "apple-run", &escaped_workspace);
    let denied: serde_json::Value = serde_json::from_slice(&denied.stdout).unwrap();
    assert_eq!(denied["accepted"], false);
    assert_eq!(denied["error"], "workspace_path_denied");
    assert!(!marker.exists());

    let accepted = cli(&address, &cli_identity, "apple-run", &request);
    assert!(
        accepted.status.success(),
        "{}",
        String::from_utf8_lossy(&accepted.stderr)
    );
    let accepted: serde_json::Value = serde_json::from_slice(&accepted.stdout).unwrap();
    assert_eq!(accepted["accepted"], true);
    let job_id = accepted["job_id"].as_str().unwrap();

    let duplicate = cli(&address, &cli_identity, "apple-run", &request);
    let duplicate: serde_json::Value = serde_json::from_slice(&duplicate.stdout).unwrap();
    assert_eq!(duplicate["job_id"], job_id);
    wait_until("marker", || {
        if marker.exists() {
            true
        } else {
            let current = events(&address, &cli_identity, job_id, 0);
            assert!(
                !current["events"].as_array().is_some_and(|items| items
                    .iter()
                    .any(|e| e["kind"] == "rejected" || e["kind"] == "completed")),
                "job terminated before executing tool: {current}"
            );
            false
        }
    });
    assert_eq!(std::fs::read_to_string(&marker).unwrap().lines().count(), 1);

    wait_until("progress", || {
        events(&address, &cli_identity, job_id, 0)["events"]
            .as_array()
            .is_some_and(|items| items.iter().any(|e| e["kind"] == "started"))
    });
    let progress = events(&address, &cli_identity, job_id, 0);
    assert!(
        progress["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["kind"] == "started")
    );
    let reconnected = events(&address, &cli_identity, job_id, 0);
    assert_eq!(progress["events"], reconnected["events"]);

    let cancelled = cli_value(
        &address,
        &cli_identity,
        "apple-cancel",
        &serde_json::json!({"job_id": job_id}),
    );
    assert_eq!(cancelled["accepted"], true);
    wait_until("cancelled event", || {
        events(&address, &cli_identity, job_id, 0)["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["kind"] == "cancelled")
    });
    assert_eq!(std::fs::read_to_string(marker).unwrap().lines().count(), 1);

    agent.kill().unwrap();
    registry.kill().unwrap();
}

fn fake_xcodebuild(root: &std::path::Path) -> std::path::PathBuf {
    #[cfg(windows)]
    {
        let path = root.join("fake-xcodebuild.cmd");
        std::fs::write(
            &path,
            "@echo off\r\nif \"%1\"==\"-version\" exit /b 0\r\necho run >> executions\r\necho compiling\r\nC:\\Windows\\System32\\ping.exe 127.0.0.1 -n 6 >nul\r\n",
        ).unwrap();
        path
    }
    #[cfg(not(windows))]
    {
        use std::os::unix::fs::PermissionsExt;
        let path = root.join("fake-xcodebuild");
        std::fs::write(
            &path,
            "#!/bin/sh\n[ \"$1\" = \"-version\" ] && exit 0\necho run >> executions\necho compiling\nsleep 30\n",
        ).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }
}

fn free_address() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().to_string()
}

fn pair(left_path: &std::path::Path, left_id: &str, right_path: &std::path::Path, right_id: &str) {
    let mut left = SecureTransport::load_or_create(left_path, left_id).unwrap();
    let mut right = SecureTransport::load_or_create(right_path, right_id).unwrap();
    let code = left.issue_pairing_code(Duration::from_secs(10));
    left.accept_pairing(&code, right.certificate_der(), Duration::ZERO)
        .unwrap();
    right
        .trust(left.machine_id(), left.certificate_der())
        .unwrap();
}

struct ChildGuard(Child);
impl std::ops::Deref for ChildGuard {
    type Target = Child;
    fn deref(&self) -> &Child {
        &self.0
    }
}
impl std::ops::DerefMut for ChildGuard {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.0
    }
}
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn(path: &str, args: &[&str]) -> ChildGuard {
    ChildGuard(
        Command::new(path)
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    )
}

fn cli<T: serde::Serialize>(
    address: &str,
    identity: &std::path::Path,
    command: &str,
    body: &T,
) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mesh-cli"))
        .args([
            "--registry",
            address,
            "--identity",
            identity.to_str().unwrap(),
            command,
            "--json-request",
            &serde_json::to_string(body).unwrap(),
        ])
        .output()
        .unwrap()
}

fn cli_value(
    address: &str,
    identity: &std::path::Path,
    command: &str,
    body: &serde_json::Value,
) -> serde_json::Value {
    serde_json::from_slice(&cli(address, identity, command, body).stdout).unwrap()
}

fn events(
    address: &str,
    identity: &std::path::Path,
    job_id: &str,
    after: u64,
) -> serde_json::Value {
    cli_value(
        address,
        identity,
        "events",
        &serde_json::json!({"job_id": job_id, "after": after}),
    )
}

fn wait_for_host(address: &str, identity: &std::path::Path) {
    wait_until("host", || {
        Command::new(env!("CARGO_BIN_EXE_mesh-cli"))
            .args([
                "--registry",
                address,
                "--identity",
                identity.to_str().unwrap(),
                "list",
                "--json",
            ])
            .output()
            .is_ok_and(|o| {
                o.status.success() && String::from_utf8_lossy(&o.stdout).contains("mac-1")
            })
    });
}

fn wait_until(label: &str, mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !condition() {
        assert!(Instant::now() < deadline, "timed out waiting for {label}");
        thread::sleep(Duration::from_millis(25));
    }
}
