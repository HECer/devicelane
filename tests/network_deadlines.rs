use device_development_mesh::secure_transport::SecureTransport;
use serde_json::Value;
use std::{
    net::TcpListener,
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

#[test]
fn client_receives_registry_agent_timeout_instead_of_timing_out_first() {
    let root = tempfile::tempdir().unwrap();
    let registry_identity = root.path().join("registry");
    let cli_identity = root.path().join("cli");
    pair(&registry_identity, &cli_identity);

    let address = free_address();
    let _registry = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_mesh-registry"))
            .args([
                "--listen",
                &address,
                "--identity",
                registry_identity.to_str().unwrap(),
                "--offline-after-ms",
                "300",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );

    let request = serde_json::json!({
        "principal_id": "principal-1",
        "host_id": "missing-agent",
        "device_id": "iphone-1",
        "workspace_id": "workspace-1",
        "request_id": "deadline-request",
        "manifest": []
    });
    let output = Command::new(env!("CARGO_BIN_EXE_mesh-cli"))
        .args([
            "--registry",
            &address,
            "--identity",
            cli_identity.to_str().unwrap(),
            "run",
            "--json-request",
            &request.to_string(),
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "client failed before the registry deadline: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["error"], "agent_timeout");
}

#[test]
fn pair_reports_a_stable_machine_readable_connection_failure() {
    let root = tempfile::tempdir().unwrap();
    let identity = root.path().join("cli");
    SecureTransport::load_or_create(&identity, "cli").unwrap();
    let address = free_address();
    let mut command = Command::new(env!("CARGO_BIN_EXE_mesh-cli"));
    command.args([
        "pair",
        "--address",
        &address,
        "--identity",
        identity.to_str().unwrap(),
    ]);
    let output = bounded_output(command, Duration::from_secs(15));

    assert!(!output.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).unwrap(),
        serde_json::json!({"error": "connection_unavailable"})
    );
}

fn bounded_output(mut command: Command, timeout: Duration) -> Output {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + timeout;
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            panic!(
                "command did not terminate within {timeout:?}; stderr={}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn pair(registry_identity: &std::path::Path, cli_identity: &std::path::Path) {
    let address = free_address();
    let mut registry = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_mesh-registry"))
            .args([
                "pair",
                "--listen",
                &address,
                "--identity",
                registry_identity.to_str().unwrap(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let output = Command::new(env!("CARGO_BIN_EXE_mesh-cli"))
        .args([
            "pair",
            "--address",
            &address,
            "--identity",
            cli_identity.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(registry.0.wait().unwrap().success());
}

fn free_address() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().to_string()
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
