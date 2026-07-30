use serde_json::Value;
use std::net::TcpListener;
use std::ops::{Deref, DerefMut};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

#[test]
fn real_vertical_slice_resumes_without_reexecution_and_survives_registry_restart() {
    let root = tempfile::tempdir().unwrap();
    let registry_id = root.path().join("registry");
    let cli_id = root.path().join("cli");
    let agent_id = root.path().join("agent");
    let agent_workspaces = root.path().join("agent-workspaces");
    pair_process(env!("CARGO_BIN_EXE_mesh-cli"), &registry_id, &cli_id);
    pair_process(env!("CARGO_BIN_EXE_mesh-agent"), &registry_id, &agent_id);

    let address = free_address();
    let mut registry_process = registry(&address, &registry_id);
    let _agent_process = agent(&address, &agent_id, &agent_workspaces);
    let request = serde_json::json!({
        "principal_id": "principal-1", "host_id": "mac-1", "device_id": "iphone-1",
        "workspace_id": "workspace-1", "request_id": "request-1",
        "manifest": [{"path": "src/main.rs", "contents": "fn main() {}"}]
    });
    let first = cli(&address, &cli_id, "run", Some(&request));
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let first: Value = serde_json::from_slice(&first.stdout).unwrap();
    let job_id = first["job_id"].as_str().unwrap();
    let first_events = first["events"].as_array().unwrap();
    assert_eq!(first_events[0]["sequence"], 1);
    assert_eq!(first_events.last().unwrap()["kind"], "exit");
    assert_eq!(first_events.last().unwrap()["payload"], "0");
    assert_eq!(first["artifact"], "manifest_files=1");
    assert_eq!(
        std::fs::read_to_string(agent_workspaces.join("mac-1/workspace-1/src/main.rs")).unwrap(),
        "fn main() {}"
    );
    assert!(
        !registry_id.join("workspaces").exists(),
        "the control plane executed a host job locally"
    );

    let cursor = first_events[0]["sequence"].as_u64().unwrap();
    let resumed = cli(
        &address,
        &cli_id,
        "events",
        Some(&serde_json::json!({"job_id": job_id, "after": cursor})),
    );
    let resumed: Value = serde_json::from_slice(&resumed.stdout).unwrap();
    assert_eq!(resumed["events"], Value::Array(first_events[1..].to_vec()));

    let duplicate = cli(&address, &cli_id, "run", Some(&request));
    let duplicate: Value = serde_json::from_slice(&duplicate.stdout).unwrap();
    assert_eq!(duplicate["job_id"], job_id);
    assert_eq!(duplicate["events"], first["events"]);
    assert_eq!(duplicate["artifact"], first["artifact"]);

    registry_process.kill().unwrap();
    registry_process.wait().unwrap();
    let _restarted_registry = registry(&address, &registry_id);
    thread::sleep(Duration::from_millis(100));
    let recovered = cli(
        &address,
        &cli_id,
        "events",
        Some(&serde_json::json!({"job_id": job_id, "after": 0})),
    );
    let recovered: Value = serde_json::from_slice(&recovered.stdout).unwrap();
    assert_eq!(recovered["events"], first["events"]);
    assert_eq!(recovered["artifact"], "manifest_files=1");
    let audit = recovered["audit"].as_array().unwrap();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0]["principal_id"], "principal-1");
    assert_eq!(audit[0]["host_id"], "mac-1");
    assert_eq!(audit[0]["device_id"], "iphone-1");
    assert_eq!(audit[0]["workspace_id"], "workspace-1");
    assert_eq!(audit[0]["job_id"], job_id);
    assert_eq!(audit[0]["result"], "succeeded");
}

fn pair_process(binary: &str, registry_identity: &std::path::Path, peer_identity: &std::path::Path) {
    let pairing_address = free_address();
    let mut pairing_server = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_mesh-registry"))
            .args([
                "pair",
                "--listen",
                &pairing_address,
                "--identity",
                registry_identity.to_str().unwrap(),
            ])
            .spawn()
            .unwrap(),
    );
    let pairing = Command::new(binary)
        .args([
            "pair",
            "--address",
            &pairing_address,
            "--identity",
            peer_identity.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        pairing.status.success(),
        "{}",
        String::from_utf8_lossy(&pairing.stderr)
    );
    assert!(pairing_server.wait().unwrap().success());
}

fn cli(
    address: &str,
    identity: &std::path::Path,
    command: &str,
    body: Option<&Value>,
) -> std::process::Output {
    let mut process = Command::new(env!("CARGO_BIN_EXE_mesh-cli"));
    process.args([
        "--registry",
        address,
        "--identity",
        identity.to_str().unwrap(),
        command,
    ]);
    if let Some(body) = body {
        process.args(["--json-request", &body.to_string()]);
    }
    process.output().unwrap()
}

fn registry(address: &str, identity: &std::path::Path) -> ChildGuard {
    ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_mesh-registry"))
            .args([
                "--listen",
                address,
                "--identity",
                identity.to_str().unwrap(),
                "--offline-after-ms",
                "300",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    )
}

fn agent(
    address: &str,
    identity: &std::path::Path,
    workspaces: &std::path::Path,
) -> ChildGuard {
    ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_mesh-agent"))
            .args([
                "--registry",
                address,
                "--identity",
                identity.to_str().unwrap(),
                "--id",
                "mac-1",
                "--os",
                "macos",
                "--arch",
                "aarch64",
                "--capability",
                "process.start@1",
                "--device",
                "iphone-1:ios:connected",
                "--heartbeat-ms",
                "25",
                "--workspace-root",
                workspaces.to_str().unwrap(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    )
}

fn free_address() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().to_string()
}

struct ChildGuard(Child);
impl Deref for ChildGuard {
    type Target = Child;
    fn deref(&self) -> &Child {
        &self.0
    }
}
impl DerefMut for ChildGuard {
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
