use device_development_mesh::secure_transport::SecureTransport;
use std::net::TcpListener;
use std::ops::{Deref, DerefMut};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[test]
fn binaries_have_stable_help_and_version_output() {
    for (name, path) in binaries() {
        let help = Command::new(path).arg("--help").output().unwrap();
        assert!(help.status.success());
        assert!(
            String::from_utf8(help.stdout)
                .unwrap()
                .starts_with(&format!("{name} "))
        );

        let version = Command::new(path).arg("--version").output().unwrap();
        assert!(version.status.success());
        assert_eq!(
            String::from_utf8(version.stdout).unwrap(),
            format!("{name} {VERSION}\n")
        );
    }
}

#[test]
fn separate_processes_pair_heartbeat_and_retain_offline_snapshot() {
    let address = free_address();
    let identities = tempfile::tempdir().unwrap();
    pair(
        identities.path().join("registry"),
        "registry",
        identities.path().join("agent"),
        "agent",
    );
    pair(
        identities.path().join("registry"),
        "registry",
        identities.path().join("cli"),
        "cli",
    );
    let registry_identity = identities
        .path()
        .join("registry")
        .to_string_lossy()
        .into_owned();
    let agent_identity = identities
        .path()
        .join("agent")
        .to_string_lossy()
        .into_owned();
    let cli_identity = identities.path().join("cli").to_string_lossy().into_owned();
    let mut registry = spawn(
        env!("CARGO_BIN_EXE_mesh-registry"),
        &[
            "--listen",
            &address,
            "--identity",
            &registry_identity,
            "--offline-after-ms",
            "300",
        ],
    );
    let mut agent = spawn(
        env!("CARGO_BIN_EXE_mesh-agent"),
        &[
            "--registry",
            &address,
            "--identity",
            &agent_identity,
            "--id",
            "mac-1",
            "--os",
            "macos",
            "--arch",
            "aarch64",
            "--capability",
            "apple.build@1",
            "--device",
            "iphone-1:ios:connected",
            "--heartbeat-ms",
            "50",
        ],
    );

    let text = eventually_list(&address, &cli_identity, &[]);
    assert!(text.status.success());
    let text = String::from_utf8(text.stdout).unwrap();
    assert!(text.contains("mac-1 macos aarch64 online"));
    assert!(text.contains("capabilities: apple.build@1"));
    assert!(text.contains("devices: iphone-1 ios connected"));

    let json = eventually_list(&address, &cli_identity, &["--json"]);
    assert!(json.status.success());
    let json: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(json[0]["id"], "mac-1");
    assert_eq!(json[0]["status"], "online");
    assert_eq!(json[0]["capabilities"][0], "apple.build@1");
    assert_eq!(json[0]["devices"][0]["id"], "iphone-1");

    agent.kill().unwrap();
    agent.wait().unwrap();
    thread::sleep(Duration::from_millis(400));
    let offline = eventually_list(&address, &cli_identity, &["--json"]);
    let offline: serde_json::Value = serde_json::from_slice(&offline.stdout).unwrap();
    assert_eq!(offline[0]["status"], "offline");
    assert_eq!(offline[0]["devices"][0]["id"], "iphone-1");

    registry.kill().unwrap();
    registry.wait().unwrap();
}

fn binaries() -> [(&'static str, &'static str); 3] {
    [
        ("mesh-registry", env!("CARGO_BIN_EXE_mesh-registry")),
        ("mesh-agent", env!("CARGO_BIN_EXE_mesh-agent")),
        ("mesh-cli", env!("CARGO_BIN_EXE_mesh-cli")),
    ]
}

fn free_address() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    drop(listener);
    address
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

fn eventually_list(address: &str, identity: &str, extra: &[&str]) -> Output {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let output = Command::new(env!("CARGO_BIN_EXE_mesh-cli"))
            .args(["--registry", address, "--identity", identity, "list"])
            .args(extra)
            .output()
            .unwrap();
        if output.status.success() && !output.stdout.is_empty() {
            return output;
        }
        assert!(
            Instant::now() < deadline,
            "agent did not appear within five seconds: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        thread::sleep(Duration::from_millis(25));
    }
}

fn pair(
    left_path: impl AsRef<std::path::Path>,
    left_id: &str,
    right_path: impl AsRef<std::path::Path>,
    right_id: &str,
) {
    let mut left = SecureTransport::load_or_create(left_path, left_id).unwrap();
    let mut right = SecureTransport::load_or_create(right_path, right_id).unwrap();
    let code = left.issue_pairing_code(Duration::from_secs(10));
    left.accept_pairing(&code, right.certificate_der(), Duration::ZERO)
        .unwrap();
    right
        .trust(left.machine_id(), left.certificate_der())
        .unwrap();
}
