use device_development_mesh::local_ipc::{
    ConnectionState, LocalEndpoint, LocalProtocolVersion, LocalRequest, LocalResponse,
    local_endpoint, send_local_request,
};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

struct Service(Child);

impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn endpoint_text(_runtime_dir: &std::path::Path) -> String {
    #[cfg(windows)]
    {
        format!(r"\\.\pipe\devicelane-test-{}", std::process::id())
    }
    #[cfg(unix)]
    {
        _runtime_dir
            .canonicalize()
            .unwrap()
            .join("devicelane.sock")
            .display()
            .to_string()
    }
}

fn run_cli(endpoint: &str, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_devicelane"));
    command.args(args).arg("--endpoint").arg(endpoint);
    command.output().expect("run devicelane")
}

fn start_service() -> (tempfile::TempDir, String, LocalEndpoint, Service) {
    let root = tempfile::tempdir().unwrap();
    let runtime = root.path().join("runtime");
    let logs = root.path().join("logs");
    std::fs::create_dir_all(&runtime).unwrap();
    std::fs::create_dir_all(&logs).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let endpoint_text = endpoint_text(&runtime);
    let endpoint = local_endpoint(&runtime, &endpoint_text).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_devicelane-service"))
        .args([
            "--identity",
            root.path().join("identity.json").to_str().unwrap(),
        ])
        .args(["--runtime-dir", runtime.to_str().unwrap()])
        .args(["--role", "workstation"])
        .args(["--registry", "registry.example:443"])
        .args(["--listen", &endpoint_text])
        .args(["--agent-peer", "agent-public-id"])
        .args(["--log-dir", logs.to_str().unwrap()])
        .arg("--foreground")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start service");
    let service = Service(child);
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        // The unreachable registry moves the daemon from Connecting to
        // Disconnected after startup. Compare CLI/direct snapshots only once
        // that initial observation has completed, not across the transition.
        if matches!(send_local_request(
            &endpoint,
            &LocalRequest::Status {
                version: LocalProtocolVersion::CURRENT,
            },
        ), Ok(LocalResponse::Snapshot(snapshot)) if snapshot.connection == ConnectionState::Disconnected)
        {
            return (root, endpoint_text, endpoint, service);
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("service did not become ready")
}

#[test]
fn unified_cli_round_trips_typed_local_requests() {
    let (root, endpoint_text, endpoint, _service) = start_service();
    let direct_status = send_local_request(
        &endpoint,
        &LocalRequest::Status {
            version: LocalProtocolVersion::CURRENT,
        },
    )
    .unwrap();
    let status = run_cli(&endpoint_text, &["status", "--local", "--json"]);
    assert!(
        status.status.success(),
        "{}",
        String::from_utf8_lossy(&status.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<LocalResponse>(&status.stdout).unwrap(),
        direct_status
    );

    let connection = run_cli(
        &endpoint_text,
        &["connection", "status", "--local", "--json"],
    );
    assert!(
        connection.status.success(),
        "{}",
        String::from_utf8_lossy(&connection.stderr)
    );
    let public: serde_json::Value = serde_json::from_slice(&connection.stdout).unwrap();
    assert_eq!(public["type"], "connection_settings");
    assert_eq!(
        public["payload"]["registry_address"],
        "registry.example:443"
    );
    assert_eq!(public["payload"]["registry_peer_id"], "registry");
    assert_eq!(public["payload"].as_object().unwrap().len(), 3);
    let human = run_cli(&endpoint_text, &["connection", "status", "--local"]);
    assert!(human.status.success());
    let human = String::from_utf8(human.stdout).unwrap();
    assert!(human.contains("registry.example:443"));
    assert!(human.contains("Expected peer: registry"));
    assert!(human.contains("Connection:"));

    // The CLI must use the same exact, one-use admin grant as native IPC.
    let target = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = target.local_addr().unwrap().to_string();
    let set = [
        "connection",
        "set",
        "--local",
        "--registry",
        &address,
        "--registry-peer",
        "selected-registry",
    ];
    let denied = run_cli(&endpoint_text, &set);
    assert!(!denied.status.success());
    assert!(
        String::from_utf8_lossy(&denied.stderr).contains("permission_denied"),
        "{}",
        String::from_utf8_lossy(&denied.stderr)
    );
    assert!(!root.path().join("identity.json/connection.json").exists());
    let request = run_cli(
        &endpoint_text,
        &[
            "approvals",
            "request",
            "--local",
            "--admin-mutation",
            "connection_set",
            "--registry",
            &address,
            "--registry-peer",
            "selected-registry",
        ],
    );
    assert!(
        request.status.success(),
        "{}",
        String::from_utf8_lossy(&request.stderr)
    );
    let list = run_cli(&endpoint_text, &["approvals", "list", "--local", "--json"]);
    assert!(list.status.success());
    let LocalResponse::PendingApprovals(mut approvals) =
        serde_json::from_slice(&list.stdout).unwrap()
    else {
        panic!("expected approvals")
    };
    assert_eq!(approvals.len(), 1);
    let approval = approvals.remove(0);
    let decide = run_cli(
        &endpoint_text,
        &[
            "approvals",
            "decide",
            "--local",
            "--approval-id",
            approval.id.as_str(),
            "--decision",
            "allow_once",
        ],
    );
    assert!(
        decide.status.success(),
        "{}",
        String::from_utf8_lossy(&decide.stderr)
    );
    let substituted = run_cli(
        &endpoint_text,
        &[
            "connection",
            "set",
            "--local",
            "--registry",
            &address,
            "--registry-peer",
            "another-registry",
        ],
    );
    assert!(!substituted.status.success());
    assert!(String::from_utf8_lossy(&substituted.stderr).contains("permission_denied"));
    let saved = run_cli(&endpoint_text, &set);
    assert!(
        saved.status.success(),
        "{}",
        String::from_utf8_lossy(&saved.stderr)
    );
    let config = device_development_mesh::connection_config::ConnectionConfig::load(
        &root.path().join("identity.json"),
    )
    .unwrap()
    .unwrap();
    assert_eq!(config.registry_address(), address);
    assert_eq!(config.registry_peer_id(), "selected-registry");
    let settings = run_cli(
        &endpoint_text,
        &["connection", "status", "--local", "--json"],
    );
    assert!(settings.status.success());
    let LocalResponse::ConnectionSettings {
        registry_address,
        registry_peer_id,
        ..
    } = serde_json::from_slice(&settings.stdout).unwrap()
    else {
        panic!("expected connection settings")
    };
    assert_eq!(registry_address.as_deref(), Some(address.as_str()));
    assert_eq!(registry_peer_id.as_deref(), Some("selected-registry"));
    let replay = run_cli(&endpoint_text, &set);
    assert!(!replay.status.success());
    assert!(String::from_utf8_lossy(&replay.stderr).contains("permission_denied"));

    let pause = run_cli(&endpoint_text, &["remote-access", "pause", "--local"]);
    assert!(
        pause.status.success(),
        "{}",
        String::from_utf8_lossy(&pause.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&pause.stdout).trim(),
        "remote access paused"
    );

    let paused = send_local_request(
        &endpoint,
        &LocalRequest::Status {
            version: LocalProtocolVersion::CURRENT,
        },
    )
    .unwrap();
    let LocalResponse::Snapshot(snapshot) = paused else {
        panic!("expected snapshot")
    };
    assert!(snapshot.remote_access_paused);

    let resume = run_cli(&endpoint_text, &["remote-access", "resume", "--local"]);
    assert!(!resume.status.success());
    assert!(String::from_utf8_lossy(&resume.stderr).contains("permission_denied"));

    let direct_diagnostics = send_local_request(
        &endpoint,
        &LocalRequest::Diagnostics {
            version: LocalProtocolVersion::CURRENT,
        },
    )
    .unwrap();
    let diagnostics = run_cli(&endpoint_text, &["diagnostics", "--local", "--json"]);
    assert!(diagnostics.status.success());
    assert_eq!(
        serde_json::from_slice::<LocalResponse>(&diagnostics.stdout).unwrap(),
        direct_diagnostics
    );
}

#[test]
fn invalid_flags_fail_without_panicking_and_legacy_cli_remains() {
    let invalid = Command::new(env!("CARGO_BIN_EXE_devicelane"))
        .args(["status", "--bogus"])
        .output()
        .unwrap();
    assert!(!invalid.status.success());
    assert!(!String::from_utf8_lossy(&invalid.stderr).contains("panicked"));

    let legacy = Command::new(env!("CARGO_BIN_EXE_mesh-cli"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(legacy.status.success());
}

#[test]
fn json_protocol_errors_are_structured_and_fail_the_process() {
    #[cfg(windows)]
    let endpoint = format!(r"\\.\pipe\devicelane-missing-{}", std::process::id());
    #[cfg(unix)]
    let endpoint = "/definitely/missing/devicelane.sock".to_owned();
    for args in [
        &["status", "--local", "--json"][..],
        &["connection", "status", "--local", "--json"][..],
    ] {
        let output = run_cli(&endpoint, args);
        assert!(!output.status.success());
        let response: LocalResponse = serde_json::from_slice(&output.stdout).unwrap();
        let LocalResponse::Error { code, message } = response else {
            panic!("expected structured daemon error")
        };
        assert_eq!(code, "local_ipc_error");
        assert!(!message.is_empty());
    }
}

#[test]
fn subcommand_help_succeeds_and_endpoint_does_not_consume_another_flag() {
    let help = Command::new(env!("CARGO_BIN_EXE_devicelane"))
        .args(["status", "--local", "--help"])
        .output()
        .unwrap();
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("devicelane status"));
    assert!(String::from_utf8_lossy(&help.stdout).contains("devicelane connection status --local"));
    assert!(
        String::from_utf8_lossy(&help.stdout)
            .contains("devicelane connection set --local --registry ADDRESS --registry-peer PEER")
    );
    assert!(String::from_utf8_lossy(&help.stdout).contains("--admin-mutation connection_set"));

    let missing = Command::new(env!("CARGO_BIN_EXE_devicelane"))
        .args(["status", "--local", "--endpoint", "--json"])
        .output()
        .unwrap();
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("missing value for --endpoint"));
}

#[test]
fn connection_flags_are_validated_before_ipc_and_never_ignored() {
    for (args, expected) in [
        (
            vec![
                "connection",
                "set",
                "--registry",
                "127.0.0.1:1",
                "--registry-peer",
                "registry",
            ],
            "require --local",
        ),
        (
            vec!["connection", "set", "--local", "--registry", "127.0.0.1:1"],
            "missing required --registry-peer",
        ),
        (
            vec![
                "connection",
                "set",
                "--local",
                "--registry",
                "https://example.invalid:443",
                "--registry-peer",
                "registry",
            ],
            "invalid --registry or --registry-peer",
        ),
        (
            vec![
                "connection",
                "set",
                "--local",
                "--registry",
                "127.0.0.1:1",
                "--registry",
                "127.0.0.1:2",
                "--registry-peer",
                "registry",
            ],
            "duplicate --registry",
        ),
        (
            vec![
                "approvals",
                "request",
                "--local",
                "--admin-mutation",
                "connection_set",
                "--registry",
                "127.0.0.1:1",
                "--registry-peer",
                "registry",
                "--rule-id",
                "unused",
            ],
            "--rule-id is not valid",
        ),
        (
            vec![
                "approvals",
                "request",
                "--local",
                "--admin-mutation",
                "policy_delete",
                "--rule-id",
                "rule",
                "--registry",
                "127.0.0.1:1",
            ],
            "--registry is not valid",
        ),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_devicelane"))
            .args(args)
            .output()
            .unwrap();
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(expected), "{stderr}");
        assert!(
            !stderr.contains("local IPC"),
            "validation contacted the daemon: {stderr}"
        );
    }
}
