use device_development_mesh::local_ipc::{
    LocalEndpoint, LocalProtocolVersion, LocalRequest, LocalResponse, local_endpoint,
    send_local_request,
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
        _runtime_dir.join("devicelane.sock").display().to_string()
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
        if send_local_request(
            &endpoint,
            &LocalRequest::Status {
                version: LocalProtocolVersion::CURRENT,
            },
        )
        .is_ok()
        {
            return (root, endpoint_text, endpoint, service);
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("service did not become ready")
}

#[test]
fn unified_cli_round_trips_typed_local_requests() {
    let (_root, endpoint_text, endpoint, _service) = start_service();
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
    assert!(
        resume.status.success(),
        "{}",
        String::from_utf8_lossy(&resume.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&resume.stdout).trim(),
        "remote access resumed"
    );

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
