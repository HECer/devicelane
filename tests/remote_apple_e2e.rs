use device_development_mesh::{
    network_processes::{LeaseRequest, ManifestUpload, RunRequest},
    remote_apple_protocol::{AppleOperation, AppleRequest, RemoteProtocolVersion},
    secure_transport::SecureTransport,
};
use sha2::{Digest, Sha256};
use std::{
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

#[test]
fn remote_apple_vertical_slice_survives_reconnect_and_registry_restart() {
    let root = tempfile::tempdir().unwrap();
    let address = free_address();
    let registry_identity = root.path().join("registry");
    let agent_identity = root.path().join("agent");
    let first_identity = root.path().join("client-1");
    let second_identity = root.path().join("client-2");
    pair(&registry_identity, "registry", &agent_identity, "agent");
    pair(&registry_identity, "registry", &first_identity, "client-1");
    pair(&registry_identity, "registry", &second_identity, "client-2");

    let workspace_root = root.path().join("workspaces");
    let project = workspace_root.join("mac-1/project");
    std::fs::create_dir_all(&project).unwrap();
    let marker = root.path().join("apple-tools.log");
    let xcodebuild = fake_tool(root.path(), "xcodebuild", &marker);
    let devicectl = fake_tool(root.path(), "devicectl", &marker);
    let simctl = fake_tool(root.path(), "simctl", &marker);

    let mut registry_process = start_registry(&address, &registry_identity);
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
            workspace_root.to_str().unwrap(),
            "--xcodebuild",
            xcodebuild.to_str().unwrap(),
            "--devicectl",
            devicectl.to_str().unwrap(),
            "--simctl",
            simctl.to_str().unwrap(),
            "--heartbeat-ms",
            "100",
            "--capability",
            "apple.project@1",
            "--capability",
            "apple.build@1",
            "--capability",
            "apple.xctest@1",
            "--capability",
            "apple.simulator@1",
            "--capability",
            "apple.device@1",
            "--device",
            "00008110-001C2D123456801E:ios:connected",
            "--device",
            "sim-1:ios:connected",
        ],
    );
    wait_for_host(&address, &first_identity);
    wait_for_host(&address, &second_identity);
    let discovered = Command::new(env!("CARGO_BIN_EXE_mesh-cli"))
        .args([
            "--registry",
            &address,
            "--identity",
            first_identity.to_str().unwrap(),
            "list",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&discovered.stdout).contains("sim-1"));

    let sync = RunRequest {
        principal_id: "client-1".into(),
        host_id: "mac-1".into(),
        device_id: "iphone-1".into(),
        workspace_id: "project".into(),
        request_id: "sync-33".into(),
        manifest: vec![ManifestUpload {
            path: "MeshApp.xcodeproj/project.pbxproj".into(),
            contents: "fixture".into(),
        }],
    };
    let synced = cli(&address, &first_identity, "run", &sync);
    assert!(synced.status.success());
    wait_until("workspace sync", || {
        project.join("MeshApp.xcodeproj/project.pbxproj").is_file()
    });

    for (index, operation) in vec![
        AppleOperation::DiscoverProject {
            container: "MeshApp.xcodeproj".into(),
        },
        AppleOperation::DiscoverSimulator,
        AppleOperation::BuildApp {
            container: "MeshApp.xcodeproj".into(),
            scheme: "MeshApp".into(),
            destination: "platform=iOS Simulator,id=sim-1".into(),
        },
        AppleOperation::InstallApp {
            app_path: "build/MeshApp.app".into(),
        },
        AppleOperation::LaunchApp {
            bundle_id: "dev.mesh.app".into(),
        },
        AppleOperation::ReadAppLogs {
            bundle_id: "dev.mesh.app".into(),
        },
        AppleOperation::RunXcTest {
            container: "MeshApp.xcodeproj".into(),
            scheme: "MeshAppTests".into(),
            destination: "platform=iOS Simulator,id=sim-1".into(),
        },
    ]
    .into_iter()
    .enumerate()
    {
        let requires_device = operation.requires_device();
        let lease_id = requires_device.then(|| {
            cli_json(
                &address,
                &first_identity,
                "lease",
                &LeaseRequest::Acquire {
                    device_id: "sim-1".into(),
                    lifetime_ms: 30_000,
                },
            )["lease_grant"]["lease_id"]
                .as_str()
                .unwrap()
                .to_owned()
        });
        let request = apple_request(index, operation.clone(), lease_id.clone());
        let accepted = cli_json(&address, &first_identity, "apple-run", &request);
        let job_id = accepted["job_id"].as_str().unwrap().to_owned();
        let terminal = wait_for_terminal(&address, &first_identity, &job_id);
        assert_eq!(
            terminal["kind"],
            "completed",
            "{operation:?}: {terminal}; markers={}",
            std::fs::read_to_string(&marker).unwrap_or_default()
        );

        let artifact = terminal["payload"].as_str().unwrap();
        let downloaded = cli_value(
            &address,
            &first_identity,
            "artifact-download",
            &serde_json::json!({"artifact_id": artifact}),
        );
        let bytes: Vec<u8> = serde_json::from_value(downloaded["bytes"].clone()).unwrap();
        assert_eq!(
            downloaded["sha256"],
            format!("{:x}", Sha256::digest(&bytes))
        );
        assert!(!bytes.is_empty());
        if let Some(lease_id) = lease_id {
            let released = cli_json(
                &address,
                &first_identity,
                "lease",
                &LeaseRequest::Release { lease_id },
            );
            assert_eq!(released["lease_status"], "released");
        }
    }

    let observed = cli_json(
        &address,
        &second_identity,
        "apple-run",
        &apple_request(
            20,
            AppleOperation::DiscoverProject {
                container: "MeshApp.xcodeproj".into(),
            },
            None,
        ),
    );
    assert!(
        wait_for_terminal(
            &address,
            &second_identity,
            observed["job_id"].as_str().unwrap()
        )["kind"]
            == "completed"
    );
    let durable = cli_json(
        &address,
        &first_identity,
        "apple-run",
        &apple_request(
            40,
            AppleOperation::BuildApp {
                container: "MeshApp.xcodeproj".into(),
                scheme: "MeshApp".into(),
                destination: "platform=iOS Simulator,id=sim-1".into(),
            },
            None,
        ),
    );
    let durable_job = durable["job_id"].as_str().unwrap().to_owned();
    let before = wait_for_terminal(&address, &first_identity, &durable_job);
    registry_process.kill().unwrap();
    registry_process.wait().unwrap();
    registry_process = start_registry(&address, &registry_identity);
    wait_for_host(&address, &first_identity);
    let after = wait_for_event_snapshot(&address, &first_identity, &durable_job, &before);
    assert!(after["events"].as_array().unwrap().contains(&before));

    agent.kill().unwrap();
    registry_process.kill().unwrap();
    let markers = std::fs::read_to_string(marker).unwrap();
    assert!(markers.lines().all(|line| line.contains("agent-tool")));
    for alternatives in [
        &["-project MeshApp.xcodeproj -list"][..],
        &[
            "-scheme MeshApp -destination \"platform=iOS Simulator,id=sim-1\" build",
            "-scheme MeshApp -destination platform=iOS Simulator,id=sim-1 build",
        ],
        &["install sim-1 build/MeshApp.app"],
        &["launch sim-1 dev.mesh.app"],
        &["spawn sim-1 log show"],
        &[
            "-scheme MeshAppTests -destination \"platform=iOS Simulator,id=sim-1\" test",
            "-scheme MeshAppTests -destination platform=iOS Simulator,id=sim-1 test",
        ],
    ] {
        assert!(
            alternatives
                .iter()
                .any(|expected| markers.contains(expected)),
            "missing one of {alternatives:?}: {markers}"
        );
    }
}

fn apple_request(
    index: usize,
    operation: AppleOperation,
    lease_id: Option<String>,
) -> AppleRequest {
    AppleRequest {
        version: RemoteProtocolVersion { major: 1, minor: 0 },
        request_id: format!("request-{index}"),
        idempotency_key: format!("idempotency-{index}"),
        capability: operation.capability().into(),
        workspace_path: "project".into(),
        device_id: operation.requires_device().then(|| "sim-1".into()),
        lease_id,
        operation,
    }
}

fn start_registry(address: &str, identity: &Path) -> ChildGuard {
    spawn(
        env!("CARGO_BIN_EXE_mesh-registry"),
        &[
            "--listen",
            address,
            "--identity",
            identity.to_str().unwrap(),
            "--offline-after-ms",
            "500",
        ],
    )
}

fn fake_tool(root: &Path, name: &str, marker: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        let path = root.join(format!("{name}.cmd"));
        std::fs::write(
            &path,
            format!(
                "@echo off\r\necho agent-tool {name} %*>>\"{}\"\r\nif \"%1\"==\"-version\" goto version\r\nif \"{name}\"==\"devicectl\" if \"%1\"==\"list\" goto devices\r\nif \"{name}\"==\"simctl\" if \"%1\"==\"list\" goto simulators\r\necho agent-tool-output {name} %*\r\nexit /b 0\r\n:version\r\necho Xcode 16\r\nexit /b 0\r\n:devices\r\necho {{\"result\":{{\"devices\":[]}}}}\r\nexit /b 0\r\n:simulators\r\necho {{\"devices\":{{\"com.apple.CoreSimulator.SimRuntime.iOS-17-0\":[{{\"udid\":\"sim-1\",\"name\":\"iPhone\",\"state\":\"Booted\",\"isAvailable\":true}}]}}}}\r\nexit /b 0\r\n",
                marker.display()
            ),
        )
        .unwrap();
        path
    }
    #[cfg(not(windows))]
    {
        use std::os::unix::fs::PermissionsExt;
        let path = root.join(name);
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\necho \"agent-tool {name} $*\" >> '{}'\n[ \"$1\" = -version ] && echo 'Xcode 16' && exit 0\n[ '{name}' = devicectl ] && [ \"$1\" = list ] && echo '{{\"result\":{{\"devices\":[]}}}}' && exit 0\n[ '{name}' = simctl ] && [ \"$1\" = list ] && echo '{{\"devices\":{{\"com.apple.CoreSimulator.SimRuntime.iOS-17-0\":[{{\"udid\":\"sim-1\",\"name\":\"iPhone\",\"state\":\"Booted\",\"isAvailable\":true}}]}}}}' && exit 0\necho \"agent-tool-output {name} $*\"\n",
                marker.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }
}

fn cli<T: serde::Serialize>(address: &str, identity: &Path, command: &str, body: &T) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_mesh-cli"))
        .args([
            "--registry",
            address,
            "--identity",
            identity.to_str().unwrap(),
            command,
            "--json-request",
            &serde_json::to_string(body).unwrap(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("mesh-cli timed out");
        }
        thread::sleep(Duration::from_millis(10));
    }
    child.wait_with_output().unwrap()
}

fn cli_json<T: serde::Serialize>(
    address: &str,
    identity: &Path,
    command: &str,
    body: &T,
) -> serde_json::Value {
    let output = cli(address, identity, command, body);
    assert!(
        output.status.success(),
        "mesh-cli {command} failed with {}; stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "mesh-cli {command} returned invalid JSON: {error}; status={}; stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn cli_value(
    address: &str,
    identity: &Path,
    command: &str,
    body: &serde_json::Value,
) -> serde_json::Value {
    cli_json(address, identity, command, body)
}

fn events(address: &str, identity: &Path, job_id: &str, after: u64) -> serde_json::Value {
    cli_value(
        address,
        identity,
        "events",
        &serde_json::json!({"job_id": job_id, "after": after}),
    )
}

fn wait_for_terminal(address: &str, identity: &Path, job_id: &str) -> serde_json::Value {
    let mut terminal = None;
    wait_until("terminal event", || {
        terminal = events(address, identity, job_id, 0)["events"]
            .as_array()
            .and_then(|items| {
                items
                    .iter()
                    .find(|event| matches!(event["kind"].as_str(), Some("completed" | "rejected")))
                    .cloned()
            });
        terminal.is_some()
    });
    terminal.unwrap()
}

fn wait_for_host(address: &str, identity: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let output = Command::new(env!("CARGO_BIN_EXE_mesh-cli"))
            .args([
                "--registry",
                address,
                "--identity",
                identity.to_str().unwrap(),
                "list",
                "--json",
            ])
            .output()
            .unwrap();
        if output.status.success()
            && serde_json::from_slice::<serde_json::Value>(&output.stdout)
                .ok()
                .and_then(|hosts| hosts.as_array().cloned())
                .is_some_and(|hosts| hosts.iter().any(|host| host["id"] == "mac-1"))
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "registry never exposed mac-1 through a valid CLI response; status={}; stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        thread::sleep(Duration::from_millis(25));
    }
}

fn wait_for_event_snapshot(
    address: &str,
    identity: &Path,
    job_id: &str,
    expected: &serde_json::Value,
) -> serde_json::Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let output = cli(
            address,
            identity,
            "events",
            &serde_json::json!({"job_id": job_id, "after": 0}),
        );
        if output.status.success() {
            if let Ok(snapshot) = serde_json::from_slice::<serde_json::Value>(&output.stdout) {
                if snapshot["events"]
                    .as_array()
                    .is_some_and(|events| events.contains(expected))
                {
                    return snapshot;
                }
            }
        }
        assert!(
            Instant::now() < deadline,
            "registry never restored the durable event snapshot; status={}; stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        thread::sleep(Duration::from_millis(25));
    }
}

fn wait_until(label: &str, mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !condition() {
        assert!(Instant::now() < deadline, "timed out waiting for {label}");
        thread::sleep(Duration::from_millis(25));
    }
}

fn pair(registry: &Path, registry_id: &str, peer: &Path, peer_id: &str) {
    let mut left = SecureTransport::load_or_create(registry, registry_id).unwrap();
    let mut right = SecureTransport::load_or_create(peer, peer_id).unwrap();
    let code = left.issue_pairing_code(Duration::from_secs(10));
    left.accept_pairing(&code, right.certificate_der(), Duration::ZERO)
        .unwrap();
    right.trust(registry_id, left.certificate_der()).unwrap();
}

fn free_address() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().to_string()
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
