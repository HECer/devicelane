use command_group::{CommandGroup, GroupChild};
use device_development_mesh::{
    network_processes::{LeaseRequest, ManifestUpload, RunRequest},
    remote_apple_protocol::{AppleOperation, AppleRequest, RemoteProtocolVersion},
    secure_transport::SecureTransport,
};
use sha2::{Digest, Sha256};
use std::{
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

#[test]
#[cfg(windows)]
fn child_guard_terminates_descendants() {
    let root = tempfile::tempdir().unwrap();
    let marker = root.path().join("descendant-pid");
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--ignored", "--exact", "child_guard_parent_fixture"])
        .env("DEVICELANE_TEST_DESCENDANT_PID", &marker);
    let parent = spawn_command(&mut command);
    let deadline = Instant::now() + Duration::from_secs(10);
    while !marker.exists() {
        assert!(Instant::now() < deadline, "descendant did not start");
        thread::sleep(Duration::from_millis(20));
    }
    let descendant: u32 = std::fs::read_to_string(&marker).unwrap().parse().unwrap();
    drop(parent);
    // Query and clean up only the PID created by this fixture. Cleanup on RED
    // prevents the deliberately exposed orphan from surviving the test.
    let result = Command::new("powershell.exe")
        .args(["-NoProfile", "-Command", &format!(
            "if (Get-Process -Id {descendant} -ErrorAction SilentlyContinue) {{ Stop-Process -Id {descendant} -Force; exit 1 }}; exit 0"
        )])
        .status()
        .unwrap();
    assert!(result.success(), "child guard left its descendant running");
}

#[test]
#[ignore = "subprocess fixture for child_guard_terminates_descendants"]
#[cfg(windows)]
fn child_guard_parent_fixture() {
    if std::env::var_os("DEVICELANE_TEST_DESCENDANT_PID").is_none() {
        return;
    }
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "child_guard_leaf_fixture"])
        .spawn()
        .unwrap();
    child.wait().unwrap();
}

#[test]
#[ignore = "subprocess fixture for child_guard_terminates_descendants"]
#[cfg(windows)]
fn child_guard_leaf_fixture() {
    let Some(marker) = std::env::var_os("DEVICELANE_TEST_DESCENDANT_PID") else {
        return;
    };
    std::fs::write(marker, std::process::id().to_string()).unwrap();
    thread::sleep(Duration::from_secs(60));
}

#[test]
fn dashboard_job_preserves_live_inventory_during_real_mesh_execution() {
    use device_development_mesh::dashboard::policy::{AccessRequest, RemoteOperationGrant};
    use device_development_mesh::dashboard::{
        ActivityId, ActivityState, ApprovalDecision, DashboardScope, DeviceId, Freshness, HostId,
        OperationId, PrincipalId, ResourceClass,
    };
    use device_development_mesh::local_ipc::{
        LocalProtocolVersion, LocalRequest, LocalResponse, local_endpoint, send_local_request,
    };
    let root = tempfile::tempdir().unwrap();
    let address = free_address();
    let registry_identity = root.path().join("registry");
    let agent_identity = root.path().join("agent");
    let other_identity = root.path().join("inventory-agent");
    let service_identity = root.path().join("mac-1");
    let controller_identity = root.path().join("windows-client");
    for (path, id) in [
        (&agent_identity, "agent"),
        (&other_identity, "inventory-agent"),
        (&service_identity, "mac-1"),
        (&controller_identity, "windows-client"),
    ] {
        pair(&registry_identity, "registry", path, id);
    }
    let _registry = spawn(
        env!("CARGO_BIN_EXE_mesh-registry"),
        &[
            "--listen",
            &address,
            "--identity",
            registry_identity.to_str().unwrap(),
            "--offline-after-ms",
            "5000",
            "--agent-peer",
            "agent",
            "--agent-peer",
            "inventory-agent",
        ],
    );
    let workspace = root.path().join("workspaces");
    std::fs::create_dir_all(workspace.join("mac-1/project/build/App.app")).unwrap();
    let marker = root.path().join("tools.log");
    let simctl = fake_tool(root.path(), "simctl", &marker);
    let xcodebuild = fake_tool(root.path(), "xcodebuild", &marker);
    let release_install = root.path().join("release-install");
    let script = std::fs::read_to_string(&simctl).unwrap();
    #[cfg(windows)]
    let script = script.replace("echo agent-tool-output", &format!(
        ":wait_install\r\nif \"%1\"==\"install\" if not exist \"{}\" (\r\n ping -n 2 127.0.0.1 >nul\r\n goto wait_install\r\n)\r\necho agent-tool-output", release_install.display()));
    #[cfg(unix)]
    let script = script.replace("echo \"agent-tool-output", &format!(
        "while [ \"$1\" = install ] && [ ! -f '{}' ]; do sleep 0.05; done\necho \"agent-tool-output", release_install.display()));
    std::fs::write(&simctl, script).unwrap();
    let _agent = spawn(
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
            "--simctl",
            simctl.to_str().unwrap(),
            "--xcodebuild",
            xcodebuild.to_str().unwrap(),
            "--capability",
            "apple.simulator@1",
            "--device",
            "sim-1:ios:connected",
            "--heartbeat-ms",
            "100",
        ],
    );
    let _other_agent = spawn(
        env!("CARGO_BIN_EXE_mesh-agent"),
        &[
            "--registry",
            &address,
            "--identity",
            other_identity.to_str().unwrap(),
            "--peer-id",
            "inventory-agent",
            "--id",
            "other-mac",
            "--os",
            "macos",
            "--arch",
            "aarch64",
            "--heartbeat-ms",
            "100",
        ],
    );
    let runtime = root.path().join("runtime");
    let logs = root.path().join("logs");
    std::fs::create_dir_all(&runtime).unwrap();
    std::fs::create_dir_all(&logs).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    #[cfg(windows)]
    let listen = format!(r"\\.\pipe\devicelane-live-job-{}", std::process::id());
    #[cfg(unix)]
    let listen = runtime
        .canonicalize()
        .unwrap()
        .join("job.sock")
        .display()
        .to_string();
    let endpoint = local_endpoint(&runtime, &listen).unwrap();
    let _service = spawn(
        env!("CARGO_BIN_EXE_devicelane-service"),
        &[
            "--identity",
            service_identity.to_str().unwrap(),
            "--runtime-dir",
            runtime.to_str().unwrap(),
            "--role",
            "workstation",
            "--registry",
            &address,
            "--listen",
            &listen,
            "--log-dir",
            logs.to_str().unwrap(),
        ],
    );
    struct ReleaseOnDrop(PathBuf);
    impl Drop for ReleaseOnDrop {
        fn drop(&mut self) {
            let _ = std::fs::write(&self.0, b"release");
        }
    }
    let _release_on_drop = ReleaseOnDrop(release_install.clone());
    let snapshot = || {
        send_local_request(
            &endpoint,
            &LocalRequest::DashboardSnapshot {
                version: LocalProtocolVersion::CURRENT,
                scope: DashboardScope::Mesh,
            },
        )
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(LocalResponse::DashboardSnapshot(snapshot)) = snapshot() {
            if snapshot
                .hosts
                .iter()
                .any(|host| host.id.as_str() == "other-mac" && host.freshness == Freshness::Live)
            {
                break;
            }
        }
        assert!(
            Instant::now() < deadline,
            "inventory observer did not become live"
        );
        thread::sleep(Duration::from_millis(25));
    }
    let device = DeviceId::parse("sim-1").unwrap();
    let activity = ActivityId::parse("live-inventory-install").unwrap();
    let access = AccessRequest {
        activity_id: activity.clone(),
        principal_id: PrincipalId::parse("windows-agent").unwrap(),
        source_host_id: HostId::parse("windows-client").unwrap(),
        target_host_id: HostId::parse("mac-1").unwrap(),
        device_id: Some(device.clone()),
        operation: OperationId::parse("apple.install_app").unwrap(),
        resources: vec![
            ResourceClass::WorkspaceRead,
            ResourceClass::DeviceLease,
            ResourceClass::ApplicationInstall,
        ],
        remote_operation: Some(
            RemoteOperationGrant::new(
                "install-live",
                "project",
                Some(device),
                AppleOperation::InstallApp {
                    app_path: "build/App.app".into(),
                },
            )
            .unwrap(),
        ),
        physical_device: false,
        user_present: true,
    };
    use device_development_mesh::local_ipc::{
        MeshRpcBoundary, PersistentMeshRpcBoundary, RemoteExecutionConfig,
    };
    let controller =
        SecureTransport::load_or_create(&controller_identity, "windows-client").unwrap();
    let (claim, client_signature) =
        device_development_mesh::controller_session::sign_mesh_access_claim(&controller, access)
            .unwrap();
    let access = claim.access.clone();
    let response = PersistentMeshRpcBoundary::default()
        .call(
            &RemoteExecutionConfig {
                registry_address: address.clone(),
                registry_peer_id: "registry".into(),
                identity_path: controller_identity,
                client_id: "windows-client".into(),
            },
            &device_development_mesh::network_processes::Request::AuthenticateDashboardAccess {
                claim,
                client_signature,
            },
        )
        .unwrap();
    assert!(
        response.accepted,
        "signed mesh access rejected: {:?}",
        response.error
    );
    let assertion = response
        .events
        .iter()
        .find(|event| event.kind == "authenticated_dashboard_access")
        .map(|event| serde_json::from_str(&event.payload).unwrap())
        .expect("missing signed assertion");
    let response = send_local_request(
        &endpoint,
        &LocalRequest::RequestAuthenticatedApproval {
            version: LocalProtocolVersion::CURRENT,
            assertion,
            lifetime_ms: 30_000,
        },
    )
    .unwrap();
    let LocalResponse::ApprovalCreated { nonce, .. } = response else {
        panic!("approval failed: {response:?}")
    };
    let response = send_local_request(
        &endpoint,
        &LocalRequest::DecideApproval {
            version: LocalProtocolVersion::CURRENT,
            nonce,
            access,
            decision: ApprovalDecision::AllowOnce,
        },
    )
    .unwrap();
    assert!(
        matches!(response, LocalResponse::ApprovalDecided { .. }),
        "{response:?}"
    );
    let response = send_local_request(
        &endpoint,
        &LocalRequest::StartRemoteExecution {
            version: LocalProtocolVersion::CURRENT,
            activity_id: activity.clone(),
            workspace_path: "project".into(),
            request_id: "install-live".into(),
            app_path: "build/App.app".into(),
        },
    )
    .unwrap();
    assert!(
        matches!(response, LocalResponse::ExecutionStarted { .. }),
        "{response:?}"
    );
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut gate_entered = None;
    let mut released = false;
    let event_diagnostics = || {
        send_local_request(
            &endpoint,
            &LocalRequest::ActivityEvents {
                version: LocalProtocolVersion::CURRENT,
                scope: DashboardScope::Mesh,
                cursor: device_development_mesh::dashboard::EventCursor {
                    epoch: 1,
                    sequence: 0,
                },
                limit: 128,
            },
        )
    };
    loop {
        let LocalResponse::DashboardSnapshot(current) = snapshot().unwrap() else {
            panic!("snapshot missing")
        };
        assert_eq!(
            current
                .hosts
                .iter()
                .find(|host| host.id.as_str() == "other-mac")
                .unwrap()
                .freshness,
            Freshness::Live,
            "remote job displaced live inventory"
        );
        let state = current
            .activities
            .iter()
            .find(|entry| entry.activity_id == activity)
            .unwrap()
            .state;
        if gate_entered.is_none()
            && std::fs::read_to_string(&marker)
                .unwrap_or_default()
                .contains("simctl install sim-1")
        {
            gate_entered = Some((Instant::now(), current.revision));
        }
        // Each inventory observation commits three topology revisions. After
        // tool entry, no controller/lease setup remains to advance this counter.
        if !released
            && gate_entered.is_some_and(|(entered, revision)| {
                entered.elapsed() >= Duration::from_millis(2200)
                    && current.revision.saturating_sub(revision) >= 6
            })
        {
            std::fs::write(&release_install, b"release").unwrap();
            released = true;
        }
        if state == ActivityState::Succeeded {
            assert!(
                released,
                "installation completed before its explicit test gate release"
            );
            break;
        }
        assert!(
            !matches!(
                state,
                ActivityState::Failed | ActivityState::Denied | ActivityState::Cancelled
            ),
            "remote job failed: {:?}; events={:?}; tools={}",
            current.activities,
            event_diagnostics(),
            std::fs::read_to_string(&marker).unwrap_or_default()
        );
        assert!(
            Instant::now() < deadline,
            "remote job did not terminate: activities={:?}; events={:?}; gate={:?}; released={released}; revision={}; tools={}",
            current.activities,
            event_diagnostics(),
            gate_entered,
            current.revision,
            std::fs::read_to_string(&marker).unwrap_or_default()
        );
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        std::fs::read_to_string(marker)
            .unwrap()
            .contains("simctl install sim-1")
    );
}

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
        let context = format!("{operation:?}");
        let terminal = wait_for_terminal(&address, &first_identity, &job_id, &context, &marker);
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
            observed["job_id"].as_str().unwrap(),
            "observer DiscoverProject",
            &marker,
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
    let before = wait_for_terminal(
        &address,
        &first_identity,
        &durable_job,
        "durable BuildApp",
        &marker,
    );
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
            "5000",
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

fn wait_for_terminal(
    address: &str,
    identity: &Path,
    job_id: &str,
    context: &str,
    marker: &Path,
) -> serde_json::Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut last_snapshot = serde_json::Value::Null;
    loop {
        let output = cli(
            address,
            identity,
            "events",
            &serde_json::json!({"job_id": job_id, "after": 0}),
        );
        let last_status = output.status.to_string();
        let last_stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        if output.status.success() {
            last_snapshot = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
                panic!(
                    "mesh-cli events returned invalid JSON for {context}/{job_id}: {error}; status={last_status}; stderr={last_stderr}"
                )
            });
            let pending_without_events = last_snapshot["accepted"] == true
                && last_snapshot["job_id"] == job_id
                && last_snapshot.get("events").is_none();
            assert!(
                last_snapshot["events"].is_array() || pending_without_events,
                "mesh-cli events returned an invalid pending state for {context}/{job_id}: snapshot={last_snapshot}; status={last_status}; stderr={last_stderr}"
            );
            if let Some(terminal) = last_snapshot["events"].as_array().and_then(|items| {
                items
                    .iter()
                    .find(|event| matches!(event["kind"].as_str(), Some("completed" | "rejected")))
            }) {
                return terminal.clone();
            }
        } else {
            let error = serde_json::from_slice::<serde_json::Value>(&output.stderr)
                .ok()
                .and_then(|value| value["error"].as_str().map(str::to_owned));
            assert_eq!(
                error.as_deref(),
                Some("connection_unavailable"),
                "mesh-cli events failed non-transiently for {context}/{job_id}; status={last_status}; stderr={last_stderr}"
            );
        }
        assert!(
            Instant::now() < deadline,
            "terminal event absent for {context}/{job_id}; last_status={last_status}; last_stderr={last_stderr}; last_snapshot={last_snapshot}; markers={}",
            std::fs::read_to_string(marker).unwrap_or_default()
        );
        thread::sleep(Duration::from_millis(25));
    }
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
                .is_some_and(|hosts| {
                    hosts
                        .iter()
                        .any(|host| host["id"] == "mac-1" && host["status"] == "online")
                })
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
    spawn_command(Command::new(path).args(args))
}

fn spawn_command(command: &mut Command) -> ChildGuard {
    command.stdout(Stdio::null()).stderr(Stdio::inherit());
    let mut group = command.group();
    #[cfg(windows)]
    group.kill_on_drop(true);
    ChildGuard(group.spawn().unwrap())
}

struct ChildGuard(GroupChild);
impl std::ops::Deref for ChildGuard {
    type Target = GroupChild;
    fn deref(&self) -> &GroupChild {
        &self.0
    }
}
impl std::ops::DerefMut for ChildGuard {
    fn deref_mut(&mut self) -> &mut GroupChild {
        &mut self.0
    }
}
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
