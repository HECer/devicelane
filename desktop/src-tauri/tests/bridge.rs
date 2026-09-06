use device_development_mesh::controller_session::current_os_principal;
use device_development_mesh::dashboard::audit::{AuditFilter, ExportManifest, ExportSignature};
use device_development_mesh::dashboard::event_log::EventRead;
use device_development_mesh::dashboard::policy::{AccessRequest, RemoteOperationGrant};
use device_development_mesh::dashboard::{
    ActivityId, ApprovalDecision, AuditRecord, AuditResult, DashboardScope, DashboardSnapshot,
    EventCursor, HostId, MetricValue, OperationId, PolicyEffect, PrincipalId, ResourceClass,
    SubscriberId,
};
use device_development_mesh::local_ipc::{
    ConnectionState, DaemonRole, DaemonSnapshot, LocalEndpoint, LocalProtocolVersion, LocalRequest,
    LocalResponse, local_endpoint, send_local_request,
};
use device_development_mesh::remote_apple_protocol::AppleOperation;
use devicelane_desktop::{
    DaemonTransport, DesktopBridge, JavaScriptWire, RepairProcess, WireEventCursor, repair_spec,
    run_smoke_probe_with_transport, sha256_file, validate_bundle_asset,
};
use sha2::Digest;
use std::ffi::OsString;
use std::fs;
use std::net::TcpListener;
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

struct FakeTransport {
    requests: Arc<Mutex<Vec<LocalRequest>>>,
    response: LocalResponse,
}

#[test]
fn connection_write_uses_exact_typed_settings_and_requires_acknowledgement() {
    use device_development_mesh::connection_config::ConnectionConfig;
    let configuration = ConnectionConfig::new("mac.local:7443", "expected-registry").unwrap();
    for (response, succeeds) in [
        (LocalResponse::Acknowledged, true),
        (
            LocalResponse::Error {
                code: "permission_denied".into(),
                message: "approval required".into(),
            },
            false,
        ),
        (
            LocalResponse::ConnectionSettings {
                registry_address: None,
                registry_peer_id: None,
                connection: ConnectionState::Disconnected,
            },
            false,
        ),
    ] {
        let requests = Arc::new(Mutex::new(vec![]));
        let bridge = DesktopBridge::new(FakeTransport {
            requests: requests.clone(),
            response,
        });
        assert_eq!(
            bridge.set_connection(configuration.clone()).is_ok(),
            succeeds
        );
        assert_eq!(
            *requests.lock().unwrap(),
            vec![LocalRequest::SetConnection {
                version: LocalProtocolVersion::CURRENT,
                configuration: configuration.clone(),
            }]
        );
    }
}

#[test]
fn connection_settings_uses_the_public_local_contract() {
    let requests = Arc::new(Mutex::new(vec![]));
    let bridge = DesktopBridge::new(FakeTransport {
        requests: Arc::clone(&requests),
        response: LocalResponse::ConnectionSettings {
            registry_address: Some("mac-registry.local:7443".into()),
            registry_peer_id: Some("registry".into()),
            connection: ConnectionState::Connecting,
        },
    });
    assert_eq!(
        serde_json::to_value(bridge.connection_settings().unwrap()).unwrap(),
        serde_json::json!({
            "registry_address": "mac-registry.local:7443",
            "registry_peer_id": "registry",
            "connection": "connecting"
        })
    );
    assert_eq!(
        *requests.lock().unwrap(),
        vec![LocalRequest::ConnectionSettings {
            version: LocalProtocolVersion::CURRENT
        }]
    );
}

#[test]
fn connection_settings_does_not_turn_daemon_errors_into_local_only_success() {
    for response in [
        LocalResponse::Error {
            code: "feature_unavailable".into(),
            message: "service update required".into(),
        },
        LocalResponse::Acknowledged,
    ] {
        let bridge = DesktopBridge::new(FakeTransport {
            requests: Arc::new(Mutex::new(vec![])),
            response,
        });
        assert!(bridge.connection_settings().is_err());
    }
}

#[test]
fn installed_desktop_smoke_probe_uses_the_same_typed_bridge() {
    let transport = FakeTransport {
        requests: Arc::new(Mutex::new(vec![])),
        response: LocalResponse::Snapshot(snapshot()),
    };
    let encoded = run_smoke_probe_with_transport(transport).unwrap();
    let decoded: DaemonSnapshot = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded, snapshot());
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
        features: Vec::new(),
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
fn remote_workspace_execution_uses_the_typed_daemon_path() {
    let requests = Arc::new(Mutex::new(vec![]));
    let transport = FakeTransport {
        requests: Arc::clone(&requests),
        response: LocalResponse::ExecutionStarted {
            activity_id: device_development_mesh::dashboard::ActivityId::parse("activity-1")
                .unwrap(),
        },
    };
    let bridge = DesktopBridge::new(transport);

    let activity_id = bridge
        .start_remote_execution("activity-1", "project", "request-1", "build/Mesh.app")
        .unwrap();

    assert_eq!(activity_id.as_str(), "activity-1");
    assert!(matches!(
        &requests.lock().unwrap()[0],
        LocalRequest::StartRemoteExecution {
            activity_id,
            workspace_path,
            request_id,
            app_path,
            ..
        } if activity_id.as_str() == "activity-1"
            && workspace_path == "project"
            && request_id == "request-1"
            && app_path == "build/Mesh.app"
    ));
}

#[test]
fn paired_process_execution_is_identical_through_ipc_cli_and_tauri_bridge() {
    let root = tempfile::tempdir().unwrap();
    let registry_identity = root.path().join("registry");
    let service_identity = root.path().join("service").join("mac-agent");
    let agent_identity = root.path().join("mesh-agent");
    let windows_identity = root.path().join("windows-client");
    pair_process_as(
        &workspace_binary("mesh-cli"),
        &registry_identity,
        &service_identity,
        "mac-controller",
    );
    pair_process(
        &workspace_binary("mesh-agent"),
        &registry_identity,
        &agent_identity,
    );
    pair_process_as(
        &workspace_binary("mesh-cli"),
        &registry_identity,
        &windows_identity,
        "windows-client",
    );

    let registry_address = free_address();
    let mut registry = spawn(
        &workspace_binary("mesh-registry"),
        &[
            "--listen",
            &registry_address,
            "--identity",
            registry_identity.to_str().unwrap(),
            "--offline-after-ms",
            "5000",
            "--agent-peer",
            "mac-agent",
        ],
    );
    let workspace_root = root.path().join("workspaces");
    std::fs::create_dir_all(workspace_root.join("mac-agent/project/build")).unwrap();
    let marker = root.path().join("agent-tool.log");
    let install_gate = root.path().join("release-install");
    let xcodebuild = fake_apple_tool(root.path(), "xcodebuild", &marker, None);
    let devicectl = fake_apple_tool(root.path(), "devicectl", &marker, None);
    let simctl = fake_apple_tool(root.path(), "simctl", &marker, Some(&install_gate));
    let _agent = spawn(
        &workspace_binary("mesh-agent"),
        &[
            "--registry",
            &registry_address,
            "--identity",
            agent_identity.to_str().unwrap(),
            "--id",
            "mac-agent",
            "--peer-id",
            "mac-agent",
            "--os",
            "macos",
            "--arch",
            "arm64",
            "--workspace-root",
            workspace_root.to_str().unwrap(),
            "--xcodebuild",
            xcodebuild.to_str().unwrap(),
            "--devicectl",
            devicectl.to_str().unwrap(),
            "--simctl",
            simctl.to_str().unwrap(),
            "--heartbeat-ms",
            "50",
            "--capability",
            "apple.simulator@1",
            "--device",
            "iphone-1:ios:connected",
        ],
    );
    wait_for_mesh_host(&registry_address, &service_identity, "mac-agent");

    let _release_on_failure = InstallGateRelease(install_gate.clone());
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
    let listen = format!(r"\\.\pipe\devicelane-mesh-e2e-{}", std::process::id());
    #[cfg(not(windows))]
    let listen = String::new();
    let endpoint = local_endpoint(&runtime, &listen).unwrap();
    let _daemon = spawn(
        &workspace_binary("devicelane-service"),
        &[
            "--identity",
            service_identity.to_str().unwrap(),
            "--runtime-dir",
            runtime.to_str().unwrap(),
            "--role",
            "agent",
            "--registry",
            &registry_address,
            "--listen",
            &listen,
            "--agent-peer",
            "mac-agent",
            "--log-dir",
            logs.to_str().unwrap(),
            "--foreground",
        ],
    );
    wait_for_daemon(&endpoint);

    let spoofed = devicelane_cli(
        &endpoint_text(&endpoint),
        &[
            "approvals",
            "request",
            "--local",
            "--json",
            "--mesh-registry",
            &registry_address,
            "--mesh-identity",
            windows_identity.to_str().unwrap(),
            "--activity-id",
            "spoofed-windows-origin",
            "--principal-id",
            "spoofed-principal",
            "--source-host-id",
            "spoofed-source",
            "--target-host-id",
            "mac-agent",
            "--device-id",
            "iphone-1",
            "--operation",
            "workspace.read",
            "--resource",
            "workspace_read",
            "--resource",
            "device_lease",
            "--physical-device",
            "--user-present",
        ],
    );
    assert!(!spoofed.status.success());
    assert!(String::from_utf8_lossy(&spoofed.stderr).contains("mesh_identity_mismatch"));
    let direct_spoof = send_local_request(
        &endpoint,
        &LocalRequest::RequestApproval {
            version: LocalProtocolVersion::CURRENT,
            access: AccessRequest {
                activity_id: ActivityId::parse("direct-spoofed-windows-origin").unwrap(),
                principal_id: PrincipalId::parse("spoofed-principal").unwrap(),
                source_host_id: HostId::parse("spoofed-source").unwrap(),
                target_host_id: HostId::parse("mac-agent").unwrap(),
                device_id: Some(
                    device_development_mesh::dashboard::DeviceId::parse("iphone-1").unwrap(),
                ),
                operation: OperationId::parse("workspace.read").unwrap(),
                resources: vec![ResourceClass::WorkspaceRead, ResourceClass::DeviceLease],
                remote_operation: None,
                physical_device: true,
                user_present: true,
            },
            lifetime_ms: 60_000,
        },
    )
    .unwrap();
    assert!(matches!(
        direct_spoof,
        LocalResponse::Error { code, .. } if code == "mesh_identity_mismatch"
    ));
    wait_for_mesh_host(&registry_address, &service_identity, "mac-agent");

    let denied_activity_id = "real-windows-to-mac-denied";
    let denied_device = device_development_mesh::dashboard::DeviceId::parse("iphone-1").unwrap();
    let denied_access = AccessRequest {
        activity_id: ActivityId::parse(denied_activity_id).unwrap(),
        principal_id: PrincipalId::parse(current_os_principal().unwrap()).unwrap(),
        source_host_id: HostId::parse("windows-client").unwrap(),
        target_host_id: HostId::parse("mac-agent").unwrap(),
        device_id: Some(denied_device.clone()),
        operation: OperationId::parse("apple.install_app").unwrap(),
        resources: vec![
            ResourceClass::WorkspaceRead,
            ResourceClass::DeviceLease,
            ResourceClass::ApplicationInstall,
        ],
        remote_operation: Some(
            RemoteOperationGrant::new(
                "request-denied",
                "project",
                Some(denied_device),
                AppleOperation::InstallApp {
                    app_path: "build/Mesh.app".into(),
                },
            )
            .unwrap(),
        ),
        physical_device: true,
        user_present: true,
    };
    let (client_pid, denied_created) = devicelane_cli_process(
        &endpoint_text(&endpoint),
        &[
            "approvals",
            "request",
            "--local",
            "--json",
            "--mesh-registry",
            &registry_address,
            "--mesh-identity",
            windows_identity.to_str().unwrap(),
            "--activity-id",
            denied_activity_id,
            "--target-host-id",
            "mac-agent",
            "--device-id",
            "iphone-1",
            "--operation",
            "apple.install_app",
            "--resource",
            "workspace_read",
            "--resource",
            "device_lease",
            "--resource",
            "application_install",
            "--remote-request-id",
            "request-denied",
            "--remote-workspace-path",
            "project",
            "--remote-app-path",
            "build/Mesh.app",
            "--physical-device",
            "--user-present",
        ],
    );
    assert!(
        client_pid > 0,
        "the Windows client must be a genuine child process"
    );
    assert!(
        denied_created.status.success(),
        "{}",
        String::from_utf8_lossy(&denied_created.stderr)
    );
    let LocalResponse::ApprovalCreated { nonce, .. } =
        serde_json::from_slice(&denied_created.stdout).unwrap()
    else {
        panic!("first approval request did not return a challenge")
    };
    let denied_digest = denied_access
        .remote_operation
        .as_ref()
        .unwrap()
        .canonical_sha256()
        .to_owned();
    let LocalResponse::PendingApprovals(pending) = send_local_request(
        &endpoint,
        &LocalRequest::PendingApprovals {
            version: LocalProtocolVersion::CURRENT,
        },
    )
    .unwrap() else {
        panic!("pending approval snapshot missing")
    };
    let pending_denial = pending
        .iter()
        .find(|item| item.activity_id.as_str() == denied_activity_id)
        .unwrap();
    assert_eq!(
        pending_denial.remote_operation_sha256.as_deref(),
        Some(denied_digest.as_str())
    );
    assert_eq!(pending_denial.operation, denied_access.operation);
    assert_eq!(pending_denial.resources, denied_access.resources);
    let denied_decision = send_local_request(
        &endpoint,
        &LocalRequest::DecideApproval {
            version: LocalProtocolVersion::CURRENT,
            nonce,
            access: denied_access.clone(),
            decision: ApprovalDecision::DenyOnce,
        },
    )
    .unwrap();
    assert!(
        matches!(
            denied_decision,
            LocalResponse::ApprovalDecided {
                decision: ApprovalDecision::DenyOnce,
                ..
            }
        ),
        "unexpected denied decision response: {denied_decision:?}"
    );

    let activity_id = "real-windows-to-mac-activity";
    let execution_device = device_development_mesh::dashboard::DeviceId::parse("iphone-1").unwrap();
    let access = AccessRequest {
        activity_id: ActivityId::parse(activity_id).unwrap(),
        principal_id: PrincipalId::parse(current_os_principal().unwrap()).unwrap(),
        source_host_id: HostId::parse("windows-client").unwrap(),
        target_host_id: HostId::parse("mac-agent").unwrap(),
        device_id: Some(execution_device.clone()),
        operation: OperationId::parse("apple.install_app").unwrap(),
        resources: vec![
            ResourceClass::WorkspaceRead,
            ResourceClass::DeviceLease,
            ResourceClass::ApplicationInstall,
        ],
        remote_operation: Some(
            RemoteOperationGrant::new(
                "request-1",
                "project",
                Some(execution_device),
                AppleOperation::InstallApp {
                    app_path: "build/Mesh.app".into(),
                },
            )
            .unwrap(),
        ),
        physical_device: true,
        user_present: true,
    };
    let operation_digest = access
        .remote_operation
        .as_ref()
        .unwrap()
        .canonical_sha256()
        .to_owned();
    let (resubmitted_pid, created) = devicelane_cli_process(
        &endpoint_text(&endpoint),
        &[
            "approvals",
            "request",
            "--local",
            "--json",
            "--mesh-registry",
            &registry_address,
            "--mesh-identity",
            windows_identity.to_str().unwrap(),
            "--activity-id",
            activity_id,
            "--target-host-id",
            "mac-agent",
            "--device-id",
            "iphone-1",
            "--operation",
            "apple.install_app",
            "--resource",
            "workspace_read",
            "--resource",
            "device_lease",
            "--resource",
            "application_install",
            "--remote-request-id",
            "request-1",
            "--remote-workspace-path",
            "project",
            "--remote-app-path",
            "build/Mesh.app",
            "--physical-device",
            "--user-present",
        ],
    );
    assert_ne!(
        client_pid, resubmitted_pid,
        "resubmission must execute a new client process"
    );
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    let LocalResponse::ApprovalCreated { nonce, .. } =
        serde_json::from_slice(&created.stdout).unwrap()
    else {
        panic!("approval request did not return a challenge")
    };
    let decided = send_local_request(
        &endpoint,
        &LocalRequest::DecideApproval {
            version: LocalProtocolVersion::CURRENT,
            nonce,
            access: access.clone(),
            decision: ApprovalDecision::AllowOnce,
        },
    )
    .unwrap();
    assert!(matches!(
        decided,
        LocalResponse::ApprovalDecided {
            decision: ApprovalDecision::AllowOnce,
            ..
        }
    ));

    let bridge = DesktopBridge::new(EndpointTransport(endpoint.clone()));
    assert_eq!(
        bridge
            .start_remote_execution(activity_id, "project", "request-1", "build/Mesh.app")
            .unwrap()
            .as_str(),
        activity_id
    );
    let running = wait_for_activity(&bridge, activity_id, "running");
    assert_eq!(
        running
            .activities
            .iter()
            .filter(|item| item.state == device_development_mesh::dashboard::ActivityState::Running)
            .count(),
        1
    );
    let activity = running
        .activities
        .iter()
        .find(|item| item.activity_id.as_str() == activity_id)
        .unwrap();
    assert_eq!(
        activity.resources,
        vec![
            ResourceClass::WorkspaceRead,
            ResourceClass::DeviceLease,
            ResourceClass::ApplicationInstall,
        ]
    );
    assert_eq!(
        activity.remote_operation_sha256.as_deref(),
        Some(operation_digest.as_str())
    );
    let occupancy_edges: std::collections::BTreeSet<_> = activity
        .resources
        .iter()
        .cloned()
        .map(|resource| (activity.activity_id.clone(), resource))
        .collect();
    assert_eq!(
        occupancy_edges,
        std::collections::BTreeSet::from([
            (activity.activity_id.clone(), ResourceClass::WorkspaceRead),
            (activity.activity_id.clone(), ResourceClass::DeviceLease),
            (
                activity.activity_id.clone(),
                ResourceClass::ApplicationInstall
            ),
        ]),
        "the running operation must expose one explicit activity-to-resource occupancy edge per resource"
    );

    let cursor = device_development_mesh::dashboard::EventCursor {
        epoch: 1,
        sequence: 0,
    };
    let direct = send_local_request(
        &endpoint,
        &LocalRequest::ActivityEvents {
            version: LocalProtocolVersion::CURRENT,
            scope: DashboardScope::Local,
            cursor,
            limit: 256,
        },
    )
    .unwrap();
    let cli = devicelane_cli(
        &endpoint_text(&endpoint),
        &["activities", "list", "--local", "--json"],
    );
    assert!(
        cli.status.success(),
        "{}",
        String::from_utf8_lossy(&cli.stderr)
    );
    let LocalResponse::ActivityEvents(direct) = direct else {
        panic!("direct activity events missing")
    };
    let LocalResponse::ActivityEvents(cli_events) = serde_json::from_slice(&cli.stdout).unwrap()
    else {
        panic!("CLI activity events missing")
    };
    let tauri_events = bridge
        .activity_events(DashboardScope::Local, cursor, 256)
        .unwrap();
    assert_eq!(direct, cli_events);
    assert_eq!(direct, tauri_events);
    let EventRead::Events { events, .. } = &direct else {
        panic!("execution events missing")
    };
    let running_event = events
        .iter()
        .find(|event| {
            event.activity_id.as_str() == activity_id
                && event.state == device_development_mesh::dashboard::ActivityState::Running
        })
        .expect("running event missing");
    for metric in [
        &running_event.metrics.current_memory_bytes,
        &running_event.metrics.peak_memory_bytes,
        &running_event.metrics.cpu_time_ms,
        &running_event.metrics.process_count,
    ] {
        assert!(
            matches!(metric, MetricValue::Unavailable { reason } if reason.as_str() == "observer_unavailable")
        );
    }

    let dispatch_deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if std::fs::read_to_string(&marker)
            .is_ok_and(|contents| contents.lines().any(|line| line.contains("simctl install")))
        {
            break;
        }
        assert!(
            Instant::now() < dispatch_deadline,
            "Mac agent never dispatched the real install process before reconnect testing"
        );
        thread::sleep(Duration::from_millis(25));
    }

    let EventRead::Events {
        next_cursor: resume_cursor,
        ..
    } = direct
    else {
        unreachable!()
    };
    assert!(matches!(
        send_local_request(
            &endpoint,
            &LocalRequest::AcknowledgeEvents {
                version: LocalProtocolVersion::CURRENT,
                subscriber_id: SubscriberId::parse("desktop-e2e-client").unwrap(),
                cursor: resume_cursor,
            }
        )
        .unwrap(),
        LocalResponse::Acknowledged
    ));
    registry.kill().unwrap();
    registry.wait().unwrap();
    wait_for_activity(&bridge, activity_id, "reconnecting");
    registry = spawn(
        &workspace_binary("mesh-registry"),
        &[
            "--listen",
            &registry_address,
            "--identity",
            registry_identity.to_str().unwrap(),
            "--offline-after-ms",
            "5000",
            "--agent-peer",
            "mac-agent",
        ],
    );
    wait_for_mesh_host(&registry_address, &service_identity, "mac-agent");

    std::fs::write(&install_gate, b"release").unwrap();
    let terminal = wait_for_activity(&bridge, activity_id, "succeeded");
    assert_eq!(
        terminal
            .activities
            .iter()
            .filter(|item| item.activity_id.as_str() == activity_id)
            .count(),
        1
    );
    let resumed = bridge
        .activity_events(DashboardScope::Local, resume_cursor, 256)
        .unwrap();
    let EventRead::Events {
        events: resumed_events,
        next_cursor,
        ..
    } = resumed
    else {
        panic!("cursor resume unexpectedly required a snapshot resync")
    };
    assert!(next_cursor.sequence > resume_cursor.sequence);
    assert!(resumed_events.iter().any(|event| {
        event.activity_id.as_str() == activity_id
            && event.state == device_development_mesh::dashboard::ActivityState::Reconnecting
    }));
    assert!(resumed_events.iter().any(|event| {
        event.activity_id.as_str() == activity_id
            && event.state == device_development_mesh::dashboard::ActivityState::Running
    }));
    assert!(
        resumed_events
            .windows(2)
            .all(|pair| pair[0].sequence < pair[1].sequence)
    );
    drop(registry);

    let direct_audit = send_local_request(
        &endpoint,
        &LocalRequest::AuditQuery {
            version: LocalProtocolVersion::CURRENT,
            filter: AuditFilter::default(),
            cursor: None,
            limit: 256,
        },
    )
    .unwrap();
    let cli_audit = devicelane_cli(
        &endpoint_text(&endpoint),
        &["audit", "list", "--local", "--json", "--limit", "256"],
    );
    assert!(
        cli_audit.status.success(),
        "{}",
        String::from_utf8_lossy(&cli_audit.stderr)
    );
    let LocalResponse::AuditRecords(direct_audit) = direct_audit else {
        panic!("direct audit records missing")
    };
    let LocalResponse::AuditRecords(cli_audit) = serde_json::from_slice(&cli_audit.stdout).unwrap()
    else {
        panic!("CLI audit records missing")
    };
    let tauri_audit = bridge
        .audit_query(AuditFilter::default(), None, 256)
        .unwrap();
    assert_eq!(direct_audit, cli_audit);
    assert_eq!(direct_audit, tauri_audit);
    let terminal_audit = direct_audit
        .items
        .iter()
        .find(|record| {
            record.activity_id.as_ref().map(|id| id.as_str()) == Some(activity_id)
                && record.result == AuditResult::Succeeded
        })
        .expect("terminal audit record missing");
    let canonical = serde_json::json!({
        "activity_id": terminal_audit.activity_id.clone(),
        "principal_id": terminal_audit.principal_id.clone(),
        "source_host_id": terminal_audit.source_host_id.clone(),
        "target_host_id": terminal_audit.target_host_id.clone(),
        "device_id": terminal_audit.device_id.clone(),
        "operation": terminal_audit.operation.clone(),
        "resources": terminal_audit.resources.clone(),
        "decision": terminal_audit.decision,
        "terminal": terminal_audit.result,
        "redaction": terminal_audit.redacted_message.clone(),
    });
    assert_eq!(canonical["principal_id"], current_os_principal().unwrap());
    assert_eq!(canonical["source_host_id"], "windows-client");
    assert_eq!(canonical["target_host_id"], "mac-agent");
    assert_eq!(canonical["device_id"], "iphone-1");
    assert_eq!(canonical["operation"], "apple.install_app");
    assert_eq!(
        canonical["resources"],
        serde_json::json!(["workspace_read", "device_lease", "application_install"])
    );
    assert_eq!(canonical["decision"], "allow");
    assert_eq!(canonical["terminal"], "succeeded");
    assert!(canonical["redaction"].is_null());
    let digest = sha2::Sha256::digest(serde_json::to_vec(&canonical).unwrap());
    assert_eq!(digest.len(), 32, "canonical audit digest must be SHA-256");
}

#[derive(Clone)]
struct EndpointTransport(LocalEndpoint);

impl DaemonTransport for EndpointTransport {
    fn send(&self, request: LocalRequest) -> Result<LocalResponse, String> {
        send_local_request(&self.0, &request).map_err(|error| error.to_string())
    }
}

fn wait_for_activity(
    bridge: &DesktopBridge<EndpointTransport>,
    activity_id: &str,
    expected: &str,
) -> DashboardSnapshot {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let snapshot = bridge.dashboard_snapshot(DashboardScope::Mesh).unwrap();
        if snapshot.activities.iter().any(|activity| {
            activity.activity_id.as_str() == activity_id
                && format!("{:?}", activity.state).eq_ignore_ascii_case(expected)
        }) {
            return snapshot;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {expected}; last snapshot: {snapshot:?}"
        );
        thread::sleep(Duration::from_millis(25));
    }
}

fn workspace_binary(name: &str) -> PathBuf {
    let debug = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let binary = debug.join(format!("{name}{}", std::env::consts::EXE_SUFFIX));
    assert!(
        binary.is_file(),
        "build workspace binaries before this gate: {}",
        binary.display()
    );
    binary
}

fn pair_process(binary: &Path, registry_identity: &Path, peer_identity: &Path) {
    let peer_id = (binary.file_stem().and_then(|value| value.to_str()) == Some("mesh-agent"))
        .then_some("mac-agent");
    pair_process_optional(binary, registry_identity, peer_identity, peer_id);
}

fn pair_process_as(binary: &Path, registry_identity: &Path, peer_identity: &Path, peer_id: &str) {
    pair_process_optional(binary, registry_identity, peer_identity, Some(peer_id));
}

fn pair_process_optional(
    binary: &Path,
    registry_identity: &Path,
    peer_identity: &Path,
    peer_id: Option<&str>,
) {
    let address = free_address();
    let mut registry = spawn(
        &workspace_binary("mesh-registry"),
        &[
            "pair",
            "--listen",
            &address,
            "--identity",
            registry_identity.to_str().unwrap(),
        ],
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let mut command = Command::new(binary);
        command.args([
            "pair",
            "--address",
            &address,
            "--identity",
            peer_identity.to_str().unwrap(),
        ]);
        if let Some(peer_id) = peer_id {
            command.args(["--peer-id", peer_id]);
        }
        let output = command.output().unwrap();
        if output.status.success() {
            break;
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        let transient_refusal = connection_unavailable(&stderr);
        assert!(
            transient_refusal,
            "pairing failed with {}; stderr={stderr}",
            output.status
        );
        assert!(
            Instant::now() < deadline,
            "pairing listener stayed unavailable for five seconds; status={}; stderr={stderr}",
            output.status
        );
        thread::sleep(Duration::from_millis(25));
    }
    assert!(registry.wait().unwrap().success());
}

fn free_address() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().to_string()
}

fn spawn(path: &Path, args: &[&str]) -> ChildGuard {
    ChildGuard(
        Command::new(path)
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    )
}

fn wait_for_mesh_host(address: &str, identity: &Path, host: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let output = Command::new(workspace_binary("mesh-cli"))
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
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !output.status.success() {
            assert!(
                connection_unavailable(&stderr),
                "mesh host lookup failed with {}; stderr={stderr}",
                output.status
            );
        } else {
            let hosts: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
                panic!(
                    "mesh host lookup returned invalid JSON: {error}; status={}; stderr={stderr}",
                    output.status
                )
            });
            if hosts.as_array().is_some_and(|items| {
                items
                    .iter()
                    .any(|item| item["id"] == host && item["status"] == "online")
            }) {
                return;
            }
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for online mesh host {host}; status={}; stderr={stderr}",
            output.status
        );
        thread::sleep(Duration::from_millis(25));
    }
}

fn connection_unavailable(stderr: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(stderr.trim())
        .is_ok_and(|error| error["error"] == "connection_unavailable")
}

fn wait_for_daemon(endpoint: &LocalEndpoint) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while send_local_request(
        endpoint,
        &LocalRequest::Status {
            version: LocalProtocolVersion::CURRENT,
        },
    )
    .is_err()
    {
        assert!(Instant::now() < deadline, "timed out waiting for daemon");
        thread::sleep(Duration::from_millis(25));
    }
}

fn endpoint_text(endpoint: &LocalEndpoint) -> String {
    match endpoint {
        #[cfg(unix)]
        LocalEndpoint::UnixSocket(path) => path.display().to_string(),
        #[cfg(windows)]
        LocalEndpoint::NamedPipe(path) => path.clone(),
    }
}

fn devicelane_cli(endpoint: &str, args: &[&str]) -> Output {
    devicelane_cli_process(endpoint, args).1
}

fn devicelane_cli_process(endpoint: &str, args: &[&str]) -> (u32, Output) {
    let child = Command::new(workspace_binary("devicelane"))
        .args(args)
        .args(["--endpoint", endpoint])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let process_id = child.id();
    (process_id, child.wait_with_output().unwrap())
}

#[test]
fn install_fixture_waits_for_explicit_release_with_cleared_environment() {
    let root = tempfile::tempdir().unwrap();
    let marker = root.path().join("tools.log");
    let gate = root.path().join("release-install");
    let tool = fake_apple_tool(root.path(), "simctl", &marker, Some(&gate));
    #[cfg(windows)]
    let mut command = {
        let cmd = PathBuf::from(std::env::var_os("SystemRoot").unwrap())
            .join("System32")
            .join("cmd.exe");
        let mut command = Command::new(cmd);
        let script = tool.to_string_lossy();
        command
            .args(["/D", "/C"])
            .arg(script.strip_prefix(r"\\?\").unwrap_or(&script))
            .args(["install", "iphone-1", "build/Mesh.app"]);
        command
    };
    #[cfg(unix)]
    let mut command = {
        let mut command = Command::new(&tool);
        command.args(["install", "iphone-1", "build/Mesh.app"]);
        command
    };
    let mut child = ChildGuard(
        command
            .env_clear()
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while !std::fs::read_to_string(&marker).is_ok_and(|text| text.contains("simctl install")) {
        assert!(
            Instant::now() < deadline,
            "install fixture did not enter: marker={:?}, status={:?}",
            std::fs::read_to_string(&marker),
            child.try_wait()
        );
        thread::sleep(Duration::from_millis(10));
    }
    // Observe a blocked process repeatedly; release is controlled by this test,
    // never inferred from how much time the host took to execute other steps.
    let observation = Instant::now() + Duration::from_millis(200);
    while Instant::now() < observation {
        assert!(
            child.try_wait().unwrap().is_none(),
            "install fixture exited before explicit gate release under env_clear"
        );
        thread::sleep(Duration::from_millis(10));
    }
    std::fs::write(&gate, b"release").unwrap();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(Instant::now() < deadline, "released fixture did not exit");
        thread::sleep(Duration::from_millis(10));
    }
}

fn fake_apple_tool(root: &Path, name: &str, marker: &Path, gate: Option<&Path>) -> PathBuf {
    #[cfg(windows)]
    {
        let path = root.join(format!("{name}.cmd"));
        let wait = gate.map(|gate| {
            let ping = PathBuf::from(std::env::var_os("SystemRoot").unwrap()).join("System32").join("ping.exe");
            format!(":wait_install\r\nif exist \"{}\" goto install_released\r\nif not exist \"{}\" exit /b 1\r\n\"{}\" -n 2 127.0.0.1 >nul\r\nif errorlevel 1 exit /b 1\r\ngoto wait_install\r\n:install_released\r\n", gate.display(), root.display(), ping.display())
        }).unwrap_or_default();
        std::fs::write(
            &path,
            format!(
                "@echo off\r\necho {name} %*>>\"{}\"\r\nif \"{name}\"==\"simctl\" if \"%1\"==\"install\" goto mutation\r\nif \"%1\"==\"-version\" goto version\r\nif \"{name}\"==\"devicectl\" if \"%1\"==\"list\" goto devices\r\nif \"{name}\"==\"simctl\" if \"%1\"==\"list\" goto simulators\r\necho complete\r\nexit /b 0\r\n:mutation\r\n{wait}echo installed\r\nexit /b 0\r\n:version\r\necho Xcode 16\r\nexit /b 0\r\n:devices\r\necho {{\"result\":{{\"devices\":[]}}}}\r\nexit /b 0\r\n:simulators\r\necho {{\"devices\":{{\"com.apple.CoreSimulator.SimRuntime.iOS-17-0\":[{{\"udid\":\"iphone-1\",\"name\":\"iPhone\",\"state\":\"Booted\",\"isAvailable\":true}}]}}}}\r\nexit /b 0\r\n",
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
        let wait = gate
            .map(|gate| {
                format!(
                    "while [ ! -f '{}' ]; do [ -d '{}' ] || exit 1; /bin/sleep 0.05 || exit 1; done;",
                    gate.display(), root.display()
                )
            })
            .unwrap_or_default();
        std::fs::write(
            &path,
            format!("#!/bin/sh\necho \"{name} $*\" >> '{}'\nif [ '{name}' = simctl ] && [ \"$1\" = install ]; then {wait} echo installed; exit 0; fi\n[ \"$1\" = -version ] && echo 'Xcode 16' && exit 0\n[ '{name}' = devicectl ] && [ \"$1\" = list ] && echo '{{\"result\":{{\"devices\":[]}}}}' && exit 0\n[ '{name}' = simctl ] && [ \"$1\" = list ] && echo '{{\"devices\":{{\"com.apple.CoreSimulator.SimRuntime.iOS-17-0\":[{{\"udid\":\"iphone-1\",\"name\":\"iPhone\",\"state\":\"Booted\",\"isAvailable\":true}}]}}}}' && exit 0\necho complete\n", marker.display()),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }
}

// Release before the owning agent is dropped if an assertion aborts the test.
// The fixture's short-lived polling child can then exit without waiting forever.
struct InstallGateRelease(PathBuf);
impl Drop for InstallGateRelease {
    fn drop(&mut self) {
        let _ = std::fs::write(&self.0, b"release");
    }
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
fn dashboard_bridge_uses_typed_versioned_requests_and_preserves_resync_details() {
    let requests = Arc::new(Mutex::new(vec![]));
    let resync = EventRead::ResyncRequired {
        oldest_available: EventCursor {
            epoch: u64::MAX,
            sequence: u64::MAX - 1,
        },
        snapshot_revision: u64::MAX - 2,
    };
    let bridge = DesktopBridge::new(FakeTransport {
        requests: Arc::clone(&requests),
        response: LocalResponse::ActivityEvents(resync.clone()),
    });

    let response = bridge
        .activity_events(
            DashboardScope::Local,
            EventCursor {
                epoch: 0,
                sequence: 0,
            },
            100,
        )
        .unwrap();

    assert_eq!(response, resync);
    assert_eq!(
        *requests.lock().unwrap(),
        vec![LocalRequest::ActivityEvents {
            version: LocalProtocolVersion::CURRENT,
            scope: DashboardScope::Local,
            cursor: EventCursor {
                epoch: 0,
                sequence: 0
            },
            limit: 100,
        }]
    );
}

#[test]
fn dashboard_snapshot_bridge_uses_the_typed_scope_and_response() {
    let requests = Arc::new(Mutex::new(vec![]));
    let snapshot = DashboardSnapshot {
        revision: 7,
        generated_at_ms: 42,
        scope: DashboardScope::Mesh,
        hosts: vec![],
        activities: vec![],
        leases: vec![],
        pending_approvals: vec![],
        warnings: vec![],
    };
    let bridge = DesktopBridge::new(FakeTransport {
        requests: Arc::clone(&requests),
        response: LocalResponse::DashboardSnapshot(snapshot.clone()),
    });

    assert_eq!(
        bridge.dashboard_snapshot(DashboardScope::Mesh).unwrap(),
        snapshot
    );
    assert_eq!(
        *requests.lock().unwrap(),
        vec![LocalRequest::DashboardSnapshot {
            version: LocalProtocolVersion::CURRENT,
            scope: DashboardScope::Mesh,
        }]
    );
}

#[test]
fn pending_approvals_bridge_uses_the_same_typed_local_request() {
    let requests = Arc::new(Mutex::new(vec![]));
    let bridge = DesktopBridge::new(FakeTransport {
        requests: Arc::clone(&requests),
        response: LocalResponse::PendingApprovals(vec![]),
    });

    assert!(bridge.pending_approvals().unwrap().is_empty());
    assert_eq!(
        *requests.lock().unwrap(),
        vec![LocalRequest::PendingApprovals {
            version: LocalProtocolVersion::CURRENT,
        }]
    );
}

#[test]
fn audit_query_bridge_preserves_filter_cursor_and_bound() {
    let requests = Arc::new(Mutex::new(vec![]));
    let filter = AuditFilter::default();
    let cursor = EventCursor {
        epoch: 7,
        sequence: 11,
    };
    let bridge = DesktopBridge::new(FakeTransport {
        requests: Arc::clone(&requests),
        response: LocalResponse::AuditRecords(device_development_mesh::dashboard::CursorPage {
            items: vec![],
            next_cursor: None,
        }),
    });

    assert!(
        bridge
            .audit_query(filter.clone(), Some(cursor), 17)
            .unwrap()
            .items
            .is_empty()
    );
    assert_eq!(
        *requests.lock().unwrap(),
        vec![LocalRequest::AuditQuery {
            version: LocalProtocolVersion::CURRENT,
            filter,
            cursor: Some(cursor),
            limit: 17,
        }]
    );
}

#[test]
fn management_bridge_uses_approval_ids_without_exposing_nonces_or_access_credentials() {
    let requests = Arc::new(Mutex::new(vec![]));
    let bridge = DesktopBridge::new(FakeTransport {
        requests: Arc::clone(&requests),
        response: LocalResponse::ApprovalDecided {
            decision: ApprovalDecision::AllowOnce,
            created_rule: None,
        },
    });

    bridge
        .decide_pending_approval("approval-42", ApprovalDecision::AllowOnce)
        .unwrap();

    let encoded = serde_json::to_string(&requests.lock().unwrap()[0]).unwrap();
    assert!(encoded.contains("approval-42"));
    assert!(!encoded.contains("nonce"));
    assert!(!encoded.contains("principal_id"));
    assert!(!encoded.contains("identity"));
}

#[test]
fn invalid_notification_lookup_never_calls_the_native_notifier() {
    let requests = Arc::new(Mutex::new(vec![]));
    let bridge = DesktopBridge::new(FakeTransport {
        requests: Arc::clone(&requests),
        response: LocalResponse::Error {
            code: "approval_expired".into(),
            message: "approval expired".into(),
        },
    });
    let mut notified = false;

    let error = bridge
        .with_pending_approval_for_notification("approval-42", |_| {
            notified = true;
            Ok(())
        })
        .unwrap_err();

    assert!(!notified);
    assert!(error.contains("approval_expired"));
    assert_eq!(
        *requests.lock().unwrap(),
        vec![LocalRequest::PendingApprovalForNotification {
            version: LocalProtocolVersion::CURRENT,
            approval_id: device_development_mesh::dashboard::ApprovalId::parse("approval-42")
                .unwrap(),
        }]
    );
}

#[test]
fn management_bridge_preserves_daemon_error_codes() {
    let bridge = DesktopBridge::new(FakeTransport {
        requests: Arc::new(Mutex::new(vec![])),
        response: LocalResponse::Error {
            code: "revision_conflict".into(),
            message: "rule changed".into(),
        },
    });

    assert_eq!(
        bridge.delete_policy_rule("rule-1", 7).unwrap_err(),
        "daemon error (revision_conflict): rule changed"
    );
}

#[test]
fn cancelled_native_audit_export_does_not_contact_the_daemon_or_create_a_file() {
    let requests = Arc::new(Mutex::new(vec![]));
    let bridge = DesktopBridge::new(FakeTransport {
        requests: Arc::clone(&requests),
        response: LocalResponse::Acknowledged,
    });

    let result = bridge
        .save_audit_export_with_picker(AuditFilter::default(), || None)
        .unwrap();

    assert!(matches!(
        result,
        devicelane_desktop::AuditSaveResult::Cancelled
    ));
    assert!(requests.lock().unwrap().is_empty());
}

struct QueueTransport {
    requests: Arc<Mutex<Vec<LocalRequest>>>,
    responses: Mutex<Vec<LocalResponse>>,
}

impl DaemonTransport for QueueTransport {
    fn send(&self, request: LocalRequest) -> Result<LocalResponse, String> {
        self.requests.lock().unwrap().push(request);
        if self.responses.lock().unwrap().is_empty() {
            return Err("unexpected daemon request".into());
        }
        Ok(self.responses.lock().unwrap().remove(0))
    }
}

#[test]
fn failed_audit_export_write_leaves_no_partial_file() {
    let missing = std::env::temp_dir()
        .join(format!(
            "devicelane-missing-export-parent-{}",
            std::process::id()
        ))
        .join("audit.json");
    let bridge = DesktopBridge::new(QueueTransport {
        requests: Arc::new(Mutex::new(vec![])),
        responses: Mutex::new(vec![
            LocalResponse::AuditExportManifest(ExportManifest {
                format_version: 1,
                record_count: 0,
                records_sha256: format!("{:x}", sha2::Sha256::digest(b"[]")),
                signature: ExportSignature::Unavailable,
            }),
            LocalResponse::AuditRecords(device_development_mesh::dashboard::CursorPage {
                items: vec![],
                next_cursor: None,
            }),
        ]),
    });

    assert!(
        bridge
            .save_audit_export_to_path(AuditFilter::default(), &missing)
            .is_err()
    );
    assert!(!missing.exists());
}

fn export_record(sequence: u64) -> AuditRecord {
    AuditRecord {
        sequence,
        occurred_at_ms: sequence,
        activity_id: None,
        principal_id: PrincipalId::parse(format!("principal-{sequence}")).unwrap(),
        source_host_id: HostId::parse("windows").unwrap(),
        target_host_id: HostId::parse("mac").unwrap(),
        device_id: None,
        operation: OperationId::parse("xcode-build").unwrap(),
        resources: vec![ResourceClass::WorkspaceRead],
        decision: PolicyEffect::Allow,
        result: AuditResult::Succeeded,
        redacted_message: None,
    }
}

#[test]
fn native_writer_saves_more_than_512_kib_through_bounded_pages() {
    let records = (1..=2_048).map(export_record).collect::<Vec<_>>();
    let records_json = serde_json::to_vec(&records).unwrap();
    assert!(records_json.len() > 512 * 1024);
    let manifest = ExportManifest {
        format_version: 1,
        record_count: records.len(),
        records_sha256: format!("{:x}", sha2::Sha256::digest(&records_json)),
        signature: ExportSignature::Unavailable,
    };
    let mut responses = vec![LocalResponse::AuditExportManifest(manifest.clone())];
    for page in records.chunks(32) {
        responses.push(LocalResponse::AuditRecords(
            device_development_mesh::dashboard::CursorPage {
                items: page.to_vec(),
                next_cursor: page.last().map(|record| EventCursor {
                    epoch: 1,
                    sequence: record.sequence,
                }),
            },
        ));
    }
    responses.push(LocalResponse::AuditRecords(
        device_development_mesh::dashboard::CursorPage {
            items: vec![],
            next_cursor: None,
        },
    ));
    let requests = Arc::new(Mutex::new(vec![]));
    let bridge = DesktopBridge::new(QueueTransport {
        requests: Arc::clone(&requests),
        responses: Mutex::new(responses),
    });
    let root = std::env::temp_dir().join(format!("devicelane-large-export-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    let output = root.join("audit.json");

    let result = bridge
        .save_audit_export_to_path(AuditFilter::default(), &output)
        .unwrap();

    assert!(
        matches!(result, devicelane_desktop::AuditSaveResult::Saved { manifest: saved, .. } if saved == manifest)
    );
    assert!(fs::metadata(&output).unwrap().len() > 512 * 1024);
    assert!(
        requests
            .lock()
            .unwrap()
            .iter()
            .all(|request| !matches!(request, LocalRequest::AuditExport { .. }))
    );
    fs::remove_file(output).unwrap();
    fs::remove_dir(root).unwrap();
}

#[test]
fn native_writer_detects_a_changed_audit_view_before_replacing_the_target() {
    let original = export_record(1);
    let records_json = serde_json::to_vec(&vec![original]).unwrap();
    let manifest = ExportManifest {
        format_version: 1,
        record_count: 1,
        records_sha256: format!("{:x}", sha2::Sha256::digest(&records_json)),
        signature: ExportSignature::Unavailable,
    };
    let changed = export_record(2);
    let bridge = DesktopBridge::new(QueueTransport {
        requests: Arc::new(Mutex::new(vec![])),
        responses: Mutex::new(vec![
            LocalResponse::AuditExportManifest(manifest),
            LocalResponse::AuditRecords(device_development_mesh::dashboard::CursorPage {
                items: vec![changed],
                next_cursor: Some(EventCursor {
                    epoch: 1,
                    sequence: 2,
                }),
            }),
            LocalResponse::AuditRecords(device_development_mesh::dashboard::CursorPage {
                items: vec![],
                next_cursor: None,
            }),
        ]),
    });
    let root =
        std::env::temp_dir().join(format!("devicelane-changed-export-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    let output = root.join("audit.json");
    fs::write(&output, b"original").unwrap();

    assert_eq!(
        bridge
            .save_audit_export_to_path(AuditFilter::default(), &output)
            .unwrap_err(),
        "audit export changed while saving"
    );
    assert_eq!(fs::read(&output).unwrap(), b"original");
    fs::remove_file(output).unwrap();
    fs::remove_dir(root).unwrap();
}

#[test]
fn dashboard_acknowledgement_parses_decimal_cursor_without_javascript_precision_loss() {
    let requests = Arc::new(Mutex::new(vec![]));
    let bridge = DesktopBridge::new(FakeTransport {
        requests: Arc::clone(&requests),
        response: LocalResponse::Acknowledged,
    });
    let cursor = WireEventCursor {
        epoch: u64::MAX.to_string(),
        sequence: (u64::MAX - 1).to_string(),
    };

    bridge
        .acknowledge_events("desktop-ui", cursor.try_into().unwrap())
        .unwrap();

    assert_eq!(
        *requests.lock().unwrap(),
        vec![LocalRequest::AcknowledgeEvents {
            version: LocalProtocolVersion::CURRENT,
            subscriber_id: SubscriberId::parse("desktop-ui").unwrap(),
            cursor: EventCursor {
                epoch: u64::MAX,
                sequence: u64::MAX - 1
            },
        }]
    );
}

#[test]
fn javascript_dashboard_wire_serializes_every_u64_as_an_exact_decimal_string() {
    let wire = serde_json::to_value(JavaScriptWire(EventRead::ResyncRequired {
        oldest_available: EventCursor {
            epoch: u64::MAX,
            sequence: u64::MAX - 1,
        },
        snapshot_revision: u64::MAX - 2,
    }))
    .unwrap();

    assert_eq!(wire["oldest_available"]["epoch"], u64::MAX.to_string());
    assert_eq!(
        wire["oldest_available"]["sequence"],
        (u64::MAX - 1).to_string()
    );
    assert_eq!(wire["snapshot_revision"], (u64::MAX - 2).to_string());
}

#[test]
fn javascript_dashboard_wire_keeps_cursor_and_limit_recovery_variants_structured() {
    let cursor_ahead = serde_json::to_value(JavaScriptWire(EventRead::CursorAhead {
        newest_available: EventCursor {
            epoch: u64::MAX,
            sequence: u64::MAX - 1,
        },
    }))
    .unwrap();
    let limit = serde_json::to_value(JavaScriptWire(EventRead::LimitExceeded)).unwrap();

    assert_eq!(cursor_ahead["result"], "cursor_ahead");
    assert_eq!(
        cursor_ahead["newest_available"]["epoch"],
        u64::MAX.to_string()
    );
    assert_eq!(limit["result"], "limit_exceeded");
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

#[test]
fn bundle_assets_reject_outside_missing_and_non_file_paths() {
    let root = std::env::temp_dir().join(format!("devicelane-assets-{}", std::process::id()));
    let outside = std::env::temp_dir().join(format!("devicelane-outside-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("directory")).unwrap();
    fs::write(&outside, b"outside").unwrap();
    assert!(
        validate_bundle_asset(&root, &outside, &sha256_file(&outside).unwrap())
            .unwrap_err()
            .contains("outside")
    );
    assert!(
        validate_bundle_asset(&root, &root.join("missing"), "00")
            .unwrap_err()
            .contains("unavailable")
    );
    assert!(
        validate_bundle_asset(&root, &root.join("directory"), "00")
            .unwrap_err()
            .contains("regular file")
    );
    fs::remove_dir_all(root).unwrap();
    fs::remove_file(outside).unwrap();
}

#[test]
fn bundle_asset_integrity_accepts_exact_hash_and_rejects_changes() {
    let root = std::env::temp_dir().join(format!("devicelane-integrity-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let asset = root.join("setup.sh");
    fs::write(&asset, b"trusted").unwrap();
    let hash = sha256_file(&asset).unwrap();
    assert_eq!(
        validate_bundle_asset(&root, &asset, &hash).unwrap(),
        asset.canonicalize().unwrap()
    );
    fs::write(&asset, b"changed").unwrap();
    assert!(
        validate_bundle_asset(&root, &asset, &hash)
            .unwrap_err()
            .contains("integrity")
    );
    fs::remove_dir_all(root).unwrap();
}

#[cfg(any(unix, windows))]
#[test]
fn bundle_assets_reject_symbolic_links() {
    let root = std::env::temp_dir().join(format!("devicelane-links-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let target = root.join("target");
    let link = root.join("link");
    fs::write(&target, b"trusted").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&target, &link).unwrap();
    #[cfg(windows)]
    if std::os::windows::fs::symlink_file(&target, &link).is_err() {
        fs::remove_dir_all(root).unwrap();
        return;
    }
    assert!(
        validate_bundle_asset(&root, &link, &sha256_file(&target).unwrap())
            .unwrap_err()
            .contains("link")
    );
    fs::remove_dir_all(root).unwrap();
}

#[cfg(windows)]
#[test]
fn hanging_repair_child_is_killed_and_reaped_at_the_deadline() {
    let spec = devicelane_desktop::RepairSpec {
        program: r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".into(),
        arguments: vec![
            "-NoProfile".into(),
            "-Command".into(),
            "Start-Sleep -Seconds 30".into(),
        ],
        service_binary: std::env::current_exe().unwrap(),
    };
    let started = Instant::now();
    let error = devicelane_desktop::execute_repair_process(&spec, Duration::from_millis(100), 1024)
        .unwrap_err();
    assert!(error.contains("timed out"));
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[cfg(windows)]
#[test]
fn oversized_repair_stderr_is_drained_but_diagnostic_is_bounded() {
    let spec = devicelane_desktop::RepairSpec {
        program: r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".into(),
        arguments: vec![
            "-NoProfile".into(),
            "-Command".into(),
            "$x='x'*200000; [Console]::Error.Write($x); exit 7".into(),
        ],
        service_binary: std::env::current_exe().unwrap(),
    };
    let error = devicelane_desktop::execute_repair_process(&spec, Duration::from_secs(5), 1024)
        .unwrap_err();
    assert!(error.contains("output truncated"));
    assert!(error.len() < 1200);
}
