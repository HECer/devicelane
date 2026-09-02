use device_development_mesh::dashboard::audit::{
    AuditFilter, AuditStore, Redactor, RetentionPolicy,
};
use device_development_mesh::dashboard::event_log::EventJournal;
use device_development_mesh::dashboard::policy::PolicyEngine;
use device_development_mesh::dashboard::service::DashboardService;
use device_development_mesh::dashboard::topology::{
    DeviceDetails, RegistryHost, TopologyProjector,
};
use device_development_mesh::dashboard::{
    ActivityId, ActivityState, ConnectionPath, DashboardScope, HostId, MetricSnapshot, MetricValue,
    SafeCode, TrustState,
};
use device_development_mesh::local_ipc::{
    ConnectionState, DaemonRole, DaemonSnapshot, DaemonState, LocalEndpoint, LocalProtocolVersion,
    LocalRequest, LocalResponse, local_endpoint, send_local_request, serve_local,
};
use device_development_mesh::network_processes::{DeviceSnapshot, HostSnapshot};
use std::{
    fs,
    path::PathBuf,
    process::Command,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn dashboard_release_gate_runs_every_client_on_every_supported_os() {
    let ci = fs::read_to_string(root().join(".github/workflows/ci.yml")).unwrap();

    for runner in ["windows-latest", "macos-latest", "ubuntu-latest"] {
        assert!(ci.contains(runner), "CI is missing {runner}");
    }
    for command in [
        "cargo test --workspace --locked",
        "cargo clippy --workspace --all-targets --all-features --locked -- -D warnings",
        "cargo fmt --all -- --check",
        "npm test -- --run",
        "npm run typecheck",
        "npm run build",
        "cargo test --manifest-path desktop/src-tauri/Cargo.toml --locked",
        "cargo test --test desktop_distribution --locked",
        "scripts/lifecycle-transaction-smoke.sh",
        "scripts/desktop-release-smoke.sh --self-test",
    ] {
        assert!(
            ci.contains(command),
            "CI is missing release gate: {command}"
        );
    }
    assert!(
        !ci.contains("continue-on-error: true"),
        "dashboard release gates must fail closed"
    );
}

#[test]
fn physical_mac_gate_requires_a_real_paired_mesh_and_redacted_evidence() {
    let script = fs::read_to_string(root().join("scripts/mac-hardware-gate.sh")).unwrap();

    for required in [
        "--mesh-controller",
        "--mesh-endpoint",
        "--windows-principal",
        "--windows-source-host",
        "--mesh-activity-id",
        "DEVICELANE_REAL_MESH_GATE",
        "mesh status",
        "activities watch",
        "approvals list",
        "audit list",
        "workspace_read",
        "device_lease",
        "observer_unavailable",
        "approval_not_allowed",
        "resync_required",
        "redacted",
        "mesh-evidence.json",
    ] {
        assert!(
            script.contains(required),
            "Mac mesh gate is missing: {required}"
        );
    }
    for forbidden in [
        "identity.json\" >",
        "audit.sqlite",
        "audit.jsonl",
        "cp \"$IDENTITY",
        "cp \"$AUDIT",
    ] {
        assert!(
            !script.contains(forbidden),
            "Mac mesh evidence may expose forbidden data: {forbidden}"
        );
    }
}

#[test]
fn release_docs_distinguish_ci_fixture_and_physical_mac_proof() {
    let readme = fs::read_to_string(root().join("README.md")).unwrap();
    let changelog = fs::read_to_string(root().join("CHANGELOG.md")).unwrap();

    for required in [
        "DeviceLane dashboard release gate",
        "DEVICELANE_REAL_MESH_GATE",
        "<MAC_HOST>",
        "<WINDOWS_CONTROLLER_HOST>",
        "redacted metadata",
        "does not prove a physical Mac pass",
    ] {
        assert!(readme.contains(required), "README is missing: {required}");
    }
    assert!(changelog.contains("Mesh dashboard end-to-end gate"));
    assert!(changelog.contains("Windows, macOS, and Linux"));
}

struct RunningFixture {
    _root: tempfile::TempDir,
    endpoint_text: String,
    endpoint: LocalEndpoint,
    state: Arc<Mutex<DaemonState>>,
}

fn host(id: &str, os: &str, arch: &str, device: Option<&str>) -> HostSnapshot {
    HostSnapshot {
        id: id.into(),
        operating_system: os.into(),
        architecture: arch.into(),
        status: "online".into(),
        capabilities: vec!["workspace_read".into(), "device_lease".into()],
        devices: device
            .into_iter()
            .map(|id| DeviceSnapshot {
                id: id.into(),
                platform: "iOS".into(),
                state: "online".into(),
            })
            .collect(),
    }
}

fn fixture() -> RunningFixture {
    static NEXT_FIXTURE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(1);
    let root = tempfile::tempdir().unwrap();
    let runtime = root.path().join("runtime");
    fs::create_dir_all(&runtime).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
    }
    #[cfg(windows)]
    let endpoint_text = format!(
        r"\\.\pipe\devicelane-mesh-e2e-{}-{}",
        std::process::id(),
        NEXT_FIXTURE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    #[cfg(unix)]
    let endpoint_text = runtime.join("mesh-e2e.sock").display().to_string();
    let endpoint = local_endpoint(&runtime, &endpoint_text).unwrap();

    let mut topology = TopologyProjector::new();
    topology
        .observe_local(1, 10, host("mac-agent", "macOS", "arm64", Some("iphone")))
        .unwrap();
    topology
        .observe_local(2, 11, host("mac-agent", "macOS", "arm64", Some("iphone")))
        .unwrap();
    topology
        .connect_registry("paired-registry", 1, true)
        .unwrap();
    let windows = RegistryHost {
        snapshot: host("windows-controller", "Windows", "x86_64", None),
        display_name: "Windows controller".into(),
        trust: TrustState::Trusted,
        connection_path: ConnectionPath::Registry,
        permissions: vec!["workspace_read".into()],
        devices: Vec::<DeviceDetails>::new(),
    };
    topology
        .observe_registry(1, 10, true, vec![windows.clone()])
        .unwrap();
    topology
        .observe_registry(2, 11, true, vec![windows])
        .unwrap();
    topology
        .track_active_lease("iphone-lease", "mac-agent", "iphone")
        .unwrap();

    let audit = Arc::new(Mutex::new(
        AuditStore::open(
            root.path().join("audit"),
            RetentionPolicy::default(),
            Redactor::default(),
        )
        .unwrap(),
    ));
    let service = DashboardService::new(
        HostId::parse("mac-agent").unwrap(),
        topology,
        EventJournal::new(1, 0),
        audit,
        PolicyEngine::new(),
    );
    let mut daemon = DaemonState::new(
        DaemonSnapshot {
            public_identity: "mac-agent".into(),
            daemon_version: "e2e".into(),
            os: "macOS".into(),
            architecture: "arm64".into(),
            role: DaemonRole::Agent,
            endpoint: endpoint_text.clone(),
            connection: ConnectionState::Connected,
            local_protocol: LocalProtocolVersion::CURRENT,
            remote_protocol: "1.0".into(),
            warnings: vec![],
            remote_access_paused: false,
            autostart: true,
            log_location: root.path().display().to_string(),
            features: vec!["dashboard_v1".into()],
        },
        vec![],
    );
    daemon.enable_dashboard(service);
    let state = Arc::new(Mutex::new(daemon));
    let server_state = Arc::clone(&state);
    let server_endpoint = endpoint.clone();
    thread::spawn(move || {
        let _ = serve_local(&server_endpoint, server_state);
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    while send_local_request(
        &endpoint,
        &LocalRequest::Status {
            version: LocalProtocolVersion::CURRENT,
        },
    )
    .is_err()
    {
        assert!(
            Instant::now() < deadline,
            "local dashboard daemon did not start"
        );
        thread::sleep(Duration::from_millis(20));
    }
    RunningFixture {
        _root: root,
        endpoint_text,
        endpoint,
        state,
    }
}

fn cli(fixture: &RunningFixture, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_devicelane"))
        .args(args)
        .args(["--endpoint", &fixture.endpoint_text])
        .output()
        .unwrap()
}

fn approval_args<'a>(activity_id: &'a str, decision: Option<&'a str>) -> Vec<&'a str> {
    let mut args = vec![
        "approvals",
        "request",
        "--local",
        "--json",
        "--activity-id",
        activity_id,
        "--principal-id",
        "windows-agent",
        "--source-host-id",
        "windows-controller",
        "--target-host-id",
        "mac-agent",
        "--device-id",
        "iphone",
        "--operation",
        "workspace.read",
        "--resource",
        "workspace_read",
        "--resource",
        "device_lease",
        "--physical-device",
    ];
    if let Some(decision) = decision {
        args[1] = "decide";
        args.extend(["--decision", decision]);
    }
    args
}

fn grant_cancel_once(fixture: &RunningFixture) {
    let common = [
        "--principal-id",
        "local-user",
        "--source-host-id",
        "mac-agent",
        "--target-host-id",
        "mac-agent",
        "--operation",
        "devicelane.activity.cancel",
        "--resource",
        "device_lane_service",
        "--user-present",
    ];
    let mut request = vec![
        "approvals",
        "request",
        "--local",
        "--json",
        "--activity-id",
        "cancel-race-grant",
    ];
    request.extend(common);
    let created = cli(fixture, &request);
    assert!(created.status.success());
    let LocalResponse::ApprovalCreated { nonce, .. } =
        serde_json::from_slice(&created.stdout).unwrap()
    else {
        panic!("cancel approval was not created")
    };
    let mut decide = vec![
        "approvals",
        "decide",
        "--local",
        "--json",
        "--activity-id",
        "cancel-race-grant",
        "--nonce",
        &nonce,
        "--decision",
        "allow_once",
    ];
    decide.extend(common);
    let allowed = cli(fixture, &decide);
    assert!(
        allowed.status.success(),
        "{}",
        String::from_utf8_lossy(&allowed.stderr)
    );
}

#[test]
fn paired_vertical_slice_preserves_one_identity_across_cli_ipc_reconnect_and_audit() {
    let fixture = fixture();
    let activity_id = "windows-to-mac-release-gate";

    let denied_request = cli(&fixture, &approval_args(activity_id, None));
    assert!(
        denied_request.status.success(),
        "{}",
        String::from_utf8_lossy(&denied_request.stderr)
    );
    let LocalResponse::ApprovalCreated {
        nonce: denied_nonce,
        ..
    } = serde_json::from_slice(&denied_request.stdout).unwrap()
    else {
        panic!("approval was not created")
    };
    let mut deny_args = approval_args(activity_id, Some("deny_once"));
    deny_args.extend(["--nonce", &denied_nonce]);
    let denied = cli(&fixture, &deny_args);
    assert!(
        denied.status.success(),
        "{}",
        String::from_utf8_lossy(&denied.stderr)
    );

    let allowed_request = cli(&fixture, &approval_args(activity_id, None));
    assert!(
        allowed_request.status.success(),
        "{}",
        String::from_utf8_lossy(&allowed_request.stderr)
    );
    let LocalResponse::ApprovalCreated {
        nonce: allowed_nonce,
        ..
    } = serde_json::from_slice(&allowed_request.stdout).unwrap()
    else {
        panic!("second approval was not created")
    };
    let mut allow_args = approval_args(activity_id, Some("allow_once"));
    allow_args.extend(["--nonce", &allowed_nonce]);
    let allowed = cli(&fixture, &allow_args);
    assert!(
        allowed.status.success(),
        "{}",
        String::from_utf8_lossy(&allowed.stderr)
    );

    let unavailable = || MetricValue::Unavailable {
        reason: SafeCode::parse("observer_unavailable").unwrap(),
    };
    let metrics = MetricSnapshot {
        current_memory_bytes: unavailable(),
        peak_memory_bytes: unavailable(),
        cpu_time_ms: unavailable(),
        process_count: unavailable(),
    };
    let id = ActivityId::parse(activity_id).unwrap();
    {
        let mut state = fixture.state.lock().unwrap();
        assert!(
            state
                .transition_dashboard_activity(
                    &id,
                    ActivityState::Running,
                    metrics.clone(),
                    None,
                    100
                )
                .unwrap()
        );
        assert!(
            state
                .transition_dashboard_activity(
                    &id,
                    ActivityState::Reconnecting,
                    metrics.clone(),
                    None,
                    101
                )
                .unwrap()
        );
        assert!(
            state
                .transition_dashboard_activity(
                    &id,
                    ActivityState::Running,
                    metrics.clone(),
                    None,
                    102
                )
                .unwrap()
        );
        assert!(
            state
                .transition_dashboard_activity(&id, ActivityState::Succeeded, metrics, None, 103)
                .unwrap()
        );
    }

    let direct_snapshot = send_local_request(
        &fixture.endpoint,
        &LocalRequest::DashboardSnapshot {
            version: LocalProtocolVersion::CURRENT,
            scope: DashboardScope::Mesh,
        },
    )
    .unwrap();
    let cli_snapshot = cli(
        &fixture,
        &["mesh", "status", "--local", "--json", "--scope", "mesh"],
    );
    assert!(cli_snapshot.status.success());
    let mut cli_value: serde_json::Value = serde_json::from_slice(&cli_snapshot.stdout).unwrap();
    let mut direct_value = serde_json::to_value(direct_snapshot).unwrap();
    cli_value["payload"]["generated_at_ms"] = serde_json::Value::Null;
    direct_value["payload"]["generated_at_ms"] = serde_json::Value::Null;
    assert_eq!(cli_value, direct_value);

    let events = send_local_request(
        &fixture.endpoint,
        &LocalRequest::ActivityEvents {
            version: LocalProtocolVersion::CURRENT,
            scope: DashboardScope::Mesh,
            cursor: device_development_mesh::dashboard::EventCursor {
                epoch: 1,
                sequence: 0,
            },
            limit: 256,
        },
    )
    .unwrap();
    let encoded = serde_json::to_value(&events).unwrap();
    let matching: Vec<_> = encoded["payload"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|event| event["activity_id"] == activity_id)
        .collect();
    assert_eq!(matching.len(), 8);
    assert_eq!(matching.last().unwrap()["state"], "succeeded");
    assert!(matching.iter().any(|event| event["state"] == "denied"));
    assert!(
        matching
            .iter()
            .any(|event| event["state"] == "reconnecting")
    );
    assert!(
        matching.iter().all(
            |event| event["resources"] == serde_json::json!(["workspace_read", "device_lease"])
        )
    );

    let audit = send_local_request(
        &fixture.endpoint,
        &LocalRequest::AuditQuery {
            version: LocalProtocolVersion::CURRENT,
            filter: AuditFilter::default(),
            cursor: None,
            limit: 256,
        },
    )
    .unwrap();
    let audit_json = serde_json::to_value(audit).unwrap();
    assert!(
        audit_json["payload"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|record| {
                record["activity_id"] == activity_id
                    && record["principal_id"] == "windows-agent"
                    && record["source_host_id"] == "windows-controller"
                    && record["target_host_id"] == "mac-agent"
            })
    );

    grant_cancel_once(&fixture);
    let raced_cancel = cli(
        &fixture,
        &[
            "activities",
            "cancel",
            "--local",
            "--json",
            "--activity-id",
            activity_id,
        ],
    );
    assert!(raced_cancel.status.success());
    assert_eq!(
        serde_json::from_slice::<LocalResponse>(&raced_cancel.stdout).unwrap(),
        LocalResponse::Cancellation { cancelled: false }
    );
}

#[test]
fn tauri_bridge_is_part_of_the_same_locked_contract_gate() {
    let bridge = fs::read_to_string(root().join("desktop/src-tauri/src/lib.rs")).unwrap();
    let bridge_tests =
        fs::read_to_string(root().join("desktop/src-tauri/tests/bridge.rs")).unwrap();
    for request in [
        "DashboardSnapshot",
        "ActivityEvents",
        "PendingApprovals",
        "AuditQuery",
    ] {
        assert!(bridge.contains(&format!("LocalRequest::{request}")));
        assert!(bridge_tests.contains(&format!("LocalRequest::{request}")));
    }
    assert!(bridge_tests.contains("preserves_resync_details"));
}

#[test]
fn failure_paths_are_actionable_and_the_focused_regressions_are_not_ignored() {
    let fixture = fixture();
    let mut offline = approval_args("offline-target", None);
    let target = offline.iter().position(|arg| *arg == "mac-agent").unwrap();
    offline[target] = "offline-mac";
    let rejected = cli(&fixture, &offline);
    assert!(!rejected.status.success());
    let response: LocalResponse = serde_json::from_slice(&rejected.stdout).unwrap();
    assert!(
        matches!(response, LocalResponse::Error { ref code, .. } if code == "unauthorized"),
        "unexpected offline-target response: {response:?}"
    );

    assert_eq!(
        LocalRequest::DashboardSnapshot {
            version: LocalProtocolVersion { major: 1, minor: 0 },
            scope: DashboardScope::Mesh,
        }
        .validate(),
        Err(device_development_mesh::local_ipc::LocalProtocolError::FeatureUnavailable)
    );

    for (path, regression) in [
        (
            "tests/dashboard_event_log.rs",
            "acknowledgement_of_an_evicted_gap_requires_resync",
        ),
        (
            "tests/dashboard_audit.rs",
            "storage_failure_blocks_remote_mutations",
        ),
        (
            "tests/dashboard_policy.rs",
            "deny_overrides_more_specific_allow_regardless_of_order",
        ),
        (
            "tests/dashboard_topology.rs",
            "stale_owner_makes_active_lease_uncertain_and_not_authorizable",
        ),
        (
            "tests/dashboard_ipc.rs",
            "restart_reconciles_one_existing_activity_id_without_starting_another",
        ),
        (
            "tests/dashboard_ipc.rs",
            "notification_lookup_returns_only_exact_live_daemon_pending_truth",
        ),
        (
            "tests/dashboard_topology.rs",
            "old_host_fixture_without_dashboard_fields_projects_as_unknown",
        ),
    ] {
        let source = fs::read_to_string(root().join(path)).unwrap();
        assert!(
            source.contains(&format!("fn {regression}")),
            "missing regression: {regression}"
        );
        let prefix = source.split(&format!("fn {regression}")).next().unwrap();
        assert!(
            !prefix
                .lines()
                .rev()
                .take(2)
                .any(|line| line.contains("#[ignore]")),
            "ignored regression: {regression}"
        );
    }
}
