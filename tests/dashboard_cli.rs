use device_development_mesh::dashboard::audit::{AuditStore, Redactor, RetentionPolicy};
use device_development_mesh::dashboard::event_log::EventJournal;
use device_development_mesh::dashboard::policy::PolicyEngine;
use device_development_mesh::dashboard::service::DashboardService;
use device_development_mesh::dashboard::topology::TopologyProjector;
use device_development_mesh::dashboard::{
    ActivityEvent, ActivityId, ActivityState, Authorization, HostId, MetricSnapshot, MetricValue,
    OperationId, PolicyEffect, PrincipalId, ResourceClass, SafeCode, SubscriberId,
};
use device_development_mesh::local_ipc::{
    ConnectionState, DaemonRole, DaemonSnapshot, DaemonState, LocalProtocolVersion, LocalRequest,
    LocalResponse, local_endpoint, send_local_request, serve_local,
};
use std::io::BufRead;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

struct Service(Child);
impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn endpoint_text(_runtime: &std::path::Path) -> String {
    #[cfg(windows)]
    {
        format!(r"\\.\pipe\devicelane-dashboard-cli-{}", std::process::id())
    }
    #[cfg(unix)]
    {
        _runtime.join("devicelane.sock").display().to_string()
    }
}

fn service() -> (
    tempfile::TempDir,
    String,
    device_development_mesh::local_ipc::LocalEndpoint,
    Service,
) {
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
    let text = endpoint_text(&runtime);
    let endpoint = local_endpoint(&runtime, &text).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_devicelane-service"))
        .args([
            "--identity",
            root.path().join("identity.json").to_str().unwrap(),
            "--runtime-dir",
            runtime.to_str().unwrap(),
            "--role",
            "workstation",
            "--registry",
            "registry.invalid:443",
            "--listen",
            &text,
            "--agent-peer",
            "agent",
            "--log-dir",
            logs.to_str().unwrap(),
            "--foreground",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
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
            return (root, text, endpoint, service);
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("service did not start")
}

fn cli_endpoint(endpoint: &str, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_devicelane"))
        .args(args)
        .args(["--endpoint", endpoint])
        .output()
        .unwrap()
}

fn grant_once(endpoint: &str, activity: &str, operation: &str, resource: &str) {
    let common = [
        "--principal-id",
        "local-user",
        "--source-host-id",
        "identity.json",
        "--target-host-id",
        "identity.json",
        "--operation",
        operation,
        "--resource",
        resource,
        "--user-present",
    ];
    let mut request = vec![
        "approvals",
        "request",
        "--local",
        "--json",
        "--activity-id",
        activity,
    ];
    request.extend(common);
    let output = cli_endpoint(endpoint, &request);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let LocalResponse::ApprovalCreated { nonce, .. } =
        serde_json::from_slice(&output.stdout).unwrap()
    else {
        panic!("approval not created")
    };
    let mut decide = vec![
        "approvals",
        "decide",
        "--local",
        "--json",
        "--nonce",
        &nonce,
        "--decision",
        "allow_once",
        "--activity-id",
        activity,
    ];
    decide.extend(common);
    let output = cli_endpoint(endpoint, &decide);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn observed_watch_service() -> (tempfile::TempDir, String, EventJournal) {
    let root = tempfile::tempdir().unwrap();
    let runtime = root.path().join("runtime");
    std::fs::create_dir_all(&runtime).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let text = format!("{}-observed", endpoint_text(&runtime));
    let endpoint = local_endpoint(&runtime, &text).unwrap();
    let journal = EventJournal::new(1, 0);
    let unavailable = || MetricValue::Unavailable {
        reason: SafeCode::parse("observer_unavailable").unwrap(),
    };
    journal
        .append(
            "watch-event",
            ActivityEvent {
                activity_id: ActivityId::parse("watch-event").unwrap(),
                sequence: 1,
                occurred_at_ms: 1,
                principal_id: PrincipalId::parse("agent").unwrap(),
                source_host_id: HostId::parse("source").unwrap(),
                target_host_id: HostId::parse("identity.json").unwrap(),
                device_id: None,
                operation: OperationId::parse("build").unwrap(),
                resources: vec![ResourceClass::WorkspaceRead],
                authorization: Authorization {
                    effect: PolicyEffect::Allow,
                    rule_id: None,
                    approval_id: None,
                },
                state: ActivityState::Running,
                message: None,
                metrics: MetricSnapshot {
                    current_memory_bytes: unavailable(),
                    peak_memory_bytes: unavailable(),
                    cpu_time_ms: unavailable(),
                    process_count: unavailable(),
                },
                started_at_ms: Some(1),
                finished_at_ms: None,
            },
        )
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
        HostId::parse("identity.json").unwrap(),
        TopologyProjector::new(),
        journal.clone(),
        audit,
        PolicyEngine::new(),
    );
    let mut state = DaemonState::new(
        DaemonSnapshot {
            public_identity: "identity.json".into(),
            daemon_version: "test".into(),
            os: std::env::consts::OS.into(),
            architecture: std::env::consts::ARCH.into(),
            role: DaemonRole::Workstation,
            endpoint: text.clone(),
            connection: ConnectionState::Connected,
            local_protocol: LocalProtocolVersion::CURRENT,
            remote_protocol: "1.0".into(),
            warnings: vec![],
            remote_access_paused: false,
            autostart: false,
            log_location: root.path().display().to_string(),
            features: vec!["dashboard_v1".into()],
        },
        vec![],
    );
    state.enable_dashboard(service);
    std::thread::spawn(move || {
        let _ = serve_local(&endpoint, Arc::new(Mutex::new(state)));
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if cli_endpoint(&text, &["status", "--local", "--json"])
            .status
            .success()
        {
            break;
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(20));
    }
    (root, text, journal)
}

fn cli(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_devicelane"))
        .args(args)
        .output()
        .expect("run devicelane")
}

#[test]
fn dashboard_commands_are_documented_and_require_local_transport() {
    for command in ["mesh", "activities", "approvals", "policy", "audit"] {
        let output = cli(&[command, "--help"]);
        assert!(
            output.status.success(),
            "{command}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("--local"));
    }
}

#[test]
fn typed_values_and_bounds_fail_before_ipc() {
    let cases: &[&[&str]] = &[
        &["mesh", "status", "--local", "--scope", "planet"],
        &["activities", "list", "--local", "--limit", "257"],
        &["approvals", "decide", "--local", "--decision", "maybe"],
        &["policy", "delete", "--local", "--rule-id", ""],
        &["audit", "list", "--local", "--result", "unknown"],
        &[
            "policy",
            "put",
            "--local",
            "--effect",
            "allow",
            "--resource",
            "shell",
        ],
    ];
    for args in cases {
        let output = cli(args);
        assert!(!output.status.success(), "accepted {args:?}");
        assert!(!String::from_utf8_lossy(&output.stderr).contains("panicked"));
    }
}

#[test]
fn every_dashboard_query_emits_structured_json_errors() {
    #[cfg(windows)]
    let endpoint = format!(
        r"\\.\pipe\devicelane-dashboard-missing-{}",
        std::process::id()
    );
    #[cfg(unix)]
    let endpoint = "/definitely/missing/devicelane-dashboard.sock".to_owned();
    let commands: &[&[&str]] = &[
        &["mesh", "status", "--local", "--json"],
        &["activities", "list", "--local", "--json"],
        &["approvals", "list", "--local", "--json"],
        &["policy", "list", "--local", "--json"],
        &["audit", "list", "--local", "--json"],
        &["audit", "export", "--local", "--json"],
    ];
    for args in commands {
        let output = Command::new(env!("CARGO_BIN_EXE_devicelane"))
            .args(*args)
            .args(["--endpoint", &endpoint])
            .stdout(Stdio::piped())
            .output()
            .unwrap();
        assert!(!output.status.success(), "accepted {args:?}");
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["type"], "error");
        assert_eq!(value["payload"]["code"], "local_ipc_error");
    }
}

#[test]
fn raw_shell_and_implicit_json_objects_are_not_accepted() {
    for args in [
        vec!["activities", "cancel", "--local", "--shell", "rm -rf /"],
        vec![
            "policy",
            "put",
            "--local",
            "--rule",
            "{\"effect\":\"allow\"}",
        ],
    ] {
        let output = cli(&args);
        assert!(!output.status.success());
    }
}

#[test]
fn command_foreign_and_unused_flags_are_rejected() {
    for args in [
        vec!["mesh", "status", "--local", "--limit", "1"],
        vec!["activities", "list", "--local", "--scope", "local"],
        vec!["approvals", "list", "--local", "--nonce", "n"],
        vec!["policy", "list", "--local", "--effect", "allow"],
        vec!["audit", "export", "--local", "--cursor", "1:0"],
        vec!["status", "--local", "--resource", "workspace_read"],
    ] {
        let output = cli(&args);
        assert!(!output.status.success(), "accepted {args:?}");
        assert!(String::from_utf8_lossy(&output.stderr).contains("not valid for"));
    }
}

#[test]
fn json_watch_transport_errors_are_structured_and_nonzero() {
    #[cfg(windows)]
    let endpoint = format!(r"\\.\pipe\devicelane-watch-missing-{}", std::process::id());
    #[cfg(unix)]
    let endpoint = "/definitely/missing/watch.sock".to_owned();
    for args in [
        vec!["mesh", "watch", "--local", "--json"],
        vec!["activities", "watch", "--local", "--json"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_devicelane"))
            .args(args)
            .args(["--endpoint", &endpoint])
            .output()
            .unwrap();
        assert!(!output.status.success());
        let error: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(error["type"], "error");
        assert_eq!(error["payload"]["code"], "local_ipc_error");
    }
}

#[test]
fn help_names_typed_resources_and_the_exact_grant_flow() {
    let output = cli(&["approvals", "--help"]);
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("approvals request"));
    assert!(text.contains("approvals decide"));
    assert!(text.contains("allow_once"));
    assert!(text.contains("workspace_read"));
    assert!(text.contains("devicelane.policy.put"));
    assert!(text.contains("devicelane.service.pause -> device_lane_service"));
    assert!(text.contains("devicelane.service.resume -> device_lane_service"));
}

#[test]
fn real_daemon_queries_match_direct_ipc_and_exact_grant_enables_mutation() {
    let (_root, endpoint_text, endpoint, _service) = service();
    let version = LocalProtocolVersion::CURRENT;
    let cases = [
        (
            vec![
                "activities",
                "list",
                "--local",
                "--json",
                "--cursor",
                "1:0",
                "--limit",
                "17",
            ],
            LocalRequest::ActivityEvents {
                version,
                cursor: device_development_mesh::dashboard::EventCursor {
                    epoch: 1,
                    sequence: 0,
                },
                limit: 17,
            },
        ),
        (
            vec!["approvals", "list", "--local", "--json"],
            LocalRequest::PendingApprovals { version },
        ),
        (
            vec!["policy", "list", "--local", "--json"],
            LocalRequest::PolicyRules { version },
        ),
        (
            vec![
                "audit", "list", "--local", "--json", "--cursor", "1:0", "--limit", "17",
            ],
            LocalRequest::AuditQuery {
                version,
                filter: Default::default(),
                cursor: Some(device_development_mesh::dashboard::EventCursor {
                    epoch: 1,
                    sequence: 0,
                }),
                limit: 17,
            },
        ),
        (
            vec!["audit", "export", "--local", "--json"],
            LocalRequest::AuditExport {
                version,
                filter: Default::default(),
            },
        ),
    ];
    for (args, request) in cases {
        let direct = send_local_request(&endpoint, &request).unwrap();
        let output = cli_endpoint(&endpoint_text, &args);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            serde_json::from_slice::<LocalResponse>(&output.stdout).unwrap(),
            direct
        );
    }
    let mesh = cli_endpoint(
        &endpoint_text,
        &["mesh", "status", "--local", "--json", "--scope", "local"],
    );
    assert!(mesh.status.success());
    assert!(matches!(
        serde_json::from_slice::<LocalResponse>(&mesh.stdout).unwrap(),
        LocalResponse::DashboardSnapshot(_)
    ));

    let mut mesh_watch = Command::new(env!("CARGO_BIN_EXE_devicelane"))
        .args([
            "mesh",
            "watch",
            "--local",
            "--json",
            "--endpoint",
            &endpoint_text,
        ])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut mesh_line = String::new();
    std::io::BufReader::new(mesh_watch.stdout.take().unwrap())
        .read_line(&mut mesh_line)
        .unwrap();
    assert!(serde_json::from_str::<LocalResponse>(&mesh_line).is_ok());
    let _ = mesh_watch.kill();
    let _ = mesh_watch.wait();

    let requested = cli_endpoint(
        &endpoint_text,
        &[
            "approvals",
            "request",
            "--local",
            "--json",
            "--activity-id",
            "cli-policy-grant",
            "--principal-id",
            "local-user",
            "--source-host-id",
            "identity.json",
            "--target-host-id",
            "identity.json",
            "--operation",
            "devicelane.policy.put",
            "--resource",
            "device_lane_policy",
            "--user-present",
        ],
    );
    assert!(
        requested.status.success(),
        "{}",
        String::from_utf8_lossy(&requested.stderr)
    );
    let created: LocalResponse = serde_json::from_slice(&requested.stdout).unwrap();
    let mut broken = Command::new(env!("CARGO_BIN_EXE_devicelane"))
        .args([
            "activities",
            "watch",
            "--local",
            "--json",
            "--cursor",
            "1:0",
            "--endpoint",
            &endpoint_text,
        ])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    drop(broken.stdout.take());
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = broken.try_wait().unwrap() {
            break status;
        }
        assert!(Instant::now() < deadline, "broken-pipe watch did not exit");
        std::thread::sleep(Duration::from_millis(20));
    };
    assert!(
        status.success(),
        "broken pipe should terminate cleanly without acknowledging unseen events"
    );
    let LocalResponse::ApprovalCreated { nonce, .. } = created else {
        panic!("approval not created")
    };
    let mut decide = vec![
        "approvals",
        "decide",
        "--local",
        "--json",
        "--nonce",
        &nonce,
        "--decision",
        "allow_once",
        "--activity-id",
        "cli-policy-grant",
        "--principal-id",
        "local-user",
        "--source-host-id",
        "identity.json",
        "--target-host-id",
        "identity.json",
        "--operation",
        "devicelane.policy.put",
        "--resource",
        "device_lane_policy",
        "--user-present",
    ];
    let decided = cli_endpoint(&endpoint_text, &decide);
    assert!(
        decided.status.success(),
        "{}",
        String::from_utf8_lossy(&decided.stderr)
    );
    decide.clear();
    let put = cli_endpoint(
        &endpoint_text,
        &[
            "policy",
            "put",
            "--local",
            "--json",
            "--rule-id",
            "cli-rule",
            "--effect",
            "deny",
            "--operation",
            "build",
            "--resource",
            "workspace_write",
            "--enabled",
        ],
    );
    assert!(
        put.status.success(),
        "{}",
        String::from_utf8_lossy(&put.stderr)
    );
    let listed = cli_endpoint(&endpoint_text, &["policy", "list", "--local", "--json"]);
    let response: LocalResponse = serde_json::from_slice(&listed.stdout).unwrap();
    assert!(
        matches!(response, LocalResponse::PolicyRules(rules) if rules.iter().any(|rule| rule.id.as_str() == "cli-rule"))
    );
    grant_once(
        &endpoint_text,
        "cli-cancel-grant",
        "devicelane.activity.cancel",
        "device_lane_service",
    );
    let cancelled = cli_endpoint(
        &endpoint_text,
        &[
            "activities",
            "cancel",
            "--local",
            "--json",
            "--activity-id",
            "cli-policy-grant",
        ],
    );
    assert!(
        cancelled.status.success(),
        "{}",
        String::from_utf8_lossy(&cancelled.stderr)
    );
    grant_once(
        &endpoint_text,
        "cli-delete-grant",
        "devicelane.policy.delete",
        "device_lane_policy",
    );
    let deleted = cli_endpoint(
        &endpoint_text,
        &[
            "policy",
            "delete",
            "--local",
            "--json",
            "--rule-id",
            "cli-rule",
        ],
    );
    assert!(
        deleted.status.success(),
        "{}",
        String::from_utf8_lossy(&deleted.stderr)
    );
}

#[test]
fn activity_watch_acknowledges_only_stdout_delivered_cursor() {
    let (_root, endpoint, journal) = observed_watch_service();
    let mut delivered = Command::new(env!("CARGO_BIN_EXE_devicelane"))
        .args([
            "activities",
            "watch",
            "--local",
            "--json",
            "--cursor",
            "1:0",
            "--limit",
            "1",
            "--endpoint",
            &endpoint,
        ])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let delivered_id = SubscriberId::parse(format!("cli-{}", delivered.id())).unwrap();
    let mut line = String::new();
    std::io::BufReader::new(delivered.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let value: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(value["activity_id"], "watch-event");
    assert_eq!(value["sequence"], 1);
    let deadline = Instant::now() + Duration::from_secs(5);
    while journal.subscriber_cursor(&delivered_id)
        != Some(device_development_mesh::dashboard::EventCursor {
            epoch: 1,
            sequence: 1,
        })
    {
        assert!(
            Instant::now() < deadline,
            "successful stdout was not acknowledged"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let _ = delivered.kill();
    let _ = delivered.wait();

    let mut broken = Command::new(env!("CARGO_BIN_EXE_devicelane"))
        .args([
            "activities",
            "watch",
            "--local",
            "--json",
            "--cursor",
            "1:0",
            "--limit",
            "1",
            "--endpoint",
            &endpoint,
        ])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let broken_id = SubscriberId::parse(format!("cli-{}", broken.id())).unwrap();
    drop(broken.stdout.take());
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = broken.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(Instant::now() < deadline, "broken watch did not exit");
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        journal.subscriber_cursor(&broken_id),
        None,
        "broken stdout must not create or advance subscriber acknowledgement"
    );
}
