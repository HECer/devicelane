use device_development_mesh::dashboard::audit::AuditFilter;
use device_development_mesh::dashboard::service::ExistingJobs;
use device_development_mesh::dashboard::{
    ActivityId, ActivityState, ApprovalDecision, DashboardScope, EventCursor, HostId, OperationId,
    PolicyEffect, PolicyOrigin, PolicyRule, PrincipalId, ResourceClass, RuleId, SubscriberId,
    policy::AccessRequest,
};

fn approval_access(target: &str) -> AccessRequest {
    AccessRequest {
        activity_id: ActivityId::parse("ipc-approval").unwrap(),
        principal_id: PrincipalId::parse("local-client").unwrap(),
        source_host_id: HostId::parse("source").unwrap(),
        target_host_id: HostId::parse(target).unwrap(),
        device_id: None,
        operation: OperationId::parse("workspace.write").unwrap(),
        resources: vec![ResourceClass::WorkspaceWrite],
        physical_device: false,
        user_present: true,
    }
}

fn user_rule() -> PolicyRule {
    PolicyRule {
        id: RuleId::parse("ipc-rule").unwrap(),
        revision: 1,
        effect: PolicyEffect::Allow,
        principal_id: Some(PrincipalId::parse("local-client").unwrap()),
        source_host_id: Some(HostId::parse("source").unwrap()),
        target_host_id: Some(HostId::parse("identity").unwrap()),
        device_id: None,
        operation: Some(OperationId::parse("workspace.write").unwrap()),
        resources: vec![ResourceClass::WorkspaceWrite],
        expires_at_ms: None,
        require_user_presence: false,
        user_presence: None,
        physical_device: None,
        match_device_exact: false,
        match_resources_exact: true,
        enabled: true,
        origin: PolicyOrigin::User,
    }
}
use device_development_mesh::local_ipc::{
    Authorizer, AutostartAdapter, ConnectionState, DaemonRole, DaemonSnapshot, DaemonState,
    DiagnosticItem, LocalProtocolError, LocalProtocolVersion, LocalRequest, LocalResponse,
    MAX_FRAME_BYTES, MAX_LOCAL_WORKERS, PeerCredentials, SameUserAuthorizer, open_local_stream,
    read_frame, send_local_request, send_raw_local_frame, validate_state_paths,
    windows_pipe_security_sddl, write_frame,
};
use std::sync::{Arc, Mutex};

#[cfg(windows)]
fn send_eventually(
    endpoint: &device_development_mesh::local_ipc::LocalEndpoint,
    request: &LocalRequest,
) -> LocalResponse {
    for _ in 0..100 {
        if let Ok(response) = send_local_request(endpoint, request) {
            return response;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    panic!("local IPC request never became available: {request:?}");
}

#[test]
fn unix_transport_does_not_swallow_timeout_or_arbitrary_socket_probe_errors() {
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/local_ipc.rs"),
    )
    .unwrap();
    assert!(!source.contains("let _ = stream.set_read_timeout"));
    assert!(!source.contains("let _ = stream.set_write_timeout"));
    assert!(source.contains("Some(libc::ECONNREFUSED)"));
}

#[test]
fn production_service_routes_autostart_requests_to_platform_lifecycle() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let ipc = std::fs::read_to_string(root.join("src/local_ipc.rs")).unwrap();
    let service = std::fs::read_to_string(root.join("src/bin/devicelane-service.rs")).unwrap();
    assert!(service.contains("DaemonState::new_with_platform_lifecycle"));
    assert!(ipc.contains("adapter.set_enabled(enabled)?"));
    assert!(ipc.contains("set_platform_autostart(enabled)"));
    assert!(service.contains("platform_autostart_enabled()"));
    assert!(!ipc.contains("\"--now\""));
    assert!(!ipc.contains("Stop-ScheduledTask -TaskName \"DeviceLane Service-$sid\""));
    assert!(!ipc.contains("Start-ScheduledTask -TaskName \"DeviceLane Service-$sid\""));
}

struct RecordingAutostart(Arc<Mutex<Vec<bool>>>);

impl AutostartAdapter for RecordingAutostart {
    fn set_enabled(&self, enabled: bool) -> Result<(), LocalProtocolError> {
        self.0.lock().unwrap().push(enabled);
        Ok(())
    }
}

#[test]
fn autostart_request_acknowledges_without_stopping_the_serving_daemon() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut state = DaemonState::new_with_autostart_adapter(
        snapshot(),
        Vec::new(),
        Arc::new(RecordingAutostart(Arc::clone(&calls))),
    );
    let response = state
        .handle(LocalRequest::SetAutostart {
            version: LocalProtocolVersion::CURRENT,
            enabled: false,
        })
        .unwrap();
    assert_eq!(response, LocalResponse::Acknowledged);
    assert_eq!(*calls.lock().unwrap(), vec![false]);
}

#[test]
fn mac_autostart_requires_an_installed_launch_agent() {
    let home = tempfile::tempdir().unwrap();
    let missing = home.path().join("dev.devicelane.service.plist");
    assert!(
        !device_development_mesh::local_ipc::launch_agent_autostart_enabled(
            &missing,
            b"disabled services = {}",
        )
    );
    std::fs::write(&missing, "plist").unwrap();
    assert!(
        device_development_mesh::local_ipc::launch_agent_autostart_enabled(
            &missing,
            b"disabled services = {}",
        )
    );
    assert!(
        !device_development_mesh::local_ipc::launch_agent_autostart_enabled(
            &missing,
            b"\"dev.devicelane.service\" => true",
        )
    );
}
use std::io::Write;
use std::io::{BufReader, Cursor};
use std::path::PathBuf;
use std::process::Command;

fn snapshot() -> DaemonSnapshot {
    DaemonSnapshot {
        public_identity: "sha256:public-fingerprint".into(),
        daemon_version: "0.1.0".into(),
        os: "test-os".into(),
        architecture: "test-arch".into(),
        role: DaemonRole::Workstation,
        endpoint: "local://devicelane".into(),
        connection: ConnectionState::Connected,
        local_protocol: LocalProtocolVersion::CURRENT,
        remote_protocol: "1.0".into(),
        warnings: vec!["certificate expires soon".into()],
        remote_access_paused: false,
        autostart: false,
        log_location: "/logs".into(),
        features: Vec::new(),
    }
}

#[test]
fn request_contract_is_strict_and_rejects_incompatible_major_versions() {
    let encoded = serde_json::to_string(&LocalRequest::Status {
        version: LocalProtocolVersion::CURRENT,
    })
    .unwrap();
    assert!(encoded.contains(r#""request":"status""#));
    let unknown = r#"{"request":"status","version":{"major":1,"minor":0},"extra":true}"#;
    assert!(serde_json::from_str::<LocalRequest>(unknown).is_err());

    let request = LocalRequest::Status {
        version: LocalProtocolVersion { major: 2, minor: 0 },
    };
    assert_eq!(
        request.validate(),
        Err(LocalProtocolError::IncompatibleVersion)
    );
}

#[test]
fn status_response_exposes_only_public_operational_fields() {
    let response = LocalResponse::Snapshot(snapshot());
    let json = serde_json::to_string(&response).unwrap();
    for expected in [
        "public_identity",
        "role",
        "endpoint",
        "connection",
        "local_protocol",
        "remote_protocol",
        "warnings",
    ] {
        assert!(json.contains(expected), "missing {expected}: {json}");
    }
    assert!(!json.contains("private_key"));
    assert!(!json.contains("private-key"));
    assert!(!json.contains("key_der"));
}

#[test]
fn daemon_state_supports_status_pause_resume_autostart_and_diagnostics() {
    let mut state = DaemonState::new(
        snapshot(),
        vec![DiagnosticItem {
            code: "ready".into(),
            message: "daemon ready".into(),
            healthy: true,
        }],
    );
    let version = LocalProtocolVersion::CURRENT;

    assert!(matches!(
        state.handle(LocalRequest::Status { version }),
        Ok(LocalResponse::Snapshot(_))
    ));
    assert_eq!(
        state.handle(LocalRequest::PauseRemoteAccess { version }),
        Ok(LocalResponse::Acknowledged)
    );
    assert!(state.snapshot().remote_access_paused);
    assert_eq!(
        state.handle(LocalRequest::ResumeRemoteAccess { version }),
        Ok(LocalResponse::Acknowledged)
    );
    assert!(!state.snapshot().remote_access_paused);
    assert_eq!(
        state.handle(LocalRequest::SetAutostart {
            version,
            enabled: true
        }),
        Ok(LocalResponse::Acknowledged)
    );
    assert!(state.snapshot().autostart);
    assert!(
        matches!(state.handle(LocalRequest::Diagnostics { version }), Ok(LocalResponse::Diagnostics(items)) if items.len() == 1)
    );
}

#[test]
fn newline_frames_round_trip_and_are_bounded() {
    let request = LocalRequest::Status {
        version: LocalProtocolVersion::CURRENT,
    };
    let mut wire = Vec::new();
    write_frame(&mut wire, &request).unwrap();
    assert_eq!(wire.last(), Some(&b'\n'));
    assert_eq!(
        read_frame::<_, LocalRequest>(&mut BufReader::new(Cursor::new(wire))).unwrap(),
        request
    );

    let oversized = vec![b'x'; MAX_FRAME_BYTES + 1];
    let error =
        read_frame::<_, LocalRequest>(&mut BufReader::new(Cursor::new(oversized))).unwrap_err();
    assert_eq!(error, LocalProtocolError::FrameTooLarge);
}

struct SameUser;

impl Authorizer for SameUser {
    fn authorize(&self, peer: &PeerCredentials) -> bool {
        matches!(peer, PeerCredentials::Unix { uid: 42, .. })
    }
}

#[test]
fn authorization_uses_os_peer_credentials() {
    assert!(SameUser.authorize(&PeerCredentials::Unix {
        uid: 42,
        gid: 7,
        pid: Some(9)
    }));
    assert!(!SameUser.authorize(&PeerCredentials::Unix {
        uid: 41,
        gid: 7,
        pid: Some(9)
    }));
}

#[test]
fn platform_authorizer_rejects_unauthenticated_and_different_users() {
    let authorizer = SameUserAuthorizer::unix(42);
    assert!(!authorizer.authorize(&PeerCredentials::Unix {
        uid: 41,
        gid: 7,
        pid: Some(9)
    }));
    assert!(authorizer.authorize(&PeerCredentials::Unix {
        uid: 42,
        gid: 7,
        pid: Some(9)
    }));
    assert!(!authorizer.authorize(&PeerCredentials::Windows {
        process_id: 9,
        user_sid: String::new()
    }));
}

#[test]
fn state_paths_must_be_absolute_before_transport_binding() {
    let absolute = if cfg!(windows) {
        PathBuf::from(r"C:\devicelane")
    } else {
        PathBuf::from("/var/lib/devicelane")
    };
    assert!(validate_state_paths([absolute.as_path()]).is_ok());
    assert_eq!(
        validate_state_paths([std::path::Path::new("relative")]),
        Err(LocalProtocolError::StatePathNotAbsolute)
    );
}

#[test]
#[cfg(windows)]
fn service_rejects_relative_state_paths_before_binding() {
    let service = env!("CARGO_BIN_EXE_devicelane-service");
    let status = Command::new(service)
        .args([
            "--identity",
            "relative",
            "--runtime-dir",
            r"C:\state\run",
            "--role",
            "workstation",
            "--registry",
            "registry.example:7443",
            "--listen",
            r"\\.\pipe\devicelane-test",
            "--agent-peer",
            "mac-agent-1",
            "--log-dir",
            r"C:\state\logs",
        ])
        .status()
        .unwrap();
    assert!(!status.success());
}

#[test]
fn workstation_service_does_not_require_remote_mesh_configuration() {
    let output = Command::new(env!("CARGO_BIN_EXE_devicelane-service"))
        .args([
            "--identity",
            "relative",
            "--runtime-dir",
            "relative",
            "--role",
            "workstation",
            "--log-dir",
            "relative",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("state paths must be absolute"));
}

#[test]
#[cfg(windows)]
fn production_named_pipe_serves_state_and_recovers_after_bad_frames() {
    let pipe = format!(r"\\.\pipe\devicelane-e2e-{}", std::process::id());
    let temp = tempfile::tempdir().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_devicelane-service"))
        .args([
            "--identity",
            temp.path().join("identity").to_str().unwrap(),
            "--runtime-dir",
            temp.path().to_str().unwrap(),
            "--role",
            "workstation",
            "--registry",
            "registry.example:7443",
            "--listen",
            &pipe,
            "--agent-peer",
            "mac-agent-1",
            "--log-dir",
            temp.path().join("logs").to_str().unwrap(),
        ])
        .spawn()
        .unwrap();

    let endpoint = device_development_mesh::local_ipc::LocalEndpoint::NamedPipe(pipe.clone());
    let request = LocalRequest::Status {
        version: LocalProtocolVersion::CURRENT,
    };
    let first = (0..100)
        .find_map(|_| {
            send_local_request(&endpoint, &request).ok().or_else(|| {
                std::thread::sleep(std::time::Duration::from_millis(20));
                None
            })
        })
        .expect("service did not bind named pipe");
    assert!(matches!(first, LocalResponse::Snapshot(snapshot) if !snapshot.remote_access_paused));

    let access = approval_access("identity");
    let created = send_local_request(
        &endpoint,
        &LocalRequest::RequestApproval {
            version: LocalProtocolVersion::CURRENT,
            access: access.clone(),
            lifetime_ms: 60_000,
        },
    )
    .unwrap();
    let nonce = match created {
        LocalResponse::ApprovalCreated { nonce, .. } => nonce,
        response => panic!("unexpected approval response: {response:?}"),
    };
    assert!(matches!(
        send_local_request(
            &endpoint,
            &LocalRequest::DecideApproval {
                version: LocalProtocolVersion::CURRENT,
                nonce,
                access: access.clone(),
                decision: ApprovalDecision::AllowOnce,
            },
        )
        .unwrap(),
        LocalResponse::ApprovalDecided { .. }
    ));
    assert!(
        matches!(send_local_request(&endpoint, &LocalRequest::PendingApprovals { version: LocalProtocolVersion::CURRENT }).unwrap(), LocalResponse::PendingApprovals(items) if items.is_empty())
    );
    assert!(matches!(
        send_local_request(
            &endpoint,
            &LocalRequest::PolicyRules {
                version: LocalProtocolVersion::CURRENT
            }
        )
        .unwrap(),
        LocalResponse::PolicyRules(_)
    ));
    assert!(matches!(
        send_local_request(
            &endpoint,
            &LocalRequest::PutPolicyRule {
                version: LocalProtocolVersion::CURRENT,
                rule: user_rule()
            }
        )
        .unwrap(),
        LocalResponse::Acknowledged
    ));
    let mut expiring = approval_access("identity");
    expiring.activity_id = ActivityId::parse("ipc-expiring").unwrap();
    let expiring_nonce = match send_local_request(
        &endpoint,
        &LocalRequest::RequestApproval {
            version: LocalProtocolVersion::CURRENT,
            access: expiring.clone(),
            lifetime_ms: 1,
        },
    )
    .unwrap()
    {
        LocalResponse::ApprovalCreated { nonce, .. } => nonce,
        response => panic!("unexpected expiring approval response: {response:?}"),
    };
    std::thread::sleep(std::time::Duration::from_millis(3));
    assert!(
        matches!(send_local_request(&endpoint, &LocalRequest::DecideApproval { version: LocalProtocolVersion::CURRENT, nonce: expiring_nonce, access: expiring, decision: ApprovalDecision::AllowOnce }).unwrap(), LocalResponse::Error { code, .. } if code == "approval_expired")
    );
    assert!(matches!(
        send_local_request(
            &endpoint,
            &LocalRequest::DeletePolicyRule {
                version: LocalProtocolVersion::CURRENT,
                rule_id: RuleId::parse("ipc-rule").unwrap()
            }
        )
        .unwrap(),
        LocalResponse::RuleDeleted { deleted: true }
    ));
    assert!(
        matches!(send_local_request(&endpoint, &LocalRequest::AuditQuery { version: LocalProtocolVersion::CURRENT, filter: AuditFilter::default(), cursor: None, limit: 32 }).unwrap(), LocalResponse::AuditRecords(page) if !page.items.is_empty())
    );
    assert!(
        matches!(send_eventually(&endpoint, &LocalRequest::AuditExport { version: LocalProtocolVersion::CURRENT, filter: AuditFilter::default() }), LocalResponse::AuditExport(export) if !export.records.is_empty())
    );
    assert!(matches!(
        send_local_request(
            &endpoint,
            &LocalRequest::CancelActivity {
                version: LocalProtocolVersion::CURRENT,
                activity_id: ActivityId::parse("ipc-approval").unwrap()
            }
        )
        .unwrap(),
        LocalResponse::Cancellation { cancelled: true }
    ));
    let events = send_local_request(
        &endpoint,
        &LocalRequest::ActivityEvents {
            version: LocalProtocolVersion::CURRENT,
            cursor: EventCursor {
                epoch: 1,
                sequence: 0,
            },
            limit: 32,
        },
    )
    .unwrap();
    let cursor = match events {
        LocalResponse::ActivityEvents(
            device_development_mesh::dashboard::event_log::EventRead::Events {
                next_cursor, ..
            },
        ) => next_cursor,
        response => panic!("unexpected event response: {response:?}"),
    };
    assert!(matches!(
        send_local_request(
            &endpoint,
            &LocalRequest::AcknowledgeEvents {
                version: LocalProtocolVersion::CURRENT,
                subscriber_id: SubscriberId::parse("ipc-ui").unwrap(),
                cursor
            }
        )
        .unwrap(),
        LocalResponse::Acknowledged
    ));
    assert!(matches!(
        send_local_request(
            &endpoint,
            &LocalRequest::DashboardSnapshot {
                version: LocalProtocolVersion::CURRENT,
                scope: DashboardScope::Local
            }
        )
        .unwrap(),
        LocalResponse::DashboardSnapshot(_)
    ));
    assert!(matches!(
        send_local_request(
            &endpoint,
            &LocalRequest::PauseRemoteAccessWithJobs {
                version: LocalProtocolVersion::CURRENT,
                existing_jobs: ExistingJobs::Finish
            }
        )
        .unwrap(),
        LocalResponse::Acknowledged
    ));
    assert!(matches!(
        send_local_request(
            &endpoint,
            &LocalRequest::ResumeRemoteAccess {
                version: LocalProtocolVersion::CURRENT
            }
        )
        .unwrap(),
        LocalResponse::Acknowledged
    ));
    let mut spoofed = access;
    spoofed.target_host_id = HostId::parse("claimed-target").unwrap();
    assert!(matches!(
        send_local_request(
            &endpoint,
            &LocalRequest::RequestApproval {
                version: LocalProtocolVersion::CURRENT,
                access: spoofed,
                lifetime_ms: 60_000,
            },
        )
        .unwrap(),
        LocalResponse::Error { code, .. } if code == "unauthorized"
    ));

    assert!(matches!(
        send_local_request(
            &endpoint,
            &LocalRequest::PauseRemoteAccess {
                version: LocalProtocolVersion::CURRENT
            }
        )
        .unwrap(),
        LocalResponse::Acknowledged
    ));
    assert!(
        matches!(send_local_request(&endpoint, &request).unwrap(), LocalResponse::Snapshot(snapshot) if snapshot.remote_access_paused)
    );

    assert!(matches!(
        send_raw_local_frame(&endpoint, b"not-json\n").unwrap(),
        LocalResponse::Error { .. }
    ));
    let oversized = vec![b'x'; MAX_FRAME_BYTES + 1];
    assert!(matches!(
        send_raw_local_frame(&endpoint, &oversized).unwrap(),
        LocalResponse::Error { .. }
    ));
    assert!(matches!(
        send_local_request(&endpoint, &request).unwrap(),
        LocalResponse::Snapshot(_)
    ));
    assert!(
        child.try_wait().unwrap().is_none(),
        "service exited instead of remaining available"
    );
    child.kill().unwrap();
    child.wait().unwrap();
}

#[test]
#[cfg(windows)]
fn production_service_restart_reconciles_one_durable_activity_id() {
    let pipe = format!(r"\\.\pipe\devicelane-restart-{}", std::process::id());
    let temp = tempfile::tempdir().unwrap();
    let identity = temp.path().join("identity");
    let runtime = temp.path().join("runtime");
    let logs = temp.path().join("logs");
    std::fs::create_dir(&runtime).unwrap();
    let args = [
        "--identity",
        identity.to_str().unwrap(),
        "--runtime-dir",
        runtime.to_str().unwrap(),
        "--role",
        "workstation",
        "--listen",
        &pipe,
        "--log-dir",
        logs.to_str().unwrap(),
    ];
    let endpoint = device_development_mesh::local_ipc::LocalEndpoint::NamedPipe(pipe.clone());
    let mut first = Command::new(env!("CARGO_BIN_EXE_devicelane-service"))
        .args(args)
        .spawn()
        .unwrap();
    let status = LocalRequest::Status {
        version: LocalProtocolVersion::CURRENT,
    };
    (0..100)
        .find_map(|_| {
            send_local_request(&endpoint, &status).ok().or_else(|| {
                std::thread::sleep(std::time::Duration::from_millis(20));
                None
            })
        })
        .expect("first service did not bind");
    send_local_request(
        &endpoint,
        &LocalRequest::RequestApproval {
            version: LocalProtocolVersion::CURRENT,
            access: approval_access("identity"),
            lifetime_ms: 60_000,
        },
    )
    .unwrap();
    first.kill().unwrap();
    first.wait().unwrap();

    let mut second = Command::new(env!("CARGO_BIN_EXE_devicelane-service"))
        .args(args)
        .spawn()
        .unwrap();
    let snapshot_request = LocalRequest::DashboardSnapshot {
        version: LocalProtocolVersion::CURRENT,
        scope: DashboardScope::Local,
    };
    let response = (0..100)
        .find_map(|_| {
            send_local_request(&endpoint, &snapshot_request)
                .ok()
                .or_else(|| {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                    None
                })
        })
        .expect("restarted service did not bind");
    assert!(
        matches!(response, LocalResponse::DashboardSnapshot(snapshot) if snapshot.activities.len() == 1 && snapshot.activities[0].activity_id.as_str() == "ipc-approval" && snapshot.activities[0].state == ActivityState::Reconnecting)
    );
    second.kill().unwrap();
    second.wait().unwrap();
}

#[test]
#[cfg(windows)]
fn failed_decision_checkpoint_keeps_pending_policy_and_activity_unchanged() {
    let pipe = format!(r"\\.\pipe\devicelane-decision-fault-{}", std::process::id());
    let temp = tempfile::tempdir().unwrap();
    let identity = temp.path().join("identity");
    let runtime = temp.path().join("runtime");
    let logs = temp.path().join("logs");
    std::fs::create_dir(&runtime).unwrap();
    let args = [
        "--identity",
        identity.to_str().unwrap(),
        "--runtime-dir",
        runtime.to_str().unwrap(),
        "--role",
        "workstation",
        "--listen",
        &pipe,
        "--log-dir",
        logs.to_str().unwrap(),
    ];
    let endpoint = device_development_mesh::local_ipc::LocalEndpoint::NamedPipe(pipe.clone());
    let mut child = Command::new(env!("CARGO_BIN_EXE_devicelane-service"))
        .args(args)
        .spawn()
        .unwrap();
    let status = LocalRequest::Status {
        version: LocalProtocolVersion::CURRENT,
    };
    (0..100)
        .find_map(|_| {
            send_local_request(&endpoint, &status).ok().or_else(|| {
                std::thread::sleep(std::time::Duration::from_millis(20));
                None
            })
        })
        .expect("service did not bind");
    let access = approval_access("identity");
    let nonce = match send_eventually(
        &endpoint,
        &LocalRequest::RequestApproval {
            version: LocalProtocolVersion::CURRENT,
            access: access.clone(),
            lifetime_ms: 60_000,
        },
    ) {
        LocalResponse::ApprovalCreated { nonce, .. } => nonce,
        response => panic!("unexpected approval response: {response:?}"),
    };
    let checkpoint = logs.join("audit").join("activity-state.json");
    std::fs::remove_file(&checkpoint).unwrap();
    std::fs::create_dir(&checkpoint).unwrap();
    assert!(
        matches!(send_eventually(&endpoint, &LocalRequest::DecideApproval { version: LocalProtocolVersion::CURRENT, nonce, access, decision: ApprovalDecision::AllowOnce }), LocalResponse::Error { code, .. } if code == "audit_unavailable")
    );
    assert!(
        matches!(send_eventually(&endpoint, &LocalRequest::PendingApprovals { version: LocalProtocolVersion::CURRENT }), LocalResponse::PendingApprovals(items) if items.len() == 1)
    );
    assert!(
        matches!(send_eventually(&endpoint, &LocalRequest::DashboardSnapshot { version: LocalProtocolVersion::CURRENT, scope: DashboardScope::Local }), LocalResponse::DashboardSnapshot(snapshot) if snapshot.activities.len() == 1 && snapshot.activities[0].state == ActivityState::AwaitingApproval)
    );
    child.kill().unwrap();
    child.wait().unwrap();
}

#[test]
#[cfg(windows)]
fn slow_client_cannot_block_a_second_named_pipe_client() {
    let pipe = format!(r"\\.\pipe\devicelane-slow-{}", std::process::id());
    let temp = tempfile::tempdir().unwrap();
    let identity = temp.path().join("identity");
    let logs = temp.path().join("logs");
    let mut child = Command::new(env!("CARGO_BIN_EXE_devicelane-service"))
        .args([
            "--identity",
            identity.to_str().unwrap(),
            "--runtime-dir",
            temp.path().to_str().unwrap(),
            "--role",
            "workstation",
            "--registry",
            "registry:7443",
            "--listen",
            &pipe,
            "--agent-peer",
            "agent",
            "--log-dir",
            logs.to_str().unwrap(),
        ])
        .spawn()
        .unwrap();
    let endpoint = device_development_mesh::local_ipc::LocalEndpoint::NamedPipe(pipe);
    let request = LocalRequest::Status {
        version: LocalProtocolVersion::CURRENT,
    };
    for _ in 0..100 {
        if send_local_request(&endpoint, &request).is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let mut slow = open_local_stream(&endpoint).unwrap();
    slow.write_all(br#"{"request":"status""#).unwrap();
    let started = std::time::Instant::now();
    assert!(matches!(
        send_local_request(&endpoint, &request).unwrap(),
        LocalResponse::Snapshot(_)
    ));
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
    drop(slow);
    assert!(child.try_wait().unwrap().is_none());
    child.kill().unwrap();
    child.wait().unwrap();
}

#[test]
#[cfg(windows)]
fn named_pipe_security_is_explicitly_current_user_and_system_only() {
    let sddl = windows_pipe_security_sddl("S-1-5-21-123").unwrap();
    assert_eq!(sddl, "D:P(A;;GA;;;SY)(A;;GA;;;S-1-5-21-123)");
    assert!(!sddl.contains("WD"));
    let authorizer = SameUserAuthorizer::windows("S-1-5-21-123");
    assert!(!authorizer.authorize(&PeerCredentials::Windows {
        process_id: 7,
        user_sid: "S-1-5-18".into()
    }));
}

#[test]
#[cfg(windows)]
fn named_pipe_worker_pool_applies_bounded_backpressure() {
    let pipe = format!(r"\\.\pipe\devicelane-saturation-{}", std::process::id());
    let temp = tempfile::tempdir().unwrap();
    let identity = temp.path().join("identity");
    let logs = temp.path().join("logs");
    let mut child = Command::new(env!("CARGO_BIN_EXE_devicelane-service"))
        .args([
            "--identity",
            identity.to_str().unwrap(),
            "--runtime-dir",
            temp.path().to_str().unwrap(),
            "--role",
            "workstation",
            "--registry",
            "registry:7443",
            "--listen",
            &pipe,
            "--agent-peer",
            "agent",
            "--log-dir",
            logs.to_str().unwrap(),
        ])
        .spawn()
        .unwrap();
    let endpoint = device_development_mesh::local_ipc::LocalEndpoint::NamedPipe(pipe);
    let mut slow = Vec::new();
    for _ in 0..MAX_LOCAL_WORKERS {
        let mut connection = loop {
            if let Ok(connection) = open_local_stream(&endpoint) {
                break connection;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        };
        connection.write_all(b"{").unwrap();
        slow.push(connection);
    }
    let started = std::time::Instant::now();
    assert!(
        send_local_request(
            &endpoint,
            &LocalRequest::Status {
                version: LocalProtocolVersion::CURRENT
            }
        )
        .is_err()
    );
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
    drop(slow);
    std::thread::sleep(std::time::Duration::from_millis(100));
    assert!(
        send_local_request(
            &endpoint,
            &LocalRequest::Status {
                version: LocalProtocolVersion::CURRENT
            }
        )
        .is_ok()
    );
    child.kill().unwrap();
    child.wait().unwrap();
}

#[test]
#[cfg(unix)]
fn production_unix_socket_serves_state_and_recovers_after_bad_frames() {
    use std::os::unix::fs::MetadataExt;
    let temp = tempfile::tempdir().unwrap();
    let socket = temp.path().join("devicelane.sock");
    let stale = std::os::unix::net::UnixDatagram::bind(&socket).unwrap();
    drop(stale);
    let identity = temp.path().join("identity");
    let logs = temp.path().join("logs");
    let mut child = Command::new(env!("CARGO_BIN_EXE_devicelane-service"))
        .args([
            "--identity",
            identity.to_str().unwrap(),
            "--runtime-dir",
            temp.path().to_str().unwrap(),
            "--role",
            "workstation",
            "--registry",
            "registry.example:7443",
            "--listen",
            socket.to_str().unwrap(),
            "--agent-peer",
            "mac-agent-1",
            "--log-dir",
            logs.to_str().unwrap(),
        ])
        .spawn()
        .unwrap();
    let endpoint = device_development_mesh::local_ipc::LocalEndpoint::UnixSocket(socket);
    let request = LocalRequest::Status {
        version: LocalProtocolVersion::CURRENT,
    };
    let first = (0..100)
        .find_map(|_| {
            send_local_request(&endpoint, &request).ok().or_else(|| {
                std::thread::sleep(std::time::Duration::from_millis(20));
                None
            })
        })
        .expect("service did not bind Unix socket");
    let socket_path = match &endpoint {
        device_development_mesh::local_ipc::LocalEndpoint::UnixSocket(path) => path,
    };
    assert_eq!(
        std::fs::metadata(socket_path).unwrap().mode() & 0o777,
        0o600
    );
    assert!(matches!(first, LocalResponse::Snapshot(snapshot) if !snapshot.remote_access_paused));
    let access = approval_access("identity");
    let created = send_local_request(
        &endpoint,
        &LocalRequest::RequestApproval {
            version: LocalProtocolVersion::CURRENT,
            access: access.clone(),
            lifetime_ms: 60_000,
        },
    )
    .unwrap();
    assert!(matches!(created, LocalResponse::ApprovalCreated { .. }));
    let mut spoofed = access;
    spoofed.target_host_id = HostId::parse("claimed-target").unwrap();
    assert!(matches!(
        send_local_request(
            &endpoint,
            &LocalRequest::RequestApproval {
                version: LocalProtocolVersion::CURRENT,
                access: spoofed,
                lifetime_ms: 60_000,
            },
        )
        .unwrap(),
        LocalResponse::Error { code, .. } if code == "unauthorized"
    ));
    assert!(matches!(
        send_local_request(
            &endpoint,
            &LocalRequest::PauseRemoteAccess {
                version: LocalProtocolVersion::CURRENT
            }
        )
        .unwrap(),
        LocalResponse::Acknowledged
    ));
    assert!(
        matches!(send_local_request(&endpoint, &request).unwrap(), LocalResponse::Snapshot(snapshot) if snapshot.remote_access_paused)
    );
    assert!(matches!(
        send_raw_local_frame(&endpoint, b"not-json\n").unwrap(),
        LocalResponse::Error { .. }
    ));
    let oversized = vec![b'x'; MAX_FRAME_BYTES + 1];
    assert!(matches!(
        send_raw_local_frame(&endpoint, &oversized).unwrap(),
        LocalResponse::Error { .. }
    ));
    assert!(matches!(
        send_local_request(&endpoint, &request).unwrap(),
        LocalResponse::Snapshot(_)
    ));
    assert!(child.try_wait().unwrap().is_none());
    child.kill().unwrap();
    child.wait().unwrap();
}

#[test]
#[cfg(unix)]
fn unix_runtime_rejects_symlinks_and_insecure_permissions() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    std::fs::create_dir(&target).unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).unwrap();
    let link = temp.path().join("link");
    symlink(&target, &link).unwrap();
    assert!(device_development_mesh::local_ipc::local_endpoint(&link, "").is_err());
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(device_development_mesh::local_ipc::local_endpoint(&target, "").is_err());
}

#[test]
fn service_managed_policy_configuration_is_paired_and_fails_closed() {
    let temp = tempfile::tempdir().unwrap();
    let identity = temp.path().join("identity");
    let runtime = temp.path().join("runtime");
    let logs = temp.path().join("logs");
    for path in [&identity, &runtime, &logs] {
        std::fs::create_dir(path).unwrap();
    }
    let policy = temp.path().join("policy.json");
    let trust = temp.path().join("admins.json");
    std::fs::write(&policy, b"{}").unwrap();
    std::fs::write(&trust, b"{}").unwrap();
    #[cfg(windows)]
    let listen = format!(r"\\.\pipe\devicelane-managed-config-{}", std::process::id());
    #[cfg(unix)]
    let listen = runtime.join("managed-config.sock").display().to_string();
    let base = [
        "--identity",
        identity.to_str().unwrap(),
        "--runtime-dir",
        runtime.to_str().unwrap(),
        "--role",
        "workstation",
        "--listen",
        &listen,
        "--log-dir",
        logs.to_str().unwrap(),
    ];
    let missing_pair = Command::new(env!("CARGO_BIN_EXE_devicelane-service"))
        .args(base)
        .args(["--managed-policy", policy.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!missing_pair.status.success());
    assert!(String::from_utf8_lossy(&missing_pair.stderr).contains("configured together"));

    let invalid = Command::new(env!("CARGO_BIN_EXE_devicelane-service"))
        .args(base)
        .args([
            "--managed-policy",
            policy.to_str().unwrap(),
            "--policy-admin-trust",
            trust.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!invalid.status.success());
    assert!(String::from_utf8_lossy(&invalid.stderr).contains("invalid policy admin trust store"));
}
