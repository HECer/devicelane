use device_development_mesh::dashboard::audit::{
    AuditFilter, AuditStore, Redactor, RetentionPolicy,
};
use device_development_mesh::dashboard::event_log::{EventJournal, EventRead};
use device_development_mesh::dashboard::policy::{AccessRequest, PolicyEngine};
use device_development_mesh::dashboard::service::DashboardService;
use device_development_mesh::dashboard::topology::TopologyProjector;
use device_development_mesh::dashboard::{
    ActivityId, ActivityState, ApprovalDecision, AuditResult, DashboardScope, DeviceId,
    EventCursor, HostId, MessageCode, OperationId, PolicyEffect, PolicyOrigin, PolicyRule,
    PrincipalId, ResourceClass, RuleId,
};
use device_development_mesh::local_ipc::{
    ConnectionState, DaemonRole, DaemonSnapshot, DaemonState, LocalEndpoint, LocalProtocolVersion,
    LocalRequest, LocalResponse, MeshRpcBoundary, RemoteExecutionConfig, RemoteExecutionFailure,
    local_endpoint, send_local_request, serve_local,
};
use device_development_mesh::network_processes::{
    LeaseGrant, LeaseRequest, NetworkEvent, Request as MeshRequest, Response as MeshResponse,
};
use std::fs;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug)]
enum ExternalFailureCase {
    TargetOfflinePreapproval,
    DisconnectPostauth,
    ObserverUnavailable,
    OverflowResync,
    StaleLease,
    OldAgentOptionalMessage,
    CancellationRace,
}

impl ExternalFailureCase {
    fn expected(self) -> MessageCode {
        match self {
            Self::TargetOfflinePreapproval => MessageCode::TargetOffline,
            Self::DisconnectPostauth => MessageCode::RegistryDisconnected,
            Self::ObserverUnavailable => MessageCode::ObserverUnavailable,
            Self::OverflowResync => MessageCode::EventResyncRequired,
            Self::StaleLease => MessageCode::LeaseStale,
            Self::OldAgentOptionalMessage => MessageCode::AgentIncompatible,
            Self::CancellationRace => MessageCode::OperationCancelled,
        }
    }
}

struct ScriptedMeshBoundary {
    case: ExternalFailureCase,
}

impl MeshRpcBoundary for ScriptedMeshBoundary {
    fn call(
        &self,
        _config: &RemoteExecutionConfig,
        request: &MeshRequest,
    ) -> Result<MeshResponse, RemoteExecutionFailure> {
        match request {
            MeshRequest::Lease {
                operation: LeaseRequest::Acquire { device_id, .. },
            } => {
                if matches!(self.case, ExternalFailureCase::TargetOfflinePreapproval) {
                    return Err(RemoteExecutionFailure::RegistryDisconnected);
                }
                Ok(response().with_lease(LeaseGrant {
                    lease_id: "lease-1".into(),
                    device_id: device_id.clone(),
                    client_id: "windows-client".into(),
                    job_id: "job-1".into(),
                    expires_at_ms: u64::MAX,
                    signature: vec![1],
                }))
            }
            MeshRequest::AppleRun { .. } => match self.case {
                ExternalFailureCase::StaleLease => Ok(response().rejected(Some("stale lease"))),
                ExternalFailureCase::OldAgentOptionalMessage => Ok(response().rejected(None)),
                _ => Ok(response().accepted_job("job-1")),
            },
            MeshRequest::Events { .. } => match self.case {
                ExternalFailureCase::DisconnectPostauth => {
                    Err(RemoteExecutionFailure::RegistryDisconnected)
                }
                ExternalFailureCase::ObserverUnavailable => {
                    Ok(response().rejected(Some("observer_unavailable")))
                }
                ExternalFailureCase::OverflowResync => {
                    Ok(response().rejected(Some("event_resync_required")))
                }
                ExternalFailureCase::CancellationRace => {
                    thread::sleep(Duration::from_millis(250));
                    Ok(response().events(vec![NetworkEvent {
                        sequence: 1,
                        kind: "completed".into(),
                        payload: String::new(),
                    }]))
                }
                _ => Ok(response().events(vec![NetworkEvent {
                    sequence: 1,
                    kind: "completed".into(),
                    payload: String::new(),
                }])),
            },
            MeshRequest::Lease {
                operation: LeaseRequest::Release { .. },
            } => Ok(response()),
            other => panic!("unexpected production request: {}", request_name(other)),
        }
    }
}

fn request_name(request: &MeshRequest) -> &'static str {
    match request {
        MeshRequest::Lease { .. } => "lease",
        MeshRequest::AppleRun { .. } => "apple_run",
        MeshRequest::Events { .. } => "events",
        _ => "other",
    }
}

fn response() -> MeshResponse {
    MeshResponse {
        accepted: false,
        hosts: vec![],
        job_id: None,
        events: vec![],
        audit: vec![],
        artifact: None,
        error: None,
        operation: None,
        apple_operation: None,
        cancel_jobs: vec![],
        artifact_metadata: None,
        artifact_chunk: None,
        confirmed_offset: None,
        lease_grant: None,
        lease_status: None,
    }
}

trait ResponseBuilder {
    fn with_lease(self, grant: LeaseGrant) -> Self;
    fn accepted_job(self, job_id: &str) -> Self;
    fn events(self, events: Vec<NetworkEvent>) -> Self;
    fn rejected(self, error: Option<&str>) -> Self;
}

impl ResponseBuilder for MeshResponse {
    fn with_lease(mut self, grant: LeaseGrant) -> Self {
        self.accepted = true;
        self.lease_grant = Some(grant);
        self
    }

    fn accepted_job(mut self, job_id: &str) -> Self {
        self.accepted = true;
        self.job_id = Some(job_id.into());
        self
    }

    fn events(mut self, events: Vec<NetworkEvent>) -> Self {
        self.accepted = true;
        self.events = events;
        self
    }

    fn rejected(mut self, error: Option<&str>) -> Self {
        self.accepted = false;
        self.error = error.map(str::to_owned);
        self
    }
}

struct Fixture {
    _root: tempfile::TempDir,
    endpoint: LocalEndpoint,
}

fn fixture(case: ExternalFailureCase) -> Fixture {
    fixture_with_policy(case, PolicyEngine::new())
}

fn fixture_with_policy(case: ExternalFailureCase, policy: PolicyEngine) -> Fixture {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(1);
    let root = tempfile::tempdir().unwrap();
    let runtime = root.path().join("runtime");
    fs::create_dir_all(&runtime).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
    }
    #[cfg(windows)]
    let listen = format!(
        r"\\.\pipe\devicelane-failure-matrix-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    #[cfg(unix)]
    let listen = runtime.join("failure-matrix.sock").display().to_string();
    let endpoint = local_endpoint(&runtime, &listen).unwrap();
    let audit = AuditStore::open(
        root.path().join("audit"),
        RetentionPolicy::default(),
        Redactor::default(),
    )
    .unwrap();
    let mut state = DaemonState::new(
        DaemonSnapshot {
            public_identity: "mac-agent".into(),
            daemon_version: "test".into(),
            os: std::env::consts::OS.into(),
            architecture: std::env::consts::ARCH.into(),
            role: DaemonRole::Agent,
            endpoint: listen,
            connection: ConnectionState::Disconnected,
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
    state.enable_dashboard(DashboardService::new(
        HostId::parse("mac-agent").unwrap(),
        TopologyProjector::new(),
        EventJournal::new(1, 0),
        Arc::new(Mutex::new(audit)),
        policy,
    ));
    state.enable_remote_execution_with_boundary(
        RemoteExecutionConfig {
            registry_address: "unused.invalid:1".into(),
            registry_peer_id: "registry".into(),
            identity_path: root.path().join("identity"),
            client_id: "windows-client".into(),
        },
        Arc::new(ScriptedMeshBoundary { case }),
        Duration::from_secs(1),
    );
    let server_endpoint = endpoint.clone();
    thread::spawn(move || {
        let _ = serve_local(&server_endpoint, Arc::new(Mutex::new(state)));
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
        assert!(Instant::now() < deadline, "daemon did not start");
        thread::sleep(Duration::from_millis(10));
    }
    Fixture {
        _root: root,
        endpoint,
    }
}

fn activity_events(
    endpoint: &LocalEndpoint,
) -> Vec<device_development_mesh::dashboard::ActivityEvent> {
    let LocalResponse::ActivityEvents(EventRead::Events { events, .. }) = send_local_request(
        endpoint,
        &LocalRequest::ActivityEvents {
            version: LocalProtocolVersion::CURRENT,
            scope: DashboardScope::Local,
            cursor: EventCursor {
                epoch: 1,
                sequence: 0,
            },
            limit: 256,
        },
    )
    .unwrap() else {
        panic!("activity events missing")
    };
    events
}

fn terminal_audit(
    endpoint: &LocalEndpoint,
    activity_id: &ActivityId,
    result: AuditResult,
) -> device_development_mesh::dashboard::AuditRecord {
    let LocalResponse::AuditRecords(page) = send_local_request(
        endpoint,
        &LocalRequest::AuditQuery {
            version: LocalProtocolVersion::CURRENT,
            filter: AuditFilter {
                result: Some(result),
                ..AuditFilter::default()
            },
            cursor: None,
            limit: 64,
        },
    )
    .unwrap() else {
        panic!("audit page missing")
    };
    page.items
        .into_iter()
        .find(|record| record.activity_id.as_ref() == Some(activity_id))
        .expect("terminal audit missing")
}

fn approved_access(endpoint: &LocalEndpoint, id: &str) -> AccessRequest {
    let access = AccessRequest {
        activity_id: ActivityId::parse(id).unwrap(),
        principal_id: PrincipalId::parse("windows-agent").unwrap(),
        source_host_id: HostId::parse("windows-client").unwrap(),
        target_host_id: HostId::parse("mac-agent").unwrap(),
        device_id: Some(DeviceId::parse("simulator-1").unwrap()),
        operation: OperationId::parse("apple.install-app").unwrap(),
        resources: vec![ResourceClass::WorkspaceRead, ResourceClass::DeviceLease],
        physical_device: false,
        user_present: true,
    };
    let LocalResponse::ApprovalCreated { nonce, .. } = send_local_request(
        endpoint,
        &LocalRequest::RequestApproval {
            version: LocalProtocolVersion::CURRENT,
            access: access.clone(),
            lifetime_ms: 30_000,
        },
    )
    .unwrap() else {
        panic!("approval was not created")
    };
    assert!(matches!(
        send_local_request(
            endpoint,
            &LocalRequest::DecideApproval {
                version: LocalProtocolVersion::CURRENT,
                nonce,
                access: access.clone(),
                decision: ApprovalDecision::AllowOnce,
            }
        )
        .unwrap(),
        LocalResponse::ApprovalDecided { .. }
    ));
    access
}

#[test]
fn external_failure_matrix_terminates_the_real_worker_with_stable_identity_and_audit() {
    for case in [
        ExternalFailureCase::TargetOfflinePreapproval,
        ExternalFailureCase::DisconnectPostauth,
        ExternalFailureCase::ObserverUnavailable,
        ExternalFailureCase::OverflowResync,
        ExternalFailureCase::StaleLease,
        ExternalFailureCase::OldAgentOptionalMessage,
    ] {
        let fixture = fixture(case);
        let access = approved_access(&fixture.endpoint, &format!("failure-{case:?}"));
        assert!(matches!(
            send_local_request(
                &fixture.endpoint,
                &LocalRequest::StartRemoteExecution {
                    version: LocalProtocolVersion::CURRENT,
                    activity_id: access.activity_id.clone(),
                    workspace_path: "project".into(),
                    request_id: format!("request-{case:?}"),
                    app_path: "build/App.app".into(),
                }
            )
            .unwrap(),
            LocalResponse::ExecutionStarted { activity_id } if activity_id == access.activity_id
        ));

        let deadline = Instant::now() + Duration::from_secs(3);
        let terminal = loop {
            let LocalResponse::DashboardSnapshot(snapshot) = send_local_request(
                &fixture.endpoint,
                &LocalRequest::DashboardSnapshot {
                    version: LocalProtocolVersion::CURRENT,
                    scope: DashboardScope::Local,
                },
            )
            .unwrap() else {
                panic!("snapshot missing")
            };
            let activity = snapshot
                .activities
                .into_iter()
                .find(|activity| activity.activity_id == access.activity_id)
                .unwrap();
            if activity.state == ActivityState::Failed {
                break activity;
            }
            assert!(Instant::now() < deadline, "{case:?} did not terminate");
            thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(terminal.activity_id, access.activity_id);
        let LocalResponse::ActivityEvents(EventRead::Events { events, .. }) = send_local_request(
            &fixture.endpoint,
            &LocalRequest::ActivityEvents {
                version: LocalProtocolVersion::CURRENT,
                scope: DashboardScope::Local,
                cursor: EventCursor {
                    epoch: 1,
                    sequence: 0,
                },
                limit: 32,
            },
        )
        .unwrap() else {
            panic!("activity events missing")
        };
        let terminal_event = events
            .into_iter()
            .rev()
            .find(|event| event.activity_id == access.activity_id)
            .expect("terminal activity event missing");
        assert_eq!(terminal_event.message.unwrap().code, case.expected());

        let LocalResponse::AuditRecords(page) = send_local_request(
            &fixture.endpoint,
            &LocalRequest::AuditQuery {
                version: LocalProtocolVersion::CURRENT,
                filter: AuditFilter {
                    result: Some(AuditResult::Failed),
                    ..AuditFilter::default()
                },
                cursor: None,
                limit: 32,
            },
        )
        .unwrap() else {
            panic!("audit page missing")
        };
        let audit = page
            .items
            .into_iter()
            .find(|record| record.activity_id.as_ref() == Some(&access.activity_id))
            .expect("terminal failure audit missing");
        assert_eq!(audit.redacted_message.unwrap().code, case.expected());
    }
}

#[test]
fn expired_approval_terminates_the_same_activity_with_actionable_audit() {
    let fixture = fixture(ExternalFailureCase::TargetOfflinePreapproval);
    let access = AccessRequest {
        activity_id: ActivityId::parse("failure-expired-approval").unwrap(),
        principal_id: PrincipalId::parse("windows-agent").unwrap(),
        source_host_id: HostId::parse("windows-client").unwrap(),
        target_host_id: HostId::parse("mac-agent").unwrap(),
        device_id: Some(DeviceId::parse("simulator-1").unwrap()),
        operation: OperationId::parse("apple.install-app").unwrap(),
        resources: vec![ResourceClass::WorkspaceRead, ResourceClass::DeviceLease],
        physical_device: false,
        user_present: true,
    };
    let LocalResponse::ApprovalCreated { nonce, .. } = send_local_request(
        &fixture.endpoint,
        &LocalRequest::RequestApproval {
            version: LocalProtocolVersion::CURRENT,
            access: access.clone(),
            lifetime_ms: 1,
        },
    )
    .unwrap() else {
        panic!("approval missing")
    };
    thread::sleep(Duration::from_millis(3));
    assert!(matches!(
        send_local_request(
            &fixture.endpoint,
            &LocalRequest::DecideApproval {
                version: LocalProtocolVersion::CURRENT,
                nonce,
                access: access.clone(),
                decision: ApprovalDecision::AllowOnce,
            }
        )
        .unwrap(),
        LocalResponse::Error { code, .. } if code == "approval_expired"
    ));
    let terminal = activity_events(&fixture.endpoint)
        .into_iter()
        .rev()
        .find(|event| event.activity_id == access.activity_id)
        .unwrap();
    assert_eq!(terminal.state, ActivityState::Failed);
    assert_eq!(terminal.message.unwrap().code, MessageCode::ApprovalExpired);
    assert_eq!(
        terminal_audit(&fixture.endpoint, &access.activity_id, AuditResult::Failed)
            .redacted_message
            .unwrap()
            .code,
        MessageCode::ApprovalExpired
    );
}

#[test]
fn deny_override_records_a_terminal_activity_in_the_production_approval_path() {
    let deny = PolicyRule {
        id: RuleId::parse("deny-all-remote").unwrap(),
        revision: 1,
        effect: PolicyEffect::Deny,
        principal_id: None,
        source_host_id: None,
        target_host_id: None,
        device_id: None,
        operation: None,
        resources: vec![],
        expires_at_ms: None,
        require_user_presence: false,
        user_presence: None,
        physical_device: None,
        match_device_exact: false,
        match_resources_exact: false,
        enabled: true,
        origin: PolicyOrigin::User,
    };
    let fixture = fixture_with_policy(
        ExternalFailureCase::TargetOfflinePreapproval,
        PolicyEngine::with_rules(vec![deny]).unwrap(),
    );
    let access = AccessRequest {
        activity_id: ActivityId::parse("failure-deny-overrides").unwrap(),
        principal_id: PrincipalId::parse("windows-agent").unwrap(),
        source_host_id: HostId::parse("windows-client").unwrap(),
        target_host_id: HostId::parse("mac-agent").unwrap(),
        device_id: Some(DeviceId::parse("simulator-1").unwrap()),
        operation: OperationId::parse("apple.install-app").unwrap(),
        resources: vec![ResourceClass::WorkspaceRead, ResourceClass::DeviceLease],
        physical_device: false,
        user_present: true,
    };
    assert!(matches!(
        send_local_request(
            &fixture.endpoint,
            &LocalRequest::RequestApproval {
                version: LocalProtocolVersion::CURRENT,
                access: access.clone(),
                lifetime_ms: 30_000,
            }
        )
        .unwrap(),
        LocalResponse::Error { code, .. } if code == "permission_denied"
    ));
    let terminal = activity_events(&fixture.endpoint)
        .into_iter()
        .find(|event| event.activity_id == access.activity_id)
        .expect("denied activity missing");
    assert_eq!(terminal.state, ActivityState::Denied);
    assert_eq!(terminal.message.unwrap().code, MessageCode::PolicyDenied);
    assert_eq!(
        terminal_audit(&fixture.endpoint, &access.activity_id, AuditResult::Denied)
            .redacted_message
            .unwrap()
            .code,
        MessageCode::PolicyDenied
    );
}

#[test]
fn cancellation_race_has_one_terminal_winner_and_preserves_activity_id() {
    let fixture = fixture(ExternalFailureCase::CancellationRace);
    let access = approved_access(&fixture.endpoint, "failure-cancellation-race");
    assert!(matches!(
        send_local_request(
            &fixture.endpoint,
            &LocalRequest::StartRemoteExecution {
                version: LocalProtocolVersion::CURRENT,
                activity_id: access.activity_id.clone(),
                workspace_path: "project".into(),
                request_id: "request-cancel-race".into(),
                app_path: "build/App.app".into(),
            }
        )
        .unwrap(),
        LocalResponse::ExecutionStarted { .. }
    ));
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if activity_events(&fixture.endpoint).into_iter().any(|event| {
            event.activity_id == access.activity_id && event.state == ActivityState::Running
        }) {
            break;
        }
        assert!(Instant::now() < deadline, "worker never reached running");
        thread::sleep(Duration::from_millis(5));
    }
    let admin = AccessRequest {
        activity_id: ActivityId::parse("admin-cancel-race").unwrap(),
        principal_id: PrincipalId::parse("local-user").unwrap(),
        source_host_id: HostId::parse("mac-agent").unwrap(),
        target_host_id: HostId::parse("mac-agent").unwrap(),
        device_id: None,
        operation: OperationId::parse("devicelane.activity.cancel").unwrap(),
        resources: vec![ResourceClass::DeviceLaneService],
        physical_device: false,
        user_present: true,
    };
    let _ = approved_access_for(&fixture.endpoint, admin);
    assert!(matches!(
        send_local_request(
            &fixture.endpoint,
            &LocalRequest::CancelActivity {
                version: LocalProtocolVersion::CURRENT,
                activity_id: access.activity_id.clone(),
            }
        )
        .unwrap(),
        LocalResponse::Cancellation { cancelled: true }
    ));
    thread::sleep(Duration::from_millis(350));
    let events: Vec<_> = activity_events(&fixture.endpoint)
        .into_iter()
        .filter(|event| event.activity_id == access.activity_id)
        .collect();
    let terminal: Vec<_> = events
        .iter()
        .filter(|event| {
            matches!(
                event.state,
                ActivityState::Succeeded
                    | ActivityState::Failed
                    | ActivityState::Denied
                    | ActivityState::Cancelled
            )
        })
        .collect();
    assert_eq!(terminal.len(), 1);
    assert_eq!(terminal[0].state, ActivityState::Cancelled);
    assert_eq!(
        terminal[0].message.as_ref().unwrap().code,
        MessageCode::OperationCancelled
    );
    assert_eq!(
        terminal_audit(
            &fixture.endpoint,
            &access.activity_id,
            AuditResult::Cancelled
        )
        .redacted_message
        .unwrap()
        .code,
        MessageCode::OperationCancelled
    );
}

#[test]
fn audit_disk_failure_fails_closed_and_surfaces_a_stable_terminal_error() {
    let fixture = fixture(ExternalFailureCase::CancellationRace);
    let access = approved_access(&fixture.endpoint, "failure-audit-disk");
    assert!(matches!(
        send_local_request(
            &fixture.endpoint,
            &LocalRequest::StartRemoteExecution {
                version: LocalProtocolVersion::CURRENT,
                activity_id: access.activity_id.clone(),
                workspace_path: "project".into(),
                request_id: "request-audit-disk".into(),
                app_path: "build/App.app".into(),
            }
        )
        .unwrap(),
        LocalResponse::ExecutionStarted { .. }
    ));
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if activity_events(&fixture.endpoint).into_iter().any(|event| {
            event.activity_id == access.activity_id && event.state == ActivityState::Running
        }) {
            break;
        }
        assert!(Instant::now() < deadline, "worker never reached running");
        thread::sleep(Duration::from_millis(5));
    }
    let segment = fs::read_dir(fixture._root.path().join("audit"))
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| {
            path.extension()
                .is_some_and(|extension| extension == "audit")
        })
        .expect("audit segment missing");
    fs::remove_file(segment).unwrap();

    let deadline = Instant::now() + Duration::from_secs(2);
    let terminal = loop {
        let event = activity_events(&fixture.endpoint)
            .into_iter()
            .rev()
            .find(|event| event.activity_id == access.activity_id)
            .unwrap();
        if event.state == ActivityState::Failed {
            break event;
        }
        assert!(
            Instant::now() < deadline,
            "audit failure did not terminate worker"
        );
        thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(terminal.activity_id, access.activity_id);
    assert_eq!(
        terminal.message.unwrap().code,
        MessageCode::AuditUnavailable
    );
    assert!(matches!(
        send_local_request(
            &fixture.endpoint,
            &LocalRequest::AuditQuery {
                version: LocalProtocolVersion::CURRENT,
                filter: AuditFilter::default(),
                cursor: None,
                limit: 32,
            }
        )
        .unwrap(),
        LocalResponse::Error { code, .. } if code == "audit_unavailable"
    ));
    let blocked = AccessRequest {
        activity_id: ActivityId::parse("blocked-after-audit-failure").unwrap(),
        ..access
    };
    assert!(matches!(
        send_local_request(
            &fixture.endpoint,
            &LocalRequest::RequestApproval {
                version: LocalProtocolVersion::CURRENT,
                access: blocked.clone(),
                lifetime_ms: 30_000,
            }
        )
        .unwrap(),
        LocalResponse::Error { code, .. } if code == "audit_unavailable"
    ));
    assert!(
        activity_events(&fixture.endpoint)
            .iter()
            .all(|event| event.activity_id != blocked.activity_id)
    );
}

fn approved_access_for(endpoint: &LocalEndpoint, access: AccessRequest) -> AccessRequest {
    let LocalResponse::ApprovalCreated { nonce, .. } = send_local_request(
        endpoint,
        &LocalRequest::RequestApproval {
            version: LocalProtocolVersion::CURRENT,
            access: access.clone(),
            lifetime_ms: 30_000,
        },
    )
    .unwrap() else {
        panic!("approval missing")
    };
    assert!(matches!(
        send_local_request(
            endpoint,
            &LocalRequest::DecideApproval {
                version: LocalProtocolVersion::CURRENT,
                nonce,
                access: access.clone(),
                decision: ApprovalDecision::AllowOnce,
            }
        )
        .unwrap(),
        LocalResponse::ApprovalDecided { .. }
    ));
    access
}
