use device_development_mesh::dashboard::audit::{
    AuditFilter, AuditStore, Redactor, RetentionPolicy,
};
use device_development_mesh::dashboard::event_log::{EventJournal, EventRead};
use device_development_mesh::dashboard::policy::AccessRequest;
use device_development_mesh::dashboard::policy::PolicyEngine;
use device_development_mesh::dashboard::service::{
    DashboardService, DashboardServiceError, ExistingJobs,
};
use device_development_mesh::dashboard::topology::TopologyProjector;
use device_development_mesh::dashboard::{
    ActivityEvent, ActivityId, ActivityState, Authorization, DashboardScope, EventCursor, HostId,
    MetricSnapshot, MetricValue, OperationId, PolicyEffect, PolicyOrigin, PolicyRule, PrincipalId,
    ResourceClass, RuleId, SafeCode, SubscriberId,
};
use device_development_mesh::local_ipc::{
    DiagnosticItem, LocalProtocolError, LocalProtocolVersion, LocalRequest, LocalResponse,
    MAX_FRAME_BYTES, enforce_response_bound, read_frame,
};
use std::io::Cursor;
use std::sync::{Arc, Mutex};

const V10: LocalProtocolVersion = LocalProtocolVersion { major: 1, minor: 0 };

#[test]
fn protocol_1_0_keeps_foundation_requests_but_gates_dashboard_features() {
    assert!(LocalRequest::Status { version: V10 }.validate().is_ok());
    assert_eq!(
        LocalRequest::DashboardSnapshot {
            version: V10,
            scope: DashboardScope::Local,
        }
        .validate(),
        Err(LocalProtocolError::FeatureUnavailable)
    );
    assert_eq!(LocalProtocolVersion::CURRENT.major, 1);
}

#[test]
fn activity_event_request_carries_an_explicit_dashboard_scope() {
    let request = r#"{"request":"activity_events","version":{"major":1,"minor":1},"scope":"local","cursor":{"epoch":1,"sequence":0},"limit":32}"#;
    assert!(serde_json::from_str::<LocalRequest>(request).is_ok());
}

#[test]
fn dashboard_contract_is_strict_and_bounded() {
    let unknown = br#"{"request":"dashboard_snapshot","version":{"major":1,"minor":1},"scope":"local","extra":true}\n"#;
    assert_eq!(
        read_frame::<_, LocalRequest>(&mut Cursor::new(unknown)),
        Err(LocalProtocolError::InvalidFrame)
    );

    let oversized = vec![b'x'; MAX_FRAME_BYTES + 1];
    assert_eq!(
        read_frame::<_, LocalRequest>(&mut Cursor::new(oversized)),
        Err(LocalProtocolError::FrameTooLarge)
    );
}

#[test]
fn oversized_dashboard_responses_fail_before_the_transport_write() {
    let response = LocalResponse::Diagnostics(vec![DiagnosticItem {
        code: "oversized".into(),
        message: "x".repeat(MAX_FRAME_BYTES),
        healthy: false,
    }]);
    assert!(matches!(
        enforce_response_bound(response),
        LocalResponse::Error { code, .. } if code == "limit_exceeded"
    ));
}

#[test]
fn all_dashboard_requests_negotiate_the_minor_feature() {
    let version = LocalProtocolVersion::CURRENT;
    let requests = [
        LocalRequest::ActivityEvents {
            version,
            scope: DashboardScope::Local,
            cursor: EventCursor {
                epoch: 1,
                sequence: 0,
            },
            limit: 32,
        },
        LocalRequest::AcknowledgeEvents {
            version,
            subscriber_id: SubscriberId::parse("ui").unwrap(),
            cursor: EventCursor {
                epoch: 1,
                sequence: 0,
            },
        },
        LocalRequest::PendingApprovals { version },
        LocalRequest::PendingApprovalForNotification {
            version,
            approval_id: device_development_mesh::dashboard::ApprovalId::parse("approval-ui")
                .unwrap(),
        },
        LocalRequest::PolicyRules { version },
        LocalRequest::CancelActivity {
            version,
            activity_id: device_development_mesh::dashboard::ActivityId::parse("job-1").unwrap(),
        },
    ];
    for request in requests {
        assert!(request.validate().is_ok(), "{request:?}");
    }
}

fn event(state: ActivityState, sequence: u64, at: u64) -> ActivityEvent {
    let unavailable = || MetricValue::Unavailable {
        reason: SafeCode::parse("observer_unavailable").unwrap(),
    };
    ActivityEvent {
        activity_id: ActivityId::parse("job-1").unwrap(),
        sequence,
        occurred_at_ms: at,
        principal_id: PrincipalId::parse("agent-1").unwrap(),
        source_host_id: HostId::parse("windows").unwrap(),
        target_host_id: HostId::parse("mac").unwrap(),
        device_id: None,
        operation: OperationId::parse("build").unwrap(),
        resources: vec![ResourceClass::WorkspaceRead],
        remote_operation_sha256: None,
        authorization: Authorization {
            effect: PolicyEffect::Allow,
            rule_id: None,
            approval_id: None,
        },
        state,
        message: None,
        metrics: MetricSnapshot {
            current_memory_bytes: unavailable(),
            peak_memory_bytes: unavailable(),
            cpu_time_ms: unavailable(),
            process_count: unavailable(),
        },
        started_at_ms: Some(10),
        finished_at_ms: None,
    }
}

#[test]
fn local_snapshot_excludes_activities_between_other_hosts() {
    let root = tempfile::tempdir().unwrap();
    let audit = Arc::new(Mutex::new(
        AuditStore::open(
            root.path().join("audit"),
            RetentionPolicy::default(),
            Redactor::default(),
        )
        .unwrap(),
    ));
    let mut service = DashboardService::new(
        HostId::parse("mac").unwrap(),
        TopologyProjector::new(),
        EventJournal::new(1, 0),
        audit,
        PolicyEngine::new(),
    );
    let mut local = event(ActivityState::Running, 1, 10);
    local.activity_id = ActivityId::parse("local-job").unwrap();
    let mut remote = event(ActivityState::Running, 1, 11);
    remote.activity_id = ActivityId::parse("remote-job").unwrap();
    remote.source_host_id = HostId::parse("linux").unwrap();
    remote.target_host_id = HostId::parse("cloud-mac").unwrap();
    service.record_activity(remote, "remote").unwrap();
    service.record_activity(local, "local").unwrap();

    let snapshot = service.snapshot(DashboardScope::Local, 20);
    assert_eq!(snapshot.activities.len(), 1);
    assert_eq!(snapshot.activities[0].activity_id.as_str(), "local-job");

    let local_events = service.events_in_scope(
        DashboardScope::Local,
        EventCursor {
            epoch: 1,
            sequence: 0,
        },
        1,
    );
    assert!(matches!(
        local_events,
        EventRead::Events { events, next_cursor }
            if events.len() == 1
                && events[0].activity_id.as_str() == "local-job"
                && next_cursor.sequence == 2
    ));

    let mesh_events = service.events_in_scope(
        DashboardScope::Mesh,
        EventCursor {
            epoch: 1,
            sequence: 0,
        },
        2,
    );
    assert!(matches!(mesh_events, EventRead::Events { events, .. } if events.len() == 2));
}

fn access(activity: &str) -> AccessRequest {
    AccessRequest {
        activity_id: ActivityId::parse(activity).unwrap(),
        principal_id: PrincipalId::parse("agent-1").unwrap(),
        source_host_id: HostId::parse("windows").unwrap(),
        target_host_id: HostId::parse("mac").unwrap(),
        device_id: None,
        operation: OperationId::parse("build").unwrap(),
        resources: vec![ResourceClass::WorkspaceRead],
        remote_operation: None,
        physical_device: false,
        user_present: true,
    }
}

fn admin_rule(
    id: &str,
    effect: PolicyEffect,
    operation: &str,
    resource: ResourceClass,
) -> PolicyRule {
    PolicyRule {
        id: RuleId::parse(id).unwrap(),
        revision: 1,
        effect,
        principal_id: Some(PrincipalId::parse("local-user").unwrap()),
        source_host_id: Some(HostId::parse("mac").unwrap()),
        target_host_id: Some(HostId::parse("mac").unwrap()),
        device_id: None,
        operation: Some(OperationId::parse(operation).unwrap()),
        resources: vec![resource],
        expires_at_ms: None,
        require_user_presence: false,
        user_presence: None,
        physical_device: None,
        match_device_exact: true,
        match_resources_exact: true,
        enabled: true,
        origin: PolicyOrigin::User,
    }
}

#[test]
fn cancellation_requires_an_explicit_one_use_admin_grant() {
    let root = tempfile::tempdir().unwrap();
    let audit = Arc::new(Mutex::new(
        AuditStore::open(
            root.path().join("audit"),
            RetentionPolicy::default(),
            Redactor::default(),
        )
        .unwrap(),
    ));
    let mut service = DashboardService::new(
        HostId::parse("mac").unwrap(),
        TopologyProjector::new(),
        EventJournal::new(1, 0),
        audit,
        PolicyEngine::new(),
    );
    service
        .record_activity(event(ActivityState::Running, 1, 10), "start")
        .unwrap();

    assert_eq!(
        service.cancel_activity(&ActivityId::parse("job-1").unwrap(), 20),
        Err(DashboardServiceError::PermissionDenied)
    );
    assert_eq!(
        service.cancel_activity(&ActivityId::parse("job-1").unwrap(), 21),
        Err(DashboardServiceError::PermissionDenied)
    );
    let audit = service
        .audit_query(AuditFilter::default(), None, 10)
        .unwrap();
    assert!(audit.items.is_empty());
    assert!(
        matches!(service.events(EventCursor { epoch: 1, sequence: 1 }, 10), EventRead::Events { events, .. } if events.is_empty())
    );
}

#[test]
fn restart_reconciles_one_existing_activity_id_without_starting_another() {
    let root = tempfile::tempdir().unwrap();
    let audit = Arc::new(Mutex::new(
        AuditStore::open(
            root.path().join("audit"),
            RetentionPolicy::default(),
            Redactor::default(),
        )
        .unwrap(),
    ));
    let mut service = DashboardService::new(
        HostId::parse("mac").unwrap(),
        TopologyProjector::new(),
        EventJournal::new(3, 0),
        audit,
        PolicyEngine::new(),
    );
    service
        .record_activity(event(ActivityState::Running, 1, 10), "start")
        .unwrap();
    service.reconcile_after_restart(30).unwrap();
    let snapshot = service.snapshot(DashboardScope::Local, 30);
    assert_eq!(snapshot.activities.len(), 1);
    assert_eq!(snapshot.activities[0].activity_id.as_str(), "job-1");
    assert_eq!(snapshot.activities[0].state, ActivityState::Failed);
    assert_eq!(
        service
            .activity(&ActivityId::parse("job-1").unwrap())
            .unwrap()
            .message
            .as_ref()
            .unwrap()
            .code,
        device_development_mesh::dashboard::MessageCode::DaemonRestarted
    );
    let audit = service
        .audit_query(
            AuditFilter {
                result: Some(device_development_mesh::dashboard::AuditResult::Failed),
                ..AuditFilter::default()
            },
            None,
            10,
        )
        .unwrap();
    let terminal = audit
        .items
        .into_iter()
        .find(|record| {
            record
                .activity_id
                .as_ref()
                .is_some_and(|id| id.as_str() == "job-1")
        })
        .expect("restart failure audit missing");
    assert_eq!(
        terminal.redacted_message.unwrap().code,
        device_development_mesh::dashboard::MessageCode::DaemonRestarted
    );
}

#[test]
fn missing_admin_grant_fails_closed_before_policy_mutation() {
    let root = tempfile::tempdir().unwrap();
    let audit = Arc::new(Mutex::new(
        AuditStore::open(
            root.path().join("audit"),
            RetentionPolicy::default(),
            Redactor::default(),
        )
        .unwrap(),
    ));
    let poison = Arc::clone(&audit);
    let _ = std::thread::spawn(move || {
        let _guard = poison.lock().unwrap();
        panic!("inject poisoned audit lock");
    })
    .join();
    let mut service = DashboardService::new(
        HostId::parse("mac").unwrap(),
        TopologyProjector::new(),
        EventJournal::new(1, 0),
        audit,
        PolicyEngine::new(),
    );
    let result = service.delete_policy_rule(
        &device_development_mesh::dashboard::RuleId::parse("r1").unwrap(),
        10,
    );
    assert_eq!(result, Err(DashboardServiceError::PermissionDenied));
    assert!(service.policy_rules().is_empty());
}

#[test]
fn subscriber_limit_is_stable_and_idle_housekeeping_frees_capacity() {
    let root = tempfile::tempdir().unwrap();
    let audit = Arc::new(Mutex::new(
        AuditStore::open(
            root.path().join("audit"),
            RetentionPolicy::default(),
            Redactor::default(),
        )
        .unwrap(),
    ));
    let service = DashboardService::new(
        HostId::parse("mac").unwrap(),
        TopologyProjector::new(),
        EventJournal::new(1, 0),
        audit,
        PolicyEngine::new(),
    );
    for index in 0..32 {
        service
            .acknowledge(
                SubscriberId::parse(format!("subscriber-{index}")).unwrap(),
                EventCursor {
                    epoch: 1,
                    sequence: 0,
                },
                1,
            )
            .unwrap();
    }
    assert_eq!(
        service.acknowledge(
            SubscriberId::parse("subscriber-33").unwrap(),
            EventCursor {
                epoch: 1,
                sequence: 0
            },
            2,
        ),
        Err(DashboardServiceError::LimitExceeded)
    );
    service
        .acknowledge(
            SubscriberId::parse("subscriber-33").unwrap(),
            EventCursor {
                epoch: 1,
                sequence: 0,
            },
            15_002,
        )
        .unwrap();
}

#[test]
fn pause_and_resume_require_separate_explicit_grants() {
    let root = tempfile::tempdir().unwrap();
    let audit = Arc::new(Mutex::new(
        AuditStore::open(
            root.path().join("audit"),
            RetentionPolicy::default(),
            Redactor::default(),
        )
        .unwrap(),
    ));
    let mut service = DashboardService::new(
        HostId::parse("mac").unwrap(),
        TopologyProjector::new(),
        EventJournal::new(1, 0),
        audit,
        PolicyEngine::new(),
    );
    assert_eq!(
        service.pause(ExistingJobs::Finish, 10),
        Err(DashboardServiceError::PermissionDenied)
    );
    assert_eq!(
        service.resume(12),
        Err(DashboardServiceError::PermissionDenied)
    );
    assert!(!service.remote_access_paused());
}

#[test]
fn persistent_service_reopen_reconciles_same_activity_id() {
    let root = tempfile::tempdir().unwrap();
    let audit_root = root.path().join("audit");
    {
        let audit = Arc::new(Mutex::new(
            AuditStore::open(&audit_root, RetentionPolicy::default(), Redactor::default()).unwrap(),
        ));
        let mut service = DashboardService::new_persistent(
            HostId::parse("mac").unwrap(),
            TopologyProjector::new(),
            EventJournal::new(1, 0),
            audit,
            PolicyEngine::new(),
        )
        .unwrap();
        service
            .record_activity(event(ActivityState::Running, 1, 10), "start")
            .unwrap();
    }
    let audit = Arc::new(Mutex::new(
        AuditStore::open(&audit_root, RetentionPolicy::default(), Redactor::default()).unwrap(),
    ));
    let service = DashboardService::new_persistent(
        HostId::parse("mac").unwrap(),
        TopologyProjector::new(),
        EventJournal::new(2, 0),
        audit,
        PolicyEngine::new(),
    )
    .unwrap();
    let snapshot = service.snapshot(DashboardScope::Local, 30);
    assert_eq!(snapshot.activities.len(), 1);
    assert_eq!(snapshot.activities[0].activity_id.as_str(), "job-1");
    assert_eq!(snapshot.activities[0].state, ActivityState::Failed);
    assert_eq!(
        service
            .activity(&ActivityId::parse("job-1").unwrap())
            .unwrap()
            .message
            .as_ref()
            .unwrap()
            .code,
        device_development_mesh::dashboard::MessageCode::DaemonRestarted
    );
}

#[test]
fn approval_request_is_audited_before_pending_state_and_emits_live_event() {
    let root = tempfile::tempdir().unwrap();
    let audit = Arc::new(Mutex::new(
        AuditStore::open(
            root.path().join("audit"),
            RetentionPolicy::default(),
            Redactor::default(),
        )
        .unwrap(),
    ));
    let mut service = DashboardService::new(
        HostId::parse("mac").unwrap(),
        TopologyProjector::new(),
        EventJournal::new(1, 0),
        audit,
        PolicyEngine::new(),
    );
    service
        .request_approval(access("approval-job"), 60_000, 10)
        .unwrap();
    assert_eq!(service.pending_approvals(11).len(), 1);
    let audit = service
        .audit_query(AuditFilter::default(), None, 10)
        .unwrap();
    assert_eq!(audit.items.len(), 1);
    assert_eq!(
        audit.items[0].result,
        device_development_mesh::dashboard::AuditResult::Attempted
    );
    assert!(
        matches!(service.events(EventCursor { epoch: 1, sequence: 0 }, 10), EventRead::Events { events, .. } if events.len() == 1 && events[0].state == ActivityState::AwaitingApproval)
    );
}

#[test]
fn notification_lookup_returns_only_exact_live_daemon_pending_truth() {
    let root = tempfile::tempdir().unwrap();
    let audit = Arc::new(Mutex::new(
        AuditStore::open(
            root.path().join("audit"),
            RetentionPolicy::default(),
            Redactor::default(),
        )
        .unwrap(),
    ));
    let mut service = DashboardService::new(
        HostId::parse("mac").unwrap(),
        TopologyProjector::new(),
        EventJournal::new(1, 0),
        audit,
        PolicyEngine::new(),
    );
    service
        .request_approval(access("notification"), 100, 10)
        .unwrap();
    let pending = service.pending_approvals(11).remove(0);

    assert_eq!(
        service.pending_approval_for_notification(&pending.id, 11),
        Ok(pending.clone())
    );
    assert_eq!(
        service.pending_approval_for_notification(&pending.id, 110),
        Err(DashboardServiceError::ApprovalExpired)
    );
    assert_eq!(
        service.pending_approval_for_notification(
            &device_development_mesh::dashboard::ApprovalId::parse("approval-forged").unwrap(),
            11,
        ),
        Err(DashboardServiceError::NotFound)
    );
}

#[test]
fn local_admin_approval_request_is_accepted_but_does_not_authorize_before_decision() {
    let root = tempfile::tempdir().unwrap();
    let state = root.path().join("state");
    let mut service = persistent_service(&state, PolicyEngine::new());
    let request = AccessRequest {
        activity_id: ActivityId::parse("admin-put").unwrap(),
        principal_id: PrincipalId::parse("local-user").unwrap(),
        source_host_id: HostId::parse("mac").unwrap(),
        target_host_id: HostId::parse("mac").unwrap(),
        device_id: None,
        operation: OperationId::parse("devicelane.policy.put").unwrap(),
        resources: vec![ResourceClass::DeviceLanePolicy],
        remote_operation: None,
        physical_device: false,
        user_present: true,
    };
    assert!(service.request_approval(request, 60_000, 10).is_ok());
    assert_eq!(
        service.put_policy_rule(
            admin_rule(
                "candidate",
                PolicyEffect::Allow,
                "build",
                ResourceClass::WorkspaceRead
            ),
            11
        ),
        Err(DashboardServiceError::PermissionDenied)
    );
}

#[test]
fn explicit_admin_deny_prevents_policy_mutation_despite_local_authentication() {
    let root = tempfile::tempdir().unwrap();
    let audit = Arc::new(Mutex::new(
        AuditStore::open(
            root.path().join("audit"),
            RetentionPolicy::default(),
            Redactor::default(),
        )
        .unwrap(),
    ));
    let deny = admin_rule(
        "deny-admin",
        PolicyEffect::Deny,
        "devicelane.policy.put",
        ResourceClass::DeviceLanePolicy,
    );
    let mut service = DashboardService::new(
        HostId::parse("mac").unwrap(),
        TopologyProjector::new(),
        EventJournal::new(1, 0),
        audit,
        PolicyEngine::with_rules(vec![deny]).unwrap(),
    );
    let candidate = admin_rule(
        "candidate",
        PolicyEffect::Allow,
        "build",
        ResourceClass::WorkspaceRead,
    );
    assert_eq!(
        service.put_policy_rule(candidate, 10),
        Err(DashboardServiceError::PermissionDenied)
    );
    assert_eq!(service.policy_rules().len(), 1);
}

#[test]
fn same_user_without_an_explicit_admin_grant_is_denied() {
    let root = tempfile::tempdir().unwrap();
    let audit = Arc::new(Mutex::new(
        AuditStore::open(
            root.path().join("audit"),
            RetentionPolicy::default(),
            Redactor::default(),
        )
        .unwrap(),
    ));
    let user_allow = admin_rule(
        "user-admin-allow",
        PolicyEffect::Allow,
        "devicelane.policy.put",
        ResourceClass::DeviceLanePolicy,
    );
    let mut service = DashboardService::new(
        HostId::parse("mac").unwrap(),
        TopologyProjector::new(),
        EventJournal::new(1, 0),
        audit,
        PolicyEngine::with_rules(vec![user_allow]).unwrap(),
    );
    let candidate = admin_rule(
        "candidate",
        PolicyEffect::Allow,
        "build",
        ResourceClass::WorkspaceRead,
    );
    assert_eq!(
        service.put_policy_rule(candidate, 10),
        Err(DashboardServiceError::PermissionDenied)
    );
    assert_eq!(service.policy_rules().len(), 1);
}

#[test]
fn restart_preserves_waiting_approval_when_pending_nonce_survives() {
    let root = tempfile::tempdir().unwrap();
    let state = root.path().join("state");
    {
        let mut service = persistent_service(&state, PolicyEngine::new());
        service
            .request_approval(access("waiting"), 60_000, 10)
            .unwrap();
    }
    let service = persistent_service(&state, PolicyEngine::new());
    let snapshot = service.snapshot(DashboardScope::Local, 11);
    assert_eq!(service.pending_approvals(11).len(), 1);
    assert_eq!(snapshot.activities.len(), 1);
    assert_eq!(
        snapshot.activities[0].state,
        ActivityState::AwaitingApproval
    );
}

#[test]
fn event_sequence_failure_does_not_leak_into_durable_checkpoint() {
    let root = tempfile::tempdir().unwrap();
    let audit_root = root.path().join("audit");
    {
        let audit = Arc::new(Mutex::new(
            AuditStore::open(&audit_root, RetentionPolicy::default(), Redactor::default()).unwrap(),
        ));
        let mut service = DashboardService::new_persistent(
            HostId::parse("mac").unwrap(),
            TopologyProjector::new(),
            EventJournal::new(1, 0),
            audit,
            PolicyEngine::new(),
        )
        .unwrap();
        let invalid_sequence = event(ActivityState::Running, 2, 10);
        assert_eq!(
            service.record_activity(invalid_sequence, "bad-sequence"),
            Err(DashboardServiceError::LimitExceeded)
        );
        assert!(
            service
                .snapshot(DashboardScope::Local, 10)
                .activities
                .is_empty()
        );
    }
    let audit = Arc::new(Mutex::new(
        AuditStore::open(&audit_root, RetentionPolicy::default(), Redactor::default()).unwrap(),
    ));
    let reopened = DashboardService::new_persistent(
        HostId::parse("mac").unwrap(),
        TopologyProjector::new(),
        EventJournal::new(2, 0),
        audit,
        PolicyEngine::new(),
    )
    .unwrap();
    assert!(
        reopened
            .snapshot(DashboardScope::Local, 20)
            .activities
            .is_empty()
    );
}

fn break_checkpoint(root: &std::path::Path) {
    let path = root.join("activity-state.json");
    if path.is_file() {
        std::fs::remove_file(&path).unwrap();
    }
    std::fs::create_dir(&path).unwrap();
}

fn persistent_service(root: &std::path::Path, policy: PolicyEngine) -> DashboardService {
    let audit = Arc::new(Mutex::new(
        AuditStore::open(root, RetentionPolicy::default(), Redactor::default()).unwrap(),
    ));
    DashboardService::new_persistent(
        HostId::parse("mac").unwrap(),
        TopologyProjector::new(),
        EventJournal::new(1, 0),
        audit,
        policy,
    )
    .unwrap()
}

#[test]
fn controller_observations_do_not_replace_registry_inventory() {
    use device_development_mesh::dashboard::{Freshness, Presence};
    use device_development_mesh::network_processes::HostSnapshot;
    let root = tempfile::tempdir().unwrap();
    let mut service = persistent_service(root.path(), PolicyEngine::new());
    let remote = HostSnapshot {
        id: "remote-mac".into(),
        operating_system: "macos".into(),
        architecture: "arm64".into(),
        status: "online".into(),
        capabilities: vec!["apple.build@1".into()],
        devices: Vec::new(),
    };
    for time in [10, 20] {
        service
            .observe_authenticated_inventory("registry", time, vec![remote.clone()])
            .unwrap();
    }
    service
        .observe_authenticated_controller("registry", 30)
        .unwrap();
    let snapshot = service.snapshot(DashboardScope::Mesh, 30);
    assert_eq!(
        snapshot
            .hosts
            .iter()
            .find(|host| host.id.as_str() == "remote-mac")
            .unwrap()
            .freshness,
        Freshness::Live
    );
    service
        .observe_authenticated_inventory("registry", 40, vec![remote])
        .unwrap();
    let snapshot = service.snapshot(DashboardScope::Mesh, 40);
    assert_eq!(
        snapshot
            .hosts
            .iter()
            .find(|host| host.id.as_str() == "registry")
            .unwrap()
            .presence,
        Presence::Online
    );
}

#[test]
fn rejected_inventory_does_not_partially_update_service_topology() {
    use device_development_mesh::network_processes::HostSnapshot;
    let root = tempfile::tempdir().unwrap();
    let mut service = persistent_service(root.path(), PolicyEngine::new());
    let before = service.snapshot(DashboardScope::Mesh, 10);
    let hosts = (0..128)
        .map(|id| HostSnapshot {
            id: format!("remote-{id}"),
            operating_system: "macos".into(),
            architecture: "arm64".into(),
            status: "online".into(),
            capabilities: Vec::new(),
            devices: Vec::new(),
        })
        .collect();
    assert!(
        service
            .observe_authenticated_inventory("registry", 10, hosts)
            .is_err()
    );
    assert_eq!(service.snapshot(DashboardScope::Mesh, 10), before);
}

#[test]
fn checkpoint_failure_rolls_back_staged_approval_request() {
    let request_root = tempfile::tempdir().unwrap();
    let state = request_root.path().join("state");
    let mut request_service = persistent_service(&state, PolicyEngine::new());
    break_checkpoint(&state);
    assert!(
        request_service
            .request_approval(access("request"), 1_000, 10)
            .is_err()
    );
    assert!(request_service.pending_approvals(11).is_empty());
}
