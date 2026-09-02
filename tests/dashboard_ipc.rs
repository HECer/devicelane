use device_development_mesh::dashboard::audit::{
    AuditFilter, AuditStore, Redactor, RetentionPolicy,
};
use device_development_mesh::dashboard::event_log::{EventJournal, EventRead};
use device_development_mesh::dashboard::policy::PolicyEngine;
use device_development_mesh::dashboard::service::{DashboardService, DashboardServiceError};
use device_development_mesh::dashboard::topology::TopologyProjector;
use device_development_mesh::dashboard::{
    ActivityEvent, ActivityId, ActivityState, Authorization, DashboardScope, EventCursor, HostId,
    MetricSnapshot, MetricValue, OperationId, PolicyEffect, PrincipalId, ResourceClass, SafeCode,
    SubscriberId,
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
fn cancellation_is_idempotent_and_audited_before_its_event() {
    let root = tempfile::tempdir().unwrap();
    let audit = Arc::new(Mutex::new(
        AuditStore::open(root.path(), RetentionPolicy::default(), Redactor::default()).unwrap(),
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
        Ok(true)
    );
    assert_eq!(
        service.cancel_activity(&ActivityId::parse("job-1").unwrap(), 21),
        Ok(false)
    );
    let audit = service
        .audit_query(AuditFilter::default(), None, 10)
        .unwrap();
    assert_eq!(audit.items.len(), 1);
    assert_eq!(audit.items[0].occurred_at_ms, 20);
    assert!(
        matches!(service.events(EventCursor { epoch: 1, sequence: 1 }, 10), EventRead::Events { events, .. } if events.len() == 1 && events[0].state == ActivityState::Cancelled)
    );
}

#[test]
fn restart_reconciles_one_existing_activity_id_without_starting_another() {
    let root = tempfile::tempdir().unwrap();
    let audit = Arc::new(Mutex::new(
        AuditStore::open(root.path(), RetentionPolicy::default(), Redactor::default()).unwrap(),
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
    assert_eq!(snapshot.activities[0].state, ActivityState::Reconnecting);
}

#[test]
fn poisoned_audit_fails_closed_before_policy_mutation() {
    let root = tempfile::tempdir().unwrap();
    let audit = Arc::new(Mutex::new(
        AuditStore::open(root.path(), RetentionPolicy::default(), Redactor::default()).unwrap(),
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
    assert_eq!(result, Err(DashboardServiceError::AuditUnavailable));
    assert!(service.policy_rules().is_empty());
}
