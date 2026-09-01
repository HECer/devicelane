use device_development_mesh::dashboard::{
    ActivityEvent, ActivityId, ActivityState, ActivitySummary, ApprovalDecision, ApprovalId,
    ApprovalRequest, AuditRecord, AuditResult, Authorization, ConnectionPath, DashboardDevice,
    DashboardHost, DashboardScope, DashboardSnapshot, DashboardWarning, DeviceId, EventCursor,
    Freshness, HostId, MetricSnapshot, MetricValue, OperationId, PolicyEffect, PolicyOrigin,
    PolicyRule, Presence, PrincipalId, ResourceClass, ResourceOccupancy, RuleId, TrustState,
    ValidatedId,
};
use serde_json::json;

fn host_id(value: &str) -> HostId {
    HostId::parse(value).unwrap()
}

fn device_id(value: &str) -> DeviceId {
    DeviceId::parse(value).unwrap()
}

fn activity_id(value: &str) -> ActivityId {
    ActivityId::parse(value).unwrap()
}

fn principal_id(value: &str) -> PrincipalId {
    PrincipalId::parse(value).unwrap()
}

fn operation_id(value: &str) -> OperationId {
    OperationId::parse(value).unwrap()
}

fn sample_host() -> DashboardHost {
    DashboardHost {
        id: host_id("mac-studio"),
        display_name: "Build Mac".into(),
        platform: "macos".into(),
        architecture: "arm64".into(),
        presence: Presence::Online,
        freshness: Freshness::Live,
        trust: TrustState::Trusted,
        connection_path: ConnectionPath::Registry,
        capabilities: vec!["xcode_build".into()],
        permissions: vec!["workspace_read".into()],
        devices: vec![DashboardDevice {
            id: device_id("iphone-1"),
            host_id: host_id("mac-studio"),
            display_name: "iPhone".into(),
            platform: "ios".into(),
            presence: Presence::Busy,
            freshness: Freshness::Live,
            capabilities: vec!["application_install".into()],
            permissions: vec!["device_lease".into()],
        }],
    }
}

fn sample_event() -> ActivityEvent {
    ActivityEvent {
        activity_id: activity_id("activity-1"),
        sequence: 2,
        occurred_at_ms: 1_788_220_800_000,
        principal_id: principal_id("agent-windows"),
        source_host_id: host_id("windows-host"),
        target_host_id: host_id("mac-studio"),
        device_id: Some(device_id("iphone-1")),
        operation: operation_id("build-ios"),
        resources: vec![ResourceClass::WorkspaceRead, ResourceClass::DeviceLease],
        authorization: Authorization {
            effect: PolicyEffect::Allow,
            rule_id: Some(RuleId::parse("rule-1").unwrap()),
            approval_id: None,
        },
        state: ActivityState::Running,
        message: Some("build started [redacted]".into()),
        metrics: MetricSnapshot {
            current_memory_bytes: MetricValue::Available { value: 512 },
            peak_memory_bytes: MetricValue::Available { value: 1024 },
            cpu_time_ms: MetricValue::Unavailable {
                reason: "observer_failed".into(),
            },
            process_count: MetricValue::Available { value: 3 },
        },
        started_at_ms: Some(1_788_220_799_000),
        finished_at_ms: None,
    }
}

#[test]
fn representative_contracts_round_trip() {
    let event = sample_event();
    let snapshot = DashboardSnapshot {
        revision: 7,
        generated_at_ms: 1_788_220_800_000,
        scope: DashboardScope::Mesh,
        hosts: vec![sample_host()],
        activities: vec![ActivitySummary::from(&event)],
        pending_approvals: vec![ApprovalRequest {
            id: ApprovalId::parse("approval-1").unwrap(),
            activity_id: event.activity_id.clone(),
            principal_id: event.principal_id.clone(),
            source_host_id: event.source_host_id.clone(),
            target_host_id: event.target_host_id.clone(),
            device_id: event.device_id.clone(),
            operation: event.operation.clone(),
            resources: event.resources.clone(),
            requested_at_ms: 1_788_220_800_000,
            expires_at_ms: 1_788_221_100_000,
            risk: "target_confirmation_required".into(),
        }],
        warnings: vec![DashboardWarning {
            code: "stale_registry".into(),
            message: "Registry observation is stale".into(),
            host_id: Some(host_id("mac-studio")),
        }],
    };
    snapshot.validate().unwrap();

    let encoded = serde_json::to_string(&snapshot).unwrap();
    let decoded: DashboardSnapshot = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded, snapshot);
    assert_eq!(
        serde_json::from_str::<ActivityEvent>(&serde_json::to_string(&event).unwrap()).unwrap(),
        event
    );
}

#[test]
fn every_representative_struct_rejects_unknown_fields() {
    let values = [
        serde_json::to_value(sample_host()).unwrap(),
        serde_json::to_value(sample_host().devices[0].clone()).unwrap(),
        serde_json::to_value(sample_event()).unwrap(),
        serde_json::to_value(ResourceOccupancy {
            activity_id: activity_id("activity-1"),
            principal_id: principal_id("agent-windows"),
            target_host_id: host_id("mac-studio"),
            device_id: Some(device_id("iphone-1")),
            resource: ResourceClass::DeviceLease,
            acquired_at_ms: 10,
        })
        .unwrap(),
        serde_json::to_value(ApprovalRequest {
            id: ApprovalId::parse("approval-1").unwrap(),
            activity_id: activity_id("activity-1"),
            principal_id: principal_id("agent-windows"),
            source_host_id: host_id("windows-host"),
            target_host_id: host_id("mac-studio"),
            device_id: None,
            operation: operation_id("build-ios"),
            resources: vec![ResourceClass::WorkspaceRead],
            requested_at_ms: 10,
            expires_at_ms: 20,
            risk: "normal".into(),
        })
        .unwrap(),
        serde_json::to_value(PolicyRule {
            id: RuleId::parse("rule-1").unwrap(),
            revision: 1,
            effect: PolicyEffect::Allow,
            principal_id: Some(principal_id("agent-windows")),
            source_host_id: Some(host_id("windows-host")),
            target_host_id: Some(host_id("mac-studio")),
            device_id: None,
            operation: Some(operation_id("build-ios")),
            resources: vec![ResourceClass::WorkspaceRead],
            expires_at_ms: None,
            require_user_presence: false,
            enabled: true,
            origin: PolicyOrigin::User,
        })
        .unwrap(),
        serde_json::to_value(AuditRecord {
            sequence: 1,
            occurred_at_ms: 10,
            activity_id: Some(activity_id("activity-1")),
            principal_id: principal_id("agent-windows"),
            source_host_id: host_id("windows-host"),
            target_host_id: host_id("mac-studio"),
            device_id: None,
            operation: operation_id("build-ios"),
            resources: vec![ResourceClass::WorkspaceRead],
            decision: PolicyEffect::Allow,
            result: AuditResult::Succeeded,
            redacted_message: Some("ok".into()),
        })
        .unwrap(),
    ];

    for mut value in values {
        value
            .as_object_mut()
            .unwrap()
            .insert("token".into(), json!("secret"));
        let text = value.to_string();
        assert!(
            serde_json::from_str::<serde_json::Value>(&text).is_ok(),
            "fixture must be valid JSON"
        );
        let rejected = serde_json::from_str::<DashboardHost>(&text).is_err()
            && serde_json::from_str::<DashboardDevice>(&text).is_err()
            && serde_json::from_str::<ActivityEvent>(&text).is_err()
            && serde_json::from_str::<ResourceOccupancy>(&text).is_err()
            && serde_json::from_str::<ApprovalRequest>(&text).is_err()
            && serde_json::from_str::<PolicyRule>(&text).is_err()
            && serde_json::from_str::<AuditRecord>(&text).is_err();
        assert!(rejected, "unknown fields must not be accepted: {text}");
    }
}

#[test]
fn ids_are_non_empty_opaque_and_type_safe() {
    assert!(ValidatedId::parse("").is_err());
    assert!(HostId::parse("").is_err());
    assert!(HostId::parse("   ").is_err());
    assert!(serde_json::from_str::<HostId>(r#""#).is_err());
    let id = HostId::parse(" host/opaque:value ").unwrap();
    assert_eq!(id.as_str(), "host/opaque:value");
}

#[test]
fn duplicate_resources_are_rejected() {
    let mut event = sample_event();
    event.resources.push(ResourceClass::WorkspaceRead);
    assert_eq!(
        event.validate().unwrap_err().code(),
        "duplicate_resource_class"
    );

    let mut rule = PolicyRule {
        id: RuleId::parse("rule-1").unwrap(),
        revision: 1,
        effect: PolicyEffect::Allow,
        principal_id: None,
        source_host_id: None,
        target_host_id: None,
        device_id: None,
        operation: None,
        resources: vec![ResourceClass::Signing, ResourceClass::Signing],
        expires_at_ms: None,
        require_user_presence: true,
        enabled: true,
        origin: PolicyOrigin::Managed,
    };
    assert_eq!(
        rule.validate().unwrap_err().code(),
        "duplicate_resource_class"
    );
    rule.resources.pop();
    rule.validate().unwrap();
}

#[test]
fn metrics_reject_peak_below_current_and_unavailable_is_not_zero() {
    let mut event = sample_event();
    event.metrics.current_memory_bytes = MetricValue::Available { value: 1024 };
    event.metrics.peak_memory_bytes = MetricValue::Available { value: 512 };
    assert_eq!(
        event.validate().unwrap_err().code(),
        "invalid_metric_snapshot"
    );

    let value = serde_json::to_value(MetricValue::Unavailable {
        reason: "observer_failed".into(),
    })
    .unwrap();
    assert_eq!(value, json!({"unavailable":{"reason":"observer_failed"}}));
    assert!(!value.to_string().contains(":0"));
}

#[test]
fn terminal_activity_requires_finished_timestamp() {
    for state in [
        ActivityState::Succeeded,
        ActivityState::Failed,
        ActivityState::Denied,
        ActivityState::Cancelled,
    ] {
        let mut event = sample_event();
        event.state = state;
        assert_eq!(event.validate().unwrap_err().code(), "missing_finished_at");
        event.finished_at_ms = Some(event.occurred_at_ms);
        event.validate().unwrap();
    }
}

#[test]
fn stale_or_offline_presence_requires_last_seen() {
    let mut host = sample_host();
    host.presence = Presence::Offline;
    host.freshness = Freshness::Unknown;
    let snapshot = DashboardSnapshot {
        revision: 1,
        generated_at_ms: 10,
        scope: DashboardScope::Local,
        hosts: vec![host],
        activities: vec![],
        pending_approvals: vec![],
        warnings: vec![],
    };
    assert_eq!(
        snapshot.validate().unwrap_err().code(),
        "missing_last_seen_at"
    );
}

#[test]
fn contract_contains_no_forbidden_sensitive_fields() {
    let encoded = serde_json::to_string(&(
        sample_host(),
        sample_event(),
        EventCursor {
            epoch: 1,
            sequence: 2,
        },
        ApprovalDecision::DenyOnce,
    ))
    .unwrap();
    for forbidden in [
        "private_key",
        "token",
        "environment",
        "workspace_content",
        "workspace_contents",
    ] {
        assert!(
            !encoded.contains(forbidden),
            "serialized contract leaked field {forbidden}"
        );
    }
}
