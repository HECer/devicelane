use device_development_mesh::dashboard::{
    ActivityEvent, ActivityId, ActivityState, ActivitySummary, ApprovalDecision, ApprovalId,
    ApprovalRequest, AuditRecord, AuditResult, Authorization, ConnectionPath, CursorPage,
    DashboardDevice, DashboardHost, DashboardScope, DashboardSnapshot, DashboardWarning, DeviceId,
    DisplayMessage, EventCursor, Freshness, HostId, MessageCode, MetricSnapshot, MetricValue,
    OperationId, PolicyEffect, PolicyOrigin, PolicyRule, Presence, PrincipalId, ResourceClass,
    ResourceOccupancy, RuleId, SafeCode, TrustState, ValidatedId,
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

fn code(value: &str) -> SafeCode {
    SafeCode::parse(value).unwrap()
}

fn message(value: MessageCode) -> DisplayMessage {
    DisplayMessage::new(value, vec![]).unwrap()
}

fn sample_host() -> DashboardHost {
    DashboardHost {
        id: host_id("mac-studio"),
        display_name: "Build Mac".into(),
        platform: code("macos"),
        architecture: code("arm64"),
        presence: Presence::Online,
        freshness: Freshness::Live,
        trust: TrustState::Trusted,
        connection_path: ConnectionPath::Registry,
        capabilities: vec![code("xcode_build")],
        permissions: vec![code("workspace_read")],
        devices: vec![DashboardDevice {
            id: device_id("iphone-1"),
            host_id: host_id("mac-studio"),
            display_name: "iPhone".into(),
            platform: code("ios"),
            presence: Presence::Busy,
            freshness: Freshness::Live,
            capabilities: vec![code("application_install")],
            permissions: vec![code("device_lease")],
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
        message: Some(message(MessageCode::ActivityStarted)),
        metrics: MetricSnapshot {
            current_memory_bytes: MetricValue::Available { value: 512 },
            peak_memory_bytes: MetricValue::Available { value: 1024 },
            cpu_time_ms: MetricValue::Unavailable {
                reason: code("observer_failed"),
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
            risk: code("target_confirmation_required"),
        }],
        warnings: vec![DashboardWarning {
            code: code("stale_registry"),
            message: message(MessageCode::RegistryStale),
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
            risk: code("normal"),
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
            user_presence: None,
            physical_device: None,
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
            redacted_message: Some(message(MessageCode::OperationSucceeded)),
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
        user_presence: None,
        physical_device: None,
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
        reason: code("observer_failed"),
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

#[test]
fn deserialization_cannot_bypass_semantic_validation() {
    let mut event = serde_json::to_value(sample_event()).unwrap();
    event["resources"] = json!(["workspace_read", "workspace_read"]);
    assert!(serde_json::from_value::<ActivityEvent>(event).is_err());

    let mut event = serde_json::to_value(sample_event()).unwrap();
    event["metrics"]["current_memory_bytes"] = json!({"available":{"value":1024}});
    event["metrics"]["peak_memory_bytes"] = json!({"available":{"value":512}});
    assert!(serde_json::from_value::<ActivityEvent>(event).is_err());

    let mut event = serde_json::to_value(sample_event()).unwrap();
    event["state"] = json!("succeeded");
    assert!(serde_json::from_value::<ActivityEvent>(event).is_err());

    let mut snapshot = serde_json::to_value(DashboardSnapshot {
        revision: 1,
        generated_at_ms: 10,
        scope: DashboardScope::Local,
        hosts: vec![sample_host()],
        activities: vec![],
        pending_approvals: vec![],
        warnings: vec![],
    })
    .unwrap();
    snapshot["hosts"][0]["presence"] = json!("offline");
    snapshot["hosts"][0]["freshness"] = json!("unknown");
    assert!(serde_json::from_value::<DashboardSnapshot>(snapshot).is_err());

    let metrics = json!({
        "current_memory_bytes":{"available":{"value":2}},
        "peak_memory_bytes":{"available":{"value":1}},
        "cpu_time_ms":{"unavailable":{"reason":"observer_failed"}},
        "process_count":{"available":{"value":1}}
    });
    assert!(serde_json::from_value::<MetricSnapshot>(metrics).is_err());

    let mut rule = serde_json::to_value(PolicyRule {
        id: RuleId::parse("rule").unwrap(),
        revision: 1,
        effect: PolicyEffect::Deny,
        principal_id: None,
        source_host_id: None,
        target_host_id: None,
        device_id: None,
        operation: None,
        resources: vec![ResourceClass::Signing],
        expires_at_ms: None,
        require_user_presence: true,
        user_presence: None,
        physical_device: None,
        enabled: true,
        origin: PolicyOrigin::User,
    })
    .unwrap();
    rule["resources"] = json!(["signing", "signing"]);
    assert!(serde_json::from_value::<PolicyRule>(rule).is_err());

    let mut audit = serde_json::to_value(AuditRecord {
        sequence: 1,
        occurred_at_ms: 1,
        activity_id: None,
        principal_id: principal_id("principal"),
        source_host_id: host_id("source"),
        target_host_id: host_id("target"),
        device_id: None,
        operation: operation_id("build"),
        resources: vec![ResourceClass::WorkspaceRead],
        decision: PolicyEffect::Allow,
        result: AuditResult::Succeeded,
        redacted_message: None,
    })
    .unwrap();
    audit["resources"] = json!(["workspace_read", "workspace_read"]);
    assert!(serde_json::from_value::<AuditRecord>(audit).is_err());
}

#[test]
fn nested_enum_struct_variants_reject_unknown_fields() {
    assert!(
        serde_json::from_value::<Freshness>(json!({
            "stale": {"last_seen_at_ms": 10, "token": "secret"}
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<MetricValue>(json!({
            "available": {"value": 7, "environment": "secret"}
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<MetricValue>(json!({
            "unavailable": {"reason": "observer_failed", "workspace_content": "secret"}
        }))
        .is_err()
    );
}

#[test]
fn event_and_summary_share_lifecycle_invariants() {
    let mut event = serde_json::to_value(sample_event()).unwrap();
    event["state"] = json!("running");
    event["started_at_ms"] = json!(null);
    assert!(serde_json::from_value::<ActivityEvent>(event).is_err());

    let mut summary = serde_json::to_value(ActivitySummary::from(&sample_event())).unwrap();
    summary["state"] = json!("queued");
    summary["started_at_ms"] = json!(10);
    assert!(serde_json::from_value::<ActivitySummary>(summary).is_err());

    let mut summary = serde_json::to_value(ActivitySummary::from(&sample_event())).unwrap();
    summary["state"] = json!("succeeded");
    summary["finished_at_ms"] = json!(null);
    assert!(serde_json::from_value::<ActivitySummary>(summary).is_err());
}

#[test]
fn activity_and_approval_times_are_monotonic_at_boundaries() {
    let mut event = serde_json::to_value(sample_event()).unwrap();
    event["occurred_at_ms"] = json!(9);
    event["started_at_ms"] = json!(10);
    assert!(serde_json::from_value::<ActivityEvent>(event).is_err());

    let mut event = serde_json::to_value(sample_event()).unwrap();
    event["state"] = json!("succeeded");
    event["started_at_ms"] = json!(u64::MAX - 1);
    event["occurred_at_ms"] = json!(u64::MAX);
    event["finished_at_ms"] = json!(u64::MAX);
    assert!(serde_json::from_value::<ActivityEvent>(event).is_ok());

    let approval = json!({
        "id":"approval-1", "activity_id":"activity-1", "principal_id":"principal-1",
        "source_host_id":"source", "target_host_id":"target", "device_id":null,
        "operation":"build", "resources":["workspace_read"], "requested_at_ms":u64::MAX,
        "expires_at_ms":u64::MAX - 1, "risk":"normal"
    });
    assert!(serde_json::from_value::<ApprovalRequest>(approval).is_err());
}

#[test]
fn ids_text_and_vectors_have_explicit_bounds() {
    assert!(HostId::parse("x".repeat(256)).is_ok());
    assert_eq!(
        HostId::parse("x".repeat(257)).unwrap_err().code(),
        "id_too_long"
    );
    assert!(SafeCode::parse("x".repeat(128)).is_ok());
    assert_eq!(
        SafeCode::parse("x".repeat(129)).unwrap_err().code(),
        "code_too_long"
    );

    let mut event = serde_json::to_value(sample_event()).unwrap();
    event["resources"] = json!(vec!["workspace_read"; 129]);
    assert!(serde_json::from_value::<ActivityEvent>(event).is_err());

    let mut host = serde_json::to_value(sample_host()).unwrap();
    host["capabilities"] = json!(vec!["x"; 129]);
    assert!(serde_json::from_value::<DashboardHost>(host).is_err());

    let page = json!({"items": vec![1_u64; 257], "next_cursor": null});
    assert!(serde_json::from_value::<CursorPage<u64>>(page).is_err());
    let page = json!({"items": vec![1_u64; 256], "next_cursor": null});
    assert!(serde_json::from_value::<CursorPage<u64>>(page).is_ok());

    let mut warning = serde_json::to_value(DashboardWarning {
        code: code("warning"),
        message: message(MessageCode::Redacted),
        host_id: None,
    })
    .unwrap();
    warning["message"] = json!({
        "code":"redacted", "params":vec!["local"; 129]
    });
    assert!(serde_json::from_value::<DashboardWarning>(warning).is_err());
}

#[test]
fn direct_deserialization_rejects_each_nested_model_invariant() {
    assert!(
        serde_json::from_value::<MetricValue>(json!({
            "unavailable":{"reason":""}
        }))
        .is_err()
    );

    let mut device = serde_json::to_value(sample_host().devices[0].clone()).unwrap();
    device["presence"] = json!("offline");
    device["freshness"] = json!("unknown");
    assert!(serde_json::from_value::<DashboardDevice>(device).is_err());

    let mut host = serde_json::to_value(sample_host()).unwrap();
    host["devices"][0]["host_id"] = json!("different-host");
    assert!(serde_json::from_value::<DashboardHost>(host).is_err());

    let mut event = serde_json::to_value(sample_event()).unwrap();
    event["state"] = json!("succeeded");
    event["finished_at_ms"] = json!(event["occurred_at_ms"].as_u64().unwrap() - 1);
    assert!(serde_json::from_value::<ActivityEvent>(event).is_err());

    let approval = json!({
        "id":"approval", "activity_id":"activity", "principal_id":"principal",
        "source_host_id":"source", "target_host_id":"target", "device_id":null,
        "operation":"build", "resources":["workspace_read", "workspace_read"],
        "requested_at_ms":1, "expires_at_ms":1, "risk":"normal"
    });
    assert!(serde_json::from_value::<ApprovalRequest>(approval).is_err());

    let warning = json!({"code":"", "message":"safe", "host_id":null});
    assert!(serde_json::from_value::<DashboardWarning>(warning).is_err());
}

#[test]
fn sensitive_message_values_are_rejected_before_serialization() {
    for sensitive in [
        "Authorization: Bearer top-secret",
        "token=top-secret",
        "PRIVATE_KEY=top-secret",
        "environment: SECRET=value",
        "workspace_content=customer source",
    ] {
        let mut event = serde_json::to_value(sample_event()).unwrap();
        event["message"] = json!(sensitive);
        assert!(
            serde_json::from_value::<ActivityEvent>(event).is_err(),
            "accepted {sensitive}"
        );

        let audit = json!({
            "sequence":1, "occurred_at_ms":10, "activity_id":null,
            "principal_id":"principal", "source_host_id":"source", "target_host_id":"target",
            "device_id":null, "operation":"build", "resources":["workspace_read"],
            "decision":"allow", "result":"succeeded", "redacted_message":sensitive
        });
        assert!(
            serde_json::from_value::<AuditRecord>(audit).is_err(),
            "accepted {sensitive}"
        );

        let warning = json!({"code":"warning", "message":sensitive, "host_id":null});
        assert!(
            serde_json::from_value::<DashboardWarning>(warning).is_err(),
            "accepted warning {sensitive}"
        );
    }
}

#[test]
fn validation_errors_include_stable_location_context() {
    let mut event = sample_event();
    event.resources.push(ResourceClass::WorkspaceRead);
    let error = event.validate().unwrap_err();
    assert_eq!(error.code(), "duplicate_resource_class");
    assert_eq!(error.path(), "resources");
    assert_eq!(error.index(), Some(2));
}

#[test]
fn invalid_in_memory_models_cannot_cross_the_serialization_boundary() {
    let mut event = sample_event();
    event.resources.push(ResourceClass::WorkspaceRead);
    assert!(serde_json::to_value(event).is_err());

    let mut metrics = sample_event().metrics;
    metrics.current_memory_bytes = MetricValue::Available { value: 2 };
    metrics.peak_memory_bytes = MetricValue::Available { value: 1 };
    assert!(serde_json::to_value(metrics).is_err());

    let mut summary = ActivitySummary::from(&sample_event());
    summary.started_at_ms = None;
    assert!(serde_json::to_value(summary).is_err());

    let mut host = sample_host();
    host.devices[0].host_id = host_id("wrong-host");
    assert!(serde_json::to_value(host).is_err());

    let mut device = sample_host().devices.remove(0);
    device.presence = Presence::Offline;
    device.freshness = Freshness::Unknown;
    assert!(serde_json::to_value(device).is_err());

    let approval = ApprovalRequest {
        id: ApprovalId::parse("approval").unwrap(),
        activity_id: activity_id("activity"),
        principal_id: principal_id("principal"),
        source_host_id: host_id("source"),
        target_host_id: host_id("target"),
        device_id: None,
        operation: operation_id("build"),
        resources: vec![ResourceClass::WorkspaceRead, ResourceClass::WorkspaceRead],
        requested_at_ms: 1,
        expires_at_ms: 2,
        risk: code("normal"),
    };
    assert!(serde_json::to_value(approval).is_err());

    let approval = ApprovalRequest {
        id: ApprovalId::parse("approval").unwrap(),
        activity_id: activity_id("activity"),
        principal_id: principal_id("principal"),
        source_host_id: host_id("source"),
        target_host_id: host_id("target"),
        device_id: None,
        operation: operation_id("build"),
        resources: vec![ResourceClass::WorkspaceRead],
        requested_at_ms: 2,
        expires_at_ms: 2,
        risk: code("normal"),
    };
    assert!(serde_json::to_value(approval).is_err());

    let rule = PolicyRule {
        id: RuleId::parse("rule").unwrap(),
        revision: 1,
        effect: PolicyEffect::Allow,
        principal_id: None,
        source_host_id: None,
        target_host_id: None,
        device_id: None,
        operation: None,
        resources: vec![ResourceClass::Signing, ResourceClass::Signing],
        expires_at_ms: None,
        require_user_presence: false,
        user_presence: None,
        physical_device: None,
        enabled: true,
        origin: PolicyOrigin::User,
    };
    assert!(serde_json::to_value(rule).is_err());

    let audit = AuditRecord {
        sequence: 1,
        occurred_at_ms: 1,
        activity_id: None,
        principal_id: principal_id("principal"),
        source_host_id: host_id("source"),
        target_host_id: host_id("target"),
        device_id: None,
        operation: operation_id("build"),
        resources: vec![ResourceClass::Signing, ResourceClass::Signing],
        decision: PolicyEffect::Allow,
        result: AuditResult::Succeeded,
        redacted_message: None,
    };
    assert!(serde_json::to_value(audit).is_err());

    let warning = DashboardWarning {
        code: code("warning"),
        message: DisplayMessage {
            code: MessageCode::Redacted,
            params: vec![device_development_mesh::dashboard::MessageParam::Local; 129],
        },
        host_id: None,
    };
    assert!(serde_json::to_value(warning).is_err());

    let oversized_page = CursorPage {
        items: vec![1_u64; 257],
        next_cursor: None,
    };
    assert!(serde_json::to_value(oversized_page).is_err());

    let invalid_snapshot = DashboardSnapshot {
        revision: 1,
        generated_at_ms: 1,
        scope: DashboardScope::Local,
        hosts: vec![sample_host(); 129],
        activities: vec![],
        pending_approvals: vec![],
        warnings: vec![],
    };
    assert!(serde_json::to_value(invalid_snapshot).is_err());
}

#[test]
fn approval_expiry_must_be_strictly_after_request_time() {
    for (requested_at_ms, expires_at_ms) in [(2, 1), (1, 1)] {
        let approval = json!({
            "id":"approval", "activity_id":"activity", "principal_id":"principal",
            "source_host_id":"source", "target_host_id":"target", "device_id":null,
            "operation":"build", "resources":["workspace_read"],
            "requested_at_ms":requested_at_ms, "expires_at_ms":expires_at_ms, "risk":"normal"
        });
        assert!(serde_json::from_value::<ApprovalRequest>(approval).is_err());
    }
}

#[test]
fn denied_and_cancelled_are_valid_before_execution_starts() {
    for state in [ActivityState::Denied, ActivityState::Cancelled] {
        let mut event = sample_event();
        event.state = state;
        event.started_at_ms = None;
        event.finished_at_ms = Some(event.occurred_at_ms);
        assert!(event.validate().is_ok());
        assert!(serde_json::to_value(event).is_ok());
    }
}

#[test]
fn nested_validation_errors_report_the_complete_object_path() {
    let mut snapshot = DashboardSnapshot {
        revision: 1,
        generated_at_ms: 1,
        scope: DashboardScope::Mesh,
        hosts: vec![sample_host()],
        activities: vec![ActivitySummary::from(&sample_event())],
        pending_approvals: vec![],
        warnings: vec![],
    };
    snapshot.hosts[0].devices[0].presence = Presence::Offline;
    snapshot.hosts[0].devices[0].freshness = Freshness::Unknown;
    assert_eq!(
        snapshot.validate().unwrap_err().path(),
        "hosts[0].devices[0].freshness"
    );

    snapshot.hosts[0].devices[0].presence = Presence::Online;
    snapshot.activities[0]
        .resources
        .push(ResourceClass::WorkspaceRead);
    assert_eq!(
        snapshot.validate().unwrap_err().path(),
        "activities[0].resources"
    );
}

#[test]
fn arbitrary_display_payloads_are_not_vetted_messages() {
    assert!(
        serde_json::from_value::<DisplayMessage>(json!("let customer_secret = workspace.read();"))
            .is_err()
    );
    assert!(
        serde_json::from_value::<DisplayMessage>(json!({
            "code":"activity_started", "params":["customer_secret"]
        }))
        .is_err()
    );
    assert!(SafeCode::parse("ToKeN : disguised-value").is_err());
}

#[test]
fn policy_rule_boolean_constraints_round_trip_and_missing_fields_are_wildcards() {
    let rule = PolicyRule {
        id: RuleId::parse("exact-booleans").unwrap(),
        revision: 1,
        effect: PolicyEffect::Allow,
        principal_id: None,
        source_host_id: None,
        target_host_id: None,
        device_id: None,
        operation: None,
        resources: vec![],
        expires_at_ms: None,
        require_user_presence: false,
        user_presence: Some(false),
        physical_device: Some(true),
        enabled: true,
        origin: PolicyOrigin::User,
    };
    let encoded = serde_json::to_value(&rule).unwrap();
    assert_eq!(encoded["require_user_presence"], false);
    assert_eq!(encoded["user_presence"], false);
    assert_eq!(encoded["physical_device"], true);
    assert_eq!(serde_json::from_value::<PolicyRule>(encoded).unwrap(), rule);

    let wildcard = serde_json::json!({
        "id": "wildcard-booleans",
        "revision": 1,
        "effect": "allow",
        "principal_id": null,
        "source_host_id": null,
        "target_host_id": null,
        "device_id": null,
        "operation": null,
        "resources": [],
        "expires_at_ms": null,
        "require_user_presence": false,
        "enabled": true,
        "origin": "user"
    });
    let wildcard: PolicyRule = serde_json::from_value(wildcard).unwrap();
    assert!(!wildcard.require_user_presence);
    assert_eq!(wildcard.user_presence, None);
    assert_eq!(wildcard.physical_device, None);

    for exact_presence in [false, true] {
        let mut redundant = rule.clone();
        redundant.require_user_presence = true;
        redundant.user_presence = Some(exact_presence);
        assert!(serde_json::to_value(&redundant).is_err());
        let mut encoded = serde_json::to_value(&wildcard).unwrap();
        encoded["require_user_presence"] = json!(true);
        encoded["user_presence"] = json!(exact_presence);
        assert!(serde_json::from_value::<PolicyRule>(encoded).is_err());
    }
}
