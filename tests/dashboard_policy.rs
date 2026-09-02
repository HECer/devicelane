use device_development_mesh::dashboard::model::{
    ActivityId, DeviceId, HostId, MAX_ID_BYTES, OperationId, PolicyEffect, PolicyOrigin,
    PolicyRule, PrincipalId, ResourceClass, RuleId,
};
use device_development_mesh::dashboard::policy::{
    AccessRequest, ApprovalError, MAX_PENDING_APPROVALS, MAX_POLICY_RULES,
    PolicyConfigurationError, PolicyDecision, PolicyEngine, PolicyError,
};

const NOW: u64 = 1_000_000;

fn request(operation: &str, resources: Vec<ResourceClass>) -> AccessRequest {
    AccessRequest {
        activity_id: ActivityId::parse("activity-1").unwrap(),
        principal_id: PrincipalId::parse("agent-1").unwrap(),
        source_host_id: HostId::parse("windows-1").unwrap(),
        target_host_id: HostId::parse("mac-1").unwrap(),
        device_id: None,
        operation: OperationId::parse(operation).unwrap(),
        resources,
        physical_device: false,
        user_present: false,
    }
}

fn rule(id: &str, effect: PolicyEffect) -> PolicyRule {
    PolicyRule {
        id: RuleId::parse(id).unwrap(),
        revision: 1,
        effect,
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
    }
}

fn evaluate(engine: &PolicyEngine, request: &AccessRequest, now_ms: u64) -> PolicyDecision {
    engine.evaluate(request, now_ms).unwrap()
}

#[test]
fn deny_overrides_more_specific_allow_regardless_of_order() {
    let req = request("workspace.read", vec![ResourceClass::WorkspaceRead]);
    let deny = rule("deny", PolicyEffect::Deny);
    let mut allow = rule("allow", PolicyEffect::Allow);
    allow.principal_id = Some(req.principal_id.clone());
    allow.source_host_id = Some(req.source_host_id.clone());
    allow.target_host_id = Some(req.target_host_id.clone());
    allow.operation = Some(req.operation.clone());
    allow.resources = req.resources.clone();

    for rules in [
        vec![allow.clone(), deny.clone()],
        vec![deny.clone(), allow.clone()],
    ] {
        let engine = PolicyEngine::with_rules(rules).unwrap();
        assert_eq!(
            evaluate(&engine, &req, NOW),
            PolicyDecision::Denied {
                rule_id: deny.id.clone()
            }
        );
    }
}

#[test]
fn matching_covers_all_scopes_presence_expiry_and_disabled_rules() {
    let mut req = request("device.logs", vec![ResourceClass::DeviceLease]);
    req.device_id = Some(DeviceId::parse("iphone-1").unwrap());
    req.user_present = true;
    let mut exact = rule("exact", PolicyEffect::Allow);
    exact.revision = 7;
    exact.principal_id = Some(req.principal_id.clone());
    exact.source_host_id = Some(req.source_host_id.clone());
    exact.target_host_id = Some(req.target_host_id.clone());
    exact.device_id = req.device_id.clone();
    exact.operation = Some(req.operation.clone());
    exact.resources = req.resources.clone();
    exact.expires_at_ms = Some(NOW + 1);
    exact.require_user_presence = true;

    let mut expired = exact.clone();
    expired.id = RuleId::parse("expired").unwrap();
    expired.effect = PolicyEffect::Deny;
    expired.expires_at_ms = Some(NOW);
    let mut disabled = exact.clone();
    disabled.id = RuleId::parse("disabled").unwrap();
    disabled.effect = PolicyEffect::Deny;
    disabled.enabled = false;

    let engine = PolicyEngine::with_rules(vec![expired, disabled, exact.clone()]).unwrap();
    assert_eq!(
        evaluate(&engine, &req, NOW),
        PolicyDecision::Allowed {
            rule_id: exact.id.clone()
        }
    );

    req.user_present = false;
    assert_eq!(
        evaluate(&engine, &req, NOW),
        PolicyDecision::ApprovalRequired {
            reason: "no_matching_rule".into()
        }
    );
}

#[test]
fn newest_revision_breaks_equal_specificity_ties_within_effect() {
    let req = request("workspace.read", vec![ResourceClass::WorkspaceRead]);
    let mut old = rule("old", PolicyEffect::Allow);
    old.operation = Some(req.operation.clone());
    let mut new = old.clone();
    new.id = RuleId::parse("new").unwrap();
    new.revision = 2;
    let engine = PolicyEngine::with_rules(vec![new.clone(), old]).unwrap();
    assert_eq!(
        evaluate(&engine, &req, NOW),
        PolicyDecision::Allowed { rule_id: new.id }
    );
}

#[test]
fn every_high_risk_class_requires_fresh_target_confirmation() {
    let cases = [
        ("debug.attach", vec![ResourceClass::Debugger], false),
        ("sign.create", vec![ResourceClass::Signing], false),
        ("keychain.read", vec![], false),
        ("screen.capture", vec![ResourceClass::ScreenCapture], false),
        ("microphone.capture", vec![ResourceClass::Microphone], false),
        (
            "device.install",
            vec![ResourceClass::ApplicationInstall],
            true,
        ),
        ("devicelane.policy.put", vec![], false),
        ("devicelane.service.restart", vec![], false),
    ];
    for (operation, resources, physical_device) in cases {
        let mut req = request(operation, resources);
        req.physical_device = physical_device;
        let mut ordinary_allow = rule("user-allow", PolicyEffect::Allow);
        ordinary_allow.operation = Some(req.operation.clone());
        let engine = PolicyEngine::with_rules(vec![ordinary_allow]).unwrap();
        assert_eq!(
            evaluate(&engine, &req, NOW),
            PolicyDecision::ApprovalRequired {
                reason: "fresh_target_confirmation".into()
            }
        );
    }
}

#[test]
fn unverified_managed_rules_are_rejected_at_the_public_boundary() {
    let req = request("debug.attach", vec![ResourceClass::Debugger]);
    let mut managed = rule("managed", PolicyEffect::Allow);
    managed.origin = PolicyOrigin::Managed;
    managed.operation = Some(req.operation.clone());
    managed.target_host_id = Some(req.target_host_id.clone());
    managed.resources = req.resources.clone();
    assert_eq!(
        PolicyEngine::with_rules(vec![managed]).unwrap_err(),
        PolicyConfigurationError::ManagedOriginRequiresVerification
    );
}

#[test]
fn additive_exact_flags_distinguish_absent_device_and_empty_resources_from_wildcards() {
    let req = request("metadata.read", vec![]);
    let mut exact = rule("exact-empty", PolicyEffect::Allow);
    exact.match_device_exact = true;
    exact.match_resources_exact = true;
    let engine = PolicyEngine::with_rules(vec![exact.clone()]).unwrap();
    assert_eq!(
        evaluate(&engine, &req, NOW),
        PolicyDecision::Allowed { rule_id: exact.id }
    );

    let mut with_device = req.clone();
    with_device.device_id = Some(DeviceId::parse("phone").unwrap());
    assert_eq!(
        evaluate(&engine, &with_device, NOW),
        PolicyDecision::ApprovalRequired {
            reason: "no_matching_rule".into()
        }
    );
    let mut with_resource = req;
    with_resource.resources = vec![ResourceClass::WorkspaceRead];
    assert_eq!(
        evaluate(&engine, &with_resource, NOW),
        PolicyDecision::ApprovalRequired {
            reason: "no_matching_rule".into()
        }
    );
}

#[test]
fn policy_and_pending_approval_collections_are_hard_bounded() {
    let rules = (0..MAX_POLICY_RULES)
        .map(|index| rule(&format!("rule-{index}"), PolicyEffect::Allow))
        .collect::<Vec<_>>();
    assert!(PolicyEngine::with_rules(rules.clone()).is_ok());
    let mut too_many = rules;
    too_many.push(rule("overflow", PolicyEffect::Allow));
    assert_eq!(
        PolicyEngine::with_rules(too_many).unwrap_err(),
        PolicyConfigurationError::RuleLimitExceeded
    );
    let duplicate = rule("duplicate", PolicyEffect::Allow);
    assert_eq!(
        PolicyEngine::with_rules(vec![duplicate.clone(), duplicate]).unwrap_err(),
        PolicyConfigurationError::DuplicateRuleId
    );

    let mut engine = PolicyEngine::new();
    for index in 0..MAX_PENDING_APPROVALS {
        let mut req = request("workspace.read", vec![ResourceClass::WorkspaceRead]);
        req.activity_id = ActivityId::parse(format!("activity-{index}")).unwrap();
        engine.create_approval(&req, NOW, 100).unwrap();
    }
    assert_eq!(
        engine.create_approval(
            &request("workspace.read", vec![ResourceClass::WorkspaceRead]),
            NOW,
            100
        ),
        Err(ApprovalError::ApprovalLimitExceeded)
    );
    assert!(
        engine
            .create_approval(
                &request("workspace.read", vec![ResourceClass::WorkspaceRead]),
                NOW + 100,
                100
            )
            .is_ok()
    );
}

#[test]
fn pairing_without_an_access_rule_still_requires_approval() {
    let req = request("mesh.pair", vec![]);
    assert_eq!(
        evaluate(&PolicyEngine::new(), &req, NOW),
        PolicyDecision::ApprovalRequired {
            reason: "no_matching_rule".into()
        }
    );
}

#[test]
fn approval_nonce_is_bounded_to_five_minutes() {
    let req = request("workspace.write", vec![ResourceClass::WorkspaceWrite]);
    let mut engine = PolicyEngine::new();
    let approval = engine.create_approval(&req, NOW, 600_000).unwrap();
    assert_eq!(approval.expires_at_ms, NOW + 300_000);
}

#[test]
fn legacy_presence_false_is_wildcard_and_true_requires_presence() {
    let mut req = request("workspace.read", vec![ResourceClass::WorkspaceRead]);
    let mut legacy = rule("legacy", PolicyEffect::Allow);
    legacy.require_user_presence = false;
    let wildcard = PolicyEngine::with_rules(vec![legacy.clone()]).unwrap();
    assert!(matches!(
        evaluate(&wildcard, &req, NOW),
        PolicyDecision::Allowed { .. }
    ));
    req.user_present = true;
    assert!(matches!(
        evaluate(&wildcard, &req, NOW),
        PolicyDecision::Allowed { .. }
    ));

    legacy.require_user_presence = true;
    let required = PolicyEngine::with_rules(vec![legacy]).unwrap();
    req.user_present = false;
    assert_eq!(
        evaluate(&required, &req, NOW),
        PolicyDecision::ApprovalRequired {
            reason: "no_matching_rule".into()
        }
    );
    req.user_present = true;
    assert!(matches!(
        evaluate(&required, &req, NOW),
        PolicyDecision::Allowed { .. }
    ));
}

#[test]
fn legacy_and_exact_presence_have_equal_specificity_and_revision_wins() {
    let mut req = request("workspace.read", vec![ResourceClass::WorkspaceRead]);
    req.user_present = true;
    let mut legacy = rule("legacy-presence", PolicyEffect::Allow);
    legacy.require_user_presence = true;
    legacy.revision = 1;
    let mut exact = rule("exact-presence", PolicyEffect::Allow);
    exact.user_presence = Some(true);
    exact.revision = 2;
    let engine = PolicyEngine::with_rules(vec![legacy, exact.clone()]).unwrap();
    assert_eq!(
        evaluate(&engine, &req, NOW),
        PolicyDecision::Allowed { rule_id: exact.id }
    );
}

#[test]
fn rule_permutations_preserve_deny_dominance_and_allow_selection() {
    let req = request("workspace.read", vec![ResourceClass::WorkspaceRead]);
    let mut wildcard_allow = rule("allow-wild", PolicyEffect::Allow);
    wildcard_allow.revision = 99;
    let mut exact_allow = rule("allow-exact", PolicyEffect::Allow);
    exact_allow.operation = Some(req.operation.clone());
    exact_allow.revision = 2;
    let mut deny = rule("deny", PolicyEffect::Deny);
    deny.target_host_id = Some(req.target_host_id.clone());
    let rules = [wildcard_allow, exact_allow, deny.clone()];

    for first in 0..rules.len() {
        for second in 0..rules.len() {
            if second == first {
                continue;
            }
            let third = (0..rules.len())
                .find(|index| *index != first && *index != second)
                .unwrap();
            let engine = PolicyEngine::with_rules(vec![
                rules[first].clone(),
                rules[second].clone(),
                rules[third].clone(),
            ])
            .unwrap();
            assert_eq!(
                evaluate(&engine, &req, NOW),
                PolicyDecision::Denied {
                    rule_id: deny.id.clone()
                }
            );
        }
    }
}

#[test]
fn raw_identifier_length_is_rejected_before_whitespace_normalization() {
    let raw = format!("{}x", " ".repeat(MAX_ID_BYTES));
    let error = HostId::parse(raw).unwrap_err();
    assert_eq!(error.code(), "id_too_long");
}

#[test]
fn malformed_resource_json_is_rejected_before_any_execution_layer() {
    let json = r#"{"activity_id":"a","principal_id":"p","source_host_id":"s","target_host_id":"t","device_id":null,"operation":"op","resources":["shell_command"],"physical_device":false,"user_present":false}"#;
    assert!(serde_json::from_str::<AccessRequest>(json).is_err());
}

#[test]
fn invalid_access_requests_cannot_serialize_deserialize_or_evaluate() {
    let duplicate = request(
        "workspace.read",
        vec![ResourceClass::WorkspaceRead, ResourceClass::WorkspaceRead],
    );
    assert!(serde_json::to_value(&duplicate).is_err());
    assert_eq!(
        PolicyEngine::new().evaluate(&duplicate, NOW),
        Err(PolicyError::InvalidRequest)
    );
    let oversized = request("workspace.read", vec![ResourceClass::WorkspaceRead; 129]);
    assert!(serde_json::to_value(&oversized).is_err());

    let duplicate_json = r#"{"activity_id":"a","principal_id":"p","source_host_id":"s","target_host_id":"t","device_id":null,"operation":"op","resources":["workspace_read","workspace_read"],"physical_device":false,"user_present":false}"#;
    assert!(serde_json::from_str::<AccessRequest>(duplicate_json).is_err());
}
