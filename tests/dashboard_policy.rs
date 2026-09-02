use device_development_mesh::dashboard::model::{
    ActivityId, ApprovalDecision, DeviceId, HostId, MAX_ID_BYTES, OperationId, PolicyEffect,
    PolicyOrigin, PolicyRule, PrincipalId, ResourceClass, RuleId,
};
use device_development_mesh::dashboard::policy::{
    AccessRequest, ApprovalError, PolicyDecision, PolicyEngine,
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
        enabled: true,
        origin: PolicyOrigin::User,
    }
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
            engine.evaluate(&req, NOW),
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
        engine.evaluate(&req, NOW),
        PolicyDecision::Allowed {
            rule_id: exact.id.clone()
        }
    );

    req.user_present = false;
    assert_eq!(
        engine.evaluate(&req, NOW),
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
        engine.evaluate(&req, NOW),
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
            engine.evaluate(&req, NOW),
            PolicyDecision::ApprovalRequired {
                reason: "fresh_target_confirmation".into()
            }
        );
    }
}

#[test]
fn only_an_explicit_matching_managed_rule_bypasses_high_risk_confirmation() {
    let req = request("debug.attach", vec![ResourceClass::Debugger]);
    let mut managed = rule("managed", PolicyEffect::Allow);
    managed.origin = PolicyOrigin::Managed;
    managed.operation = Some(req.operation.clone());
    managed.target_host_id = Some(req.target_host_id.clone());
    managed.resources = req.resources.clone();
    let engine = PolicyEngine::with_rules(vec![managed.clone()]).unwrap();
    assert_eq!(
        engine.evaluate(&req, NOW),
        PolicyDecision::Allowed {
            rule_id: managed.id
        }
    );
}

#[test]
fn pairing_without_an_access_rule_still_requires_approval() {
    let req = request("mesh.pair", vec![]);
    assert_eq!(
        PolicyEngine::new().evaluate(&req, NOW),
        PolicyDecision::ApprovalRequired {
            reason: "no_matching_rule".into()
        }
    );
}

#[test]
fn approval_nonce_is_exact_target_bounded_one_use_and_remember_is_least_privilege() {
    let req = request("workspace.write", vec![ResourceClass::WorkspaceWrite]);
    let mut engine = PolicyEngine::new();
    let approval = engine.create_approval(&req, NOW, 600_000).unwrap();
    assert_eq!(approval.expires_at_ms, NOW + 300_000);

    let wrong_target = engine.decide(
        &approval.nonce,
        &HostId::parse("windows-1").unwrap(),
        &req,
        ApprovalDecision::AllowOnce,
        NOW + 1,
    );
    assert_eq!(wrong_target, Err(ApprovalError::WrongTarget));

    let mut changed = req.clone();
    changed.operation = OperationId::parse("workspace.read").unwrap();
    assert_eq!(
        engine.decide(
            &approval.nonce,
            &req.target_host_id,
            &changed,
            ApprovalDecision::AllowOnce,
            NOW + 1
        ),
        Err(ApprovalError::RequestMismatch)
    );
    for changed in [
        AccessRequest {
            physical_device: true,
            ..req.clone()
        },
        AccessRequest {
            user_present: true,
            ..req.clone()
        },
    ] {
        assert_eq!(
            engine.decide(
                &approval.nonce,
                &req.target_host_id,
                &changed,
                ApprovalDecision::AllowOnce,
                NOW + 1,
            ),
            Err(ApprovalError::RequestMismatch)
        );
    }

    let outcome = engine
        .decide(
            &approval.nonce,
            &req.target_host_id,
            &req,
            ApprovalDecision::AllowAndRemember,
            NOW + 1,
        )
        .unwrap();
    let remembered = outcome.created_rule.unwrap();
    assert_eq!(remembered.effect, PolicyEffect::Allow);
    assert_eq!(remembered.principal_id.as_ref(), Some(&req.principal_id));
    assert_eq!(
        remembered.source_host_id.as_ref(),
        Some(&req.source_host_id)
    );
    assert_eq!(
        remembered.target_host_id.as_ref(),
        Some(&req.target_host_id)
    );
    assert_eq!(remembered.operation.as_ref(), Some(&req.operation));
    assert_eq!(remembered.resources, req.resources);
    assert_eq!(remembered.device_id, req.device_id);
    assert!(!remembered.require_user_presence);
    assert_eq!(remembered.user_presence, Some(false));
    assert_eq!(remembered.physical_device, Some(false));
    assert_eq!(
        engine.decide(
            &approval.nonce,
            &req.target_host_id,
            &req,
            ApprovalDecision::AllowOnce,
            NOW + 2
        ),
        Err(ApprovalError::AlreadyUsed)
    );
}

#[test]
fn exact_remembered_rules_do_not_spill_across_presence_or_physical_device() {
    for (user_present, physical_device) in [(false, false), (true, true)] {
        let mut req = request("workspace.write", vec![ResourceClass::WorkspaceWrite]);
        req.user_present = user_present;
        req.physical_device = physical_device;
        let mut engine = PolicyEngine::new();
        let approval = engine.create_approval(&req, NOW, 100).unwrap();
        let created = engine
            .decide(
                &approval.nonce,
                &req.target_host_id,
                &req,
                ApprovalDecision::AllowAndRemember,
                NOW + 1,
            )
            .unwrap()
            .created_rule
            .unwrap();
        assert!(!created.require_user_presence);
        assert_eq!(created.user_presence, Some(user_present));
        assert_eq!(created.physical_device, Some(physical_device));
        assert!(matches!(
            engine.evaluate(&req, NOW + 2),
            PolicyDecision::Allowed { .. }
        ));

        let mut opposite_presence = req.clone();
        opposite_presence.user_present = !user_present;
        assert_eq!(
            engine.evaluate(&opposite_presence, NOW + 2),
            PolicyDecision::ApprovalRequired {
                reason: "no_matching_rule".into()
            }
        );
        let mut opposite_physical = req.clone();
        opposite_physical.physical_device = !physical_device;
        assert_eq!(
            engine.evaluate(&opposite_physical, NOW + 2),
            PolicyDecision::ApprovalRequired {
                reason: "no_matching_rule".into()
            }
        );
    }
}

#[test]
fn expired_approval_is_rejected_and_deny_block_creates_exact_deny() {
    let mut req = request("device.install", vec![ResourceClass::ApplicationInstall]);
    req.device_id = Some(DeviceId::parse("iphone-1").unwrap());
    req.physical_device = true;
    let mut engine = PolicyEngine::new();
    let expired = engine.create_approval(&req, NOW, 1).unwrap();
    assert_eq!(
        engine.decide(
            &expired.nonce,
            &req.target_host_id,
            &req,
            ApprovalDecision::DenyOnce,
            NOW + 2
        ),
        Err(ApprovalError::Expired)
    );
    let approval = engine.create_approval(&req, NOW, 100).unwrap();
    let block = engine
        .decide(
            &approval.nonce,
            &req.target_host_id,
            &req,
            ApprovalDecision::DenyAndBlock,
            NOW + 1,
        )
        .unwrap()
        .created_rule
        .unwrap();
    assert_eq!(block.effect, PolicyEffect::Deny);
    assert_eq!(block.device_id, req.device_id);
    assert_eq!(block.resources, req.resources);
    assert!(!block.require_user_presence);
    assert_eq!(block.user_presence, Some(false));
    assert_eq!(block.physical_device, Some(true));
}

#[test]
fn exact_block_rules_do_not_deny_opposite_presence_or_physical_device() {
    let mut req = request("workspace.write", vec![ResourceClass::WorkspaceWrite]);
    req.user_present = true;
    req.physical_device = true;
    let mut engine = PolicyEngine::new();
    let approval = engine.create_approval(&req, NOW, 100).unwrap();
    engine
        .decide(
            &approval.nonce,
            &req.target_host_id,
            &req,
            ApprovalDecision::DenyAndBlock,
            NOW + 1,
        )
        .unwrap();

    let mut opposite_presence = req.clone();
    opposite_presence.user_present = false;
    assert_eq!(
        engine.evaluate(&opposite_presence, NOW + 2),
        PolicyDecision::ApprovalRequired {
            reason: "no_matching_rule".into()
        }
    );
    let mut opposite_physical = req;
    opposite_physical.physical_device = false;
    assert_eq!(
        engine.evaluate(&opposite_physical, NOW + 2),
        PolicyDecision::ApprovalRequired {
            reason: "no_matching_rule".into()
        }
    );
}

#[test]
fn legacy_presence_false_is_wildcard_and_true_requires_presence() {
    let mut req = request("workspace.read", vec![ResourceClass::WorkspaceRead]);
    let mut legacy = rule("legacy", PolicyEffect::Allow);
    legacy.require_user_presence = false;
    let wildcard = PolicyEngine::with_rules(vec![legacy.clone()]).unwrap();
    assert!(matches!(
        wildcard.evaluate(&req, NOW),
        PolicyDecision::Allowed { .. }
    ));
    req.user_present = true;
    assert!(matches!(
        wildcard.evaluate(&req, NOW),
        PolicyDecision::Allowed { .. }
    ));

    legacy.require_user_presence = true;
    let required = PolicyEngine::with_rules(vec![legacy]).unwrap();
    req.user_present = false;
    assert_eq!(
        required.evaluate(&req, NOW),
        PolicyDecision::ApprovalRequired {
            reason: "no_matching_rule".into()
        }
    );
    req.user_present = true;
    assert!(matches!(
        required.evaluate(&req, NOW),
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
        engine.evaluate(&req, NOW),
        PolicyDecision::Allowed { rule_id: exact.id }
    );
}

#[test]
fn approval_expires_at_its_expiry_boundary() {
    let req = request("workspace.read", vec![ResourceClass::WorkspaceRead]);
    let mut engine = PolicyEngine::new();
    let approval = engine.create_approval(&req, NOW, 10).unwrap();
    assert_eq!(
        engine.decide(
            &approval.nonce,
            &req.target_host_id,
            &req,
            ApprovalDecision::AllowOnce,
            NOW + 10,
        ),
        Err(ApprovalError::Expired)
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
                engine.evaluate(&req, NOW),
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
