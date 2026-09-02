use device_development_mesh::dashboard::managed_policy::{
    ManagedPolicyFile, ManagedPolicyLoadError, ManagedPolicyStore, PolicyAdminTrustEntry,
    PolicyAdminTrustFile, PolicyAdminTrustStore, canonical_rules_digest,
};
use device_development_mesh::dashboard::{
    HostId, OperationId, PolicyEffect, PolicyOrigin, PolicyRule, ResourceClass, RuleId,
    audit::{AuditStore, Redactor, RetentionPolicy},
    event_log::EventJournal,
    policy::PolicyEngine,
    service::{DashboardService, DashboardServiceError},
    topology::TopologyProjector,
};
use device_development_mesh::secure_transport::SecureTransport;
use std::sync::{Arc, Mutex};

fn managed_rule() -> PolicyRule {
    PolicyRule {
        id: RuleId::parse("managed-debug").unwrap(),
        revision: 1,
        effect: PolicyEffect::Allow,
        principal_id: None,
        source_host_id: None,
        target_host_id: None,
        device_id: None,
        operation: Some(OperationId::parse("debug.attach").unwrap()),
        resources: vec![ResourceClass::Debugger],
        expires_at_ms: None,
        require_user_presence: false,
        user_presence: None,
        physical_device: None,
        match_device_exact: false,
        match_resources_exact: true,
        enabled: true,
        origin: PolicyOrigin::Managed,
    }
}

fn secure_file(_path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn verified_engine(root: &std::path::Path, rules: Vec<PolicyRule>) -> PolicyEngine {
    let signer = SecureTransport::load_or_create(root.join("signer"), "signer").unwrap();
    let path = root.join("signer").join("managed.json");
    let trust_path = root.join("signer").join("admins.json");
    std::fs::write(
        &path,
        serde_json::to_vec(&ManagedPolicyFile {
            signer_id: "signer".into(),
            signature: signer
                .sign(&canonical_rules_digest(&rules).unwrap())
                .unwrap(),
            rules,
        })
        .unwrap(),
    )
    .unwrap();
    secure_file(&path);
    let trust = write_admin_trust(
        &trust_path,
        vec![PolicyAdminTrustEntry {
            signer_id: "signer".into(),
            certificate_der: signer.certificate_der().to_vec(),
            role: "policy_signer".into(),
            revoked: false,
        }],
    );
    let bundle = ManagedPolicyStore::load(&path, &trust).unwrap();
    let mut engine = PolicyEngine::new();
    engine.add_verified_managed_rules(bundle).unwrap();
    engine
}

fn admin_rule(id: &str, effect: PolicyEffect, origin: PolicyOrigin) -> PolicyRule {
    PolicyRule {
        id: RuleId::parse(id).unwrap(),
        revision: 1,
        effect,
        principal_id: Some(
            device_development_mesh::dashboard::PrincipalId::parse("local-user").unwrap(),
        ),
        source_host_id: Some(HostId::parse("mac").unwrap()),
        target_host_id: Some(HostId::parse("mac").unwrap()),
        device_id: None,
        operation: Some(OperationId::parse("devicelane.policy.put").unwrap()),
        resources: vec![ResourceClass::DeviceLanePolicy],
        expires_at_ms: None,
        require_user_presence: false,
        user_presence: None,
        physical_device: None,
        match_device_exact: true,
        match_resources_exact: true,
        enabled: true,
        origin,
    }
}

fn service(root: &std::path::Path, engine: PolicyEngine) -> DashboardService {
    DashboardService::new(
        HostId::parse("mac").unwrap(),
        TopologyProjector::new(),
        EventJournal::new(1, 0),
        Arc::new(Mutex::new(
            AuditStore::open(
                root.join("audit"),
                RetentionPolicy::default(),
                Redactor::default(),
            )
            .unwrap(),
        )),
        engine,
    )
}

#[test]
fn verified_managed_admin_allow_is_unattended_but_deny_still_dominates() {
    let allowed_root = tempfile::tempdir().unwrap();
    let mut allowed = service(
        allowed_root.path(),
        verified_engine(
            allowed_root.path(),
            vec![admin_rule(
                "managed-allow",
                PolicyEffect::Allow,
                PolicyOrigin::Managed,
            )],
        ),
    );
    assert_eq!(
        allowed.put_policy_rule(
            admin_rule("candidate", PolicyEffect::Allow, PolicyOrigin::User),
            10
        ),
        Ok(())
    );

    let denied_root = tempfile::tempdir().unwrap();
    let mut engine = verified_engine(
        denied_root.path(),
        vec![admin_rule(
            "managed-allow",
            PolicyEffect::Allow,
            PolicyOrigin::Managed,
        )],
    );
    engine
        .put_user_rule(admin_rule(
            "user-deny",
            PolicyEffect::Deny,
            PolicyOrigin::User,
        ))
        .unwrap();
    let mut denied = service(denied_root.path(), engine);
    assert_eq!(
        denied.put_policy_rule(
            admin_rule("candidate", PolicyEffect::Allow, PolicyOrigin::User),
            10
        ),
        Err(DashboardServiceError::PermissionDenied)
    );
}

fn write_admin_trust(
    path: &std::path::Path,
    entries: Vec<PolicyAdminTrustEntry>,
) -> PolicyAdminTrustStore {
    std::fs::write(
        path,
        serde_json::to_vec(&PolicyAdminTrustFile { signers: entries }).unwrap(),
    )
    .unwrap();
    secure_file(path);
    PolicyAdminTrustStore::load(path, ["S-1-5-32-544".into()]).unwrap()
}

#[test]
fn signed_owned_bundle_loads_and_untrusted_or_tampered_bundle_is_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let signer = SecureTransport::load_or_create(temp.path().join("signer"), "signer").unwrap();
    let mut paired_peer =
        SecureTransport::load_or_create(temp.path().join("verifier"), "verifier").unwrap();
    paired_peer
        .trust("signer", signer.certificate_der())
        .unwrap();
    let rules = vec![managed_rule()];
    let digest = canonical_rules_digest(&rules).unwrap();
    let signature = signer.sign(&digest).unwrap();
    let path = temp.path().join("verifier").join("managed-policy.json");
    let trust_path = temp.path().join("verifier").join("policy-admins.json");
    std::fs::write(
        &path,
        serde_json::to_vec(&ManagedPolicyFile {
            signer_id: "signer".into(),
            rules: rules.clone(),
            signature: signature.clone(),
        })
        .unwrap(),
    )
    .unwrap();
    secure_file(&path);
    let empty_trust = write_admin_trust(&trust_path, Vec::new());
    assert!(matches!(
        ManagedPolicyStore::load(&path, &empty_trust),
        Err(ManagedPolicyLoadError::SignerNotAuthorized)
    ));
    let admin_trust = write_admin_trust(
        &trust_path,
        vec![PolicyAdminTrustEntry {
            signer_id: "signer".into(),
            certificate_der: signer.certificate_der().to_vec(),
            role: "policy_signer".into(),
            revoked: false,
        }],
    );
    let verified = ManagedPolicyStore::load(&path, &admin_trust).unwrap();
    let mut user_deny = managed_rule();
    user_deny.id = RuleId::parse("user-deny").unwrap();
    user_deny.effect = PolicyEffect::Deny;
    user_deny.origin = PolicyOrigin::User;
    let mut engine = PolicyEngine::with_rules(vec![user_deny]).unwrap();
    engine.add_verified_managed_rules(verified).unwrap();
    assert_eq!(engine.rules().len(), 2);

    let mut tampered: ManagedPolicyFile =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    tampered.rules[0].revision += 1;
    std::fs::write(&path, serde_json::to_vec(&tampered).unwrap()).unwrap();
    secure_file(&path);
    assert!(matches!(
        ManagedPolicyStore::load(&path, &admin_trust),
        Err(ManagedPolicyLoadError::InvalidSignature)
    ));

    std::fs::write(
        &path,
        serde_json::to_vec(&ManagedPolicyFile {
            signer_id: "signer".into(),
            rules,
            signature,
        })
        .unwrap(),
    )
    .unwrap();
    secure_file(&path);
    let revoked = write_admin_trust(
        &trust_path,
        vec![PolicyAdminTrustEntry {
            signer_id: "signer".into(),
            certificate_der: signer.certificate_der().to_vec(),
            role: "policy_signer".into(),
            revoked: true,
        }],
    );
    assert!(matches!(
        ManagedPolicyStore::load(&path, &revoked),
        Err(ManagedPolicyLoadError::SignerNotAuthorized)
    ));

    let rotated = SecureTransport::load_or_create(temp.path().join("rotated"), "rotated").unwrap();
    let rotated_trust = write_admin_trust(
        &trust_path,
        vec![PolicyAdminTrustEntry {
            signer_id: "rotated".into(),
            certificate_der: rotated.certificate_der().to_vec(),
            role: "policy_signer".into(),
            revoked: false,
        }],
    );
    assert!(matches!(
        ManagedPolicyStore::load(&path, &rotated_trust),
        Err(ManagedPolicyLoadError::SignerNotAuthorized)
    ));
}

#[test]
#[cfg(unix)]
fn permissive_bundle_permissions_are_rejected_before_signature_verification() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let identity =
        SecureTransport::load_or_create(temp.path().join("identity"), "identity").unwrap();
    let path = temp.path().join("identity").join("managed-policy.json");
    std::fs::write(&path, b"{}").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        ManagedPolicyStore::load(
            &path,
            &write_admin_trust(
                &temp.path().join("identity").join("admins.json"),
                vec![PolicyAdminTrustEntry {
                    signer_id: "identity".into(),
                    certificate_der: identity.certificate_der().to_vec(),
                    role: "policy_signer".into(),
                    revoked: false,
                }]
            )
        ),
        Err(ManagedPolicyLoadError::InsecureOwnerOrPermissions)
    ));
}
