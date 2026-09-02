use device_development_mesh::dashboard::managed_policy::{
    ManagedPolicyFile, ManagedPolicyLoadError, ManagedPolicyStore, PolicyAdminTrustEntry,
    PolicyAdminTrustFile, PolicyAdminTrustStore, canonical_rules_digest,
};
use device_development_mesh::dashboard::{
    OperationId, PolicyEffect, PolicyOrigin, PolicyRule, ResourceClass, RuleId,
    policy::PolicyEngine,
};
use device_development_mesh::secure_transport::SecureTransport;

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
