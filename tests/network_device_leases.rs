use device_development_mesh::{
    network_processes::{LeaseGrant, LeaseRequest},
    secure_transport::SecureTransport,
};

#[test]
fn registry_lease_grants_are_signed_and_job_bound() {
    let root = tempfile::tempdir().unwrap();
    let registry_root = root.path().join("registry");
    let agent_root = root.path().join("agent");
    let registry = SecureTransport::load_or_create(&registry_root, "registry").unwrap();
    let mut agent = SecureTransport::load_or_create(&agent_root, "agent").unwrap();
    agent.trust("registry", registry.certificate_der()).unwrap();
    let mut grant = LeaseGrant {
        lease_id: "lease-1".into(),
        device_id: "iphone-1".into(),
        client_id: "client-a".into(),
        job_id: "job-1".into(),
        expires_at_ms: 1000,
        signature: Vec::new(),
    };
    grant.signature = registry.sign(&grant.signed_payload()).unwrap();

    assert_eq!(grant.job_id, "job-1");
    assert!(
        agent
            .verify_peer_signature("registry", &grant.signed_payload(), &grant.signature)
            .is_ok()
    );
    grant.job_id = "job-2".into();
    assert!(
        agent
            .verify_peer_signature("registry", &grant.signed_payload(), &grant.signature)
            .is_err()
    );
    assert!(matches!(
        LeaseRequest::Acquire {
            device_id: "iphone-1".into(),
            lifetime_ms: 1000,
        },
        LeaseRequest::Acquire { .. }
    ));
}
