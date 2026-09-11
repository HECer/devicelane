use device_development_mesh::controller_session::{
    ControllerSessionError, ControllerSessionReplayCache, current_os_principal,
    issue_controller_session, issue_mesh_approval, sign_mesh_access_claim,
    verify_and_consume_controller_session, verify_controller_session, verify_mesh_approval,
};
use device_development_mesh::dashboard::policy::{AccessRequest, RemoteOperationGrant};
use device_development_mesh::dashboard::{
    ActivityId, DeviceId, HostId, OperationId, PrincipalId, ResourceClass,
};
use device_development_mesh::remote_apple_protocol::AppleOperation;
use device_development_mesh::secure_transport::SecureTransport;
use std::process::Command;

#[test]
fn signed_controller_session_derives_identity_and_rejects_endpoint_or_payload_mismatch() {
    let root = tempfile::tempdir().unwrap();
    let controller_root = root.path().join("controller");
    let verifier_root = root.path().join("mac-agent");
    let mut controller =
        SecureTransport::load_or_create(&controller_root, "windows-controller").unwrap();
    let mut verifier = SecureTransport::load_or_create(&verifier_root, "mac-agent").unwrap();
    controller
        .trust("mac-agent", verifier.certificate_der())
        .unwrap();
    verifier
        .trust("windows-controller", controller.certificate_der())
        .unwrap();

    let assertion = issue_controller_session(
        &controller,
        "192.168.0.61:7443",
        "challenge-from-mac",
        1_000,
        60_000,
    )
    .unwrap();
    let verified = verify_controller_session(
        &verifier,
        &assertion,
        "192.168.0.61:7443",
        "windows-controller",
        "challenge-from-mac",
        2_000,
    )
    .unwrap();
    assert_eq!(verified.controller_peer_id, "windows-controller");
    assert_eq!(verified.source_host_id, "windows-controller");
    assert!(!verified.principal_id.is_empty());
    assert!(!verified.session_id.is_empty());

    assert_eq!(
        verify_controller_session(
            &verifier,
            &assertion,
            "192.168.0.99:7443",
            "windows-controller",
            "challenge-from-mac",
            2_000,
        ),
        Err(ControllerSessionError::ControllerEndpointMismatch)
    );

    let mut tampered = assertion;
    tampered.payload.principal_id.push_str("-spoofed");
    assert_eq!(
        verify_controller_session(
            &verifier,
            &tampered,
            "192.168.0.61:7443",
            "windows-controller",
            "challenge-from-mac",
            2_000,
        ),
        Err(ControllerSessionError::InvalidSignature)
    );
}

#[test]
fn unified_cli_verifies_only_the_signed_remote_session_values() {
    let root = tempfile::tempdir().unwrap();
    let controller_root = root.path().join("controller");
    let verifier_root = root.path().join("mac-agent");
    let controller =
        SecureTransport::load_or_create(&controller_root, "windows-controller").unwrap();
    let mut verifier = SecureTransport::load_or_create(&verifier_root, "mac-agent").unwrap();
    verifier
        .trust("windows-controller", controller.certificate_der())
        .unwrap();
    let assertion_path = root.path().join("controller-session.json");
    let binary = env!("CARGO_BIN_EXE_devicelane");
    let issued = Command::new(binary)
        .args([
            "controller-session",
            "issue",
            "--identity",
            controller_root.to_str().unwrap(),
            "--mesh-controller",
            "192.168.0.61:7443",
            "--challenge",
            "fresh-mac-challenge",
            "--lifetime-ms",
            "60000",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        issued.status.success(),
        "{}",
        String::from_utf8_lossy(&issued.stderr)
    );
    std::fs::write(&assertion_path, &issued.stdout).unwrap();

    let verified = Command::new(binary)
        .args([
            "controller-session",
            "verify",
            "--identity",
            verifier_root.to_str().unwrap(),
            "--assertion",
            assertion_path.to_str().unwrap(),
            "--mesh-controller",
            "192.168.0.61:7443",
            "--controller-peer-id",
            "windows-controller",
            "--challenge",
            "fresh-mac-challenge",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        verified.status.success(),
        "{}",
        String::from_utf8_lossy(&verified.stderr)
    );
    let derived: serde_json::Value = serde_json::from_slice(&verified.stdout).unwrap();
    assert_eq!(derived["controller_peer_id"], "windows-controller");
    assert_eq!(derived["source_host_id"], "windows-controller");
    assert!(
        derived["principal_id"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
    );

    let replay_cache = verifier_root.join("controller-session-replay.json");
    let consumed = Command::new(binary)
        .args([
            "controller-session",
            "consume",
            "--identity",
            verifier_root.to_str().unwrap(),
            "--assertion",
            assertion_path.to_str().unwrap(),
            "--mesh-controller",
            "192.168.0.61:7443",
            "--controller-peer-id",
            "windows-controller",
            "--challenge",
            "fresh-mac-challenge",
            "--replay-cache",
            replay_cache.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        consumed.status.success(),
        "{}",
        String::from_utf8_lossy(&consumed.stderr)
    );
    let replayed = Command::new(binary)
        .args([
            "controller-session",
            "consume",
            "--identity",
            verifier_root.to_str().unwrap(),
            "--assertion",
            assertion_path.to_str().unwrap(),
            "--mesh-controller",
            "192.168.0.61:7443",
            "--controller-peer-id",
            "windows-controller",
            "--challenge",
            "fresh-mac-challenge",
            "--replay-cache",
            replay_cache.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(!replayed.status.success());
    assert!(String::from_utf8_lossy(&replayed.stderr).contains("ReplayDetected"));

    let mismatched = Command::new(binary)
        .args([
            "controller-session",
            "verify",
            "--identity",
            verifier_root.to_str().unwrap(),
            "--assertion",
            assertion_path.to_str().unwrap(),
            "--mesh-controller",
            "192.168.0.99:7443",
            "--controller-peer-id",
            "windows-controller",
            "--challenge",
            "fresh-mac-challenge",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(!mismatched.status.success());
    assert!(String::from_utf8_lossy(&mismatched.stderr).contains("ControllerEndpointMismatch"));
}

#[test]
fn registry_attests_the_signed_os_principal_and_exact_access_for_the_target() {
    let root = tempfile::tempdir().unwrap();
    let mut registry =
        SecureTransport::load_or_create(root.path().join("registry"), "registry").unwrap();
    let mut windows =
        SecureTransport::load_or_create(root.path().join("windows-client"), "windows-client")
            .unwrap();
    let mut target =
        SecureTransport::load_or_create(root.path().join("mac-target"), "mac-target").unwrap();
    registry
        .trust("windows-client", windows.certificate_der())
        .unwrap();
    windows
        .trust("registry", registry.certificate_der())
        .unwrap();
    target
        .trust("registry", registry.certificate_der())
        .unwrap();
    let access = AccessRequest {
        activity_id: ActivityId::parse("signed-mesh-access").unwrap(),
        principal_id: PrincipalId::parse("spoofed-before-signing").unwrap(),
        source_host_id: HostId::parse("spoofed-before-signing").unwrap(),
        target_host_id: HostId::parse("mac-target").unwrap(),
        device_id: Some(DeviceId::parse("iphone-1").unwrap()),
        operation: OperationId::parse("workspace.read").unwrap(),
        resources: vec![ResourceClass::WorkspaceRead, ResourceClass::DeviceLease],
        remote_operation: None,
        physical_device: true,
        user_present: true,
    };
    let (claim, client_signature) = sign_mesh_access_claim(&windows, access).unwrap();
    assert_eq!(
        claim.access.principal_id.as_str(),
        current_os_principal().unwrap()
    );
    assert_eq!(claim.access.source_host_id.as_str(), "windows-client");
    let assertion = issue_mesh_approval(
        &registry,
        "windows-client",
        claim.clone(),
        &client_signature,
        1_000,
        60_000,
    )
    .unwrap();
    let verified = verify_mesh_approval(
        &target,
        &assertion,
        "registry",
        &HostId::parse("mac-target").unwrap(),
        2_000,
    )
    .unwrap();
    assert_eq!(verified, claim.access);

    let mut spoofed_claim = claim;
    spoofed_claim.os_principal_id = "spoofed-after-signing".into();
    spoofed_claim.access.principal_id = PrincipalId::parse("spoofed-after-signing").unwrap();
    assert_eq!(
        issue_mesh_approval(
            &registry,
            "windows-client",
            spoofed_claim,
            &client_signature,
            1_000,
            60_000,
        ),
        Err(ControllerSessionError::InvalidSignature)
    );
    let mut tampered_assertion = assertion;
    tampered_assertion.payload.access.operation = OperationId::parse("workspace.write").unwrap();
    assert_eq!(
        verify_mesh_approval(
            &target,
            &tampered_assertion,
            "registry",
            &HostId::parse("mac-target").unwrap(),
            2_000,
        ),
        Err(ControllerSessionError::InvalidSignature)
    );
}

#[test]
fn signed_access_binds_the_exact_remote_install_envelope_and_canonical_digest() {
    let root = tempfile::tempdir().unwrap();
    let mut registry =
        SecureTransport::load_or_create(root.path().join("registry"), "registry").unwrap();
    let windows =
        SecureTransport::load_or_create(root.path().join("windows-client"), "windows-client")
            .unwrap();
    let mut target =
        SecureTransport::load_or_create(root.path().join("mac-target"), "mac-target").unwrap();
    registry
        .trust("windows-client", windows.certificate_der())
        .unwrap();
    target
        .trust("registry", registry.certificate_der())
        .unwrap();

    let grant = RemoteOperationGrant::new(
        "request-install-1",
        "project",
        Some(DeviceId::parse("iphone-1").unwrap()),
        AppleOperation::InstallApp {
            app_path: "build/Mesh.app".into(),
        },
    )
    .unwrap();
    let access = AccessRequest {
        activity_id: ActivityId::parse("signed-install-access").unwrap(),
        principal_id: PrincipalId::parse("replaced-by-signer").unwrap(),
        source_host_id: HostId::parse("replaced-by-signer").unwrap(),
        target_host_id: HostId::parse("mac-target").unwrap(),
        device_id: Some(DeviceId::parse("iphone-1").unwrap()),
        operation: OperationId::parse("apple.install_app").unwrap(),
        resources: vec![
            ResourceClass::WorkspaceRead,
            ResourceClass::DeviceLease,
            ResourceClass::ApplicationInstall,
        ],
        remote_operation: Some(grant.clone()),
        physical_device: true,
        user_present: true,
    };
    let (claim, signature) = sign_mesh_access_claim(&windows, access).unwrap();
    let assertion = issue_mesh_approval(
        &registry,
        "windows-client",
        claim,
        &signature,
        1_000,
        60_000,
    )
    .unwrap();
    let verified = verify_mesh_approval(
        &target,
        &assertion,
        "registry",
        &HostId::parse("mac-target").unwrap(),
        2_000,
    )
    .unwrap();
    assert_eq!(verified.remote_operation.as_ref(), Some(&grant));
    assert_eq!(
        verified.remote_operation.unwrap().canonical_sha256(),
        grant.canonical_sha256()
    );

    let mut tampered = serde_json::to_value(&assertion).unwrap();
    tampered["payload"]["access"]["remote_operation"]["operation"]["app_path"] =
        serde_json::json!("build/Other.app");
    assert!(serde_json::from_value::<
        device_development_mesh::controller_session::MeshApprovalAssertion,
    >(tampered)
    .is_err());
}

#[test]
fn controller_session_is_consumed_once_persistently_and_cache_fails_closed() {
    let root = tempfile::tempdir().unwrap();
    let controller =
        SecureTransport::load_or_create(root.path().join("controller"), "windows-controller")
            .unwrap();
    let mut verifier =
        SecureTransport::load_or_create(root.path().join("target"), "mac-target").unwrap();
    verifier
        .trust("windows-controller", controller.certificate_der())
        .unwrap();
    let cache_path = root.path().join("target").join("controller-sessions.json");
    let cache = ControllerSessionReplayCache::open(&cache_path, 2).unwrap();
    let assertion = issue_controller_session(
        &controller,
        "192.168.0.61:7443",
        "one-use-challenge-1",
        1_000,
        10,
    )
    .unwrap();
    verify_and_consume_controller_session(
        &verifier,
        &cache,
        &assertion,
        "192.168.0.61:7443",
        "windows-controller",
        "one-use-challenge-1",
        1_001,
    )
    .unwrap();

    let reopened = ControllerSessionReplayCache::open(&cache_path, 2).unwrap();
    assert_eq!(
        verify_and_consume_controller_session(
            &verifier,
            &reopened,
            &assertion,
            "192.168.0.61:7443",
            "windows-controller",
            "one-use-challenge-1",
            1_002,
        ),
        Err(ControllerSessionError::ReplayDetected)
    );

    let fresh = issue_controller_session(
        &controller,
        "192.168.0.61:7443",
        "one-use-challenge-2",
        1_011,
        60_000,
    )
    .unwrap();
    verify_and_consume_controller_session(
        &verifier,
        &reopened,
        &fresh,
        "192.168.0.61:7443",
        "windows-controller",
        "one-use-challenge-2",
        1_011,
    )
    .unwrap();

    std::fs::write(&cache_path, b"corrupt-after-crash").unwrap();
    let after_crash = ControllerSessionReplayCache::open(&cache_path, 2).unwrap();
    let another = issue_controller_session(
        &controller,
        "192.168.0.61:7443",
        "one-use-challenge-3",
        1_012,
        60_000,
    )
    .unwrap();
    assert_eq!(
        verify_and_consume_controller_session(
            &verifier,
            &after_crash,
            &another,
            "192.168.0.61:7443",
            "windows-controller",
            "one-use-challenge-3",
            1_012,
        ),
        Err(ControllerSessionError::ReplayCacheUnavailable)
    );
}
