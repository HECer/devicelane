use device_development_mesh::controller_session::{
    ControllerSessionError, issue_controller_session, verify_controller_session,
};
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
