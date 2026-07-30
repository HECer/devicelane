use device_development_mesh::identity::{AuditEvent, MachineIdentity, PairingError};
use std::time::Duration;

#[test]
fn fresh_machines_pair_once_and_establish_mutual_tls() {
    let mut mac = MachineIdentity::new("mac").unwrap();
    let mut windows = MachineIdentity::new("windows").unwrap();
    let code = mac.issue_pairing_code(Duration::from_secs(30));

    let mac_certificate = mac
        .accept_pairing(&code, windows.certificate(), Duration::ZERO)
        .unwrap();
    windows.trust("mac", &mac_certificate).unwrap();

    assert!(mac.mutual_tls_with(&windows).is_ok());
    assert!(windows.mutual_tls_with(&mac).is_ok());
    assert_eq!(
        mac.accept_pairing(&code, windows.certificate(), Duration::ZERO),
        Err(PairingError::CodeReused)
    );
    assert!(
        matches!(mac.audit_log().last(), Some(AuditEvent::PairingRejected { reason, .. }) if *reason == "code_reused")
    );
}

#[test]
fn invalid_and_expired_codes_are_rejected_and_audited() {
    let mut host = MachineIdentity::new("host").unwrap();
    let peer = MachineIdentity::new("peer").unwrap();
    let code = host.issue_pairing_code(Duration::from_secs(1));

    assert_eq!(
        host.accept_pairing("wrong", peer.certificate(), Duration::ZERO),
        Err(PairingError::InvalidCode)
    );
    assert_eq!(
        host.accept_pairing(&code, peer.certificate(), Duration::from_secs(2)),
        Err(PairingError::CodeExpired)
    );
    assert!(host.audit_log().iter().any(|event| matches!(event, AuditEvent::PairingRejected { reason, .. } if *reason == "invalid_code")));
    assert!(host.audit_log().iter().any(|event| matches!(event, AuditEvent::PairingRejected { reason, .. } if *reason == "code_expired")));
}

#[test]
fn unencrypted_and_foreign_signed_connections_are_rejected_after_pairing() {
    let mut host = MachineIdentity::new("host").unwrap();
    let mut peer = MachineIdentity::new("peer").unwrap();
    let stranger = MachineIdentity::new("stranger").unwrap();
    let code = host.issue_pairing_code(Duration::from_secs(30));
    let host_certificate = host
        .accept_pairing(&code, peer.certificate(), Duration::ZERO)
        .unwrap();
    peer.trust("host", &host_certificate).unwrap();

    assert_eq!(
        host.accept_unencrypted("peer"),
        Err(PairingError::TlsRequired)
    );
    assert_eq!(
        host.mutual_tls_with(&stranger),
        Err(PairingError::UntrustedPeer)
    );
}
