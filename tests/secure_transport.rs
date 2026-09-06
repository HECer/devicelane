use device_development_mesh::secure_transport::{AuditEvent, SecureTransport, TransportError};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[test]
fn missing_private_key_preserves_certificate_and_trust() {
    assert_partial_identity_is_preserved("private-key.der", "certificate.der");
}

#[test]
fn missing_certificate_preserves_private_key_and_trust() {
    assert_partial_identity_is_preserved("certificate.der", "private-key.der");
}

#[test]
fn empty_private_key_fails_closed_without_changing_identity_or_trust() {
    assert_invalid_identity_is_preserved("private-key.der", |_| Vec::new());
}

#[test]
fn truncated_private_key_fails_closed_without_changing_identity_or_trust() {
    assert_invalid_identity_is_preserved("private-key.der", |original| original[..16].to_vec());
}

#[test]
fn foreign_private_key_fails_closed_without_changing_identity_or_trust() {
    let foreign = rcgen::generate_simple_self_signed(vec!["foreign".to_owned()]).unwrap();
    assert_invalid_identity_is_preserved("private-key.der", |_| foreign.key_pair.serialize_der());
}

#[test]
fn invalid_certificate_fails_closed_without_changing_identity_or_trust() {
    assert_invalid_identity_is_preserved("certificate.der", |original| original[..16].to_vec());
}

fn assert_invalid_identity_is_preserved(damaged_name: &str, damage: impl FnOnce(&[u8]) -> Vec<u8>) {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("host");
    let mut host = SecureTransport::load_or_create(&root, "host").unwrap();
    let peer = SecureTransport::load_or_create(directory.path().join("peer"), "peer").unwrap();
    host.trust("peer", peer.certificate_der()).unwrap();
    host.revoke("peer").unwrap();
    let damaged_path = root.join(damaged_name);
    let damaged = damage(&std::fs::read(&damaged_path).unwrap());
    std::fs::write(&damaged_path, damaged).unwrap();
    let snapshots = [
        "certificate.der",
        "private-key.der",
        "trust/peer.der",
        "revoked",
    ]
    .map(|name| (name, std::fs::read(root.join(name)).unwrap()));
    for _ in 0..2 {
        assert_eq!(
            SecureTransport::load_or_create(&root, "host").unwrap_err(),
            TransportError::InvalidCertificate
        );
        for (name, original) in &snapshots {
            assert_eq!(&std::fs::read(root.join(name)).unwrap(), original);
        }
    }
}

#[cfg(windows)]
#[test]
fn unreadable_credential_is_not_treated_as_absent() {
    use std::os::windows::fs::OpenOptionsExt;
    for name in ["certificate.der", "private-key.der"] {
        let directory = tempfile::tempdir().unwrap();
        SecureTransport::load_or_create(directory.path(), "host").unwrap();
        let path = directory.path().join(name);
        let original = std::fs::read(&path).unwrap();
        let locked = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&path)
            .unwrap();
        assert_eq!(
            SecureTransport::load_or_create(directory.path(), "host").unwrap_err(),
            TransportError::Io
        );
        drop(locked);
        assert_eq!(std::fs::read(&path).unwrap(), original);
    }
}

#[cfg(unix)]
#[test]
fn unreadable_credential_is_not_treated_as_absent() {
    use std::os::unix::fs::PermissionsExt;
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("unreadable case unavailable: root bypasses file permissions");
        return;
    }
    for name in ["certificate.der", "private-key.der"] {
        let directory = tempfile::tempdir().unwrap();
        SecureTransport::load_or_create(directory.path(), "host").unwrap();
        let path = directory.path().join(name);
        let original = std::fs::read(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0)).unwrap();
        let result = SecureTransport::load_or_create(directory.path(), "host");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(result.unwrap_err(), TransportError::Io);
        assert_eq!(std::fs::read(&path).unwrap(), original);
    }
}

fn assert_partial_identity_is_preserved(missing: &str, remaining: &str) {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("host");
    let mut host = SecureTransport::load_or_create(&root, "host").unwrap();
    let peer = SecureTransport::load_or_create(directory.path().join("peer"), "peer").unwrap();
    host.trust("peer", peer.certificate_der()).unwrap();
    host.revoke("peer").unwrap();
    let original = std::fs::read(root.join(remaining)).unwrap();
    let trust = std::fs::read(root.join("trust/peer.der")).unwrap();
    let revoked = std::fs::read(root.join("revoked")).unwrap();
    std::fs::remove_file(root.join(missing)).unwrap();
    for _ in 0..2 {
        let result = SecureTransport::load_or_create(&root, "host");
        assert!(result.is_err(), "partial identity must fail closed");
        assert!(!root.join(missing).exists());
        assert_eq!(std::fs::read(root.join(remaining)).unwrap(), original);
        assert_eq!(std::fs::read(root.join("trust/peer.der")).unwrap(), trust);
        assert_eq!(std::fs::read(root.join("revoked")).unwrap(), revoked);
    }
}

#[test]
fn nonregular_credentials_do_not_initialize_identity() {
    for name in ["certificate.der", "private-key.der"] {
        let directory = tempfile::tempdir().unwrap();
        std::fs::create_dir(directory.path().join(name)).unwrap();
        assert!(SecureTransport::load_or_create(directory.path(), "host").is_err());
        let other = if name == "certificate.der" {
            "private-key.der"
        } else {
            "certificate.der"
        };
        assert!(!directory.path().join(other).exists());
    }
}

#[cfg(any(unix, windows))]
#[test]
fn linked_credentials_are_rejected_without_touching_targets() {
    for name in ["certificate.der", "private-key.der"] {
        for dangling in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let root = directory.path().join("host");
            SecureTransport::load_or_create(&root, "host").unwrap();
            let path = root.join(name);
            let target = directory.path().join("target.der");
            std::fs::rename(&path, &target).unwrap();
            let original = std::fs::read(&target).unwrap();
            if dangling {
                std::fs::remove_file(&target).unwrap();
            }
            #[cfg(unix)]
            std::os::unix::fs::symlink(&target, &path).unwrap();
            #[cfg(windows)]
            if let Err(error) = std::os::windows::fs::symlink_file(&target, &path) {
                // Windows needs Developer Mode or SeCreateSymbolicLinkPrivilege.
                if error.raw_os_error() == Some(1314) {
                    eprintln!("symlink case unavailable: Windows symlink privilege required");
                    return;
                }
                panic!("cannot create fixture symlink: {error}");
            }
            assert!(SecureTransport::load_or_create(&root, "host").is_err());
            assert!(
                std::fs::symlink_metadata(&path)
                    .unwrap()
                    .file_type()
                    .is_symlink()
            );
            if dangling {
                assert!(!target.exists());
            } else {
                assert_eq!(std::fs::read(&target).unwrap(), original);
            }
        }
    }
}

#[test]
fn revoked_peer_cannot_verify_an_previously_valid_signature() {
    let directory = tempfile::tempdir().unwrap();
    let signer =
        SecureTransport::load_or_create(directory.path().join("signer"), "signer").unwrap();
    let mut verifier =
        SecureTransport::load_or_create(directory.path().join("verifier"), "verifier").unwrap();
    verifier.trust("signer", signer.certificate_der()).unwrap();
    let signature = signer.sign(b"bound-message").unwrap();
    verifier
        .verify_peer_signature("signer", b"bound-message", &signature)
        .unwrap();

    verifier.revoke("signer").unwrap();
    assert_eq!(
        verifier.verify_peer_signature("signer", b"bound-message", &signature),
        Err(TransportError::RevokedPeer)
    );
}

#[test]
fn persists_distinct_identities_and_completes_real_mutual_tls_over_loopback() {
    let directory = tempfile::tempdir().unwrap();
    let mut server =
        SecureTransport::load_or_create(directory.path().join("server"), "server").unwrap();
    let mut client =
        SecureTransport::load_or_create(directory.path().join("client"), "client").unwrap();
    pair(&mut server, &mut client);

    let server_key = std::fs::read(directory.path().join("server/private-key.der")).unwrap();
    let server_certificate = server.certificate_der().to_vec();
    let server =
        SecureTransport::load_or_create(directory.path().join("server"), "server").unwrap();
    let client =
        SecureTransport::load_or_create(directory.path().join("client"), "client").unwrap();
    assert_eq!(server.certificate_der(), server_certificate);
    assert_eq!(
        std::fs::read(directory.path().join("server/private-key.der")).unwrap(),
        server_key
    );

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = Arc::new(server);
    let serving = {
        let server = Arc::clone(&server);
        thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = server.accept_tls(stream).unwrap();
            let mut request = [0; 4];
            stream.read_exact(&mut request).unwrap();
            assert_eq!(&request, b"ping");
            stream.write_all(b"pong").unwrap();
        })
    };
    let mut stream = client
        .connect_tls(TcpStream::connect(address).unwrap(), "server")
        .unwrap();
    stream.write_all(b"ping").unwrap();
    let mut response = [0; 4];
    stream.read_exact(&mut response).unwrap();
    assert_eq!(&response, b"pong");
    serving.join().unwrap();

    let reloaded =
        SecureTransport::load_or_create(directory.path().join("server"), "server").unwrap();
    assert_eq!(server.certificate_der(), reloaded.certificate_der());
    assert_ne!(server.certificate_der(), client.certificate_der());
    assert_restrictive(directory.path().join("server/private-key.der"));
    assert_restrictive(directory.path().join("server/trust/client.der"));
    assert_restrictive(directory.path().join("server/trust"));
    assert!(!format!("{:?}", server).contains("PRIVATE KEY"));
}

#[test]
fn pairing_code_is_random_expiring_and_single_use() {
    let directory = tempfile::tempdir().unwrap();
    let mut host = SecureTransport::load_or_create(directory.path().join("host"), "host").unwrap();
    let peer = SecureTransport::load_or_create(directory.path().join("peer"), "peer").unwrap();
    let first = host.issue_pairing_code(Duration::from_secs(10));
    let second = host.issue_pairing_code(Duration::from_secs(10));
    assert_ne!(first, second);
    assert_eq!(
        host.accept_pairing(&second, peer.certificate_der(), Duration::ZERO),
        Ok(())
    );
    assert_eq!(
        host.accept_pairing(&second, peer.certificate_der(), Duration::ZERO),
        Err(TransportError::CodeReused)
    );
    let expired = host.issue_pairing_code(Duration::from_secs(1));
    assert_eq!(
        host.accept_pairing(&expired, peer.certificate_der(), Duration::from_secs(2)),
        Err(TransportError::CodeExpired)
    );
}

#[test]
fn rejects_and_audits_cleartext_foreign_and_revoked_peers_before_rpc() {
    let directory = tempfile::tempdir().unwrap();
    let mut host = SecureTransport::load_or_create(directory.path().join("host"), "host").unwrap();
    let mut peer = SecureTransport::load_or_create(directory.path().join("peer"), "peer").unwrap();
    let stranger =
        SecureTransport::load_or_create(directory.path().join("stranger"), "stranger").unwrap();
    pair(&mut host, &mut peer);

    assert_eq!(
        host.process_cleartext_rpc(),
        Err(TransportError::TlsRequired)
    );
    assert_eq!(
        host.process_rpc(stranger.certificate_der()),
        Err(TransportError::UntrustedPeer)
    );
    host.revoke("peer").unwrap();
    assert_eq!(
        host.process_rpc(peer.certificate_der()),
        Err(TransportError::RevokedPeer)
    );
    assert_eq!(host.rpc_count(), 0);
    let audit = host.audit_log();
    assert!(audit.contains(&AuditEvent::Rejected("tls_required")));
    assert!(audit.contains(&AuditEvent::Rejected("untrusted_peer")));
    assert!(audit.contains(&AuditEvent::Rejected("revoked_peer")));
}

fn pair(left: &mut SecureTransport, right: &mut SecureTransport) {
    let code = left.issue_pairing_code(Duration::from_secs(10));
    left.accept_pairing(&code, right.certificate_der(), Duration::ZERO)
        .unwrap();
    right
        .trust(left.machine_id(), left.certificate_der())
        .unwrap();
}

#[cfg(unix)]
fn assert_restrictive(path: impl AsRef<std::path::Path>) {
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(path).unwrap().permissions().mode() & 0o077,
        0
    );
}

#[cfg(windows)]
fn assert_restrictive(path: impl AsRef<std::path::Path>) {
    let output = std::process::Command::new("icacls")
        .arg(path.as_ref())
        .output()
        .unwrap();
    let acl = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(!acl.contains("BUILTIN\\Users"));
    assert!(!acl.contains("Everyone"));
}
