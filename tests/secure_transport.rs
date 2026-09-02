use device_development_mesh::secure_transport::{AuditEvent, SecureTransport, TransportError};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

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
