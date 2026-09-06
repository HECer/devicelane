use device_development_mesh::secure_transport::{
    SecureTransport,
    pairing_tls::{PairingTls, PairingTlsError},
};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
};
use std::{
    fs,
    io::{ErrorKind, Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

fn socket(stream: TcpStream) -> std::io::Result<TcpStream> {
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    Ok(stream)
}

struct JoinOnDrop<T>(Option<thread::JoinHandle<T>>);
impl<T> JoinOnDrop<T> {
    fn join(mut self) -> thread::Result<T> {
        self.0.take().unwrap().join()
    }
}
impl<T> Drop for JoinOnDrop<T> {
    fn drop(&mut self) {
        if let Some(worker) = self.0.take() {
            let _ = worker.join();
        }
    }
}

fn accept_with_timeout(listener: TcpListener) -> Option<TcpStream> {
    listener.set_nonblocking(true).ok()?;
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).ok()?;
                return Some(stream);
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(_) => return None,
        }
    }
}

fn roots(certificate: &[u8]) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(certificate.to_vec()))
        .unwrap();
    roots
}
fn key(path: &Path) -> PrivateKeyDer<'static> {
    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        fs::read(path.join("private-key.der")).unwrap(),
    ))
}
fn exchange(server: PairingTls, client: PairingTls) -> (bool, bool) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let worker = JoinOnDrop(Some(thread::spawn(move || {
        let Some(stream) = accept_with_timeout(listener) else {
            return false;
        };
        let Ok(stream) = socket(stream) else {
            return false;
        };
        let Ok(mut tls) = server.accept(stream) else {
            return false;
        };
        let mut request = [0; 4];
        if tls.read_exact(&mut request).is_err() || request != *b"ping" {
            return false;
        }
        tls.write_all(b"pong").is_ok() && tls.flush().is_ok()
    })));
    let client_ok = (|| {
        let stream = TcpStream::connect_timeout(&address, Duration::from_secs(3)).ok()?;
        let mut tls = client.connect(socket(stream).ok()?).ok()?;
        tls.write_all(b"ping").ok()?;
        tls.flush().ok()?;
        let mut response = [0; 4];
        tls.read_exact(&mut response).ok()?;
        Some(response == *b"pong")
    })()
    .unwrap_or(false);
    (worker.join().unwrap(), client_ok)
}
fn raw_client(
    root: &[u8],
    chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
    alpn: bool,
) -> ClientConfig {
    let mut config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots(root))
        .with_client_auth_cert(chain, private_key)
        .unwrap();
    config.alpn_protocols = if alpn {
        vec![b"devicelane-pairing/1".to_vec()]
    } else {
        Vec::new()
    };
    config
}
fn raw_server(
    root: &[u8],
    chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
    alpn: bool,
) -> ServerConfig {
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots(root)))
        .build()
        .unwrap();
    let mut config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, private_key)
        .unwrap();
    config.alpn_protocols = if alpn {
        vec![b"devicelane-pairing/1".to_vec()]
    } else {
        Vec::new()
    };
    config
}
fn against_raw_client(server: PairingTls, config: ClientConfig) -> Result<(), PairingTlsError> {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let worker = JoinOnDrop(Some(thread::spawn(move || {
        accept_with_timeout(listener)
            .ok_or(PairingTlsError::Tls)
            .and_then(|stream| socket(stream).map_err(|_| PairingTlsError::Tls))
            .and_then(|stream| server.accept(stream).map(|_| ()))
    })));
    let setup = (|| -> std::io::Result<()> {
        let mut io = socket(TcpStream::connect_timeout(
            &address,
            Duration::from_secs(3),
        )?)?;
        let mut connection =
            ClientConnection::new(Arc::new(config), ServerName::try_from("server").unwrap())
                .unwrap();
        let _ = connection.complete_io(&mut io);
        Ok(())
    })();
    let result = worker.join().unwrap();
    setup.expect("raw client setup must succeed");
    result
}
fn against_raw_server(client: PairingTls, config: ServerConfig) -> Result<(), PairingTlsError> {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let worker = JoinOnDrop(Some(thread::spawn(move || {
        let Some(stream) = accept_with_timeout(listener) else {
            return;
        };
        let Ok(mut io) = socket(stream) else {
            return;
        };
        let mut connection = ServerConnection::new(Arc::new(config)).unwrap();
        let _ = connection.complete_io(&mut io);
    })));
    let setup = TcpStream::connect_timeout(&address, Duration::from_secs(3)).and_then(socket);
    let result = setup
        .map_err(|_| PairingTlsError::Tls)
        .and_then(|io| client.connect(io).map(|_| ()));
    worker.join().unwrap();
    result
}

struct Closed;
impl Read for Closed {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        Ok(0)
    }
}
impl Write for Closed {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn peer_closing_before_handshake_fails_closed() {
    let root = tempfile::tempdir().unwrap();
    let local = SecureTransport::load_or_create(root.path().join("local"), "local").unwrap();
    let peer = SecureTransport::load_or_create(root.path().join("peer"), "peer").unwrap();
    let pairing = PairingTls::new(&local, "peer", peer.certificate_der()).unwrap();
    assert_eq!(pairing.connect(Closed).err(), Some(PairingTlsError::Tls));
}

#[test]
fn candidate_only_tls_connects_without_persisting_trust() {
    let root = tempfile::tempdir().unwrap();
    let left_path = root.path().join("left");
    let right_path = root.path().join("right");
    let left = SecureTransport::load_or_create(&left_path, "left").unwrap();
    let right = SecureTransport::load_or_create(&right_path, "right").unwrap();
    let left_certificate = fs::read(left_path.join("certificate.der")).unwrap();
    let right_certificate = fs::read(right_path.join("certificate.der")).unwrap();
    let left_key = fs::read(left_path.join("private-key.der")).unwrap();
    let right_key = fs::read(right_path.join("private-key.der")).unwrap();
    let client = PairingTls::new(&left, "right", right.certificate_der()).unwrap();
    let server = PairingTls::new(&right, "left", left.certificate_der()).unwrap();
    assert_eq!(exchange(server, client), (true, true));
    assert!(left.authorize_peer(right.certificate_der()).is_err());
    assert!(right.authorize_peer(left.certificate_der()).is_err());
    assert_eq!(
        fs::read(left_path.join("certificate.der")).unwrap(),
        left_certificate
    );
    assert_eq!(
        fs::read(right_path.join("certificate.der")).unwrap(),
        right_certificate
    );
    assert_eq!(
        fs::read(left_path.join("private-key.der")).unwrap(),
        left_key
    );
    assert_eq!(
        fs::read(right_path.join("private-key.der")).unwrap(),
        right_key
    );
    assert!(
        fs::read_dir(left_path.join("trust"))
            .unwrap()
            .next()
            .is_none()
    );
    assert!(
        fs::read_dir(right_path.join("trust"))
            .unwrap()
            .next()
            .is_none()
    );
    assert!(
        SecureTransport::load_or_create(&left_path, "left")
            .unwrap()
            .authorize_peer(&right_certificate)
            .is_err()
    );
}
#[test]
fn candidate_validation_rejects_without_trust_changes() {
    let root = tempfile::tempdir().unwrap();
    let mut local = SecureTransport::load_or_create(root.path().join("local"), "local").unwrap();
    let peer = SecureTransport::load_or_create(root.path().join("peer"), "peer").unwrap();
    let other = SecureTransport::load_or_create(root.path().join("other"), "peer").unwrap();
    let mut trailing = peer.certificate_der().to_vec();
    trailing.push(0);
    for (id, certificate) in [
        ("wrong", peer.certificate_der()),
        ("peer", &[][..]),
        ("peer", &trailing[..]),
        ("local", local.certificate_der()),
    ] {
        assert_eq!(
            PairingTls::new(&local, id, certificate).err(),
            Some(PairingTlsError::InvalidCandidate)
        );
    }
    assert_eq!(
        PairingTls::new(&local, &"a".repeat(254), peer.certificate_der()).err(),
        Some(PairingTlsError::InvalidCandidate)
    );
    assert_eq!(
        PairingTls::new(&local, "peer", &vec![0; 16385]).err(),
        Some(PairingTlsError::InvalidCandidate)
    );
    local.trust("peer", peer.certificate_der()).unwrap();
    let before = fs::read(root.path().join("local/trust/peer.der")).unwrap();
    assert_eq!(
        PairingTls::new(&local, "peer", peer.certificate_der()).err(),
        Some(PairingTlsError::AlreadyPaired)
    );
    assert_eq!(
        PairingTls::new(&local, "peer", other.certificate_der()).err(),
        Some(PairingTlsError::ConflictingTrust)
    );
    local.revoke("peer").unwrap();
    assert_eq!(
        PairingTls::new(&local, "peer", peer.certificate_der()).err(),
        Some(PairingTlsError::RevokedPeer)
    );
    assert_eq!(
        fs::read(root.path().join("local/trust/peer.der")).unwrap(),
        before
    );
}
fn ca_descendant(
    id: &str,
) -> (
    Vec<u8>,
    Vec<CertificateDer<'static>>,
    PrivateKeyDer<'static>,
) {
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec![id.into()]).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = params.self_signed(&ca_key).unwrap();
    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let leaf = rcgen::CertificateParams::new(vec![id.into()])
        .unwrap()
        .signed_by(&leaf_key, &ca, &ca_key)
        .unwrap();
    (
        ca.der().to_vec(),
        vec![leaf.der().clone(), ca.der().clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
    )
}
#[test]
fn exact_server_pin_rejects_an_otherwise_valid_ca_descendant() {
    let root = tempfile::tempdir().unwrap();
    let client = SecureTransport::load_or_create(root.path(), "client").unwrap();
    let (candidate, chain, leaf_key) = ca_descendant("server");
    let pairing = PairingTls::new(&client, "server", &candidate).unwrap();
    assert_eq!(
        against_raw_server(
            pairing,
            raw_server(client.certificate_der(), chain, leaf_key, true)
        ),
        Err(PairingTlsError::PinMismatch)
    );
    assert_eq!(fs::read_dir(root.path().join("trust")).unwrap().count(), 0);
}
#[test]
fn exact_client_pin_rejects_an_otherwise_valid_ca_descendant() {
    let root = tempfile::tempdir().unwrap();
    let server = SecureTransport::load_or_create(root.path(), "server").unwrap();
    let (candidate, chain, leaf_key) = ca_descendant("client");
    let pairing = PairingTls::new(&server, "client", &candidate).unwrap();
    assert_eq!(
        against_raw_client(
            pairing,
            raw_client(server.certificate_der(), chain, leaf_key, true)
        ),
        Err(PairingTlsError::PinMismatch)
    );
    assert_eq!(fs::read_dir(root.path().join("trust")).unwrap().count(), 0);
}
#[test]
fn missing_pairing_alpn_is_rejected_in_both_directions() {
    let root = tempfile::tempdir().unwrap();
    let server_path = root.path().join("server");
    let client_path = root.path().join("client");
    let server = SecureTransport::load_or_create(&server_path, "server").unwrap();
    let client = SecureTransport::load_or_create(&client_path, "client").unwrap();
    let server_pairing = PairingTls::new(&server, "client", client.certificate_der()).unwrap();
    let server_result = against_raw_client(
        server_pairing,
        raw_client(
            server.certificate_der(),
            vec![CertificateDer::from(client.certificate_der().to_vec())],
            key(&client_path),
            false,
        ),
    );
    let client_pairing = PairingTls::new(&client, "server", server.certificate_der()).unwrap();
    let client_result = against_raw_server(
        client_pairing,
        raw_server(
            client.certificate_der(),
            vec![CertificateDer::from(server.certificate_der().to_vec())],
            key(&server_path),
            false,
        ),
    );
    assert_eq!(
        (server_result, client_result),
        (
            Err(PairingTlsError::WrongProtocol),
            Err(PairingTlsError::WrongProtocol)
        )
    );
}
#[derive(Debug)]
struct MismatchedKey(Arc<rustls::sign::CertifiedKey>);
impl rustls::client::ResolvesClientCert for MismatchedKey {
    fn resolve(
        &self,
        _: &[&[u8]],
        _: &[rustls::SignatureScheme],
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }
    fn has_certs(&self) -> bool {
        true
    }
}
#[test]
fn replaying_candidate_certificate_without_its_private_key_fails() {
    let root = tempfile::tempdir().unwrap();
    let server = SecureTransport::load_or_create(root.path().join("server"), "server").unwrap();
    let client = SecureTransport::load_or_create(root.path().join("client"), "client").unwrap();
    let foreign_path = root.path().join("foreign");
    SecureTransport::load_or_create(&foreign_path, "foreign").unwrap();
    let signer = rustls::crypto::aws_lc_rs::sign::any_supported_type(&key(&foreign_path)).unwrap();
    let mismatch = rustls::sign::CertifiedKey::new(
        vec![CertificateDer::from(client.certificate_der().to_vec())],
        signer,
    );
    let mut config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots(server.certificate_der()))
        .with_client_cert_resolver(Arc::new(MismatchedKey(Arc::new(mismatch))));
    config.alpn_protocols = vec![b"devicelane-pairing/1".to_vec()];
    let pairing = PairingTls::new(&server, "client", client.certificate_der()).unwrap();
    assert_eq!(
        against_raw_client(pairing, config),
        Err(PairingTlsError::Tls)
    );
    assert_eq!(
        fs::read_dir(root.path().join("server/trust"))
            .unwrap()
            .count(),
        0
    );
}
#[test]
fn unrelated_existing_trust_is_not_a_session_root() {
    let root = tempfile::tempdir().unwrap();
    let mut server = SecureTransport::load_or_create(root.path().join("server"), "server").unwrap();
    let candidate =
        SecureTransport::load_or_create(root.path().join("candidate"), "candidate").unwrap();
    let other_path = root.path().join("other");
    let other = SecureTransport::load_or_create(&other_path, "other").unwrap();
    server.trust("other", other.certificate_der()).unwrap();
    let pairing = PairingTls::new(&server, "candidate", candidate.certificate_der()).unwrap();
    let config = raw_client(
        server.certificate_der(),
        vec![CertificateDer::from(other.certificate_der().to_vec())],
        key(&other_path),
        true,
    );
    assert_eq!(
        against_raw_client(pairing, config),
        Err(PairingTlsError::Tls)
    );
    assert_eq!(
        fs::read(root.path().join("server/trust/other.der")).unwrap(),
        other.certificate_der()
    );
}
#[test]
fn multiple_dns_identities_are_rejected() {
    let root = tempfile::tempdir().unwrap();
    let local = SecureTransport::load_or_create(root.path(), "local").unwrap();
    let peer = rcgen::generate_simple_self_signed(vec!["peer".into(), "alias".into()]).unwrap();
    assert_eq!(
        PairingTls::new(&local, "peer", peer.cert.der()).err(),
        Some(PairingTlsError::InvalidCandidate)
    );
}
#[test]
fn tls12_only_peer_is_rejected() {
    let root = tempfile::tempdir().unwrap();
    let server_path = root.path().join("server");
    let client_path = root.path().join("client");
    let server = SecureTransport::load_or_create(&server_path, "server").unwrap();
    let client = SecureTransport::load_or_create(&client_path, "client").unwrap();
    let verifier =
        rustls::server::WebPkiClientVerifier::builder(Arc::new(roots(client.certificate_der())))
            .build()
            .unwrap();
    let mut tls12_server = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![CertificateDer::from(server.certificate_der().to_vec())],
            key(&server_path),
        )
        .unwrap();
    tls12_server.alpn_protocols = vec![b"devicelane-pairing/1".to_vec()];
    let pairing = PairingTls::new(&client, "server", server.certificate_der()).unwrap();
    let client_result = against_raw_server(pairing, tls12_server);

    let mut tls12_client = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])
        .with_root_certificates(roots(server.certificate_der()))
        .with_client_auth_cert(
            vec![CertificateDer::from(client.certificate_der().to_vec())],
            key(&client_path),
        )
        .unwrap();
    tls12_client.alpn_protocols = vec![b"devicelane-pairing/1".to_vec()];
    let pairing = PairingTls::new(&server, "client", client.certificate_der()).unwrap();
    let server_result = against_raw_client(pairing, tls12_client);
    assert_eq!(
        (client_result, server_result),
        (Err(PairingTlsError::Tls), Err(PairingTlsError::Tls))
    );
}
