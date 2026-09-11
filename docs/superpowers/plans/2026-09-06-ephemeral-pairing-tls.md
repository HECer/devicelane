# Ephemeral pairing TLS implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Follow test-driven development and independent spec review followed by quality review. Steps use checkbox syntax.

**Goal:** Establish a real, mutually authenticated, exactly pinned pairing-only TLS channel without changing persistent trust.

**Architecture:** A separate `secure_transport::pairing_tls` module builds TLS configurations from an existing daemon-owned identity and exactly one untrusted candidate. It holds no identity path, cannot write trust, and cannot dispatch normal RPC. The later daemon session owns invitations, visual confirmation, absolute deadlines, audit and commit.

**Tech Stack:** Existing Rust/rustls 0.23, x509-parser and rcgen; no new dependency.

## Authority and limits

This implements the transport boundary required by the approved desktop product design and `../specs/2026-09-06-onboarding-pairing-gap-assessment.md`. Independent design review accepts OOB pin + normal mTLS in principle. Its requirements are binding: independently compare fingerprints on both devices (not merely approve a fingerprint contained in an untrusted invitation), keep server session metadata authoritative, reject preface abuse before prompts/mutation, and report partial distributed commits honestly. This unit is not complete pairing or a deployable wizard.

The remaining vertical path is mandatory: daemon-owned monotonic session, bounded preface and attempts, token only after pinned TLS, exact local approval bound to both certificates/identities/roles/endpoint/session, audited crash-safe persistence, post-commit mTLS, UI/CLI and installed Windows/Mac verification. No new legacy-pairing call site is allowed.

## Acceptance criteria

- Construct from an existing `SecureTransport`; no credential bytes or identity paths in the public API.
- A candidate is one complete DER certificate of at most 16 KiB with exactly one DNS SAN equal to a valid expected peer ID (at most 253 bytes). Reject self-identity, malformed/trailing/ambiguous certificate input.
- Check existing revocation and trust before allocating TLS configuration. Return distinct revoked/conflicting/already-paired outcomes; never silently overwrite or reuse existing trust as a new pairing.
- Only candidate certificate is a session trust root; ordinary trusted peers are excluded.
- TLS 1.3, mutual certificate authentication, ALPN `devicelane-pairing/1`, no client resumption, no server tickets. Never use a permissive verifier.
- Both directions check exact negotiated peer leaf DER after TLS verifies proof of key possession. No application stream is returned on pin or protocol mismatch.
- Adapter has no disk mutation or normal RPC method. The caller must supply deadline-bounded I/O; absolute session deadlines are not provided by this unit.
- Real socket tests prove success, wrong candidate/identity, missing private-key proof, wrong ALPN, CA-descendant substitution and unchanged persistent identity/trust. Existing secure transport tests remain green.
- Observe RED before production implementation; obtain independent spec and quality reviews. Preserve unrelated WIP; do not stage all of `src/lib.rs`.

## Files

- Add `src/secure_transport/pairing_tls.rs`: session-only TLS adapter.
- Modify only the `pub mod secure_transport` declaration area of `src/lib.rs`: export child module.
- Add `tests/pairing_tls.rs`: real TLS tests. Test utilities stay here.
- No daemon/UI/CLI behavior change in this unit.

## Task 1: Nonpersistent candidate TLS

- [ ] Add the following test file first. Start with the success/no-mutation test and observe the missing module compile failure; then add a temporary constructor returning `InvalidCandidate` to obtain a behavioral RED at `PairingTls::new(...).unwrap()` before implementing the constructor/handshake. Do not count a typo or compile error as behavioral proof.

```rust
use device_development_mesh::secure_transport::{
    SecureTransport,
    pairing_tls::{PairingTls, PairingTlsError},
};
use std::{io::{Read, Write}, net::{TcpListener, TcpStream}, thread, time::Duration};

fn socket(stream: TcpStream) -> TcpStream {
    stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    stream.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
    stream
}

fn exchange(server: PairingTls, client: PairingTls) -> (bool, bool) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let worker = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let Ok(mut tls) = server.accept(socket(stream)) else { return false };
        let mut request = [0; 4];
        if tls.read_exact(&mut request).is_err() || &request != b"ping" {
            return false;
        }
        tls.write_all(b"pong").is_ok() && tls.flush().is_ok()
    });
    let client_ok = (|| {
        let stream = TcpStream::connect_timeout(&address, Duration::from_secs(3)).ok()?;
        let mut tls = client.connect(socket(stream)).ok()?;
        tls.write_all(b"ping").ok()?;
        tls.flush().ok()?;
        let mut response = [0; 4];
        tls.read_exact(&mut response).ok()?;
        Some(&response == b"pong")
    })().unwrap_or(false);
    (worker.join().unwrap(), client_ok)
}

#[test]
fn candidate_tls_exchanges_without_persisting_trust() {
    let root = tempfile::tempdir().unwrap();
    let server_path = root.path().join("server");
    let client_path = root.path().join("client");
    let server = SecureTransport::load_or_create(&server_path, "server").unwrap();
    let client = SecureTransport::load_or_create(&client_path, "client").unwrap();
    let before = [&server_path, &client_path].map(|path| [
        std::fs::read(path.join("certificate.der")).unwrap(),
        std::fs::read(path.join("private-key.der")).unwrap(),
    ]);
    let server_tls = PairingTls::new(&server, "client", client.certificate_der()).unwrap();
    let client_tls = PairingTls::new(&client, "server", server.certificate_der()).unwrap();
    assert_eq!(exchange(server_tls, client_tls), (true, true));
    for (index, path) in [&server_path, &client_path].iter().enumerate() {
        assert_eq!(std::fs::read(path.join("certificate.der")).unwrap(), before[index][0]);
        assert_eq!(std::fs::read(path.join("private-key.der")).unwrap(), before[index][1]);
        assert_eq!(std::fs::read_dir(path.join("trust")).unwrap().count(), 0);
    }
    assert!(server.authorize_peer(client.certificate_der()).is_err());
    assert!(client.authorize_peer(server.certificate_der()).is_err());
    let reloaded = SecureTransport::load_or_create(&server_path, "server").unwrap();
    assert!(reloaded.authorize_peer(client.certificate_der()).is_err());
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
        assert_eq!(PairingTls::new(&local, id, certificate).err(), Some(PairingTlsError::InvalidCandidate));
    }
    assert_eq!(PairingTls::new(&local, "peer", &vec![0; 16385]).err(), Some(PairingTlsError::InvalidCandidate));
    local.trust("peer", peer.certificate_der()).unwrap();
    let before = std::fs::read(root.path().join("local/trust/peer.der")).unwrap();
    assert_eq!(PairingTls::new(&local, "peer", peer.certificate_der()).err(), Some(PairingTlsError::AlreadyPaired));
    assert_eq!(PairingTls::new(&local, "peer", other.certificate_der()).err(), Some(PairingTlsError::ConflictingTrust));
    local.revoke("peer").unwrap();
    assert_eq!(PairingTls::new(&local, "peer", peer.certificate_der()).err(), Some(PairingTlsError::RevokedPeer));
    assert_eq!(std::fs::read(root.path().join("local/trust/peer.der")).unwrap(), before);
}
```

- [ ] Run `cargo test -p devicelane --test pairing_tls --locked --jobs 1`, recording the behavioral RED.
- [ ] Add `pub mod pairing_tls;` inside `pub mod secure_transport` and implement this source after RED:

```rust
//! Candidate-only TLS. This is not a trust decision or complete pairing.
//! The daemon must provide bounded I/O and independently enforce its absolute
//! session deadline, token, local confirmation, audit and durable commit.
use super::{SecureTransport, peer_server_name};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
    pki_types::CertificateDer,
};
use std::{io::{Read, Write}, sync::Arc};
use x509_parser::{extensions::GeneralName, prelude::FromDer};

const ALPN: &[u8] = b"devicelane-pairing/1";
const MAX_CERTIFICATE_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingTlsError {
    InvalidCandidate,
    InvalidLocalIdentity,
    RevokedPeer,
    ConflictingTrust,
    AlreadyPaired,
    Tls,
    PinMismatch,
    WrongProtocol,
}

pub struct PairingTls {
    peer_id: String,
    certificate: Vec<u8>,
    client: Arc<ClientConfig>,
    server: Arc<ServerConfig>,
}

impl PairingTls {
    pub fn new(
        identity: &SecureTransport,
        peer_id: &str,
        certificate: &[u8],
    ) -> Result<Self, PairingTlsError> {
        let invalid = || PairingTlsError::InvalidCandidate;
        if peer_id.is_empty() || peer_id.len() > 253
            || certificate.is_empty() || certificate.len() > MAX_CERTIFICATE_BYTES
            || !super::valid_machine_id(peer_id)
        {
            return Err(invalid());
        }
        peer_server_name(peer_id).map_err(|_| invalid())?;
        let (rest, parsed) = x509_parser::certificate::X509Certificate::from_der(certificate)
            .map_err(|_| invalid())?;
        let san = parsed.subject_alternative_name().map_err(|_| invalid())?
            .ok_or_else(invalid)?;
        if !rest.is_empty()
            || san.value.general_names.len() != 1
            || !matches!(&san.value.general_names[0], GeneralName::DNSName(name) if *name == peer_id)
            || identity.identity_id().map_err(|_| PairingTlsError::InvalidLocalIdentity)? == peer_id
        {
            return Err(invalid());
        }
        if identity.revoked.contains(peer_id) {
            return Err(PairingTlsError::RevokedPeer);
        }
        if let Some(existing) = identity.trusted.get(peer_id) {
            return Err(if existing.as_slice() == certificate {
                PairingTlsError::AlreadyPaired
            } else {
                PairingTlsError::ConflictingTrust
            });
        }
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(certificate.to_vec())).map_err(|_| invalid())?;
        let roots = Arc::new(roots);
        let mut client = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(Arc::clone(&roots))
            .with_client_auth_cert(identity.cert_chain(), identity.key().map_err(|_| PairingTlsError::InvalidLocalIdentity)?)
            .map_err(|_| PairingTlsError::InvalidLocalIdentity)?;
        client.alpn_protocols = vec![ALPN.to_vec()];
        client.resumption = rustls::client::Resumption::disabled();
        let verifier = rustls::server::WebPkiClientVerifier::builder(roots)
            .build().map_err(|_| invalid())?;
        let mut server = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_client_cert_verifier(verifier)
            .with_single_cert(identity.cert_chain(), identity.key().map_err(|_| PairingTlsError::InvalidLocalIdentity)?)
            .map_err(|_| PairingTlsError::InvalidLocalIdentity)?;
        server.alpn_protocols = vec![ALPN.to_vec()];
        server.send_tls13_tickets = 0;
        Ok(Self {
            peer_id: peer_id.into(),
            certificate: certificate.to_vec(),
            client: Arc::new(client),
            server: Arc::new(server),
        })
    }

    pub fn connect<T: Read + Write>(
        &self,
        mut io: T,
    ) -> Result<StreamOwned<ClientConnection, T>, PairingTlsError> {
        let name = peer_server_name(&self.peer_id).map_err(|_| PairingTlsError::InvalidCandidate)?;
        let mut connection = ClientConnection::new(Arc::clone(&self.client), name)
            .map_err(|_| PairingTlsError::Tls)?;
        connection.complete_io(&mut io).map_err(|_| PairingTlsError::Tls)?;
        self.check(connection.peer_certificates(), connection.alpn_protocol())?;
        Ok(StreamOwned::new(connection, io))
    }

    pub fn accept<T: Read + Write>(
        &self,
        mut io: T,
    ) -> Result<StreamOwned<ServerConnection, T>, PairingTlsError> {
        let mut connection = ServerConnection::new(Arc::clone(&self.server))
            .map_err(|_| PairingTlsError::Tls)?;
        connection.complete_io(&mut io).map_err(|_| PairingTlsError::Tls)?;
        self.check(connection.peer_certificates(), connection.alpn_protocol())?;
        Ok(StreamOwned::new(connection, io))
    }

    fn check(
        &self,
        certificates: Option<&[CertificateDer<'_>]>,
        protocol: Option<&[u8]>,
    ) -> Result<(), PairingTlsError> {
        if certificates.and_then(|chain| chain.first()).map(|cert| cert.as_ref())
            != Some(self.certificate.as_slice())
        {
            return Err(PairingTlsError::PinMismatch);
        }
        if protocol != Some(ALPN) {
            return Err(PairingTlsError::WrongProtocol);
        }
        Ok(())
    }
}
```

The existing `identity.key()` error is mapped explicitly to `InvalidLocalIdentity` at both configuration call sites.

- [ ] Run the focused test to GREEN and existing `cargo test -p devicelane --test secure_transport --test pairing_listener --locked --jobs 1`.
- [ ] Execute Task 2 before marking this unit complete.
- [ ] Independent spec review, then quality/security review. Fix findings and repeat affected tests.
- [ ] `cargo clippy -p devicelane --lib --test pairing_tls --locked -- -D warnings`, `cargo fmt --all -- --check`, `git diff --check`.
- [ ] Stage only new module, test and plan, plus the isolated module declaration in `src/lib.rs`. Review the staged diff before a scoped commit. No deployment or complete-pairing claim.


### Task 2: Real adversarial TLS fixtures

- [ ] Append these helpers and tests to the same test file. Before accepting GREEN, temporarily remove each post-handshake exact-pin check and ALPN check and verify the relevant tests fail, then restore checks. These negative mutations are scoped to the new module only.

```rust
use rustls::{
    ClientConfig, ClientConnection, ServerConfig, ServerConnection, RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
};
use std::{path::Path, sync::Arc};

fn roots(certificate: &[u8]) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(certificate.to_vec())).unwrap();
    roots
}

fn key(path: &Path) -> PrivateKeyDer<'static> {
    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        std::fs::read(path.join("private-key.der")).unwrap()
    ))
}

fn raw_client(root: &[u8], chain: Vec<CertificateDer<'static>>, key: PrivateKeyDer<'static>, alpn: bool) -> ClientConfig {
    let mut config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots(root)).with_client_auth_cert(chain, key).unwrap();
    config.alpn_protocols = if alpn { vec![b"devicelane-pairing/1".to_vec()] } else { vec![] };
    config
}

fn raw_server(root: &[u8], chain: Vec<CertificateDer<'static>>, key: PrivateKeyDer<'static>, alpn: bool) -> ServerConfig {
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots(root))).build().unwrap();
    let mut config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_client_cert_verifier(verifier).with_single_cert(chain, key).unwrap();
    config.alpn_protocols = if alpn { vec![b"devicelane-pairing/1".to_vec()] } else { vec![] };
    config
}

fn against_raw_client(server: PairingTls, config: ClientConfig) -> Result<(), PairingTlsError> {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let worker = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        server.accept(socket(stream)).map(|_| ())
    });
    let mut io = socket(TcpStream::connect_timeout(&address, Duration::from_secs(3)).unwrap());
    let mut connection = ClientConnection::new(Arc::new(config), ServerName::try_from("server").unwrap()).unwrap();
    let _ = connection.complete_io(&mut io);
    drop(io);
    worker.join().unwrap()
}

fn against_raw_server(client: PairingTls, config: ServerConfig) -> Result<(), PairingTlsError> {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let worker = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut io = socket(stream);
        let mut connection = ServerConnection::new(Arc::new(config)).unwrap();
        let _ = connection.complete_io(&mut io);
    });
    let io = socket(TcpStream::connect_timeout(&address, Duration::from_secs(3)).unwrap());
    let result = client.connect(io).map(|_| ());
    worker.join().unwrap();
    result
}

fn ca_descendant(id: &str) -> (Vec<u8>, Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec![id.into()]).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = params.self_signed(&ca_key).unwrap();
    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let leaf = rcgen::CertificateParams::new(vec![id.into()]).unwrap()
        .signed_by(&leaf_key, &ca, &ca_key).unwrap();
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
    let server = raw_server(client.certificate_der(), chain, leaf_key, true);
    assert_eq!(against_raw_server(pairing, server), Err(PairingTlsError::PinMismatch));
    assert_eq!(std::fs::read_dir(root.path().join("trust")).unwrap().count(), 0);
}

#[test]
fn exact_client_pin_rejects_an_otherwise_valid_ca_descendant() {
    let root = tempfile::tempdir().unwrap();
    let server = SecureTransport::load_or_create(root.path(), "server").unwrap();
    let (candidate, chain, leaf_key) = ca_descendant("client");
    let pairing = PairingTls::new(&server, "client", &candidate).unwrap();
    let client = raw_client(server.certificate_der(), chain, leaf_key, true);
    assert_eq!(against_raw_client(pairing, client), Err(PairingTlsError::PinMismatch));
    assert_eq!(std::fs::read_dir(root.path().join("trust")).unwrap().count(), 0);
}

#[test]
fn missing_pairing_alpn_is_rejected_in_both_directions() {
    let root = tempfile::tempdir().unwrap();
    let server_path = root.path().join("server");
    let client_path = root.path().join("client");
    let server = SecureTransport::load_or_create(&server_path, "server").unwrap();
    let client = SecureTransport::load_or_create(&client_path, "client").unwrap();
    let server_pairing = PairingTls::new(&server, "client", client.certificate_der()).unwrap();
    let raw = raw_client(server.certificate_der(), vec![CertificateDer::from(client.certificate_der().to_vec())], key(&client_path), false);
    assert_eq!(against_raw_client(server_pairing, raw), Err(PairingTlsError::WrongProtocol));
    let client_pairing = PairingTls::new(&client, "server", server.certificate_der()).unwrap();
    let raw = raw_server(client.certificate_der(), vec![CertificateDer::from(server.certificate_der().to_vec())], key(&server_path), false);
    assert_eq!(against_raw_server(client_pairing, raw), Err(PairingTlsError::WrongProtocol));
}

#[derive(Debug)]
struct MismatchedKey(Arc<rustls::sign::CertifiedKey>);
impl rustls::client::ResolvesClientCert for MismatchedKey {
    fn resolve(&self, _: &[&[u8]], _: &[rustls::SignatureScheme]) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }
    fn has_certs(&self) -> bool { true }
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
        vec![CertificateDer::from(client.certificate_der().to_vec())], signer,
    );
    let mut config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots(server.certificate_der()))
        .with_client_cert_resolver(Arc::new(MismatchedKey(Arc::new(mismatch))));
    config.alpn_protocols = vec![b"devicelane-pairing/1".to_vec()];
    let pairing = PairingTls::new(&server, "client", client.certificate_der()).unwrap();
    assert_eq!(against_raw_client(pairing, config), Err(PairingTlsError::Tls));
    assert_eq!(std::fs::read_dir(root.path().join("server/trust")).unwrap().count(), 0);
}

#[test]
fn unrelated_existing_trust_is_not_a_session_root() {
    let root = tempfile::tempdir().unwrap();
    let mut server = SecureTransport::load_or_create(root.path().join("server"), "server").unwrap();
    let candidate = SecureTransport::load_or_create(root.path().join("candidate"), "candidate").unwrap();
    let other_path = root.path().join("other");
    let other = SecureTransport::load_or_create(&other_path, "other").unwrap();
    server.trust("other", other.certificate_der()).unwrap();
    let pairing = PairingTls::new(&server, "candidate", candidate.certificate_der()).unwrap();
    let config = raw_client(server.certificate_der(), vec![CertificateDer::from(other.certificate_der().to_vec())], key(&other_path), true);
    assert_eq!(against_raw_client(pairing, config), Err(PairingTlsError::Tls));
    assert_eq!(std::fs::read(root.path().join("server/trust/other.der")).unwrap(), other.certificate_der());
}

#[test]
fn multiple_dns_identities_are_rejected() {
    let root = tempfile::tempdir().unwrap();
    let local = SecureTransport::load_or_create(root.path(), "local").unwrap();
    let peer = rcgen::generate_simple_self_signed(vec!["peer".into(), "alias".into()]).unwrap();
    assert_eq!(PairingTls::new(&local, "peer", peer.cert.der()).err(), Some(PairingTlsError::InvalidCandidate));
}
```

- [ ] Run `cargo test -p devicelane --test pairing_tls --locked --jobs 1`. Expected: all 8 tests pass after scoped implementation; exact PinMismatch and WrongProtocol results ensure the attack fixtures reach the intended check.
- [ ] If a fixture fails earlier with a TLS error, repair the fixture using the actual rustls/rcgen APIs and repeat; do not weaken the expected PinMismatch/WrongProtocol assertion.
- [ ] Apply the independent reviews and verification commands from Task 1 before any scoped commit.

## Evidence record

Parent worktree has frozen transport WIP; preserve it. Baseline pairing-listener tests passed (3/3) but do not cover this new trust boundary. The first implementer handoff left a constructor/error skeleton and the initial socket test; that is not a completed adapter or a verified GREEN result. Continue from the same execution handle/state, not by restarting a build solely because observation timed out.

Process correction: the first implementation attempt preceded captured behavioral RED evidence. It was discarded, not retained as the completed implementation. The implementer subsequently reported a direct executable run against the recreated skeleton: `candidate_only_tls_connects_without_persisting_trust` failed at constructor unwrap with `InvalidCandidate`, one failed test in 0.39 seconds. The later fresh implementation remains subject to the full validation/attack tests and independent verification; a preliminary one-test success is not completion evidence.

The test helper implementations above must use bounded listener acceptance and join workers on client failure/panic as required by the task handoff. Socket read/write timeouts alone do not bound a worker waiting in `accept`. Add a TLS-1.2-only peer regression before replacing the inherited default-version builders with the specified TLS-1.3-only builders.

Root independently ran `npm test -- --run src/components/ConnectionSettingsCard.test.tsx` in `desktop`: 6 passed, process exit 0. This confirms the existing settings editor baseline only, not the new pairing wizard or installed Windows/Mac behavior.

Primary API reference: [rustls configuration builder](https://docs.rs/rustls/latest/rustls/struct.ConfigBuilder.html). Normal client-certificate configuration and root verification are used; no dangerous verifier API.

### Root verification, 2026-09-06

- Final focused run completed with process exit 0: pairing listener 3/3, candidate TLS 10/10, existing secure transport 13/13. This verifies the primitive, not installed UI, daemon pairing, or Windows-to-Mac operation.
- TLS-version behavioral RED: with inherited default protocol versions, the TLS-1.2-only peer was accepted (`Ok(())` instead of `Err(Tls)`); 9 tests passed and that regression failed. Explicit TLS-1.3-only builders were then added. The final test exercises both directions.
- Exact-pin sensitivity: temporarily disabling only the leaf comparison made both CA-descendant tests fail with `Ok(())` instead of `Err(PinMismatch)`. The comparison was restored.
- ALPN sensitivity: temporarily disabling only the protocol check produced `(Ok(()), Ok(()))` instead of two `WrongProtocol` errors. Both directions were evaluated before assertion. The check was restored before the final passing run.
- Windows fixture correction: sockets accepted from a nonblocking listener inherited nonblocking mode. The helper now explicitly restores blocking mode before setting bounded socket I/O. Earlier handshake failures cannot all be attributed to the adapter loop: the fixture mode was a confounding factor.
- The first root Clippy check found two `obfuscated_if_else` warnings in test configuration helpers; the formatting check also found new-file differences. Both were corrected. Root reran scoped Clippy with `-D warnings` (exit 0) and workspace formatting verification (exit 0).
- Independent specification review found client setup could panic before joining test workers. Socket configuration now returns errors and `JoinOnDrop` joins on unwind; normal paths explicitly join and surface worker panics. The reviewer re-inspected and reported SPEC PASS. Root reran all 26 focused tests after this fix: all passed, exit 0.
- A separate read-only quality/security reviewer reported READY with no production defect found in this bounded adapter. A nonblocking test limitation remains: socket/accept setup failures in some raw-peer helpers can map to a generic `Tls` rejection and satisfy those assertions during infrastructure failure. Exact `PinMismatch` and `WrongProtocol` assertions cannot be satisfied by that setup failure. This limitation is retained explicitly rather than presenting generic rejection tests as complete proof of every intended failure cause. The review is not a security certification or a complete-product readiness claim.

Runtime integration remains required: the current `devicelane-service` role label does not itself start the registry worker. Pairing must authenticate the same certificate actually presented by the advertised registry endpoint. A separately keyed legacy registry is not evidence that daemon-owned onboarding works; no implicit key copying or trust migration is authorized by this primitive.

Provenance: AI-assisted implementation plan based on inspected code and an independent bounded design review. No human-authorship claim.
