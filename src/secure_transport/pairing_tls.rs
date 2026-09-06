//! Candidate-only TLS for a single pairing attempt.
//!
//! This adapter neither makes a trust decision nor completes pairing. Callers must provide
//! deadline-bounded I/O and independently enforce absolute session deadlines, local approval,
//! auditing, and any durable trust commit.

use super::{SecureTransport, peer_server_name, valid_machine_id};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
    pki_types::CertificateDer,
};
use std::{
    io::{Read, Write},
    sync::Arc,
};
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

/// TLS configurations for exactly one candidate certificate.
///
/// It owns no path, persistent trust state, RPC access, or exposed private-key bytes.
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
        if peer_id.is_empty()
            || peer_id.len() > 253
            || certificate.is_empty()
            || certificate.len() > MAX_CERTIFICATE_BYTES
            || !valid_machine_id(peer_id)
        {
            return Err(invalid());
        }
        peer_server_name(peer_id).map_err(|_| invalid())?;
        let (remaining, parsed) = x509_parser::certificate::X509Certificate::from_der(certificate)
            .map_err(|_| invalid())?;
        let san = parsed
            .subject_alternative_name()
            .map_err(|_| invalid())?
            .ok_or_else(invalid)?;
        if !remaining.is_empty()
            || san.value.general_names.len() != 1
            || !matches!(&san.value.general_names[0], GeneralName::DNSName(name) if *name == peer_id)
            || identity
                .identity_id()
                .map_err(|_| PairingTlsError::InvalidLocalIdentity)?
                == peer_id
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
        roots
            .add(CertificateDer::from(certificate.to_vec()))
            .map_err(|_| invalid())?;
        let roots = Arc::new(roots);
        let private_key = identity
            .key()
            .map_err(|_| PairingTlsError::InvalidLocalIdentity)?;
        let mut client = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(Arc::clone(&roots))
            .with_client_auth_cert(identity.cert_chain(), private_key)
            .map_err(|_| PairingTlsError::InvalidLocalIdentity)?;
        client.alpn_protocols = vec![ALPN.to_vec()];
        client.resumption = rustls::client::Resumption::disabled();

        let verifier = rustls::server::WebPkiClientVerifier::builder(roots)
            .build()
            .map_err(|_| invalid())?;
        let private_key = identity
            .key()
            .map_err(|_| PairingTlsError::InvalidLocalIdentity)?;
        let mut server = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_client_cert_verifier(verifier)
            .with_single_cert(identity.cert_chain(), private_key)
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
        let name =
            peer_server_name(&self.peer_id).map_err(|_| PairingTlsError::InvalidCandidate)?;
        let mut connection = ClientConnection::new(Arc::clone(&self.client), name)
            .map_err(|_| PairingTlsError::Tls)?;
        while connection.is_handshaking() {
            let progress = connection
                .complete_io(&mut io)
                .map_err(|_| PairingTlsError::Tls)?;
            if progress == (0, 0) {
                return Err(PairingTlsError::Tls);
            }
        }
        self.check(connection.peer_certificates(), connection.alpn_protocol())?;
        Ok(StreamOwned::new(connection, io))
    }

    pub fn accept<T: Read + Write>(
        &self,
        mut io: T,
    ) -> Result<StreamOwned<ServerConnection, T>, PairingTlsError> {
        let mut connection =
            ServerConnection::new(Arc::clone(&self.server)).map_err(|_| PairingTlsError::Tls)?;
        while connection.is_handshaking() {
            let progress = connection
                .complete_io(&mut io)
                .map_err(|_| PairingTlsError::Tls)?;
            if progress == (0, 0) {
                return Err(PairingTlsError::Tls);
            }
        }
        self.check(connection.peer_certificates(), connection.alpn_protocol())?;
        Ok(StreamOwned::new(connection, io))
    }

    fn check(
        &self,
        certificates: Option<&[CertificateDer<'_>]>,
        protocol: Option<&[u8]>,
    ) -> Result<(), PairingTlsError> {
        if certificates
            .and_then(|chain| chain.first())
            .map(|certificate| certificate.as_ref())
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
