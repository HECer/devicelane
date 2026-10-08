//! In-memory approval state for one authenticated pairing channel.
//!
//! The caller must create a session only after candidate-only TLS has verified both exact leaf
//! pins and the pairing ALPN. Local approval must come from the authenticated local IPC path. The
//! caller must terminate the session when that pinned channel closes. This module never mutates
//! trust or persistent configuration.

use crate::{local_ipc::DaemonRole, secure_transport::peer_server_name};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::{Duration, Instant},
};
use x509_parser::{extensions::GeneralName, prelude::FromDer};

pub const MAX_PAIRING_SESSION_LIFETIME: Duration = Duration::from_secs(120);
const MAX_CERTIFICATE_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingSessionError {
    InvalidPeerIdentity,
    InvalidEndpoint,
    SamePeer,
    InvalidInvitation,
    InvitationConsumed,
    AuthenticatedPeerMismatch,
    InvalidDeadline,
    Expired,
    TupleMismatch,
    SessionClosed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct PairingSessionId([u8; 16]);

impl PairingSessionId {
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub fn random() -> Self {
        let mut bytes = [0; 16];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairingPeer {
    identity_id: String,
    certificate_sha256: [u8; 32],
    role: DaemonRole,
}

impl PairingPeer {
    /// Binds the stable identity and role to the exact certificate DER bytes.
    pub fn from_certificate(
        identity_id: &str,
        role: DaemonRole,
        certificate_der: &[u8],
    ) -> Result<Self, PairingSessionError> {
        if certificate_der.is_empty()
            || certificate_der.len() > MAX_CERTIFICATE_BYTES
            || peer_server_name(identity_id).is_err()
        {
            return Err(PairingSessionError::InvalidPeerIdentity);
        }

        let (remaining, certificate) =
            x509_parser::certificate::X509Certificate::from_der(certificate_der)
                .map_err(|_| PairingSessionError::InvalidPeerIdentity)?;
        let subject_alt_name = certificate
            .subject_alternative_name()
            .map_err(|_| PairingSessionError::InvalidPeerIdentity)?
            .ok_or(PairingSessionError::InvalidPeerIdentity)?;
        if !remaining.is_empty()
            || subject_alt_name.value.general_names.len() != 1
            || !matches!(
                &subject_alt_name.value.general_names[0],
                GeneralName::DNSName(name) if *name == identity_id
            )
        {
            return Err(PairingSessionError::InvalidPeerIdentity);
        }

        Ok(Self {
            identity_id: identity_id.to_owned(),
            certificate_sha256: Sha256::digest(certificate_der).into(),
            role,
        })
    }

    pub fn identity_id(&self) -> &str {
        &self.identity_id
    }

    pub fn certificate_sha256(&self) -> &[u8; 32] {
        &self.certificate_sha256
    }

    pub const fn role(&self) -> DaemonRole {
        self.role
    }
}

/// Immutable identities, roles, and numeric endpoints approved by both pairing peers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairingSessionTuple {
    protocol_version: u16,
    session_id: PairingSessionId,
    controller: PairingPeer,
    candidate: PairingPeer,
    pairing_endpoint: SocketAddr,
    registry_endpoint: SocketAddr,
}

impl PairingSessionTuple {
    pub fn new(
        session_id: PairingSessionId,
        controller: PairingPeer,
        candidate: PairingPeer,
        pairing_endpoint: SocketAddr,
        registry_endpoint: SocketAddr,
    ) -> Result<Self, PairingSessionError> {
        if controller.identity_id == candidate.identity_id
            || controller.certificate_sha256 == candidate.certificate_sha256
        {
            return Err(PairingSessionError::SamePeer);
        }
        if !valid_pairing_endpoint(pairing_endpoint) || !valid_registry_endpoint(registry_endpoint)
        {
            return Err(PairingSessionError::InvalidEndpoint);
        }

        Ok(Self {
            protocol_version: 1,
            session_id,
            controller,
            candidate,
            pairing_endpoint,
            registry_endpoint,
        })
    }

    pub const fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    pub const fn session_id(&self) -> PairingSessionId {
        self.session_id
    }

    pub fn controller(&self) -> &PairingPeer {
        &self.controller
    }

    pub fn candidate(&self) -> &PairingPeer {
        &self.candidate
    }

    pub const fn pairing_endpoint(&self) -> SocketAddr {
        self.pairing_endpoint
    }

    pub const fn registry_endpoint(&self) -> SocketAddr {
        self.registry_endpoint
    }
}

/// Controller-authoritative fields fixed when an invitation is created or imported.
#[derive(Debug, Eq, PartialEq)]
pub struct PairingInvitationBinding {
    session_id: PairingSessionId,
    controller: PairingPeer,
    candidate_role: DaemonRole,
    pairing_endpoint: SocketAddr,
    registry_endpoint: SocketAddr,
    created_at: Instant,
    deadline: Instant,
    candidate_claimed: bool,
}

impl PairingInvitationBinding {
    pub fn new(
        session_id: PairingSessionId,
        controller: PairingPeer,
        candidate_role: DaemonRole,
        pairing_endpoint: SocketAddr,
        registry_endpoint: SocketAddr,
        created_at: Instant,
        deadline: Instant,
    ) -> Result<Self, PairingSessionError> {
        if !valid_pairing_endpoint(pairing_endpoint) || !valid_registry_endpoint(registry_endpoint)
        {
            return Err(PairingSessionError::InvalidEndpoint);
        }
        if deadline <= created_at
            || deadline.duration_since(created_at) > MAX_PAIRING_SESSION_LIFETIME
        {
            return Err(PairingSessionError::InvalidDeadline);
        }

        Ok(Self {
            session_id,
            controller,
            candidate_role,
            pairing_endpoint,
            registry_endpoint,
            created_at,
            deadline,
            candidate_claimed: false,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingSessionState {
    CandidatePending,
    LocallyConfirmed,
    PeerConfirmed,
    BothConfirmed,
    Rejected,
    Cancelled,
    Expired,
    ChannelLost,
}

pub struct PairingSession {
    session_id: PairingSessionId,
    tuple: Option<PairingSessionTuple>,
    authenticated_peer: Option<PairingPeer>,
    state: PairingSessionState,
    deadline: Instant,
}

impl PairingSession {
    /// Starts the in-memory approval phase for the exact remote leaf authenticated by TLS.
    /// `created_at` and `deadline` must come from the controller-owned invitation.
    pub fn new(
        invitation: &mut PairingInvitationBinding,
        tuple: PairingSessionTuple,
        authenticated_peer_certificate: &[u8],
        now: Instant,
    ) -> Result<Self, PairingSessionError> {
        if invitation.session_id != tuple.session_id
            || invitation.controller != tuple.controller
            || invitation.candidate_role != tuple.candidate.role
            || invitation.pairing_endpoint != tuple.pairing_endpoint
            || invitation.registry_endpoint != tuple.registry_endpoint
        {
            return Err(PairingSessionError::InvalidInvitation);
        }
        if now < invitation.created_at {
            return Err(PairingSessionError::InvalidDeadline);
        }
        if now >= invitation.deadline {
            return Err(PairingSessionError::Expired);
        }
        if invitation.candidate_claimed {
            return Err(PairingSessionError::InvitationConsumed);
        }

        let authenticated_peer = [&tuple.controller, &tuple.candidate]
            .into_iter()
            .find_map(|peer| {
                let authenticated = PairingPeer::from_certificate(
                    peer.identity_id(),
                    peer.role(),
                    authenticated_peer_certificate,
                )
                .ok()?;
                (authenticated == *peer).then_some(authenticated)
            })
            .ok_or(PairingSessionError::AuthenticatedPeerMismatch)?;
        invitation.candidate_claimed = true;

        Ok(Self {
            session_id: invitation.session_id,
            tuple: Some(tuple),
            authenticated_peer: Some(authenticated_peer),
            state: PairingSessionState::CandidatePending,
            deadline: invitation.deadline,
        })
    }

    pub const fn session_id(&self) -> PairingSessionId {
        self.session_id
    }

    pub fn tuple(&self) -> Option<&PairingSessionTuple> {
        self.tuple.as_ref()
    }

    /// Returns the state at a monotonic time, expiring and clearing candidates as needed.
    pub fn state_at(&mut self, now: Instant) -> PairingSessionState {
        if is_open(self.state) && now >= self.deadline {
            self.terminate(PairingSessionState::Expired);
        }
        self.state
    }

    /// Records exact local approval. The caller must first authenticate and authorize the local
    /// IPC request and show the complete tuple to the user.
    pub fn confirm_local(
        &mut self,
        approved: &PairingSessionTuple,
        now: Instant,
    ) -> Result<PairingSessionState, PairingSessionError> {
        let state = self.state_at(now);
        self.require_open(state)?;
        if self.tuple.as_ref() != Some(approved) {
            self.terminate(PairingSessionState::Rejected);
            return Err(PairingSessionError::TupleMismatch);
        }
        if state == PairingSessionState::BothConfirmed {
            return Ok(state);
        }

        self.state = if state == PairingSessionState::PeerConfirmed {
            PairingSessionState::BothConfirmed
        } else {
            PairingSessionState::LocallyConfirmed
        };
        Ok(self.state)
    }

    /// Records confirmation from the already pinned remote peer on the same live pairing channel.
    pub fn confirm_peer(
        &mut self,
        confirmation: &PairingSessionTuple,
        authenticated_peer_certificate: &[u8],
        now: Instant,
    ) -> Result<PairingSessionState, PairingSessionError> {
        let state = self.state_at(now);
        self.require_open(state)?;
        if self.tuple.as_ref() != Some(confirmation) {
            self.terminate(PairingSessionState::Rejected);
            return Err(PairingSessionError::TupleMismatch);
        }

        let Some(pinned_peer) = self.authenticated_peer.as_ref() else {
            return Err(PairingSessionError::SessionClosed);
        };
        let authenticated_peer = PairingPeer::from_certificate(
            pinned_peer.identity_id(),
            pinned_peer.role(),
            authenticated_peer_certificate,
        )
        .ok();
        if authenticated_peer.as_ref() != Some(pinned_peer) {
            self.terminate(PairingSessionState::Rejected);
            return Err(PairingSessionError::AuthenticatedPeerMismatch);
        }
        if state == PairingSessionState::BothConfirmed
            || state == PairingSessionState::PeerConfirmed
        {
            return Ok(state);
        }

        self.state = if state == PairingSessionState::LocallyConfirmed {
            PairingSessionState::BothConfirmed
        } else {
            PairingSessionState::PeerConfirmed
        };
        Ok(self.state)
    }

    /// Indicates that the caller may begin audited persistence after its own revocation and
    /// trust-state revalidation. It does not itself change trust.
    pub fn ready_for_persistence(&mut self, now: Instant) -> bool {
        self.state_at(now) == PairingSessionState::BothConfirmed
    }

    pub fn cancel(&mut self, now: Instant) -> Result<(), PairingSessionError> {
        let state = self.state_at(now);
        self.require_open(state)?;
        self.terminate(PairingSessionState::Cancelled);
        Ok(())
    }

    pub fn reject_local(
        &mut self,
        reviewed: &PairingSessionTuple,
        now: Instant,
    ) -> Result<(), PairingSessionError> {
        let state = self.state_at(now);
        self.require_open(state)?;
        if self.tuple.as_ref() != Some(reviewed) {
            self.terminate(PairingSessionState::Rejected);
            return Err(PairingSessionError::TupleMismatch);
        }
        self.terminate(PairingSessionState::Rejected);
        Ok(())
    }

    pub fn reject_peer(
        &mut self,
        rejection: &PairingSessionTuple,
        authenticated_peer_certificate: &[u8],
        now: Instant,
    ) -> Result<(), PairingSessionError> {
        let state = self.state_at(now);
        self.require_open(state)?;
        if self.tuple.as_ref() != Some(rejection) {
            self.terminate(PairingSessionState::Rejected);
            return Err(PairingSessionError::TupleMismatch);
        }
        let Some(pinned_peer) = self.authenticated_peer.as_ref() else {
            return Err(PairingSessionError::SessionClosed);
        };
        let authenticated_peer = PairingPeer::from_certificate(
            pinned_peer.identity_id(),
            pinned_peer.role(),
            authenticated_peer_certificate,
        )
        .ok();
        if authenticated_peer.as_ref() != Some(pinned_peer) {
            self.terminate(PairingSessionState::Rejected);
            return Err(PairingSessionError::AuthenticatedPeerMismatch);
        }
        self.terminate(PairingSessionState::Rejected);
        Ok(())
    }

    /// The caller must invoke this on loss of the authenticated pairing channel, including after
    /// either side confirmed. A new invitation is required to resume.
    pub fn channel_closed(&mut self, now: Instant) {
        let state = self.state_at(now);
        if is_open(state) {
            self.terminate(PairingSessionState::ChannelLost);
        }
    }

    fn require_open(&self, state: PairingSessionState) -> Result<(), PairingSessionError> {
        match state {
            PairingSessionState::Expired => Err(PairingSessionError::Expired),
            state if is_open(state) => Ok(()),
            _ => Err(PairingSessionError::SessionClosed),
        }
    }

    fn terminate(&mut self, state: PairingSessionState) {
        self.tuple = None;
        self.authenticated_peer = None;
        self.state = state;
    }
}

fn is_open(state: PairingSessionState) -> bool {
    matches!(
        state,
        PairingSessionState::CandidatePending
            | PairingSessionState::LocallyConfirmed
            | PairingSessionState::PeerConfirmed
            | PairingSessionState::BothConfirmed
    )
}

fn valid_pairing_endpoint(endpoint: SocketAddr) -> bool {
    if endpoint.port() == 0 || !valid_scope(endpoint) || !canonical_flow_info(endpoint) {
        return false;
    }
    match endpoint.ip() {
        IpAddr::V4(ip) => is_private_or_loopback_v4(ip),
        IpAddr::V6(ip) => is_private_or_loopback_v6(ip, endpoint),
    }
}

fn valid_registry_endpoint(endpoint: SocketAddr) -> bool {
    endpoint.port() != 0
        && !endpoint.ip().is_unspecified()
        && !endpoint.ip().is_multicast()
        && valid_scope(endpoint)
        && canonical_flow_info(endpoint)
}

fn is_private_or_loopback_v4(ip: Ipv4Addr) -> bool {
    ip.is_private() || ip.is_loopback() || (ip.octets()[0] == 169 && ip.octets()[1] == 254)
}

fn is_private_or_loopback_v6(ip: Ipv6Addr, endpoint: SocketAddr) -> bool {
    ip.is_loopback() || ip.is_unique_local() || (ip.is_unicast_link_local() && has_scope(endpoint))
}

fn valid_scope(endpoint: SocketAddr) -> bool {
    match endpoint {
        SocketAddr::V6(address) if address.ip().is_unicast_link_local() => address.scope_id() != 0,
        SocketAddr::V6(address) => address.scope_id() == 0,
        _ => true,
    }
}

fn has_scope(endpoint: SocketAddr) -> bool {
    matches!(endpoint, SocketAddr::V6(address) if address.scope_id() != 0)
}

fn canonical_flow_info(endpoint: SocketAddr) -> bool {
    !matches!(endpoint, SocketAddr::V6(address) if address.flowinfo() != 0)
}
