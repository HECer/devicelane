use device_development_mesh::{
    local_ipc::DaemonRole,
    pairing_session::{
        PairingInvitationBinding, PairingPeer, PairingSession, PairingSessionError,
        PairingSessionId, PairingSessionState, PairingSessionTuple,
    },
};
use std::{
    net::{Ipv6Addr, SocketAddr, SocketAddrV6},
    time::{Duration, Instant},
};

fn certificate(identity: &str) -> Vec<u8> {
    rcgen::generate_simple_self_signed(vec![identity.to_owned()])
        .unwrap()
        .cert
        .der()
        .to_vec()
}

fn peer(identity: &str, role: DaemonRole, certificate: &[u8]) -> PairingPeer {
    PairingPeer::from_certificate(identity, role, certificate).unwrap()
}

fn tuple(
    id: u8,
    controller: PairingPeer,
    candidate: PairingPeer,
    pairing_endpoint: SocketAddr,
    registry_endpoint: SocketAddr,
) -> PairingSessionTuple {
    PairingSessionTuple::new(
        PairingSessionId::new([id; 16]),
        controller,
        candidate,
        pairing_endpoint,
        registry_endpoint,
    )
    .unwrap()
}

fn session(
    tuple: PairingSessionTuple,
    candidate_certificate: &[u8],
    now: Instant,
) -> PairingSession {
    let mut invitation = binding(&tuple, now, now + Duration::from_secs(120)).unwrap();
    PairingSession::new(&mut invitation, tuple, candidate_certificate, now).unwrap()
}

fn binding(
    tuple: &PairingSessionTuple,
    created_at: Instant,
    deadline: Instant,
) -> Result<PairingInvitationBinding, PairingSessionError> {
    PairingInvitationBinding::new(
        tuple.session_id(),
        tuple.controller().clone(),
        tuple.candidate().role(),
        tuple.pairing_endpoint(),
        tuple.registry_endpoint(),
        created_at,
        deadline,
    )
}

fn participants() -> (Vec<u8>, Vec<u8>, PairingPeer, PairingPeer) {
    let controller_certificate = certificate("controller");
    let candidate_certificate = certificate("candidate");
    let controller = peer(
        "controller",
        DaemonRole::Workstation,
        &controller_certificate,
    );
    let candidate = peer("candidate", DaemonRole::Agent, &candidate_certificate);
    (
        controller_certificate,
        candidate_certificate,
        controller,
        candidate,
    )
}

#[test]
fn persistence_requires_both_confirmations_for_the_exact_session_tuple() {
    let now = Instant::now();
    let (_, candidate_certificate, controller, candidate) = participants();
    let tuple = tuple(
        1,
        controller,
        candidate,
        "192.168.1.10:4444".parse().unwrap(),
        "192.168.1.10:8443".parse().unwrap(),
    );
    let mut session = session(tuple.clone(), &candidate_certificate, now);

    assert_eq!(session.state_at(now), PairingSessionState::CandidatePending);
    assert_eq!(
        session.confirm_peer(&tuple, &candidate_certificate, now),
        Ok(PairingSessionState::PeerConfirmed)
    );
    assert!(!session.ready_for_persistence(now));
    assert_eq!(
        session.confirm_local(&tuple, now),
        Ok(PairingSessionState::BothConfirmed)
    );
    assert!(session.ready_for_persistence(now));
}

#[test]
fn local_confirmation_first_still_requires_the_exact_peer_confirmation() {
    let now = Instant::now();
    let (_, candidate_certificate, controller, candidate) = participants();
    let tuple = tuple(
        16,
        controller,
        candidate,
        "192.168.1.10:4444".parse().unwrap(),
        "192.168.1.10:8443".parse().unwrap(),
    );
    let mut session = session(tuple.clone(), &candidate_certificate, now);

    assert_eq!(
        session.confirm_local(&tuple, now),
        Ok(PairingSessionState::LocallyConfirmed)
    );
    assert!(!session.ready_for_persistence(now));
    assert_eq!(
        session.confirm_peer(&tuple, &candidate_certificate, now),
        Ok(PairingSessionState::BothConfirmed)
    );
    assert!(session.ready_for_persistence(now));
}

#[test]
fn cancellation_and_either_peer_rejection_clear_the_session() {
    let now = Instant::now();
    let (_, candidate_certificate, controller, candidate) = participants();
    let tuple = tuple(
        17,
        controller,
        candidate,
        "192.168.1.10:4444".parse().unwrap(),
        "192.168.1.10:8443".parse().unwrap(),
    );

    let mut cancelled = session(tuple.clone(), &candidate_certificate, now);
    cancelled.cancel(now).unwrap();
    assert_eq!(cancelled.state_at(now), PairingSessionState::Cancelled);
    assert!(cancelled.tuple().is_none());
    assert!(!cancelled.ready_for_persistence(now));

    let mut local_rejection = session(tuple.clone(), &candidate_certificate, now);
    local_rejection.reject_local(&tuple, now).unwrap();
    assert_eq!(local_rejection.state_at(now), PairingSessionState::Rejected);
    assert!(local_rejection.tuple().is_none());

    let mut peer_rejection = session(tuple.clone(), &candidate_certificate, now);
    peer_rejection
        .reject_peer(&tuple, &candidate_certificate, now)
        .unwrap();
    assert_eq!(peer_rejection.state_at(now), PairingSessionState::Rejected);
    assert!(peer_rejection.tuple().is_none());
}

#[test]
fn a_changed_tuple_rejects_and_clears_the_candidate_session() {
    let now = Instant::now();
    let (_, candidate_certificate, controller, candidate) = participants();
    let original = tuple(
        2,
        controller.clone(),
        candidate.clone(),
        "192.168.1.10:4444".parse().unwrap(),
        "192.168.1.10:8443".parse().unwrap(),
    );
    let variants = [
        tuple(
            3,
            controller.clone(),
            candidate.clone(),
            "192.168.1.10:4444".parse().unwrap(),
            "192.168.1.10:8443".parse().unwrap(),
        ),
        tuple(
            2,
            peer(
                "controller",
                DaemonRole::Registry,
                &certificate("controller"),
            ),
            candidate.clone(),
            "192.168.1.10:4444".parse().unwrap(),
            "192.168.1.10:8443".parse().unwrap(),
        ),
        tuple(
            2,
            controller.clone(),
            peer("candidate", DaemonRole::Registry, &certificate("candidate")),
            "192.168.1.10:4444".parse().unwrap(),
            "192.168.1.10:8443".parse().unwrap(),
        ),
        tuple(
            2,
            controller.clone(),
            peer("candidate", DaemonRole::Agent, &certificate("candidate")),
            "192.168.1.10:4444".parse().unwrap(),
            "192.168.1.11:8443".parse().unwrap(),
        ),
        tuple(
            2,
            controller.clone(),
            peer(
                "replacement-candidate",
                DaemonRole::Agent,
                &certificate("replacement-candidate"),
            ),
            "192.168.1.10:4444".parse().unwrap(),
            "192.168.1.10:8443".parse().unwrap(),
        ),
        tuple(
            2,
            controller.clone(),
            candidate.clone(),
            "192.168.1.11:4444".parse().unwrap(),
            "192.168.1.10:8443".parse().unwrap(),
        ),
    ];

    for changed in variants {
        let mut session = session(original.clone(), &candidate_certificate, now);
        assert_eq!(
            session.confirm_local(&changed, now),
            Err(PairingSessionError::TupleMismatch)
        );
        assert_eq!(session.state_at(now), PairingSessionState::Rejected);
        assert!(session.tuple().is_none());
    }
}

#[test]
fn the_authenticated_remote_may_be_either_role_in_the_shared_tuple() {
    let now = Instant::now();
    let (controller_certificate, candidate_certificate, controller, candidate) = participants();
    let tuple = tuple(
        8,
        controller,
        candidate,
        "192.168.1.10:4444".parse().unwrap(),
        "192.168.1.10:8443".parse().unwrap(),
    );

    let mut controller_side = session(tuple.clone(), &candidate_certificate, now);
    let mut candidate_side = session(tuple, &controller_certificate, now);

    assert_eq!(
        controller_side.state_at(now),
        PairingSessionState::CandidatePending
    );
    assert_eq!(
        candidate_side.state_at(now),
        PairingSessionState::CandidatePending
    );
}

#[test]
fn candidate_tuple_must_match_controller_owned_invitation_fields() {
    let now = Instant::now();
    let (_, candidate_certificate, controller, candidate) = participants();
    let authoritative = tuple(
        11,
        controller.clone(),
        candidate.clone(),
        "192.168.1.10:4444".parse().unwrap(),
        "192.168.1.10:8443".parse().unwrap(),
    );
    let mut invitation = PairingInvitationBinding::new(
        authoritative.session_id(),
        controller,
        candidate.role(),
        authoritative.pairing_endpoint(),
        authoritative.registry_endpoint(),
        now,
        now + Duration::from_secs(120),
    )
    .unwrap();
    let altered = tuple(
        11,
        authoritative.controller().clone(),
        peer("candidate", DaemonRole::Registry, &candidate_certificate),
        authoritative.pairing_endpoint(),
        authoritative.registry_endpoint(),
    );

    assert_eq!(
        PairingSession::new(&mut invitation, altered, &candidate_certificate, now).err(),
        Some(PairingSessionError::InvalidInvitation)
    );
}

#[test]
fn an_invitation_binding_admits_only_one_candidate_session() {
    let now = Instant::now();
    let (_, candidate_certificate, controller, candidate) = participants();
    let tuple = tuple(
        12,
        controller,
        candidate,
        "192.168.1.10:4444".parse().unwrap(),
        "192.168.1.10:8443".parse().unwrap(),
    );
    let mut invitation = binding(&tuple, now, now + Duration::from_secs(120)).unwrap();

    let mut first =
        PairingSession::new(&mut invitation, tuple.clone(), &candidate_certificate, now).unwrap();
    first.channel_closed(now);
    assert_eq!(first.state_at(now), PairingSessionState::ChannelLost);
    assert_eq!(
        PairingSession::new(&mut invitation, tuple, &candidate_certificate, now).err(),
        Some(PairingSessionError::InvitationConsumed)
    );
}

#[test]
fn pairing_listener_endpoint_must_be_private_or_loopback() {
    let (_, _, controller, candidate) = participants();

    let result = PairingSessionTuple::new(
        PairingSessionId::new([9; 16]),
        controller,
        candidate,
        "8.8.8.8:4444".parse().unwrap(),
        "192.168.1.10:8443".parse().unwrap(),
    );

    assert_eq!(result.err(), Some(PairingSessionError::InvalidEndpoint));
}

#[test]
fn ipv6_scope_ids_are_only_valid_for_link_local_endpoints() {
    let (_, _, controller, candidate) = participants();
    let pairing_link_local = SocketAddr::V6(SocketAddrV6::new(
        "fe80::1".parse::<Ipv6Addr>().unwrap(),
        4444,
        0,
        3,
    ));
    let registry_link_local = SocketAddr::V6(SocketAddrV6::new(
        "fe80::2".parse::<Ipv6Addr>().unwrap(),
        8443,
        0,
        3,
    ));
    assert!(
        PairingSessionTuple::new(
            PairingSessionId::new([13; 16]),
            controller.clone(),
            candidate.clone(),
            pairing_link_local,
            registry_link_local,
        )
        .is_ok()
    );

    let scoped_ula = SocketAddr::V6(SocketAddrV6::new(
        "fd00::1".parse::<Ipv6Addr>().unwrap(),
        4444,
        0,
        3,
    ));
    assert_eq!(
        PairingSessionTuple::new(
            PairingSessionId::new([14; 16]),
            controller.clone(),
            candidate.clone(),
            scoped_ula,
            "192.168.1.10:8443".parse().unwrap(),
        )
        .err(),
        Some(PairingSessionError::InvalidEndpoint)
    );

    let scoped_global = SocketAddr::V6(SocketAddrV6::new(
        "2001:db8::1".parse::<Ipv6Addr>().unwrap(),
        8443,
        0,
        3,
    ));
    assert_eq!(
        PairingSessionTuple::new(
            PairingSessionId::new([15; 16]),
            controller,
            candidate,
            "192.168.1.10:4444".parse().unwrap(),
            scoped_global,
        )
        .err(),
        Some(PairingSessionError::InvalidEndpoint)
    );
}

#[test]
fn authenticated_candidate_must_match_the_certificate_in_the_tuple() {
    let now = Instant::now();
    let (_, candidate_certificate, controller, candidate) = participants();
    let tuple = tuple(
        4,
        controller,
        candidate,
        "192.168.1.10:4444".parse().unwrap(),
        "192.168.1.10:8443".parse().unwrap(),
    );
    let replacement_certificate = certificate("candidate");

    assert_eq!(
        PairingSession::new(
            &mut binding(&tuple, now, now + Duration::from_secs(120)).unwrap(),
            tuple,
            &replacement_certificate,
            now,
        )
        .err(),
        Some(PairingSessionError::AuthenticatedPeerMismatch)
    );
    assert_ne!(candidate_certificate, replacement_certificate);
}

#[test]
fn expiration_clears_the_candidate_and_prevents_confirmation() {
    let now = Instant::now();
    let (_, candidate_certificate, controller, candidate) = participants();
    let tuple = tuple(
        5,
        controller,
        candidate,
        "192.168.1.10:4444".parse().unwrap(),
        "192.168.1.10:8443".parse().unwrap(),
    );
    let mut session = session(tuple.clone(), &candidate_certificate, now);
    let expired_at = now + Duration::from_secs(120);

    assert_eq!(session.state_at(expired_at), PairingSessionState::Expired);
    assert_eq!(
        session.confirm_local(&tuple, expired_at),
        Err(PairingSessionError::Expired)
    );
    assert!(session.tuple().is_none());
    assert!(!session.ready_for_persistence(expired_at));
}

#[test]
fn the_session_deadline_cannot_exceed_two_minutes() {
    let now = Instant::now();
    let (_, _, controller, candidate) = participants();
    let tuple = tuple(
        6,
        controller,
        candidate,
        "192.168.1.10:4444".parse().unwrap(),
        "192.168.1.10:8443".parse().unwrap(),
    );

    assert_eq!(
        binding(&tuple, now, now + Duration::from_secs(121)).err(),
        Some(PairingSessionError::InvalidDeadline)
    );
}

#[test]
fn losing_the_authenticated_channel_terminates_the_session() {
    let now = Instant::now();
    let (_, candidate_certificate, controller, candidate) = participants();
    let tuple = tuple(
        7,
        controller,
        candidate,
        "192.168.1.10:4444".parse().unwrap(),
        "192.168.1.10:8443".parse().unwrap(),
    );
    let mut session = session(tuple.clone(), &candidate_certificate, now);

    session.channel_closed(now);

    assert_eq!(session.state_at(now), PairingSessionState::ChannelLost);
    assert_eq!(
        session.confirm_peer(&tuple, &candidate_certificate, now),
        Err(PairingSessionError::SessionClosed)
    );
    assert!(session.tuple().is_none());
}
