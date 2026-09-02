use device_development_mesh::dashboard::topology::{
    DeviceDetails, LeaseState, RegistryHost, TopologyErrorKind, TopologyProjector,
};
use device_development_mesh::dashboard::{
    ConnectionPath, DashboardScope, Freshness, HostId, Presence, TrustState,
};
use device_development_mesh::network_processes::{DeviceSnapshot, HostSnapshot};

fn host(id: &str, status: &str, devices: &[(&str, &str, &str)]) -> HostSnapshot {
    HostSnapshot {
        id: id.into(),
        operating_system: "macOS".into(),
        architecture: "arm64".into(),
        status: status.into(),
        capabilities: vec!["xcode_test".into(), "xcode_build".into()],
        devices: devices
            .iter()
            .map(|(id, platform, state)| DeviceSnapshot {
                id: (*id).into(),
                platform: (*platform).into(),
                state: (*state).into(),
            })
            .collect(),
    }
}

fn registry_host(id: &str, devices: &[(&str, &str, &str)]) -> RegistryHost {
    RegistryHost {
        snapshot: host(id, "online", devices),
        display_name: format!("Remote {id}"),
        trust: TrustState::Trusted,
        connection_path: ConnectionPath::Registry,
        permissions: vec!["screen_capture".into()],
        devices: devices
            .iter()
            .map(|(id, _, _)| DeviceDetails {
                id: (*id).into(),
                display_name: format!("Device {id}"),
                capabilities: vec!["debugger".into()],
                permissions: vec!["developer_mode".into()],
            })
            .collect(),
    }
}

fn connect(projector: &mut TopologyProjector, session: &str, epoch: u64) {
    projector.connect_registry(session, epoch, true).unwrap();
}

#[test]
fn normalized_snapshot_text_is_bounded_before_normalization() {
    let mut oversized_os = host("local", "online", &[]);
    oversized_os.operating_system = format!("{}linux", " ".repeat(128));
    let mut projector = TopologyProjector::new();
    assert_eq!(
        projector
            .observe_local(1, 1, oversized_os)
            .unwrap_err()
            .kind(),
        TopologyErrorKind::InvalidField
    );

    let mut oversized_arch = host("local", "online", &[]);
    oversized_arch.architecture = format!("{}arm64", " ".repeat(128));
    assert_eq!(
        projector
            .observe_local(1, 1, oversized_arch)
            .unwrap_err()
            .kind(),
        TopologyErrorKind::InvalidField
    );

    let mut oversized_status = host("local", "online", &[]);
    oversized_status.status = format!("{}online", " ".repeat(4096));
    assert_eq!(
        projector
            .observe_local(1, 1, oversized_status)
            .unwrap_err()
            .kind(),
        TopologyErrorKind::InvalidField
    );

    let mut oversized_device = host("local", "online", &[("phone", "iOS", "online")]);
    oversized_device.devices[0].platform = format!("{}ios", " ".repeat(128));
    assert_eq!(
        projector
            .observe_local(1, 1, oversized_device)
            .unwrap_err()
            .kind(),
        TopologyErrorKind::InvalidField
    );

    let mut oversized_device_state = host("local", "online", &[("phone", "iOS", "online")]);
    oversized_device_state.devices[0].state = format!("{}online", " ".repeat(4096));
    assert_eq!(
        projector
            .observe_local(1, 1, oversized_device_state)
            .unwrap_err()
            .kind(),
        TopologyErrorKind::InvalidField
    );
}

#[test]
fn hybrid_projection_is_stable_and_local_host_wins() {
    let mut projector = TopologyProjector::new();
    connect(&mut projector, "registry-a", 1);
    projector
        .observe_registry(
            7,
            100,
            true,
            vec![
                registry_host("z-remote", &[("z-phone", "iOS", "online")]),
                registry_host("local", &[("wrong", "iOS", "online")]),
                registry_host(
                    "a-remote",
                    &[("b-phone", "iOS", "online"), ("a-phone", "iOS", "online")],
                ),
            ],
        )
        .unwrap();
    projector
        .observe_local(
            3,
            101,
            host("local", "online", &[("local-phone", "iOS", "online")]),
        )
        .unwrap();

    let snapshot = projector.snapshot(110);
    assert_eq!(snapshot.scope, DashboardScope::Mesh);
    assert_eq!(
        snapshot
            .hosts
            .iter()
            .map(|host| host.id.as_str())
            .collect::<Vec<_>>(),
        vec!["local", "a-remote", "z-remote"]
    );
    let local = &snapshot.hosts[0];
    assert_eq!(local.trust, TrustState::Local);
    assert_eq!(local.connection_path, ConnectionPath::Local);
    assert_eq!(local.devices[0].id.as_str(), "local-phone");
    let remote = &snapshot.hosts[1];
    assert_eq!(remote.permissions[0].as_str(), "screen_capture");
    assert_eq!(
        remote
            .capabilities
            .iter()
            .map(|value| value.as_str())
            .collect::<Vec<_>>(),
        vec!["xcode_build", "xcode_test"]
    );
    assert_eq!(
        remote
            .devices
            .iter()
            .map(|device| device.id.as_str())
            .collect::<Vec<_>>(),
        vec!["a-phone", "b-phone"]
    );
    assert!(
        remote
            .devices
            .iter()
            .all(|device| device.host_id == remote.id)
    );
    assert_eq!(remote.devices[0].capabilities[0].as_str(), "debugger");
    assert_eq!(remote.devices[0].permissions[0].as_str(), "developer_mode");
}

#[test]
fn authentication_controls_scope_and_authenticated_replays_are_ignored() {
    let mut projector = TopologyProjector::new();
    projector
        .observe_local(1, 10, host("local", "online", &[]))
        .unwrap();
    projector.connect_registry("registry-a", 1, false).unwrap();
    projector.observe_registry(5, 11, false, vec![]).unwrap();
    assert_eq!(projector.snapshot(11).scope, DashboardScope::Local);

    connect(&mut projector, "registry-a", 1);
    projector
        .observe_registry(6, 12, true, vec![registry_host("remote", &[])])
        .unwrap();
    projector
        .observe_registry(5, 13, true, vec![registry_host("replayed", &[])])
        .unwrap();
    let snapshot = projector.snapshot(13);
    assert_eq!(snapshot.scope, DashboardScope::Mesh);
    assert!(
        snapshot
            .hosts
            .iter()
            .any(|host| host.id.as_str() == "remote")
    );
    assert!(
        !snapshot
            .hosts
            .iter()
            .any(|host| host.id.as_str() == "replayed")
    );
}

#[test]
fn disconnect_retains_topology_and_reconnects_with_the_same_ids() {
    let mut projector = TopologyProjector::new();
    connect(&mut projector, "registry-a", 1);
    projector
        .observe_registry(
            1,
            100,
            true,
            vec![registry_host("remote", &[("phone", "iOS", "online")])],
        )
        .unwrap();
    let first = projector.snapshot(100);
    assert_eq!(first.hosts[0].freshness, Freshness::Unknown);

    projector
        .mark_disconnected(&HostId::parse("remote").unwrap(), 120)
        .unwrap();
    let stale = projector.snapshot(121);
    assert_eq!(stale.hosts[0].presence, Presence::Offline);
    assert_eq!(
        stale.hosts[0].freshness,
        Freshness::Stale {
            last_seen_at_ms: 100
        }
    );
    assert_eq!(stale.hosts[0].devices[0].presence, Presence::Offline);
    assert_eq!(
        stale.hosts[0].devices[0].freshness,
        Freshness::Stale {
            last_seen_at_ms: 100
        }
    );

    projector
        .observe_registry(
            2,
            130,
            true,
            vec![registry_host("remote", &[("phone", "iOS", "online")])],
        )
        .unwrap();
    let reconnected = projector.snapshot(130);
    assert_eq!(reconnected.hosts[0].id, stale.hosts[0].id);
    assert_eq!(
        reconnected.hosts[0].devices[0].id,
        stale.hosts[0].devices[0].id
    );
    assert_eq!(reconnected.hosts[0].freshness, Freshness::Live);
}

#[test]
fn stale_owner_makes_active_lease_uncertain_and_not_authorizable() {
    let mut projector = TopologyProjector::new();
    connect(&mut projector, "registry-a", 1);
    projector
        .observe_registry(
            1,
            100,
            true,
            vec![registry_host("remote", &[("phone", "iOS", "online")])],
        )
        .unwrap();
    projector
        .track_active_lease("lease-1", "remote", "phone")
        .unwrap();
    assert_eq!(projector.lease_state("lease-1"), Some(LeaseState::Active));
    assert!(!projector.lease_authorizable("lease-1"));
    projector
        .observe_registry(
            2,
            110,
            true,
            vec![registry_host("remote", &[("phone", "iOS", "online")])],
        )
        .unwrap();
    projector
        .track_active_lease("lease-1", "remote", "phone")
        .unwrap();
    assert!(projector.lease_authorizable("lease-1"));

    projector
        .mark_disconnected(&HostId::parse("remote").unwrap(), 120)
        .unwrap();
    assert_eq!(
        projector.lease_state("lease-1"),
        Some(LeaseState::Uncertain)
    );
    assert!(!projector.lease_authorizable("lease-1"));
}

#[test]
fn leases_require_authenticated_trusted_ownership_and_registry_disconnect_revokes_scope() {
    let mut projector = TopologyProjector::new();
    connect(&mut projector, "registry-a", 1);
    projector
        .observe_registry(
            1,
            10,
            true,
            vec![registry_host("remote", &[("phone", "iOS", "online")])],
        )
        .unwrap();
    projector
        .observe_registry(
            2,
            11,
            true,
            vec![registry_host("remote", &[("phone", "iOS", "online")])],
        )
        .unwrap();
    projector
        .track_active_lease("lease", "remote", "phone")
        .unwrap();
    assert!(projector.lease_authorizable("lease"));

    projector.disconnect_registry(20).unwrap();
    assert_eq!(projector.snapshot(20).scope, DashboardScope::Local);
    assert_eq!(projector.lease_state("lease"), Some(LeaseState::Uncertain));
    assert!(!projector.lease_authorizable("lease"));

    connect(&mut projector, "registry-b", 2);
    let mut revoked = registry_host("remote", &[("phone", "iOS", "online")]);
    revoked.trust = TrustState::Revoked;
    projector
        .observe_registry(1, 30, true, vec![revoked])
        .unwrap();
    projector
        .track_active_lease("revoked", "remote", "phone")
        .unwrap();
    assert!(!projector.lease_authorizable("revoked"));
}

#[test]
fn local_lease_is_authorized_only_for_projector_owned_local_host() {
    let mut projector = TopologyProjector::new();
    projector
        .observe_local(
            1,
            10,
            host("local", "online", &[("phone", "iOS", "online")]),
        )
        .unwrap();
    projector
        .observe_local(
            2,
            11,
            host("local", "online", &[("phone", "iOS", "online")]),
        )
        .unwrap();
    projector
        .track_active_lease("local-lease", "local", "phone")
        .unwrap();
    assert!(projector.lease_authorizable("local-lease"));

    let mut forged = registry_host("forged", &[("other", "iOS", "online")]);
    forged.trust = TrustState::Local;
    connect(&mut projector, "registry-a", 1);
    let error = projector
        .observe_registry(1, 11, true, vec![forged])
        .unwrap_err();
    assert_eq!(error.kind(), TopologyErrorKind::InvalidTrust);
}

#[test]
fn new_authorization_requires_online_live_host_and_device() {
    for state in [
        "offline",
        "busy",
        "connecting",
        "attention_required",
        "paused",
    ] {
        let mut projector = TopologyProjector::new();
        connect(&mut projector, "registry-a", 1);
        let remote = registry_host("remote", &[("phone", "iOS", state)]);
        projector
            .observe_registry(1, 10, true, vec![remote.clone()])
            .unwrap();
        projector
            .observe_registry(2, 11, true, vec![remote])
            .unwrap();
        projector
            .track_active_lease("lease", "remote", "phone")
            .unwrap();
        assert!(
            !projector.lease_authorizable("lease"),
            "device state {state}"
        );
    }

    for state in [
        "offline",
        "busy",
        "connecting",
        "attention_required",
        "paused",
    ] {
        let mut projector = TopologyProjector::new();
        connect(&mut projector, "registry-a", 1);
        let mut remote = registry_host("remote", &[("phone", "iOS", "online")]);
        remote.snapshot.status = state.into();
        projector
            .observe_registry(1, 10, true, vec![remote.clone()])
            .unwrap();
        projector
            .observe_registry(2, 11, true, vec![remote])
            .unwrap();
        projector
            .track_active_lease("lease", "remote", "phone")
            .unwrap();
        assert!(!projector.lease_authorizable("lease"), "host state {state}");
    }
}

#[test]
fn registry_paths_are_explicit_and_unsafe_paths_are_rejected() {
    for path in [ConnectionPath::Local, ConnectionPath::Unavailable] {
        let mut projector = TopologyProjector::new();
        connect(&mut projector, "registry-a", 1);
        let mut remote = registry_host("remote", &[]);
        remote.connection_path = path;
        let before = projector.snapshot(9);
        let error = projector
            .observe_registry(1, 10, true, vec![remote])
            .unwrap_err();
        assert_eq!(error.kind(), TopologyErrorKind::InvalidConnectionPath);
        assert_eq!(projector.snapshot(10).revision, before.revision);
        assert_eq!(projector.snapshot(10).hosts, before.hosts);
    }
    for path in [ConnectionPath::Direct, ConnectionPath::Registry] {
        let mut projector = TopologyProjector::new();
        connect(&mut projector, "registry-a", 1);
        let mut remote = registry_host("remote", &[("phone", "iOS", "online")]);
        remote.connection_path = path;
        projector
            .observe_registry(1, 10, true, vec![remote.clone()])
            .unwrap();
        projector
            .observe_registry(2, 11, true, vec![remote])
            .unwrap();
        projector
            .track_active_lease("lease", "remote", "phone")
            .unwrap();
        assert!(projector.lease_authorizable("lease"));
    }
}

#[test]
fn unauthenticated_invalid_session_revokes_and_revision_exhaustion_is_atomic() {
    let mut projector = TopologyProjector::new();
    connect(&mut projector, "registry-a", 1);
    projector.connect_registry("", 2, false).unwrap();
    assert_eq!(projector.snapshot(10).scope, DashboardScope::Local);

    let mut exhausted = TopologyProjector::new_at_revision(u64::MAX);
    let before = exhausted.snapshot(1);
    let error = exhausted
        .observe_local(1, 2, host("local", "online", &[]))
        .unwrap_err();
    assert_eq!(error.kind(), TopologyErrorKind::RevisionExhausted);
    assert_eq!(exhausted.snapshot(2).hosts, before.hosts);
    assert_eq!(exhausted.snapshot(2).revision, before.revision);
    let error = exhausted
        .connect_registry("registry", 1, false)
        .unwrap_err();
    assert_eq!(error.kind(), TopologyErrorKind::RevisionExhausted);
    assert_eq!(exhausted.snapshot(2).revision, before.revision);

    let mut epoch = TopologyProjector::new();
    connect(&mut epoch, "registry-a", 5);
    let before = epoch.snapshot(1);
    let error = epoch.connect_registry("registry-b", 5, true).unwrap_err();
    assert_eq!(error.kind(), TopologyErrorKind::InvalidRegistryEpoch);
    assert_eq!(epoch.snapshot(2).revision, before.revision);
}

#[test]
fn authenticated_new_epoch_accepts_lower_revision_but_unauthenticated_reset_revokes_immediately() {
    let mut projector = TopologyProjector::new();
    connect(&mut projector, "registry-a", 9);
    projector
        .observe_registry(50, 10, true, vec![registry_host("old", &[])])
        .unwrap();
    projector.connect_registry("registry-b", 10, false).unwrap();
    assert_eq!(projector.snapshot(11).scope, DashboardScope::Local);
    let error = projector
        .observe_registry(1, 12, false, vec![registry_host("forged", &[])])
        .unwrap_err();
    assert_eq!(error.kind(), TopologyErrorKind::UnauthenticatedRegistry);

    connect(&mut projector, "registry-b", 10);
    projector
        .observe_registry(1, 13, true, vec![registry_host("new", &[])])
        .unwrap();
    let snapshot = projector.snapshot(13);
    assert!(snapshot.hosts.iter().any(|host| host.id.as_str() == "new"));
}

#[test]
fn complete_snapshot_marks_absent_remote_hosts_and_leases_stale() {
    let mut projector = TopologyProjector::new();
    connect(&mut projector, "registry-a", 1);
    projector
        .observe_registry(
            1,
            10,
            true,
            vec![
                registry_host("one", &[("phone", "iOS", "online")]),
                registry_host("two", &[]),
            ],
        )
        .unwrap();
    projector
        .track_active_lease("lease", "one", "phone")
        .unwrap();
    projector
        .observe_registry(2, 20, true, vec![registry_host("two", &[])])
        .unwrap();

    let snapshot = projector.snapshot(20);
    let absent = snapshot
        .hosts
        .iter()
        .find(|host| host.id.as_str() == "one")
        .unwrap();
    assert_eq!(absent.presence, Presence::Offline);
    assert_eq!(
        absent.freshness,
        Freshness::Stale {
            last_seen_at_ms: 10
        }
    );
    assert_eq!(projector.lease_state("lease"), Some(LeaseState::Uncertain));
}

#[test]
fn invalid_or_oversized_registry_updates_are_atomic_and_bounded() {
    let mut projector = TopologyProjector::new();
    connect(&mut projector, "registry-a", 1);
    projector
        .observe_registry(1, 10, true, vec![registry_host("valid", &[])])
        .unwrap();
    let before = projector.snapshot(10);

    let mut invalid = registry_host("invalid", &[]);
    invalid.display_name = "x".repeat(device_development_mesh::dashboard::MAX_TEXT_BYTES + 1);
    let error = projector
        .observe_registry(2, 11, true, vec![registry_host("partial", &[]), invalid])
        .unwrap_err();
    assert_eq!(error.kind(), TopologyErrorKind::InvalidField);
    assert_eq!(projector.snapshot(11).hosts, before.hosts);

    let too_many = (0..=device_development_mesh::dashboard::MAX_COLLECTION_ITEMS)
        .map(|index| registry_host(&format!("host-{index}"), &[]))
        .collect();
    let error = projector
        .observe_registry(2, 12, true, too_many)
        .unwrap_err();
    assert_eq!(error.kind(), TopologyErrorKind::LimitExceeded);

    let full = (0..device_development_mesh::dashboard::MAX_COLLECTION_ITEMS)
        .map(|index| registry_host(&format!("old-{index}"), &[]))
        .collect();
    projector.observe_registry(2, 13, true, full).unwrap();
    let replacement = (0..device_development_mesh::dashboard::MAX_COLLECTION_ITEMS)
        .map(|index| registry_host(&format!("new-{index}"), &[]))
        .collect();
    projector
        .observe_registry(3, 14, true, replacement)
        .unwrap();
    assert_eq!(
        projector.snapshot(14).hosts.len(),
        device_development_mesh::dashboard::MAX_COLLECTION_ITEMS
    );
}

#[test]
fn old_host_fixture_without_dashboard_fields_projects_as_unknown() {
    let old: HostSnapshot =
        serde_json::from_str(include_str!("fixtures/host_snapshot_v1.json")).unwrap();
    let mut projector = TopologyProjector::new();
    projector.observe_local(1, 50, old).unwrap();
    let snapshot = projector.snapshot(50);
    assert_eq!(snapshot.hosts[0].freshness, Freshness::Unknown);
    assert!(snapshot.hosts[0].permissions.is_empty());
}
