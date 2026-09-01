use device_development_mesh::dashboard::topology::{
    DeviceDetails, LeaseState, RegistryHost, TopologyProjector,
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

#[test]
fn hybrid_projection_is_stable_and_local_host_wins() {
    let mut projector = TopologyProjector::new();
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
fn authentication_controls_scope_and_replayed_revisions_are_ignored() {
    let mut projector = TopologyProjector::new();
    projector
        .observe_local(1, 10, host("local", "online", &[]))
        .unwrap();
    projector
        .observe_registry(5, 11, false, vec![registry_host("remote", &[])])
        .unwrap();
    assert_eq!(projector.snapshot(11).scope, DashboardScope::Local);

    projector
        .observe_registry(6, 12, true, vec![registry_host("remote", &[])])
        .unwrap();
    projector
        .observe_registry(5, 13, false, vec![registry_host("replayed", &[])])
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

    projector.mark_disconnected(&HostId::parse("remote").unwrap(), 120);
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
    assert!(projector.lease_authorizable("lease-1"));

    projector.mark_disconnected(&HostId::parse("remote").unwrap(), 120);
    assert_eq!(
        projector.lease_state("lease-1"),
        Some(LeaseState::Uncertain)
    );
    assert!(!projector.lease_authorizable("lease-1"));
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
