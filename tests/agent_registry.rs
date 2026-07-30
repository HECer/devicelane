use device_development_mesh::discovery::{Agent, AgentHeartbeat, CapabilitySnapshot, Registry};
use std::time::Duration;

fn heartbeat(toolchain: &str) -> AgentHeartbeat {
    AgentHeartbeat {
        agent_id: "mac-1".into(),
        operating_system: "macos".into(),
        architecture: "aarch64".into(),
        snapshot: CapabilitySnapshot {
            capabilities: vec!["apple.build@1".into()],
            toolchains: vec![toolchain.into()],
        },
    }
}

#[test]
fn started_agent_appears_in_cli_within_five_seconds() {
    let mut registry = Registry::new(Duration::from_secs(10));
    Agent::new(heartbeat("xcode=16.0")).start(&mut registry, Duration::ZERO);

    let output = registry.cli_agents(Duration::from_secs(5));

    assert!(output.contains("mac-1"));
    assert!(output.contains("macos"));
    assert!(output.contains("aarch64"));
    assert!(output.contains("apple.build@1"));
    assert!(output.contains("xcode=16.0"));
    assert!(output.contains("online"));
}

#[test]
fn ended_agent_is_retained_as_offline_after_heartbeat_window() {
    let mut registry = Registry::new(Duration::from_secs(10));
    registry.record_heartbeat(heartbeat("xcode=16.0"), Duration::from_secs(3));

    let output = registry.cli_agents(Duration::from_secs(13));

    assert!(output.contains("mac-1"));
    assert!(output.contains("offline"));
    assert!(!output.contains("online"));
}

#[test]
fn changed_toolchain_snapshot_gets_a_new_monotonic_revision() {
    let mut registry = Registry::new(Duration::from_secs(10));
    registry.record_heartbeat(heartbeat("xcode=16.0"), Duration::ZERO);
    assert_eq!(registry.snapshot_revision("mac-1"), Some(1));

    registry.record_heartbeat(heartbeat("xcode=16.0"), Duration::from_secs(1));
    assert_eq!(registry.snapshot_revision("mac-1"), Some(1));

    registry.record_heartbeat(heartbeat("xcode=16.1"), Duration::from_secs(2));
    assert_eq!(registry.snapshot_revision("mac-1"), Some(2));
    assert!(
        registry
            .cli_agents(Duration::from_secs(2))
            .contains("revision=2")
    );
}
