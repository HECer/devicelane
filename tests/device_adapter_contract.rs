use device_development_mesh::authorization::{PolicyEngine, Role};
use device_development_mesh::device_adapter::{
    AdapterContext, AdapterError, DeviceAdapter, DeviceState, FakeDeviceAdapter,
};
use std::time::Duration;

struct ContractFixture<'a> {
    device_id: &'a str,
    application: &'a str,
    install_artifact: &'a [u8],
    expected_logs: &'a [u8],
    expected_artifact: &'a [u8],
}

fn contract(mut adapter: impl DeviceAdapter, fixture: ContractFixture<'_>) {
    let mut policy = PolicyEngine::new();
    for capability in [
        "device.discover",
        "device.lease",
        "device.install",
        "process.start",
        "process.stop",
        "logs.read",
        "artifact.read",
    ] {
        policy.grant("developer", Role::Operator, capability);
    }
    let mut context = AdapterContext::new(&mut policy, "developer");

    let devices = adapter.discover(&mut context).unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].id, fixture.device_id);
    adapter
        .lease(&mut context, fixture.device_id, Duration::from_secs(30))
        .unwrap();
    adapter
        .install(&mut context, fixture.device_id, fixture.install_artifact)
        .unwrap();
    adapter
        .launch(&mut context, fixture.device_id, fixture.application)
        .unwrap();
    assert_eq!(
        adapter.logs(&mut context, fixture.device_id).unwrap(),
        fixture.expected_logs
    );
    assert_eq!(
        adapter.artifact(&mut context, fixture.device_id).unwrap(),
        fixture.expected_artifact
    );
    adapter.stop(&mut context, fixture.device_id).unwrap();
}

#[test]
fn fake_device_adapter_satisfies_the_shared_contract() {
    contract(
        FakeDeviceAdapter::new(),
        ContractFixture {
            device_id: "fake-1",
            application: "mesh.app",
            install_artifact: b"application",
            expected_logs: b"mesh.app launched",
            expected_artifact: b"application",
        },
    );
}

#[test]
fn operations_cannot_bypass_policy_or_the_device_lease() {
    let mut policy = PolicyEngine::new();
    policy.grant("developer", Role::Operator, "device.install");
    let mut context = AdapterContext::new(&mut policy, "developer");
    let mut adapter = FakeDeviceAdapter::new();

    assert_eq!(
        adapter.install(&mut context, "fake-1", b"application"),
        Err(AdapterError::LeaseInactive)
    );
}

#[test]
fn unsupported_operations_return_the_stable_error_code() {
    let mut policy = PolicyEngine::new();
    policy.grant("developer", Role::Operator, "device.lease");
    policy.grant("developer", Role::Operator, "debug.attach");
    let mut context = AdapterContext::new(&mut policy, "developer");
    let mut adapter = FakeDeviceAdapter::new();
    adapter
        .lease(&mut context, "fake-1", Duration::from_secs(30))
        .unwrap();

    assert_eq!(
        adapter.attach_debugger(&mut context, "fake-1"),
        Err(AdapterError::UnsupportedCapability)
    );
    assert_eq!(
        AdapterError::UnsupportedCapability.code(),
        "unsupported_capability"
    );
}

#[test]
fn detach_during_launch_returns_waiting_for_device() {
    let mut policy = PolicyEngine::new();
    policy.grant("developer", Role::Operator, "device.lease");
    policy.grant("developer", Role::Operator, "process.start");
    let mut context = AdapterContext::new(&mut policy, "developer");
    let mut adapter = FakeDeviceAdapter::new();
    adapter
        .lease(&mut context, "fake-1", Duration::from_secs(30))
        .unwrap();
    adapter.set_state(DeviceState::Detached);

    assert_eq!(
        adapter.launch(&mut context, "fake-1", "mesh.app"),
        Err(AdapterError::WaitingForDevice)
    );
    assert_eq!(AdapterError::WaitingForDevice.code(), "waiting_for_device");
}
