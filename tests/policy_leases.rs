use device_development_mesh::authorization::{AuthorizationError, Operation, PolicyEngine, Role};
use std::time::Duration;

#[test]
fn missing_capability_is_rejected_before_adapter_execution() {
    let mut engine = PolicyEngine::new();
    engine.grant("developer", Role::Operator, "logs.read");
    let lease = engine
        .acquire_lease("iphone-1", "developer", Duration::from_secs(30))
        .unwrap();
    let mut adapter_calls = 0;

    let result = engine.execute(
        "developer",
        Operation::InstallDevice {
            device_id: "iphone-1",
        },
        Some(lease),
        || adapter_calls += 1,
    );

    assert_eq!(result, Err(AuthorizationError::CapabilityDenied));
    assert_eq!(adapter_calls, 0);
}

#[test]
fn only_one_writer_or_debugger_can_lease_a_device() {
    let mut engine = PolicyEngine::new();
    engine.grant("writer", Role::Operator, "device.install");
    engine.grant("debugger", Role::Operator, "process.start");
    let first = engine
        .acquire_lease("iphone-1", "writer", Duration::from_secs(30))
        .unwrap();

    assert_eq!(
        engine.acquire_lease("iphone-1", "debugger", Duration::from_secs(30)),
        Err(AuthorizationError::DeviceAlreadyLeased)
    );
    assert!(engine.lease_is_active(first));
}

#[test]
fn expired_revoked_or_foreign_lease_cannot_start_an_operation() {
    let mut engine = PolicyEngine::new();
    engine.grant("writer", Role::Operator, "device.install");
    engine.grant("debugger", Role::Operator, "device.install");
    let expired = engine
        .acquire_lease("iphone-1", "writer", Duration::ZERO)
        .unwrap();
    assert_eq!(
        engine.execute(
            "writer",
            Operation::InstallDevice {
                device_id: "iphone-1"
            },
            Some(expired),
            || ()
        ),
        Err(AuthorizationError::LeaseInactive)
    );

    let revoked = engine
        .acquire_lease("iphone-1", "debugger", Duration::from_secs(30))
        .unwrap();
    assert_eq!(
        engine.execute(
            "writer",
            Operation::InstallDevice {
                device_id: "iphone-1"
            },
            Some(revoked),
            || ()
        ),
        Err(AuthorizationError::LeaseInactive)
    );
    engine.revoke_lease(revoked);
    assert_eq!(
        engine.execute(
            "debugger",
            Operation::InstallDevice {
                device_id: "iphone-1"
            },
            Some(revoked),
            || ()
        ),
        Err(AuthorizationError::LeaseInactive)
    );
}

#[test]
fn observer_can_read_granted_logs_but_cannot_mutate_processes_or_devices() {
    let mut engine = PolicyEngine::new();
    engine.grant("observer", Role::Observer, "logs.read");
    engine.grant("observer", Role::Observer, "process.start");

    assert_eq!(
        engine.execute("observer", Operation::ReadLogs, None, || "logs"),
        Ok("logs")
    );
    assert_eq!(
        engine.execute(
            "observer",
            Operation::StartProcess {
                device_id: "iphone-1"
            },
            None,
            || ()
        ),
        Err(AuthorizationError::ObserverReadOnly)
    );
}
