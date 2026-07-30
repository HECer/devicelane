use device_development_mesh::apple_simulator::{
    AppleSimulator, SimulatorError, SimulatorOperation, SimulatorState,
};
use device_development_mesh::authorization::{PolicyEngine, Role};
use device_development_mesh::device_adapter::{AdapterContext, DeviceAdapter};
use device_development_mesh::preflight::{AppleTool, AppleToolRunner};
use std::fs;
use std::time::Duration;
use tempfile::tempdir;

fn simulator(root: &std::path::Path) -> AppleSimulator {
    let tool = root.join(if cfg!(windows) {
        "simctl.cmd"
    } else {
        "simctl"
    });
    write_fake_tool(&tool);
    let runner = AppleToolRunner::new(root, [(AppleTool::Simctl, tool)]).unwrap();
    AppleSimulator::new(runner, Duration::from_secs(5))
}

#[cfg(windows)]
fn write_fake_tool(path: &std::path::Path) {
    fs::write(path, "@echo %*>>simctl-calls.txt\r\n").unwrap();
}

#[cfg(unix)]
fn write_fake_tool(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    fs::write(path, "#!/bin/sh\necho \"$*\" >> simctl-calls.txt\n").unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

fn context<'a>(policy: &'a mut PolicyEngine) -> AdapterContext<'a> {
    for capability in [
        "device.lease",
        "simulator.lifecycle",
        "device.install",
        "process.start",
        "process.stop",
        "simulator.screenshot",
        "logs.read",
        "simulator.location",
        "simulator.privacy",
        "simulator.media",
    ] {
        policy.grant("developer", Role::Operator, capability);
    }
    AdapterContext::new(policy, "developer")
}

#[test]
fn lifecycle_and_app_actions_are_typed_simctl_operations() {
    assert_eq!(
        SimulatorOperation::Create {
            name: "Mesh Phone".into(),
            device_type: "com.apple.CoreSimulator.SimDeviceType.iPhone-16".into(),
            runtime: "com.apple.CoreSimulator.SimRuntime.iOS-18-0".into()
        }
        .arguments(),
        vec![
            "create",
            "Mesh Phone",
            "com.apple.CoreSimulator.SimDeviceType.iPhone-16",
            "com.apple.CoreSimulator.SimRuntime.iOS-18-0"
        ]
    );
    assert_eq!(SimulatorOperation::Boot.arguments(), vec!["boot", "sim-1"]);
    assert_eq!(
        SimulatorOperation::BootStatus.arguments(),
        vec!["bootstatus", "sim-1", "-b"]
    );
    assert_eq!(
        SimulatorOperation::Shutdown.arguments(),
        vec!["shutdown", "sim-1"]
    );
    assert_eq!(
        SimulatorOperation::Delete.arguments(),
        vec!["delete", "sim-1"]
    );
    assert_eq!(
        SimulatorOperation::Install {
            path: "Build/Mesh.app".into()
        }
        .arguments(),
        vec!["install", "sim-1", "Build/Mesh.app"]
    );
    assert_eq!(
        SimulatorOperation::Uninstall {
            bundle_id: "dev.mesh.App".into()
        }
        .arguments(),
        vec!["uninstall", "sim-1", "dev.mesh.App"]
    );
    assert_eq!(
        SimulatorOperation::Launch {
            bundle_id: "dev.mesh.App".into()
        }
        .arguments(),
        vec!["launch", "sim-1", "dev.mesh.App"]
    );
    assert_eq!(
        SimulatorOperation::Terminate {
            bundle_id: "dev.mesh.App".into()
        }
        .arguments(),
        vec!["terminate", "sim-1", "dev.mesh.App"]
    );
}

#[test]
fn development_automation_requires_capability_lease_and_workspace_paths() {
    let root = tempdir().unwrap();
    fs::write(root.path().join("photo.png"), b"media").unwrap();
    let mut simulator = simulator(root.path());
    let mut policy = PolicyEngine::new();
    let mut ctx = context(&mut policy);
    assert_eq!(
        simulator.execute(
            &mut ctx,
            "sim-1",
            SimulatorOperation::Screenshot {
                path: "screen.png".into()
            }
        ),
        Err(SimulatorError::LeaseInactive)
    );
    simulator
        .lease(&mut ctx, "sim-1", Duration::from_secs(30))
        .unwrap();
    for operation in [
        SimulatorOperation::Screenshot {
            path: "screen.png".into(),
        },
        SimulatorOperation::LogStream,
        SimulatorOperation::Location {
            latitude: "52.52".into(),
            longitude: "13.405".into(),
        },
        SimulatorOperation::Privacy {
            service: "camera".into(),
            bundle_id: "dev.mesh.App".into(),
            grant: true,
        },
        SimulatorOperation::AddMedia {
            paths: vec!["photo.png".into()],
        },
    ] {
        let description = format!("{operation:?}");
        assert!(
            simulator.execute(&mut ctx, "sim-1", operation).is_ok(),
            "failed fake operation: {description}"
        );
    }
    let calls = fs::read_to_string(root.path().join("simctl-calls.txt")).unwrap();
    for command in [
        "io sim-1 screenshot",
        "spawn sim-1 log stream",
        "location sim-1 set",
        "privacy sim-1 grant",
        "addmedia sim-1",
    ] {
        assert!(
            calls.contains(command),
            "missing fake simctl call: {command}"
        );
    }
    assert_eq!(
        simulator.execute(
            &mut ctx,
            "sim-1",
            SimulatorOperation::AddMedia {
                paths: vec!["../outside.png".into()]
            }
        ),
        Err(SimulatorError::WorkspaceEscape)
    );
}

#[test]
fn lifecycle_is_idempotent_and_errors_have_stable_codes() {
    let root = tempdir().unwrap();
    let mut simulator = simulator(root.path());
    let mut policy = PolicyEngine::new();
    let mut ctx = context(&mut policy);
    simulator
        .lease(&mut ctx, "sim-1", Duration::from_secs(30))
        .unwrap();
    assert_eq!(
        simulator
            .execute(&mut ctx, "sim-1", SimulatorOperation::Boot)
            .unwrap(),
        SimulatorState::Booted
    );
    assert_eq!(
        simulator
            .execute(&mut ctx, "sim-1", SimulatorOperation::Boot)
            .unwrap(),
        SimulatorState::Booted
    );
    assert_eq!(
        simulator
            .execute(&mut ctx, "sim-1", SimulatorOperation::Shutdown)
            .unwrap(),
        SimulatorState::Shutdown
    );
    assert_eq!(
        simulator
            .execute(&mut ctx, "sim-1", SimulatorOperation::Delete)
            .unwrap(),
        SimulatorState::Deleted
    );
    assert_eq!(
        simulator
            .execute(&mut ctx, "sim-1", SimulatorOperation::Delete)
            .unwrap(),
        SimulatorState::Deleted
    );
    let calls = fs::read_to_string(root.path().join("simctl-calls.txt")).unwrap();
    assert_eq!(
        calls.lines().filter(|line| *line == "delete sim-1").count(),
        1
    );
    assert_eq!(
        simulator
            .execute(&mut ctx, "sim-1", SimulatorOperation::Shutdown)
            .unwrap(),
        SimulatorState::Shutdown
    );
    assert_eq!(SimulatorError::Busy.code(), "busy");
    assert_eq!(SimulatorError::BootFailed.code(), "boot_failed");
    assert_eq!(SimulatorError::RuntimeMissing.code(), "runtime_missing");
    assert_eq!(SimulatorError::Detached.code(), "detach");
}

#[test]
fn fake_simctl_flow_satisfies_the_device_adapter_contract_without_hardware() {
    let root = tempdir().unwrap();
    let mut adapter = simulator(root.path());
    let mut policy = PolicyEngine::new();
    policy_capabilities_are_complete(&mut policy);
    let mut ctx = context(&mut policy);
    assert_eq!(adapter.discover(&mut ctx).unwrap()[0].id, "sim-1");
    DeviceAdapter::lease(&mut adapter, &mut ctx, "sim-1", Duration::from_secs(30)).unwrap();
    adapter.install(&mut ctx, "sim-1", b"application").unwrap();
    adapter.launch(&mut ctx, "sim-1", "mesh.app").unwrap();
    assert_eq!(
        adapter.logs(&mut ctx, "sim-1").unwrap(),
        b"mesh.app launched"
    );
    assert_eq!(adapter.artifact(&mut ctx, "sim-1").unwrap(), b"application");
    adapter.stop(&mut ctx, "sim-1").unwrap();
    assert_eq!(
        adapter.attach_debugger(&mut ctx, "sim-1"),
        Err(device_development_mesh::device_adapter::AdapterError::UnsupportedCapability)
    );
}

#[test]
fn adapter_denial_does_not_write_and_detach_is_normalized() {
    let root = tempdir().unwrap();
    let mut adapter = simulator(root.path());
    let mut denied_policy = PolicyEngine::new();
    denied_policy.grant("developer", Role::Operator, "device.install");
    let mut denied = AdapterContext::new(&mut denied_policy, "developer");
    assert!(adapter.install(&mut denied, "sim-1", b"denied").is_err());
    assert!(!root.path().join(".mesh-simulator-install.app").exists());

    let tool = root.path().join(if cfg!(windows) {
        "detach.cmd"
    } else {
        "detach"
    });
    write_failure_tool(&tool, "detach");
    let runner = AppleToolRunner::new(root.path(), [(AppleTool::Simctl, tool)]).unwrap();
    let mut adapter = AppleSimulator::new(runner, Duration::from_secs(5));
    let mut policy = PolicyEngine::new();
    policy_capabilities_are_complete(&mut policy);
    let mut ctx = context(&mut policy);
    DeviceAdapter::lease(&mut adapter, &mut ctx, "sim-1", Duration::from_secs(30)).unwrap();
    assert_eq!(
        adapter.launch(&mut ctx, "sim-1", "detach"),
        Err(device_development_mesh::device_adapter::AdapterError::WaitingForDevice)
    );
}

#[test]
fn fake_tool_failures_map_to_stable_errors() {
    for (marker, expected) in [
        ("boot_failed", SimulatorError::BootFailed),
        ("runtime_missing", SimulatorError::RuntimeMissing),
        ("other_failure", SimulatorError::Busy),
    ] {
        let root = tempdir().unwrap();
        let tool = root.path().join(if cfg!(windows) {
            "failure.cmd"
        } else {
            "failure"
        });
        write_failure_tool(&tool, marker);
        let runner = AppleToolRunner::new(root.path(), [(AppleTool::Simctl, tool)]).unwrap();
        let mut simulator = AppleSimulator::new(runner, Duration::from_secs(5));
        let mut policy = PolicyEngine::new();
        let mut ctx = context(&mut policy);
        simulator
            .lease(&mut ctx, "sim-1", Duration::from_secs(30))
            .unwrap();
        assert_eq!(
            simulator.execute(
                &mut ctx,
                "sim-1",
                SimulatorOperation::Location {
                    latitude: "0".into(),
                    longitude: "0".into()
                }
            ),
            Err(expected)
        );
    }
}

#[cfg(windows)]
fn write_failure_tool(path: &std::path::Path, marker: &str) {
    fs::write(path, format!("@echo {marker} 1>&2\r\n@exit /b 1\r\n")).unwrap();
}

#[cfg(unix)]
fn write_failure_tool(path: &std::path::Path, marker: &str) {
    use std::os::unix::fs::PermissionsExt;
    fs::write(path, format!("#!/bin/sh\necho {marker} >&2\nexit 1\n")).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

fn policy_capabilities_are_complete(policy: &mut PolicyEngine) {
    for capability in ["device.discover", "artifact.read", "debug.attach"] {
        policy.grant("developer", Role::Operator, capability);
    }
}
