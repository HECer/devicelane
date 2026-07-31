use device_development_mesh::apple_physical_device::{
    ApplePhysicalDevice, PhysicalDeviceError, PhysicalDeviceOperation,
};
use device_development_mesh::authorization::{PolicyEngine, Role};
use device_development_mesh::device_adapter::AdapterContext;
use device_development_mesh::preflight::{AppleTool, AppleToolRunner};
use serde_json::Value;
use std::fs;
use std::time::Duration;
use tempfile::tempdir;

const PLANS: &str = include_str!("fixtures/v1/apple/devicectl-plans.json");
const ERRORS: &str = include_str!("fixtures/v1/apple/devicectl-errors.json");

#[test]
fn devicectl_plans_match_the_versioned_fixture() {
    let plans: Value = serde_json::from_str(PLANS).unwrap();
    let operations = [
        (
            "install",
            PhysicalDeviceOperation::Install {
                app_path: "Build/Mesh.app".into(),
            },
        ),
        (
            "launch",
            PhysicalDeviceOperation::Launch {
                bundle_id: "dev.mesh.App".into(),
            },
        ),
        (
            "terminate",
            PhysicalDeviceOperation::Terminate {
                bundle_id: "dev.mesh.App".into(),
            },
        ),
        (
            "uninstall",
            PhysicalDeviceOperation::Uninstall {
                bundle_id: "dev.mesh.App".into(),
            },
        ),
        ("info", PhysicalDeviceOperation::DeviceInfo),
        (
            "logs",
            PhysicalDeviceOperation::LogStream {
                bundle_id: "dev.mesh.App".into(),
            },
        ),
    ];
    for (name, operation) in operations {
        let expected: Vec<String> = serde_json::from_value(plans[name].clone()).unwrap();
        assert_eq!(operation.arguments("iphone-1"), Ok(expected));
    }
}

#[test]
fn mutations_require_an_exclusive_lease_and_the_matching_apple_capability() {
    let root = tempdir().unwrap();
    fs::create_dir(root.path().join("Build")).unwrap();
    fs::create_dir(root.path().join("Build/Mesh.app")).unwrap();
    let mut device = physical_device(root.path());
    let mut policy = PolicyEngine::new();
    policy.grant("operator", Role::Operator, "device.lease");
    policy.grant("operator", Role::Operator, "apple.app.install@1");
    let mut context = AdapterContext::new(&mut policy, "operator");
    assert_eq!(
        device.execute(
            &mut context,
            "iphone-1",
            PhysicalDeviceOperation::Install {
                app_path: "Build/Mesh.app".into()
            }
        ),
        Err(PhysicalDeviceError::LeaseInactive)
    );
    device
        .lease(&mut context, "iphone-1", Duration::from_secs(30))
        .unwrap();
    assert!(
        device
            .execute(
                &mut context,
                "iphone-1",
                PhysicalDeviceOperation::Install {
                    app_path: "Build/Mesh.app".into()
                }
            )
            .is_ok()
    );
    assert_eq!(
        device.execute(
            &mut context,
            "iphone-1",
            PhysicalDeviceOperation::Launch {
                bundle_id: "dev.mesh.App".into()
            }
        ),
        Err(PhysicalDeviceError::CapabilityDenied)
    );

    let mut second_policy = PolicyEngine::new();
    second_policy.grant("other", Role::Operator, "device.lease");
    let mut other = AdapterContext::new(&mut second_policy, "other");
    assert_eq!(
        device.lease(&mut other, "iphone-1", Duration::from_secs(30)),
        Err(PhysicalDeviceError::DeviceBusy)
    );
}

#[test]
fn every_mutation_checks_its_own_capability_and_lease() {
    let root = tempdir().unwrap();
    fs::create_dir(root.path().join("Mesh.app")).unwrap();
    let cases = [
        (
            "apple.app.install@1",
            PhysicalDeviceOperation::Install {
                app_path: "Mesh.app".into(),
            },
        ),
        (
            "apple.app.launch@1",
            PhysicalDeviceOperation::Launch {
                bundle_id: "dev.mesh.App".into(),
            },
        ),
        (
            "apple.app.terminate@1",
            PhysicalDeviceOperation::Terminate {
                bundle_id: "dev.mesh.App".into(),
            },
        ),
        (
            "apple.app.uninstall@1",
            PhysicalDeviceOperation::Uninstall {
                bundle_id: "dev.mesh.App".into(),
            },
        ),
        (
            "apple.app.logs@1",
            PhysicalDeviceOperation::LogStream {
                bundle_id: "dev.mesh.App".into(),
            },
        ),
    ];
    for (capability, operation) in cases {
        let mut device = physical_device(root.path());
        let mut policy = PolicyEngine::new();
        policy.grant("operator", Role::Operator, "device.lease");
        policy.grant("operator", Role::Operator, capability);
        let mut context = AdapterContext::new(&mut policy, "operator");
        assert_eq!(
            device.execute(&mut context, "iphone-1", operation.clone()),
            Err(PhysicalDeviceError::LeaseInactive)
        );

        let mut device = physical_device(root.path());
        let mut policy = PolicyEngine::new();
        policy.grant("operator", Role::Operator, "device.lease");
        let mut context = AdapterContext::new(&mut policy, "operator");
        device
            .lease(&mut context, "iphone-1", Duration::from_secs(30))
            .unwrap();
        assert_eq!(
            device.execute(&mut context, "iphone-1", operation),
            Err(PhysicalDeviceError::CapabilityDenied)
        );
    }
}

#[test]
fn install_executes_with_the_canonical_validated_app_path() {
    let root = tempdir().unwrap();
    fs::create_dir(root.path().join("Build")).unwrap();
    fs::create_dir(root.path().join("Build/Mesh.app")).unwrap();
    let mut device = physical_device(root.path());
    let mut policy = PolicyEngine::new();
    for capability in ["device.lease", "apple.app.install@1"] {
        policy.grant("operator", Role::Operator, capability);
    }
    let mut context = AdapterContext::new(&mut policy, "operator");
    device
        .lease(&mut context, "iphone-1", Duration::from_secs(30))
        .unwrap();
    device
        .execute(
            &mut context,
            "iphone-1",
            PhysicalDeviceOperation::Install {
                app_path: "Build/../Build/Mesh.app".into(),
            },
        )
        .unwrap();
    let call = fs::read_to_string(root.path().join("devicectl-calls.txt")).unwrap();
    let canonical = fs::canonicalize(root.path().join("Build/Mesh.app")).unwrap();
    assert!(call.contains(canonical.to_str().unwrap()));
}

#[test]
fn observers_can_only_read_released_logs() {
    let root = tempdir().unwrap();
    let mut device = physical_device(root.path());
    device.release_logs("iphone-1", b"ready\n".to_vec());
    let mut policy = PolicyEngine::new();
    policy.grant("observer", Role::Observer, "apple.app.logs.read@1");
    policy.grant("observer", Role::Observer, "apple.device.info@1");
    let mut context = AdapterContext::new(&mut policy, "observer");
    assert_eq!(
        device.read_released_logs(&mut context, "iphone-1"),
        Ok(b"ready\n".to_vec())
    );
    assert_eq!(
        device.execute(
            &mut context,
            "iphone-1",
            PhysicalDeviceOperation::DeviceInfo
        ),
        Err(PhysicalDeviceError::ObserverReadOnly)
    );
}

#[test]
fn tool_failures_are_normalized_with_concrete_repairs() {
    let errors: Value = serde_json::from_str(ERRORS).unwrap();
    for (name, expected) in [
        ("locked", PhysicalDeviceError::Locked),
        ("untrusted", PhysicalDeviceError::Untrusted),
        (
            "developer_mode_disabled",
            PhysicalDeviceError::DeveloperModeDisabled,
        ),
        ("signing_failed", PhysicalDeviceError::SigningFailed),
        ("device_busy", PhysicalDeviceError::DeviceBusy),
        ("detached", PhysicalDeviceError::Detached),
    ] {
        let error = ApplePhysicalDevice::normalize_failure(errors[name].as_str().unwrap());
        assert_eq!(error, expected);
        assert!(!error.repair().is_empty());
    }
}

#[test]
fn identifiers_and_paths_are_validated_before_any_tool_execution() {
    let root = tempdir().unwrap();
    fs::create_dir(root.path().join("Build")).unwrap();
    fs::create_dir(root.path().join("Build/Mesh.app")).unwrap();
    let mut device = physical_device(root.path());
    let mut policy = PolicyEngine::new();
    for capability in ["device.lease", "apple.app.install@1", "apple.app.launch@1"] {
        policy.grant("operator", Role::Operator, capability);
    }
    let mut context = AdapterContext::new(&mut policy, "operator");
    device
        .lease(&mut context, "iphone-1", Duration::from_secs(30))
        .unwrap();
    assert_eq!(
        device.execute(
            &mut context,
            "iphone-1; reboot",
            PhysicalDeviceOperation::Launch {
                bundle_id: "dev.mesh.App".into()
            }
        ),
        Err(PhysicalDeviceError::InvalidDeviceId)
    );
    assert_eq!(
        device.execute(
            &mut context,
            "iphone-1",
            PhysicalDeviceOperation::Launch {
                bundle_id: "dev.mesh.App --flag".into()
            }
        ),
        Err(PhysicalDeviceError::InvalidBundleId)
    );
    assert_eq!(
        device.execute(
            &mut context,
            "iphone-1",
            PhysicalDeviceOperation::Install {
                app_path: "../Outside.app".into()
            }
        ),
        Err(PhysicalDeviceError::InvalidAppPath)
    );
    assert!(!root.path().join("devicectl-calls.txt").exists());
}

fn physical_device(root: &std::path::Path) -> ApplePhysicalDevice {
    let tool = root.join(if cfg!(windows) {
        "devicectl.cmd"
    } else {
        "devicectl"
    });
    write_fake_tool(&tool);
    let runner = AppleToolRunner::new(root, [(AppleTool::Devicectl, tool)]).unwrap();
    ApplePhysicalDevice::new(runner, Duration::from_secs(5))
}

#[cfg(windows)]
fn write_fake_tool(path: &std::path::Path) {
    fs::write(
        path,
        "@echo %*>>devicectl-calls.txt\r\n@echo tool-output\r\n",
    )
    .unwrap();
}

#[cfg(unix)]
fn write_fake_tool(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    fs::write(
        path,
        "#!/bin/sh\necho \"$*\" >> devicectl-calls.txt\necho tool-output\n",
    )
    .unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}
