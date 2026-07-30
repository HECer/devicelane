use device_development_mesh::apple_discovery::{
    AppleDiscovery, AppleDiscoveryError, Availability, Connection, DeveloperMode, DeviceSnapshot,
    Trust,
};
use device_development_mesh::preflight::{AppleTool, AppleToolRunner};
use serde_json::Value;
use std::{fs, process::Command, time::Duration};
use tempfile::tempdir;

const DEVICECTL: &str = include_str!("fixtures/v1/apple/devicectl-devices.json");
const SIMCTL: &str = include_str!("fixtures/v1/apple/simctl-devices.json");

#[test]
fn versioned_tool_outputs_are_normalized_into_stable_snapshots() {
    let devices = AppleDiscovery::from_outputs(DEVICECTL, SIMCTL).unwrap();
    assert_eq!(
        devices[0],
        DeviceSnapshot {
            id: "00008110-001C2D123456801E".into(),
            name: "Ada's iPhone".into(),
            platform: "ios".into(),
            os_version: "17.5".into(),
            connection: Connection::Usb,
            trust: Trust::Trusted,
            developer_mode: DeveloperMode::Enabled,
            availability: Availability::Available,
            capabilities: vec!["apple.app.install@1".into(), "apple.app.launch@1".into()],
            repair: None,
        }
    );
    assert_eq!(devices[5].id, "SIM-BOOTED");
    assert_eq!(devices[5].platform, "ios-simulator");
    assert_eq!(devices[5].os_version, "17.5");
}

#[test]
fn non_executable_devices_have_no_app_capabilities_and_a_repair_hint() {
    let devices = AppleDiscovery::from_outputs(DEVICECTL, SIMCTL).unwrap();
    for id in [
        "00008120-LOCKED",
        "00008130-UNTRUSTED",
        "00008140-DISCONNECTED",
        "00008150-UNAVAILABLE",
        "SIM-MISSING",
    ] {
        let device = devices.iter().find(|device| device.id == id).unwrap();
        assert!(device.capabilities.is_empty());
        assert!(
            device
                .repair
                .as_ref()
                .is_some_and(|repair| !repair.is_empty())
        );
    }
    assert_eq!(devices[1].availability, Availability::Locked);
    assert_eq!(devices[2].trust, Trust::Untrusted);
    assert_eq!(devices[4].availability, Availability::Unavailable);
    assert_eq!(devices[6].availability, Availability::RuntimeMissing);
}

#[test]
fn missing_required_fields_return_one_stable_error_without_inventory() {
    let malformed = DEVICECTL.replace("\"identifier\": \"00008120-LOCKED\",", "");
    assert_eq!(
        AppleDiscovery::from_outputs(&malformed, SIMCTL),
        Err(AppleDiscoveryError::MalformedToolOutput)
    );
    assert_eq!(
        AppleDiscoveryError::MalformedToolOutput.code(),
        "malformed_tool_output"
    );
}

#[test]
fn discovery_executes_both_tools_through_the_typed_runner() {
    let root = tempdir().unwrap();
    let devicectl = root.path().join(if cfg!(windows) {
        "devicectl.cmd"
    } else {
        "devicectl"
    });
    let simctl = root.path().join(if cfg!(windows) {
        "simctl.cmd"
    } else {
        "simctl"
    });
    write_devicectl_tool(&devicectl, "devicectl-devices.json");
    write_fixture_tool(&simctl, "simctl-devices.json", "list devices --json");
    let runner = AppleToolRunner::new(
        root.path(),
        [
            (AppleTool::Devicectl, devicectl),
            (AppleTool::Simctl, simctl),
        ],
    )
    .unwrap();
    let devices = AppleDiscovery::discover(&runner, ".", Duration::from_secs(5)).unwrap();
    assert_eq!(devices.len(), 7);
}

#[test]
fn discovery_uses_a_unique_output_file_and_cleans_it_up() {
    let root = tempdir().unwrap();
    fs::write(root.path().join(".mesh-devicectl-devices.json"), "stale").unwrap();
    let devicectl = root.path().join(if cfg!(windows) {
        "devicectl.cmd"
    } else {
        "devicectl"
    });
    let simctl = root.path().join(if cfg!(windows) {
        "simctl.cmd"
    } else {
        "simctl"
    });
    write_devicectl_tool(&devicectl, "devicectl-devices.json");
    write_fixture_tool(&simctl, "simctl-devices.json", "list devices --json");
    let runner = AppleToolRunner::new(
        root.path(),
        [
            (AppleTool::Devicectl, devicectl),
            (AppleTool::Simctl, simctl),
        ],
    )
    .unwrap();

    assert_eq!(
        AppleDiscovery::discover(&runner, ".", Duration::from_secs(5))
            .unwrap()
            .len(),
        7
    );
    assert!(
        !fs::read_dir(root.path())
            .unwrap()
            .filter_map(Result::ok)
            .any(|entry| entry
                .file_name()
                .to_string_lossy()
                .starts_with(".mesh-devicectl-devices-"))
    );
}

#[test]
fn cli_emits_the_same_inventory_as_json() {
    let root = tempdir().unwrap();
    let devicectl = root.path().join(if cfg!(windows) {
        "devicectl.cmd"
    } else {
        "devicectl"
    });
    let simctl = root.path().join(if cfg!(windows) {
        "simctl.cmd"
    } else {
        "simctl"
    });
    write_devicectl_tool(&devicectl, "devicectl-devices.json");
    write_fixture_tool(&simctl, "simctl-devices.json", "list devices --json");
    let output = Command::new(env!("CARGO_BIN_EXE_mesh-cli"))
        .args([
            "apple-discover",
            "--workspace",
            root.path().to_str().unwrap(),
            "--devicectl",
            devicectl.to_str().unwrap(),
            "--simctl",
            simctl.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let cli: Vec<DeviceSnapshot> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        cli,
        AppleDiscovery::from_outputs(DEVICECTL, SIMCTL).unwrap()
    );
}

fn write_fixture_tool(path: &std::path::Path, fixture: &str, expected_args: &str) {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/v1/apple")
        .join(fixture);
    write_tool(path, &fixture, expected_args);
}

fn write_devicectl_tool(path: &std::path::Path, fixture: &str) {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/v1/apple")
        .join(fixture);
    write_devicectl(path, &fixture);
}

#[cfg(windows)]
fn write_tool(path: &std::path::Path, fixture: &std::path::Path, expected_args: &str) {
    fs::write(
        path,
        format!(
            "@if not \"%*\"==\"{expected_args}\" exit /b 9\r\n@type \"{}\"\r\n",
            fixture.display()
        ),
    )
    .unwrap();
}

#[cfg(windows)]
fn write_devicectl(path: &std::path::Path, fixture: &std::path::Path) {
    fs::write(path, format!("@if not \"%1 %2 %3\"==\"list devices --json-output\" exit /b 9\r\n@if exist \"%4\" exit /b 8\r\n@type \"{}\" > \"%4\"\r\n", fixture.display())).unwrap();
}

#[cfg(unix)]
fn write_tool(path: &std::path::Path, fixture: &std::path::Path, expected_args: &str) {
    use std::os::unix::fs::PermissionsExt;
    fs::write(
        path,
        format!(
            "#!/bin/sh\n[ \"$*\" = \"{expected_args}\" ] || exit 9\ncat '{}'\n",
            fixture.display()
        ),
    )
    .unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

#[cfg(unix)]
fn write_devicectl(path: &std::path::Path, fixture: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    fs::write(path, format!("#!/bin/sh\n[ \"$1 $2 $3\" = \"list devices --json-output\" ] || exit 9\n[ ! -e \"$4\" ] || exit 8\ncat '{}' > \"$4\"\n", fixture.display())).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn snapshots_are_json_values_without_private_tool_fields() {
    let value: Value =
        serde_json::to_value(AppleDiscovery::from_outputs(DEVICECTL, SIMCTL).unwrap()).unwrap();
    assert!(value[0].get("futureField").is_none());
}
