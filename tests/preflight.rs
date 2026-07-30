use device_development_mesh::preflight::{
    AdbDeviceState, AndroidPreflight, ApplePreflight, CommandOutput, PreflightError,
};
use std::cell::RefCell;

const XCODE_VERSION: &str = include_str!("fixtures/v1/apple/xcodebuild-version.txt");
const SDK_VERSION: &str = include_str!("fixtures/v1/apple/xcodebuild-sdk-version.txt");
const DEVICECTL_VERSION: &str = include_str!("fixtures/v1/apple/devicectl-version.txt");
const SIMCTL_VERSION: &str = include_str!("fixtures/v1/apple/simctl-version.txt");
const ADB_VERSION: &str = include_str!("fixtures/v1/android/adb-version.txt");
const ADB_DEVICES: &str = include_str!("fixtures/v1/android/adb-devices.txt");

#[test]
fn apple_preflight_reports_tool_versions_on_macos() {
    let commands = RefCell::new(Vec::new());
    let snapshot = ApplePreflight::run("macos", |program, args| {
        commands.borrow_mut().push((
            program.to_owned(),
            args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>(),
        ));
        match (program, args) {
            ("xcodebuild", ["-version"]) => Ok(CommandOutput::success(XCODE_VERSION)),
            ("xcrun", ["--sdk", "iphoneos", "--show-sdk-version"]) => {
                Ok(CommandOutput::success(SDK_VERSION))
            }
            ("xcrun", ["devicectl", "--version"]) => Ok(CommandOutput::success(DEVICECTL_VERSION)),
            ("xcrun", ["simctl", "--version"]) => Ok(CommandOutput::success(SIMCTL_VERSION)),
            _ => unreachable!(),
        }
    })
    .unwrap();

    assert_eq!(snapshot.xcode, "16.4");
    assert_eq!(snapshot.sdk, "18.5");
    assert_eq!(snapshot.devicectl, "397.21");
    assert_eq!(snapshot.simctl, "1015.2");
    assert_eq!(commands.borrow().len(), 4);
}

#[test]
fn apple_preflight_rejects_non_macos_without_running_commands() {
    let result = ApplePreflight::run("windows", |_, _| -> Result<CommandOutput, PreflightError> {
        panic!("Xcode command must not be invoked")
    });

    assert_eq!(result, Err(PreflightError::UnsupportedHost));
}

#[test]
fn android_preflight_normalizes_fixture_device_states() {
    let snapshot = AndroidPreflight::from_outputs(ADB_VERSION, ADB_DEVICES).unwrap();

    assert_eq!(snapshot.adb_version, "35.0.2-12147458");
    assert_eq!(snapshot.devices.len(), 3);
    assert_eq!(snapshot.devices[0].id, "emulator-5554");
    assert_eq!(snapshot.devices[0].state, AdbDeviceState::Authorized);
    assert_eq!(snapshot.devices[1].state, AdbDeviceState::Unauthorized);
    assert_eq!(snapshot.devices[2].state, AdbDeviceState::Offline);
}

#[test]
fn android_preflight_collects_adb_version_and_devices() {
    let snapshot = AndroidPreflight::run(|program, args| match (program, args) {
        ("adb", ["version"]) => Ok(CommandOutput::success(ADB_VERSION)),
        ("adb", ["devices", "-l"]) => Ok(CommandOutput::success(ADB_DEVICES)),
        _ => unreachable!(),
    })
    .unwrap();

    assert_eq!(snapshot.adb_version, "35.0.2-12147458");
    assert_eq!(snapshot.devices.len(), 3);
}
