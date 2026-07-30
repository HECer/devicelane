use device_development_mesh::preflight::{
    AppleCheckState, ApplePreflight, ApplePreflightState, CommandOutput, PreflightError,
};
use std::cell::Cell;

const SUCCESS: &str = include_str!("fixtures/v2/apple/preflight-success.txt");
const MISSING_TOOL: &str = include_str!("fixtures/v2/apple/preflight-missing-tool.txt");
const LICENSE_ERROR: &str = include_str!("fixtures/v2/apple/preflight-license-error.txt");
const DEVELOPER_DIR_ERROR: &str =
    include_str!("fixtures/v2/apple/preflight-developer-directory-error.txt");

#[test]
fn reports_machine_readable_ready_states_for_every_required_apple_tool() {
    let report = ApplePreflight::inspect("macos", fixture(SUCCESS));

    assert_eq!(report.state, ApplePreflightState::Ready);
    for name in [
        "macos",
        "full_xcode",
        "developer_directory",
        "xcodebuild",
        "devicectl",
        "simctl",
        "xcresulttool",
        "xctrace",
        "lldb-dap",
    ] {
        assert_eq!(report.check(name).unwrap().state, AppleCheckState::Ready);
    }
}

#[test]
fn missing_tool_fixture_has_a_concrete_repair_hint() {
    let report = ApplePreflight::inspect("macos", fixture(MISSING_TOOL));
    let check = report.check("devicectl").unwrap();

    assert_eq!(report.state, ApplePreflightState::NeedsRepair);
    assert_eq!(check.state, AppleCheckState::MissingTool);
    assert!(check.repair.unwrap().contains("Xcode"));
}

#[test]
fn license_fixture_has_a_concrete_repair_hint() {
    let report = ApplePreflight::inspect("macos", fixture(LICENSE_ERROR));
    let check = report.check("xcodebuild").unwrap();

    assert_eq!(
        report.check("full_xcode").unwrap().state,
        AppleCheckState::Ready
    );
    assert_eq!(check.state, AppleCheckState::LicenseNotAccepted);
    assert!(check.repair.unwrap().contains("xcodebuild -license accept"));
}

#[test]
fn developer_directory_fixture_has_a_concrete_repair_hint() {
    let report = ApplePreflight::inspect("macos", fixture(DEVELOPER_DIR_ERROR));
    let check = report.check("developer_directory").unwrap();

    assert_eq!(check.state, AppleCheckState::InvalidDeveloperDirectory);
    assert!(check.repair.unwrap().contains("xcode-select --switch"));
}

#[test]
fn non_macos_is_unsupported_without_spawning_a_process() {
    let called = Cell::new(false);
    let report = ApplePreflight::inspect("windows", |_, _| {
        called.set(true);
        Err(PreflightError::CommandFailed)
    });

    assert_eq!(report.state, ApplePreflightState::UnsupportedHost);
    assert_eq!(
        report.check("macos").unwrap().state,
        AppleCheckState::UnsupportedHost
    );
    assert!(!called.get());
}

fn fixture(
    text: &'static str,
) -> impl FnMut(&str, &[&str]) -> Result<CommandOutput, PreflightError> {
    move |program, args| {
        let key = format!("{} {}", program, args.join(" "));
        let line = text
            .lines()
            .find(|line| line.starts_with(&format!("{key}|")))
            .unwrap();
        let mut fields = line.splitn(4, '|');
        fields.next();
        let success = fields.next().unwrap() == "ok";
        let stdout = fields.next().unwrap().replace("\\n", "\n");
        let stderr = fields.next().unwrap().replace("\\n", "\n");
        Ok(CommandOutput::new(success, stdout, stderr))
    }
}
