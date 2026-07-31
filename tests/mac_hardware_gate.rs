use std::{fs, path::PathBuf};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn hardware_gate_requires_real_device_signing_and_complete_evidence() {
    let script = fs::read_to_string(root().join("scripts/mac-hardware-gate.sh")).unwrap();

    for required in [
        "MESH_HARDWARE_GATE_TEST_MODE",
        "xcode-select -p",
        "xcrun --find devicectl",
        "xcrun --find xcodebuild",
        "xcrun --find xcresulttool",
        "platform=iOS,id=$DEVICE_ID",
        "CODE_SIGN_STYLE=Automatic",
        "device install app",
        "process launch",
        "process terminate",
        "test-without-building",
        "resultBundlePath",
        "device.log",
        "manifest.json",
        "manifest.sha256",
        "security cms -S",
        "hardware-gate.tar.gz",
        "--archive-stdout",
    ] {
        assert!(
            script.contains(required),
            "missing hardware gate token: {required}"
        );
    }

    for forbidden in ["simctl", "booted", "iPhone Simulator", "MESH_FAKE_SUCCESS"] {
        assert!(
            !script.contains(forbidden),
            "hardware gate must not accept simulator/mock path: {forbidden}"
        );
    }
}

#[test]
fn bundled_gate_app_contains_an_app_and_an_xcui_screenshot_test() {
    let project = root().join("hardware/DeviceMeshGate");
    for file in [
        "DeviceMeshGate.xcodeproj/project.pbxproj",
        "DeviceMeshGate/AppDelegate.swift",
        "DeviceMeshGate/SceneDelegate.swift",
        "DeviceMeshGate/ViewController.swift",
        "DeviceMeshGate/Info.plist",
        "DeviceMeshGateUITests/DeviceMeshGateUITests.swift",
        "DeviceMeshGateUITests/Info.plist",
    ] {
        assert!(project.join(file).is_file(), "missing {file}");
    }

    let ui_test =
        fs::read_to_string(project.join("DeviceMeshGateUITests/DeviceMeshGateUITests.swift"))
            .unwrap();
    assert!(ui_test.contains("XCUIApplication"));
    assert!(ui_test.contains("XCUIScreen.main.screenshot()"));
    assert!(ui_test.contains("XCTAttachment"));
    assert!(ui_test.contains("lifetime = .keepAlways"));
}

#[test]
fn bootstrap_installs_the_hardware_gate_beside_the_agent() {
    let setup = fs::read_to_string(root().join("scripts/setup-mac.sh")).unwrap();
    assert!(setup.contains("mac-hardware-gate.sh"));
    assert!(setup.contains("DeviceMeshGate"));
    assert!(setup.contains("hardware-gate"));
    assert!(setup.contains("--hardware-gate"));
    let cli = fs::read_to_string(root().join("src/bin/mesh-cli.rs")).unwrap();
    assert!(cli.contains("hardware-gate"));
    assert!(cli.contains("apple.hardware-gate@1"));
    assert!(cli.contains("ArtifactRead"));
    assert!(cli.contains("openssl"));
    assert!(cli.contains("AppleRootCA.pem"));
    assert!(cli.contains("verify_evidence_archive"));
    let agent = fs::read_to_string(root().join("src/bin/mesh-agent.rs")).unwrap();
    assert!(agent.contains("controlled_home"));
    assert!(agent.contains("/usr/bin:/bin"));
}
