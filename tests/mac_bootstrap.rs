use std::fs;
#[cfg(unix)]
use std::process::Command;

#[test]
fn mac_bootstrap_defines_the_complete_user_launch_agent_lifecycle() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let setup = fs::read_to_string(root.join("scripts/setup-mac.sh")).unwrap();
    let smoke = fs::read_to_string(root.join("scripts/mac-bootstrap-smoke")).unwrap();

    for required in [
        "cargo build --workspace --release",
        "\"$CLI_PATH\" doctor",
        "\"$PROGRAM_PATH\" pair",
        "launchctl bootstrap",
        "launchctl kickstart",
        "launchctl print",
        "--upgrade",
        "--status",
        "--uninstall",
        "--controller",
        "CONTROLLER_HOST",
    ] {
        assert!(
            setup.contains(required),
            "missing bootstrap step: {required}"
        );
    }
    assert!(smoke.contains("cargo test --test mac_bootstrap"));
    assert!(smoke.contains("setup-mac.sh --dry-run"));
}

#[test]
fn launch_agent_is_restricted_absolute_and_contains_no_secrets() {
    let setup = fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/setup-mac.sh"),
    )
    .unwrap();

    for required in [
        "<key>KeepAlive</key>",
        "<key>ThrottleInterval</key>",
        "chmod 600",
        "chmod 700",
        "<key>ProgramArguments</key>",
    ] {
        assert!(
            setup.contains(required),
            "missing launch agent safeguard: {required}"
        );
    }
    assert!(setup.contains("PROGRAM_PATH"));
    assert!(setup.contains("PLIST_REGISTRY_ADDRESS"));
    assert!(!setup.contains("<string>127.0.0.1:7443</string>"));
    assert!(setup.contains("HOME_DIR=\"$(pwd)/$HOME_DIR\""));
    assert!(!setup.contains("<key>PairingCode</key>"));
    assert!(!setup.contains("<key>PrivateKey</key>"));
    assert!(!setup.contains("<key>SigningSecret</key>"));
    assert!(setup.contains("[REDACTED]"));
    assert!(setup.contains("xml_escape"));
    assert!(setup.contains("\\&amp;"));
}

#[test]
fn production_launch_agent_uses_resolved_apple_tools_without_dummy_devices() {
    let setup = fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/setup-mac.sh"),
    )
    .unwrap();

    for tool in [
        "xcodebuild",
        "devicectl",
        "simctl",
        "xcresulttool",
        "xctrace",
        "lldb-dap",
    ] {
        assert!(
            setup.contains(&format!("xcrun --find {tool}")),
            "setup must resolve {tool} through xcrun"
        );
    }
    for argument in ["--xcodebuild", "--devicectl", "--simctl"] {
        assert!(
            setup.contains(argument),
            "LaunchAgent must receive {argument}"
        );
    }
    assert!(!setup.contains("<string>process.start@1</string>"));
    assert!(!setup.contains("<string>none:ios:disconnected</string>"));
}

#[test]
fn production_install_rejects_loopback_controller_and_unresolved_tools() {
    let setup = fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/setup-mac.sh"),
    )
    .unwrap();

    assert!(setup.contains("production controller must not use loopback"));
    assert!(setup.contains("unable to resolve required Apple tool"));
    assert!(setup.contains("test -x"));
}

#[test]
#[cfg(unix)]
fn dry_run_has_no_side_effects_and_reports_only_handoff_and_diagnostics() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let home = tempfile::tempdir().unwrap();
    let output = Command::new("sh")
        .arg(root.join("scripts/setup-mac.sh"))
        .args(["--dry-run", "--home", home.path().to_str().unwrap()])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!home.path().join("Library/LaunchAgents").exists());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let lines: Vec<_> = stdout.lines().collect();
    assert_eq!(lines.len(), 2);
    assert!(lines[0].starts_with("NEXT_CONTROLLER_COMMAND="));
    assert!(lines[0].contains("mesh-registry pair"));
    assert!(lines[1].starts_with("DIAGNOSTIC_BUNDLE="));
}

#[test]
fn uninstall_preserves_identity_and_audit_by_default() {
    let setup = fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/setup-mac.sh"),
    )
    .unwrap();

    assert!(setup.contains("rm -f \"$PLIST_PATH\""));
    assert!(setup.contains("rm -f \"$PROGRAM_PATH\" \"$CLI_PATH\""));
    assert!(setup.contains("rmdir \"$PROGRAM_DIR/bin\" \"$PROGRAM_DIR\""));
    assert!(!setup.contains("rm -rf \"$PROGRAM_DIR\""));
    assert!(!setup.contains("rm -rf \"$IDENTITY_DIR\""));
    assert!(!setup.contains("rm -rf \"$AUDIT_DIR\""));
}
