use device_development_mesh::mac_bootstrap::validate_production_launch_agent;
use std::fs;
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
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let setup = fs::read_to_string(root.join("scripts/setup-mac.sh")).unwrap();
    let agent = fs::read_to_string(root.join("src/bin/mesh-agent.rs")).unwrap();

    for tool in [
        "xcodebuild",
        "devicectl",
        "simctl",
        "xcresulttool",
        "xctrace",
        "lldb-dap",
    ] {
        assert!(
            setup.contains(&format!("--find {tool}")),
            "setup must resolve {tool} through xcrun"
        );
    }
    for argument in [
        "--xcodebuild",
        "--devicectl",
        "--simctl",
        "--xcresulttool",
        "--xctrace",
        "--lldb-dap",
    ] {
        assert!(
            setup.contains(argument),
            "LaunchAgent must receive {argument}"
        );
        assert!(
            agent.contains(&format!("optional_value(&args, \"{argument}\")")),
            "mesh-agent must consume {argument}"
        );
    }
    assert!(!setup.contains("<string>process.start@1</string>"));
    assert!(!setup.contains("<string>none:ios:disconnected</string>"));
    assert!(agent.contains("optional_value(&args, \"--peer-id\")"));
    assert!(setup.contains("--agent-peer $PEER_ID"));
    assert!(setup.contains("/usr/bin/uuidgen"));
    assert!(setup.contains("<string>--peer-id</string>"));
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
    assert!(setup.contains("MESH_BOOTSTRAP_TEST_MODE"));
    assert!(setup.contains("PLIST_STAGE"));
    assert!(setup.contains("\"$PLUTIL\" -lint \"$PLIST_STAGE\""));
    assert!(setup.contains("mv \"$PLIST_STAGE\" \"$PLIST_PATH\""));
}

#[test]
fn rendered_production_plist_rejects_fake_loopback_and_unresolved_configuration() {
    let setup = fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/setup-mac.sh"),
    )
    .unwrap();
    let template = setup
        .split("cat >\"$PLIST_STAGE\" <<EOF\n")
        .nth(1)
        .and_then(|tail| tail.split("\nEOF").next())
        .expect("setup must render one staged LaunchAgent plist");
    let developer = "/Applications/Xcode.app/Contents/Developer";
    let tools = [
        format!("{developer}/usr/bin/xcodebuild"),
        format!("{developer}/usr/bin/devicectl"),
        format!("{developer}/usr/bin/simctl"),
        format!("{developer}/usr/bin/xcresulttool"),
        format!("{developer}/usr/bin/xctrace"),
        format!("{developer}/usr/bin/lldb-dap"),
    ];
    let mut rendered = template
        .replace("$PLIST_PROGRAM_PATH", "/Users/dev/.local/bin/mesh-agent")
        .replace("$PLIST_REGISTRY_ADDRESS", "192.0.2.10:7443")
        .replace(
            "$PLIST_IDENTITY_DIR",
            "/Users/dev/Library/Application Support/Mesh/identity",
        )
        .replace(
            "$PLIST_PEER_ID",
            "mac-agent-11111111-1111-1111-1111-111111111111",
        )
        .replace(
            "$PLIST_WORKSPACE_DIR",
            "/Users/dev/Library/Application Support/Mesh/workspaces",
        )
        .replace("$PLIST_LOG_DIR", "/Users/dev/Library/Logs/Mesh")
        .replace("$PLIST_XCODEBUILD", &tools[0])
        .replace("$PLIST_DEVICECTL", &tools[1])
        .replace("$PLIST_SIMCTL", &tools[2])
        .replace("$PLIST_XCRESULTTOOL", &tools[3])
        .replace("$PLIST_XCTRACE", &tools[4])
        .replace("$PLIST_LLDB_DAP", &tools[5])
        .replace(
            "$PLIST_HARDWARE_GATE_PATH",
            "/Users/dev/.local/lib/device-development-mesh/hardware-gate/mac-hardware-gate.sh",
        )
        .replace("$(uname -m)", "arm64");
    let tool_refs: Vec<_> = tools.iter().map(String::as_str).collect();

    assert!(
        validate_production_launch_agent(&rendered, "192.0.2.10", developer, &tool_refs).is_ok()
    );
    let loopback_plist = rendered.replace("192.0.2.10:7443", "127.0.0.1:7443");
    assert!(
        validate_production_launch_agent(&loopback_plist, "127.0.0.1", developer, &tool_refs)
            .is_err()
    );
    assert!(
        validate_production_launch_agent(&loopback_plist, "192.0.2.10", developer, &tool_refs)
            .is_err()
    );
    for loopback in ["LOCALHOST", "0:0:0:0:0:0:0:1", "0.0.0.0"] {
        assert!(
            validate_production_launch_agent(&rendered, loopback, developer, &tool_refs).is_err(),
            "accepted loopback controller {loopback}"
        );
    }
    let mut fake_tools = tool_refs.clone();
    fake_tools[0] = "/tmp/fake-xcodebuild";
    assert!(
        validate_production_launch_agent(&rendered, "192.0.2.10", developer, &fake_tools).is_err()
    );
    rendered.push_str("$PLIST_UNRESOLVED");
    assert!(
        validate_production_launch_agent(&rendered, "192.0.2.10", developer, &tool_refs).is_err()
    );
}

#[test]
fn fresh_agent_identity_reports_and_reuses_its_unique_peer_id() {
    let identity = tempfile::tempdir().unwrap();
    let expected = "mac-agent-11111111-2222-3333-4444-555555555555";
    for _ in 0..2 {
        let output = Command::new(env!("CARGO_BIN_EXE_mesh-agent"))
            .args([
                "peer-id",
                "--identity",
                identity.path().to_str().unwrap(),
                "--peer-id",
                expected,
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), expected);
    }
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

#[test]
fn mac_daemon_launch_agent_has_complete_lifecycle() {
    let setup = fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/setup-mac.sh"),
    )
    .unwrap();

    for required in [
        "--repair",
        "--autostart-enable",
        "--autostart-disable",
        "--logs",
        "devicelane-service",
        "dev.devicelane.service",
        "<key>KeepAlive</key>",
        "<key>RunAtLoad</key>",
    ] {
        assert!(
            setup.contains(required),
            "missing macOS daemon lifecycle: {required}"
        );
    }
    assert!(setup.contains("Identity and logs were preserved"));
    assert!(setup.contains(
        "DAEMON_PLIST_PROGRAM_PATH=$(printf '%s' \"$DAEMON_PROGRAM_PATH\" | xml_escape)"
    ));
    assert!(setup.contains("Installed="));
    assert!(setup.contains("Autostart="));
    assert!(setup.contains("Logs=%s"));
    assert!(setup.contains("\"$DAEMON_LOG_DIR\""));
}

#[test]
fn mac_repair_is_transactional_and_absent_status_is_explicit() {
    let setup = fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/setup-mac.sh"),
    )
    .unwrap();
    for required in [
        "activate_mac_service",
        "DAEMON_PROGRAM_BACKUP",
        "DAEMON_PLIST_BACKUP",
        "rollback_mac_service",
        "launchctl print \"$DAEMON_SERVICE\"",
        "already loaded",
        "Installed=false",
        "Autostart=unavailable",
        "WAS_DAEMON_DISABLED",
        "launchctl enable \"$DAEMON_SERVICE\"",
        "launchctl disable \"$DAEMON_SERVICE\"",
        "refusing to overwrite existing DeviceLane recovery artifacts",
        "rollback error: restore daemon binary",
        "rollback error: restore LaunchAgent",
        "rollback error: restore launchd override",
        "rollback error: health verification",
    ] {
        assert!(
            setup.contains(required),
            "missing transactional macOS repair: {required}"
        );
    }
    assert!(!setup.contains(
        "launchctl bootstrap \"gui/$(id -u)\" \"$DAEMON_PLIST_PATH\" 2>/dev/null || true"
    ));
}
