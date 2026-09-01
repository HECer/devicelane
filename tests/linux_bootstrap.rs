use std::fs;

#[test]
fn linux_user_service_has_complete_secret_free_lifecycle() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let setup = fs::read_to_string(root.join("scripts/setup-linux.sh")).unwrap();

    for required in [
        "--install",
        "--repair",
        "--status",
        "--autostart-enable",
        "--autostart-disable",
        "--logs",
        "--uninstall",
        "devicelane-service",
        ".config/systemd/user/devicelane.service",
        "Restart=on-failure",
        "NoNewPrivileges=true",
        "systemctl --user daemon-reload",
        "systemctl --user enable",
        "systemctl --user disable",
        "journalctl --user-unit devicelane.service",
    ] {
        assert!(
            setup.contains(required),
            "missing Linux lifecycle contract: {required}"
        );
    }
    assert!(setup.contains("Identity and logs were preserved"));
    assert!(setup.contains("Installed="));
    assert!(setup.contains("Autostart="));
    assert!(setup.contains("Logs=%s"));
    assert!(setup.contains("\"$LOG_DIR\""));
    assert!(setup.contains("RUNTIME_DIR=\"$RUNTIME_BASE/devicelane\""));
    assert!(!setup.contains("rm -rf \"$IDENTITY_DIR\""));
    assert!(!setup.contains("private_key"));
    assert!(!setup.contains("pairing_code"));
}

#[test]
fn linux_service_uses_per_user_state_and_documents_foreground_fallback() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let setup = fs::read_to_string(root.join("scripts/setup-linux.sh")).unwrap();
    let readme = fs::read_to_string(root.join("README.md")).unwrap();

    assert!(setup.contains("$HOME_DIR/.local/state/devicelane"));
    assert!(setup.contains("$HOME_DIR/.local/share/devicelane/identity"));
    assert!(setup.contains("$HOME_DIR/.local/lib/devicelane/bin"));
    assert!(readme.contains("systemd --user"));
    assert!(readme.contains("--foreground"));
    assert!(setup.contains("ExecStart=\"$SERVICE_PATH\""));
}

#[test]
fn linux_repair_is_transactional_and_rejects_unsafe_systemd_paths() {
    let setup = fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/setup-linux.sh"),
    )
    .unwrap();
    for required in [
        "activate_linux_service",
        "BINARY_STAGE",
        "UNIT_STAGE",
        "BINARY_BACKUP",
        "UNIT_BACKUP",
        "systemctl --user daemon-reload",
        "systemctl --user restart devicelane.service",
        "systemctl --user is-active --quiet devicelane.service",
        "rollback_linux_service",
        "WAS_ENABLED",
        "ROLLBACK_FAILED",
        "refusing to overwrite existing DeviceLane recovery artifacts",
        "rollback error: restore binary",
        "rollback error: restore unit",
        "rollback error: daemon-reload",
        "rollback error: restore autostart",
        "rollback error: restart",
        "rollback error: health verification",
        "validate_systemd_path",
    ] {
        assert!(
            setup.contains(required),
            "missing transactional Linux repair: {required}"
        );
    }
    for unsafe_byte in ["newline", "double quote", "backslash", "percent"] {
        assert!(
            setup.contains(unsafe_byte),
            "missing rejection for {unsafe_byte}"
        );
    }
}
