use serde_json::Value;
use std::process::Command;

#[test]
fn doctor_emits_machine_readable_checks_and_repairs() {
    let identity = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_mesh-cli"))
        .args(["doctor", "--identity", identity.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema_version"], 1);
    let checks = report["checks"].as_array().unwrap();
    for id in [
        "rust",
        "network",
        "xcode",
        "adb",
        "certificates",
        "file_permissions",
    ] {
        let check = checks.iter().find(|check| check["id"] == id).unwrap();
        assert!(matches!(check["status"].as_str(), Some("ok" | "repair")));
        assert!(check["repair"].is_string());
    }
}

#[test]
fn bootstrap_assets_define_idempotent_setup_and_real_hardware_gates() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let windows = std::fs::read_to_string(root.join("scripts/setup-windows.ps1")).unwrap();
    let mac = std::fs::read_to_string(root.join("scripts/setup-mac.sh")).unwrap();
    let smoke = std::fs::read_to_string(root.join("scripts/bootstrap-smoke")).unwrap();
    let readme = std::fs::read_to_string(root.join("README.md")).unwrap();

    assert!(windows.contains("New-Item -ItemType Directory -Force"));
    assert!(windows.matches("$LASTEXITCODE").count() >= 2);
    for option in [
        "--controller-install",
        "--controller-status",
        "--controller-uninstall",
    ] {
        assert!(windows.contains(option));
        assert!(readme.contains(option));
    }
    assert!(windows.contains("Register-ScheduledTask"));
    assert!(windows.contains("--agent-peer"));
    for option in [
        "--controller-listen",
        "--controller-identity",
        "--controller-log-dir",
    ] {
        assert!(windows.contains(option));
        assert!(readme.contains(option));
    }
    assert!(windows.contains("$CurrentUserSid"));
    assert!(windows.contains("DeviceLane Registry-$CurrentUserSid"));
    assert!(windows.contains("New-ScheduledTaskPrincipal -UserId $UserId"));
    assert!(windows.matches("Unregister-ScheduledTask").count() >= 2);
    assert!(!windows.contains("Remove-Item"));
    assert!(mac.contains("mkdir -p"));
    assert!(smoke.contains("cargo test --test bootstrap"));
    assert!(readme.contains("Windows"));
    assert!(readme.contains("macOS"));
    assert!(readme.contains("Linux"));
    assert!(readme.contains("iPhone-Hardware-Gate"));
    assert!(readme.contains("Android-Hardware-Gate"));
    assert!(readme.contains("Mocks gelten nicht als Nachweis"));
    assert!(!readme.lines().any(|line| line.starts_with("mesh-cli ")));
    assert!(!readme.lines().any(|line| line.starts_with("mesh-agent ")));
    assert!(
        !readme
            .lines()
            .any(|line| line.starts_with("mesh-registry "))
    );
}

#[test]
fn windows_controller_install_requires_every_public_runtime_argument_before_building() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let script = root.join("scripts/setup-windows.ps1");
    let data = tempfile::tempdir().unwrap();
    let identity = data.path().join("identity");
    let logs = data.path().join("logs");
    let required = [
        ("--agent-peer", "mac-agent-1"),
        ("--controller-listen", "127.0.0.1:7443"),
        ("--controller-identity", identity.to_str().unwrap()),
        ("--controller-log-dir", logs.to_str().unwrap()),
    ];

    for (missing, _) in required {
        let mut command = Command::new("powershell.exe");
        command
            .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"])
            .arg(&script)
            .arg("--controller-install")
            .env("LOCALAPPDATA", data.path())
            .env("PATH", "");
        for (option, value) in required {
            if option != missing {
                command.args([option, value]);
            }
        }
        let output = command.output().unwrap();
        assert!(
            !output.status.success(),
            "install accepted missing {missing}"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(&format!("requires explicit {missing}")),
            "unexpected error for missing {missing}: {stderr}"
        );
    }
}
