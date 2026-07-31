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

#[cfg(windows)]
#[test]
fn doctor_rejects_an_additional_windows_acl_principal() {
    for target in ["", "private-key.der"] {
        let identity = tempfile::tempdir().unwrap();
        assert_eq!(permission_status(&doctor(identity.path())), "ok");
        let path = identity.path().join(target);
        assert!(
            Command::new("icacls")
                .arg(path)
                .args(["/grant", "*S-1-5-32-544:F"])
                .status()
                .unwrap()
                .success()
        );
        assert_eq!(permission_status(&doctor(identity.path())), "repair");
    }
}

#[cfg(windows)]
fn doctor(identity: &std::path::Path) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_mesh-cli"))
        .args(["doctor", "--identity", identity.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    serde_json::from_slice(&output.stdout).unwrap()
}

#[cfg(windows)]
fn permission_status(report: &Value) -> &str {
    report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|check| check["id"] == "file_permissions")
        .unwrap()["status"]
        .as_str()
        .unwrap()
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
