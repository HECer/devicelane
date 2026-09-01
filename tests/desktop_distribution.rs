use std::fs;

fn read(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_else(|error| panic!("cannot read {}: {}", path, error))
}

#[test]
fn native_bundles_and_release_integrity_are_declared() {
    let config = read("desktop/src-tauri/tauri.conf.json");
    let workflow = read(".github/workflows/desktop-release.yml");

    for declaration in ["msi", "dmg", "appimage", "deb", "--locked"] {
        assert!(
            config.contains(declaration) || workflow.contains(declaration),
            "missing {}",
            declaration
        );
    }
    for declaration in [
        "SHA256SUMS",
        "cargo cyclonedx --all",
        "SBOM",
        "cosign sign-blob",
        "APPLE_CERTIFICATE",
        "APPLE_SIGNING_IDENTITY",
        "APPLE_ID",
        "APPLE_PASSWORD",
        "APPLE_TEAM_ID",
        "hardenedRuntime",
        "notarization",
        "windows-latest",
        "macos-latest",
        "ubuntu-latest",
    ] {
        assert!(
            workflow.contains(declaration) || config.contains(declaration),
            "missing {}",
            declaration
        );
    }
}

#[test]
fn release_sidecar_build_uses_the_workspace_lockfile() {
    let stage = read("desktop/scripts/stage-sidecar.mjs");
    assert!(stage.contains(r#"...(debug ? [] : ["--release"]), "--locked""#));
}

#[test]
fn unsigned_artifacts_can_never_be_published_as_production() {
    let workflow = read(".github/workflows/desktop-release.yml");
    assert!(workflow.contains("unsigned-ci"));
    assert!(
        workflow
            .contains("if: github.event_name == 'workflow_dispatch' && inputs.production == true")
    );
    assert!(
        workflow.contains("Refusing production release without signing and notarization inputs")
    );
    assert!(workflow.contains("environment: production-release"));
    assert!(!workflow.contains("continue-on-error: true"));
}

#[test]
fn smoke_scripts_cover_first_run_and_preserve_identity() {
    for path in [
        "scripts/desktop-release-smoke.ps1",
        "scripts/desktop-release-smoke.sh",
    ] {
        let smoke = read(path);
        for operation in [
            "install",
            "autostart",
            "status",
            "repair",
            "logs",
            "uninstall",
            "identity",
        ] {
            assert!(
                smoke.to_lowercase().contains(operation),
                "{} omits {}",
                path,
                operation
            );
        }
        assert!(smoke.contains("DEVICELANE_SMOKE_ROOT"));
        assert!(smoke.contains("DEVICELANE_SERVICE_BINARY"));
    }
}

#[test]
fn staging_manifest_and_install_root_boundary_are_enforced() {
    let workflow = read(".github/workflows/desktop-release.yml");
    let windows = read("scripts/desktop-release-smoke.ps1");
    let unix = read("scripts/desktop-release-smoke.sh");
    assert!(workflow.contains("sidecar-manifest.sha256"));
    assert!(windows.contains("installation root must not be writable"));
    assert!(unix.contains("installation root must not be writable"));
    assert!(workflow.contains("No TOCTOU security guarantee"));
}

#[test]
fn windows_smoke_has_a_non_ci_temporary_directory_fallback() {
    let windows = read("scripts/desktop-release-smoke.ps1");
    assert!(windows.contains("$env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { $env:TEMP"));
}

#[test]
fn linux_smoke_exercises_the_documented_foreground_fallback() {
    let unix = read("scripts/desktop-release-smoke.sh");
    assert!(unix.contains("systemctl --user show-environment"));
    assert!(unix.contains("--foreground"));
    assert!(unix.contains(r#"--endpoint "$runtime/devicelane.sock""#));
}
