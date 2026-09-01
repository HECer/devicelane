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
        "cargo build --release --locked --bin devicelane --bin devicelane-service",
        "`${binary}-${targetTriple}${executableSuffix}`",
        r#""externalBin": ["binaries/devicelane-service", "binaries/devicelane"]"#,
    ] {
        assert!(
            workflow.contains(declaration)
                || read("desktop/scripts/stage-sidecar.mjs").contains(declaration)
                || config.contains(declaration),
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
        "windows-2025",
        "macos-15",
        "ubuntu-24.04",
    ] {
        assert!(
            workflow.contains(declaration) || config.contains(declaration),
            "missing {}",
            declaration
        );
    }
}

#[test]
fn native_installer_icons_are_declared() {
    let config = read("desktop/src-tauri/tauri.conf.json");
    for icon in ["icons/icon.ico", "icons/icon.icns", "icons/icon.png"] {
        assert!(
            config.contains(icon),
            "missing native bundle icon: {}",
            icon
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
    assert!(workflow.contains("unsigned-native:"));
    assert!(workflow.contains("production-native:"));
    let unsigned = workflow
        .split("unsigned-native:")
        .nth(1)
        .unwrap()
        .split("production-native:")
        .next()
        .unwrap();
    assert!(!unsigned.contains("secrets."));
    assert!(!unsigned.contains("environment:"));
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
        assert!(smoke.contains("DEVICELANE_DESKTOP_ARTIFACT"));
        assert!(smoke.contains("--smoke-probe") || smoke.contains("-SmokeProbe"));
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
    assert!(unix.contains("--foreground"));
    assert!(unix.contains(r#"--endpoint "$runtime/devicelane.sock""#));
}

#[test]
fn native_artifacts_are_installed_before_the_smoke_probe() {
    let windows = read("scripts/desktop-release-smoke.ps1");
    assert!(windows.contains("msiexec.exe"));
    assert!(windows.contains("/i"));
    assert!(windows.contains("/x"));
    assert!(windows.contains("@('/a', $Artifact"));
    assert!(windows.contains("/l*v"));

    let unix = read("scripts/desktop-release-smoke.sh");
    for declaration in [
        "hdiutil attach",
        "ditto",
        "--appimage-extract",
        "dpkg-deb -x",
    ] {
        assert!(
            unix.contains(declaration),
            "missing native install step: {}",
            declaration
        );
    }
    assert!(read("desktop/src-tauri/src/lib.rs").contains("DEVICELANE_RUNTIME_DIR"));
}

#[test]
fn bundled_windows_lifecycle_runs_on_inbox_windows_powershell() {
    let lifecycle = read("scripts/setup-windows.ps1");
    assert!(!lifecycle.contains("IsPathFullyQualified"));
    assert!(lifecycle.contains("[System.IO.Path]::IsPathRooted"));
    assert!(lifecycle.contains("Wait-ServiceTaskStopped"));
    let smoke = read("scripts/desktop-release-smoke.ps1");
    assert!(smoke.contains("Invoke-LocalStatusWithRetry"));
    assert!(smoke.contains("if ($LASTEXITCODE -ne 0)"));
    assert!(smoke.contains("$ErrorActionPreference = \"Continue\""));
}

#[test]
fn workflow_pins_build_environment_and_records_inputs() {
    let workflow = read(".github/workflows/desktop-release.yml");
    let toolchain = read("rust-toolchain.toml");
    for declaration in [
        "windows-2025",
        "macos-15",
        "ubuntu-24.04",
        "node-version: 22.20.0",
        "BUILD-INPUTS.txt",
    ] {
        assert!(
            workflow.contains(declaration),
            "missing pinned build input: {}",
            declaration
        );
    }
    assert!(toolchain.contains(r#"channel = "1.95.0""#));
    assert!(!workflow.contains("uses: actions/checkout@v"));
    assert!(!workflow.contains("uses: actions/setup-node@v"));
}

#[test]
fn windows_desktop_does_not_require_a_separately_installed_msvc_runtime() {
    let cargo_config = read(".cargo/config.toml");
    assert!(cargo_config.contains("x86_64-pc-windows-msvc"));
    assert!(cargo_config.contains("target-feature=+crt-static"));
}

#[test]
fn tauri_build_embeds_the_native_application_manifest() {
    let build = read("desktop/src-tauri/build.rs");
    let manifest = read("desktop/src-tauri/Cargo.toml");
    assert!(build.contains("tauri_build::build()"));
    assert!(manifest.contains("tauri-build = { version = \"2\""));
}
