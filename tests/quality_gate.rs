use std::{fs, path::Path};

#[test]
fn story_13_quality_gate_is_complete() {
    let config = fs::read_to_string(".yoke/config.yaml").unwrap();
    for command in [
        "cargo test --workspace",
        "cargo clippy --workspace --all-targets -- -D warnings",
        "cargo fmt --all -- --check",
    ] {
        assert!(
            config.contains(command),
            "verification gate is missing {command}"
        );
    }

    let ci = fs::read_to_string(".github/workflows/ci.yml").unwrap();
    for runner in ["windows-latest", "macos-latest", "ubuntu-latest"] {
        assert!(ci.contains(runner), "CI matrix is missing {runner}");
    }
    assert!(ci.contains("cargo build --workspace"));
    assert!(ci.contains("cargo test --workspace"));

    let catalog = fs::read_to_string(".yoke/acceptance-tests.yaml").unwrap();
    for story in 14..=20 {
        assert!(
            catalog.contains(&format!("STORY-{story}:")),
            "acceptance catalog is missing STORY-{story}"
        );
    }
    assert!(catalog.contains("tests/process_execution.rs"));
    assert!(catalog.contains("tests/artifacts.rs"));
    assert!(catalog.contains("tests/device_adapter_contract.rs"));
    assert!(catalog.contains("tests/secure_transport.rs"));
    assert!(catalog.contains("tests/network_processes.rs"));
    assert!(catalog.contains("tests/e2e_vertical_slice.rs"));
    assert!(catalog.contains("scripts/bootstrap-smoke"));

    let readme = fs::read_to_string("README.md").unwrap();
    assert!(readme.contains("story-spezifische Akzeptanzprüfung"));
    assert!(readme.contains("`passes: true`"));

    assert!(Path::new(".github/workflows/ci.yml").is_file());
}
