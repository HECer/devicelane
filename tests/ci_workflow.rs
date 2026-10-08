use std::{fs, path::Path};

#[test]
fn ci_workflow_covers_supported_platforms_and_rust_checks() {
    let ci = fs::read_to_string(".github/workflows/ci.yml").unwrap();
    for runner in ["windows-latest", "macos-latest", "ubuntu-latest"] {
        assert!(ci.contains(runner), "CI matrix is missing {runner}");
    }
    assert!(ci.contains("cargo build --workspace"));
    assert!(ci.contains("cargo test --workspace"));
    assert!(Path::new(".github/workflows/ci.yml").is_file());
}
