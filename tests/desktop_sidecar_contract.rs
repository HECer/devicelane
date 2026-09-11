use std::fs;

#[test]
fn tauri_declares_and_stages_the_service_with_target_triple_conventions() {
    let config = fs::read_to_string("desktop/src-tauri/tauri.conf.json").unwrap();
    let stage = fs::read_to_string("desktop/scripts/stage-sidecar.mjs").unwrap();
    let service = fs::read_to_string("src/bin/devicelane-service.rs").unwrap();

    assert!(
        config.contains(r#""externalBin": ["binaries/devicelane-service", "binaries/devicelane"]"#)
    );
    assert!(stage.contains(r#"checked("rustc", ["-vV"])"#));
    assert!(stage.contains("`${binary}-${targetTriple}${executableSuffix}`"));
    assert!(stage.contains("cargo build --release --bin devicelane-service"));
    assert!(stage.contains("--bin\", \"devicelane\", \"--bin\", \"devicelane-service"));
    assert!(service.contains("--print-executable-path"));
}

#[test]
fn ci_stages_each_native_sidecar_before_the_matrix_workspace_build() {
    let workflow = fs::read_to_string(".github/workflows/ci.yml").unwrap();
    let matrix_job = workflow
        .split("  build-and-test:")
        .nth(1)
        .expect("build-and-test matrix job");

    assert!(matrix_job.contains("os: [windows-latest, macos-latest, ubuntu-latest]"));
    let stage = matrix_job
        .find("run: npm run stage:sidecar --prefix desktop -- --debug")
        .expect("cross-platform debug sidecar staging step");
    let frontend = matrix_job
        .find("name: Dashboard UI production build")
        .expect("Tauri frontend production build");
    let workspace_build = matrix_job
        .find("run: cargo build --workspace --locked")
        .expect("locked workspace build");
    assert!(
        frontend < stage && stage < workspace_build,
        "frontendDist and externalBin files must exist before Cargo evaluates the workspace"
    );
    assert_eq!(
        matrix_job
            .matches("name: Dashboard UI production build")
            .count(),
        1,
        "the prerequisite build must not duplicate the production build"
    );
}
