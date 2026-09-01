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
