use device_development_mesh::apple_xctest::{
    XCTestOperation, XCTestRunEnd, XCTestTerminal, finish_xctest, normalize_xcresult,
    register_xctest_artifacts,
};
use device_development_mesh::artifacts::ArtifactStore;
use std::collections::HashMap;
use std::fs;
use tempfile::tempdir;

#[test]
fn creates_typed_build_for_testing_and_selected_test_without_building_operations() {
    let build = XCTestOperation::BuildForTesting {
        test_plan: Some("Regression".into()),
    };
    assert_eq!(
        build.arguments(),
        vec!["build-for-testing", "-testPlan", "Regression"]
    );

    let test = XCTestOperation::TestWithoutBuilding {
        test_plan: Some("Regression".into()),
        only_testing: vec!["AppTests/LoginTests/testHappyPath".into()],
        ui_tests: vec!["AppUITests/CheckoutTests".into()],
    };
    assert_eq!(
        test.arguments(),
        vec![
            "test-without-building",
            "-testPlan",
            "Regression",
            "-only-testing:AppTests/LoginTests/testHappyPath",
            "-only-testing:AppUITests/CheckoutTests",
        ]
    );
}

#[test]
fn normalizes_suites_cases_failures_attachments_and_coverage_with_sources() {
    let result =
        normalize_xcresult(include_str!("fixtures/v1/apple/xcresult-success.json")).unwrap();
    assert_eq!(result.suites[0].name, "AppTests");
    assert_eq!(result.suites[0].tests[0].identifier, "LoginTests/testLogin");
    let failure = result.suites[0].tests[0].failure.as_ref().unwrap();
    assert_eq!(failure.message, "expected true");
    assert_eq!(failure.source.file, "Tests/LoginTests.swift");
    assert_eq!(failure.source.line, 42);
    assert_eq!(result.attachments[0].name, "failure.png");
    assert_eq!(result.attachments[0].path, "attachments/failure.png");
    assert_eq!(result.coverage[0].target, "MeshApp");
    assert_eq!(result.coverage[0].line_percent, 87.5);
    assert_eq!(
        result.coverage[0].source.as_ref().unwrap().file,
        "Sources/Login.swift"
    );
}

#[test]
fn registers_result_bundle_and_media_as_hashed_redacted_artifacts() {
    let root = tempdir().unwrap();
    let bundle = root.path().join("Test.xcresult");
    fs::create_dir_all(bundle.join("attachments")).unwrap();
    fs::write(bundle.join("attachments/failure.png"), b"\xffpng secret").unwrap();
    fs::write(bundle.join("run.mp4"), b"video secret").unwrap();
    fs::write(bundle.join("diagnostics.log"), b"API_TOKEN=secret").unwrap();
    fs::write(bundle.join("data"), b"raw secret").unwrap();
    let mut store = ArtifactStore::new(root.path().join("store")).unwrap();

    let artifacts = register_xctest_artifacts(
        &bundle,
        "job-27",
        "session-27",
        &mut store,
        100,
        200,
        &HashMap::from([("API_TOKEN".into(), "secret".into())]),
    )
    .unwrap();

    assert_eq!(artifacts.len(), 4);
    let mut stored = Vec::new();
    for artifact in artifacts {
        let bytes = store.read("session-27", &artifact.sha256, 100).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("secret"));
        stored.push(bytes);
    }
    assert!(stored.iter().any(|bytes| bytes.starts_with(b"\xffpng")));
    let packed = stored.last().unwrap();
    let mut cursor = 0;
    while cursor < packed.len() {
        cursor += packed[cursor..].iter().position(|byte| *byte == 0).unwrap() + 1;
        let size = u64::from_le_bytes(packed[cursor..cursor + 8].try_into().unwrap()) as usize;
        cursor += 8 + size;
    }
    assert_eq!(cursor, packed.len());
}

#[test]
fn all_failures_emit_one_terminal_and_preserve_partial_results() {
    for (end, terminal) in [
        (XCTestRunEnd::Cancelled, XCTestTerminal::Cancelled),
        (XCTestRunEnd::Exited(65), XCTestTerminal::TestsFailed),
        (XCTestRunEnd::Exited(70), XCTestTerminal::RunnerCrashed),
        (XCTestRunEnd::DeviceDisconnected, XCTestTerminal::DeviceLost),
        (
            XCTestRunEnd::Exited(0),
            XCTestTerminal::IncompatibleResultSchema,
        ),
    ] {
        let fixture = if terminal == XCTestTerminal::IncompatibleResultSchema {
            include_str!("fixtures/v1/apple/xcresult-incompatible.json")
        } else {
            include_str!("fixtures/v1/apple/xcresult-partial.json")
        };
        let outcome = finish_xctest(fixture, end).unwrap();
        assert_eq!(outcome.terminals().count(), 1);
        assert_eq!(outcome.terminals().next(), Some(&terminal));
        assert_eq!(outcome.result.suites[0].tests.len(), 1);
    }
}

#[test]
fn rejects_incompatible_xcresult_schema() {
    assert!(normalize_xcresult(r#"{"schema_version":2}"#).is_err());
}

#[test]
fn accepts_missing_optional_partial_sections_and_classifies_success() {
    let fixture = r#"{"schema_version":1,"test_summaries":{"_values":[]}}"#;
    let outcome = finish_xctest(fixture, XCTestRunEnd::Exited(0)).unwrap();
    assert_eq!(outcome.terminals().next(), Some(&XCTestTerminal::Succeeded));
    assert!(outcome.result.attachments.is_empty());
    assert!(outcome.result.coverage.is_empty());
}
