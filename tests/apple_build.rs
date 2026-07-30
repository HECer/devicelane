use device_development_mesh::apple_build::{
    AppleBuildJob, BuildAction, BuildPlan, SigningReference,
};
use device_development_mesh::apple_project_discovery::ContainerKind;
use device_development_mesh::artifacts::ArtifactStore;
use device_development_mesh::process_execution::{CancellationToken, EventKind, TerminalStatus};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;
use std::time::Instant;

fn workspace() -> PathBuf {
    let root = env::temp_dir().join(format!("mesh-apple-build-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("lease/job")).unwrap();
    root
}

fn plan(action: BuildAction) -> BuildPlan {
    BuildPlan {
        action,
        container_kind: ContainerKind::Workspace,
        container: "App.xcworkspace".into(),
        scheme: "Mesh App".into(),
        configuration: "Debug".into(),
        destination: "platform=iOS Simulator,name=iPhone 16".into(),
        derived_data: "DerivedData".into(),
        result_bundle: "Results/Test.xcresult".into(),
        signing: Some(SigningReference::Identity(
            "Apple Development: Local".into(),
        )),
        protected_build_settings: HashMap::from([("API_TOKEN".into(), "very-secret".into())]),
    }
}

#[test]
fn creates_explicit_typed_build_and_test_plans_inside_lease() {
    for (action, verb) in [(BuildAction::Build, "build"), (BuildAction::Test, "test")] {
        let args = plan(action).arguments().unwrap();
        assert_eq!(args[0], verb);
        for expected in [
            "-workspace",
            "App.xcworkspace",
            "-scheme",
            "Mesh App",
            "-configuration",
            "Debug",
            "-destination",
            "platform=iOS Simulator,name=iPhone 16",
            "-derivedDataPath",
            "DerivedData",
            "-resultBundlePath",
            "Results/Test.xcresult",
        ] {
            assert!(args.iter().any(|arg| arg == expected), "missing {expected}");
        }
        assert!(!args.iter().any(|arg| arg.contains("very-secret")));
    }
    let mut escaped = plan(BuildAction::Build);
    escaped.derived_data = "../outside".into();
    assert!(escaped.arguments().is_err());
}

#[test]
fn streams_resumable_redacted_events_and_registers_success_outputs() {
    let root = workspace();
    let mut store = ArtifactStore::new(root.join("artifacts")).unwrap();
    let job = AppleBuildJob::with_prefix(
        &root,
        env::current_exe().unwrap(),
        ["API_TOKEN"],
        [
            "--ignored",
            "--exact",
            "apple_build_helper",
            "--nocapture",
            "--",
        ],
    )
    .unwrap()
    .with_local_signing_references([SigningReference::Identity(
        "Apple Development: Local".into(),
    )]);
    let mut build = plan(BuildAction::Test);
    build.container = "--ignored".into();
    build.scheme = "apple_build_helper".into();
    build.configuration = "--nocapture".into();
    let result = job
        .execute(
            "job-24",
            "session-24",
            build,
            &mut store,
            100,
            200,
            Duration::from_secs(5),
            CancellationToken::new(),
        )
        .unwrap();
    assert_eq!(
        result.events.iter().map(|e| e.sequence).collect::<Vec<_>>(),
        (1..=result.events.len() as u64).collect::<Vec<_>>()
    );
    assert!(matches!(
        result.events.last().unwrap().kind,
        EventKind::Terminal(TerminalStatus::Exited(0))
    ));
    let visible = result
        .events
        .iter()
        .flat_map(|e| e.payload.clone())
        .collect::<Vec<_>>();
    assert!(!String::from_utf8_lossy(&visible).contains("very-secret"));
    assert_eq!(result.resume(1), result.events[1..]);
    assert_eq!(result.artifacts.len(), 3);
    for artifact in result.artifacts {
        assert!(
            !store
                .read("session-24", &artifact.sha256, 100)
                .unwrap()
                .is_empty()
        );
    }
    assert!(!result.audit.contains("very-secret"));
}

#[test]
fn rejects_signing_reference_that_is_not_locally_available() {
    let root = workspace();
    let mut store = ArtifactStore::new(root.join("artifacts")).unwrap();
    let job = AppleBuildJob::new(&root, env::current_exe().unwrap(), ["API_TOKEN"]).unwrap();
    assert!(
        job.execute(
            "job",
            "session",
            plan(BuildAction::Build),
            &mut store,
            100,
            200,
            Duration::from_secs(1),
            CancellationToken::new()
        )
        .is_err()
    );
}

#[test]
fn build_stream_preserves_live_output_while_redacting_only_secret_values() {
    let root = workspace();
    let job = AppleBuildJob::with_prefix(
        &root,
        env::current_exe().unwrap(),
        ["API_TOKEN"],
        [
            "--ignored",
            "--exact",
            "apple_build_stream_helper",
            "--nocapture",
            "--",
        ],
    )
    .unwrap()
    .with_local_signing_references([SigningReference::Identity(
        "Apple Development: Local".into(),
    )]);
    let build = plan(BuildAction::Build);
    let began = Instant::now();
    let mut stream = job
        .start(&build, Duration::from_secs(5), CancellationToken::new())
        .unwrap();

    let mut events = Vec::new();
    for event in stream.by_ref() {
        let is_visible_output = matches!(event.kind, EventKind::Stdout)
            && String::from_utf8_lossy(&event.payload).contains("build-phase-visible");
        events.push(event);
        if is_visible_output {
            break;
        }
    }
    assert!(
        began.elapsed() < Duration::from_millis(700),
        "stdout was buffered until the helper exited"
    );
    let output = events
        .iter()
        .flat_map(|event| event.payload.clone())
        .collect::<Vec<_>>();
    let output = String::from_utf8_lossy(&output);
    assert!(output.contains("build-phase-visible"));
    assert!(output.contains("[REDACTED]"));
    assert!(!output.contains("very-secret"));

    events.extend(stream);
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event.kind, EventKind::Terminal(_)))
            .count(),
        1
    );
}

#[test]
fn build_stream_timeout_and_cancel_each_emit_one_terminal_status() {
    let root = workspace();
    let job = AppleBuildJob::with_prefix(
        &root,
        env::current_exe().unwrap(),
        ["API_TOKEN"],
        [
            "--ignored",
            "--exact",
            "apple_build_slow_helper",
            "--nocapture",
            "--",
        ],
    )
    .unwrap()
    .with_local_signing_references([SigningReference::Identity(
        "Apple Development: Local".into(),
    )]);
    let build = plan(BuildAction::Build);

    let timed_out = job
        .start(&build, Duration::from_millis(50), CancellationToken::new())
        .unwrap()
        .collect::<Vec<_>>();
    assert_eq!(
        timed_out
            .iter()
            .filter(|event| matches!(event.kind, EventKind::Terminal(TerminalStatus::TimedOut)))
            .count(),
        1
    );

    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let cancelled = job
        .start(&build, Duration::from_secs(5), cancellation)
        .unwrap()
        .collect::<Vec<_>>();
    assert_eq!(
        cancelled
            .iter()
            .filter(|event| matches!(event.kind, EventKind::Terminal(TerminalStatus::Cancelled)))
            .count(),
        1
    );
}

#[test]
#[ignore]
fn apple_build_helper() {
    fs::create_dir_all("DerivedData/Build/Products/Debug/Mesh.app").unwrap();
    fs::write("DerivedData/Build/Products/Debug/Mesh.app/Mesh", b"app").unwrap();
    fs::create_dir_all("DerivedData/Build/Products/Debug/Mesh.app.dSYM").unwrap();
    fs::write(
        "DerivedData/Build/Products/Debug/Mesh.app.dSYM/symbols",
        b"dsym",
    )
    .unwrap();
    fs::create_dir_all("Results/Test.xcresult").unwrap();
    fs::write("Results/Test.xcresult/data", b"result").unwrap();
    println!("stdout {}", env::var("API_TOKEN").unwrap());
    eprintln!("stderr {}", env::var("API_TOKEN").unwrap());
}

#[test]
#[ignore]
fn apple_build_stream_helper() {
    println!("build-phase-visible {}", env::var("API_TOKEN").unwrap());
    std::io::stdout().flush().unwrap();
    std::thread::sleep(Duration::from_millis(900));
}

#[test]
#[ignore]
fn apple_build_slow_helper() {
    std::thread::sleep(Duration::from_secs(30));
}
