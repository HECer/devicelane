use device_development_mesh::preflight::{AppleTool, AppleToolRunner};
use device_development_mesh::process_execution::{CancellationToken, EventKind, TerminalStatus};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::time::Duration;
use tempfile::tempdir;

#[test]
fn runner_uses_typed_allowlist_clean_environment_and_workspace_boundary() {
    let root = tempdir().unwrap();
    let helper = env::current_exe().unwrap();
    let runner = AppleToolRunner::new(root.path(), [(AppleTool::Xcodebuild, helper)]).unwrap();
    let mut environment = HashMap::new();
    environment.insert("DEVELOPER_DIR".into(), "clean".into());

    let events = runner
        .execute(
            AppleTool::Xcodebuild,
            vec![
                "--exact".into(),
                "apple_runner_helper".into(),
                "--nocapture".into(),
            ],
            ".",
            environment,
            Duration::from_secs(5),
            CancellationToken::new(),
        )
        .unwrap();
    assert!(
        events
            .iter()
            .any(|event| event.payload.windows(5).any(|v| v == b"clean"))
    );
    assert!(
        !events
            .iter()
            .any(|event| event.payload.windows(6).any(|v| v == b"leaked"))
    );

    assert!(
        runner
            .execute(
                AppleTool::Xcodebuild,
                Vec::new(),
                "..",
                HashMap::new(),
                Duration::from_secs(1),
                CancellationToken::new(),
            )
            .is_err()
    );
}

#[test]
fn runner_enforces_timeout_and_cancellation() {
    let root = tempdir().unwrap();
    let helper = env::current_exe().unwrap();
    let runner = AppleToolRunner::new(root.path(), [(AppleTool::Xctrace, helper)]).unwrap();

    let timed_out = runner
        .execute(
            AppleTool::Xctrace,
            vec![
                "--exact".into(),
                "apple_runner_slow_helper".into(),
                "--nocapture".into(),
            ],
            ".",
            HashMap::from([("DEVELOPER_DIR".into(), "slow".into())]),
            Duration::from_millis(50),
            CancellationToken::new(),
        )
        .unwrap();
    assert_eq!(
        timed_out.last().unwrap().kind,
        EventKind::Terminal(TerminalStatus::TimedOut)
    );

    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let cancelled = runner
        .execute(
            AppleTool::Xctrace,
            vec![
                "--exact".into(),
                "apple_runner_slow_helper".into(),
                "--nocapture".into(),
            ],
            ".",
            HashMap::from([("DEVELOPER_DIR".into(), "slow".into())]),
            Duration::from_secs(5),
            cancellation,
        )
        .unwrap();
    assert_eq!(
        cancelled.last().unwrap().kind,
        EventKind::Terminal(TerminalStatus::Cancelled)
    );
}

#[test]
fn apple_runner_helper() {
    if env::var("DEVELOPER_DIR").as_deref() == Ok("clean") && env::var("PATH").is_err() {
        println!("clean");
    } else {
        println!("leaked");
    }
}

#[test]
fn apple_runner_slow_helper() {
    if env::var("DEVELOPER_DIR").as_deref() == Ok("slow") {
        std::thread::sleep(Duration::from_secs(30));
    }
}

#[test]
fn apple_tools_are_exactly_the_required_allowlist() {
    assert_eq!(
        AppleTool::ALL,
        [
            AppleTool::Xcodebuild,
            AppleTool::Devicectl,
            AppleTool::Simctl,
            AppleTool::Xcresulttool,
            AppleTool::Xctrace,
            AppleTool::LldbDap,
        ]
    );
    assert!(
        !fs::read_to_string("tests/apple_tool_runner.rs")
            .unwrap()
            .is_empty()
    );
}
