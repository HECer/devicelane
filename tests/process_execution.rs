use device_development_mesh::process_execution::{
    CancellationToken, EventKind, ProcessError, ProcessExecutor, ProcessRequest, TerminalStatus,
};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

fn workspace(name: &str) -> PathBuf {
    let path = env::temp_dir().join(format!("mesh-process-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).unwrap();
    path
}

fn executor(root: &PathBuf) -> ProcessExecutor {
    ProcessExecutor::new(root, [env::current_exe().unwrap()], ["MESH_ALLOWED"])
        .expect("valid executor")
}

fn request(args: &[&str]) -> ProcessRequest {
    ProcessRequest {
        program: env::current_exe().unwrap(),
        args: args.iter().map(|value| value.to_string()).collect(),
        working_directory: PathBuf::from("job"),
        environment: HashMap::new(),
    }
}

#[test]
fn allowed_helper_runs_in_workspace_with_clean_environment_and_sequenced_events() {
    let root = workspace("allowed");
    fs::create_dir(root.join("job")).unwrap();
    unsafe { env::set_var("MESH_SECRET_FROM_PARENT", "must-not-leak") };
    let mut request = request(&[
        "--ignored",
        "--exact",
        "process_helper_reports_context",
        "--nocapture",
    ]);
    request
        .environment
        .insert("MESH_ALLOWED".into(), "visible".into());

    let events = executor(&root)
        .execute(request, Duration::from_secs(5), CancellationToken::new())
        .unwrap();

    assert_eq!(events.first().unwrap().kind, EventKind::Started);
    assert!(events.iter().any(|event| {
        event.kind == EventKind::Stdout
            && String::from_utf8_lossy(&event.payload).contains("allowed=visible")
    }));
    assert!(events.iter().any(|event| {
        event.kind == EventKind::Stdout
            && String::from_utf8_lossy(&event.payload).contains("parent_secret=false")
    }));
    let reported_cwd = events
        .iter()
        .filter(|event| event.kind == EventKind::Stdout)
        .find_map(|event| {
            String::from_utf8_lossy(&event.payload)
                .lines()
                .find_map(|line| line.strip_prefix("cwd=").map(PathBuf::from))
        })
        .expect("helper reports its working directory");
    assert_eq!(
        reported_cwd.canonicalize().unwrap(),
        root.join("job").canonicalize().unwrap()
    );
    assert!(events.iter().any(|event| {
        event.kind == EventKind::Stderr
            && String::from_utf8_lossy(&event.payload).contains("helper-stderr")
    }));
    assert_eq!(
        events.last().unwrap().kind,
        EventKind::Terminal(TerminalStatus::Exited(0))
    );
    assert_eq!(
        events
            .iter()
            .map(|event| event.sequence)
            .collect::<Vec<_>>(),
        (1..=events.len() as u64).collect::<Vec<_>>()
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event.kind, EventKind::Terminal(_)))
            .count(),
        1
    );
}

#[test]
fn stdout_is_available_before_the_process_exits() {
    let root = workspace("streaming");
    fs::create_dir(root.join("job")).unwrap();
    let request = request(&[
        "--ignored",
        "--exact",
        "process_helper_streams_before_exit",
        "--nocapture",
    ]);

    let mut stream = executor(&root)
        .start(request, Duration::from_secs(5), CancellationToken::new())
        .unwrap();
    let started_at = Instant::now();
    let mut saw_first_output = false;
    while started_at.elapsed() < Duration::from_millis(500) {
        let event = stream
            .next_timeout(Duration::from_millis(100))
            .expect("event before helper exits");
        if event.kind == EventKind::Stdout
            && String::from_utf8_lossy(&event.payload).contains("first")
        {
            saw_first_output = true;
            break;
        }
    }
    assert!(saw_first_output, "stdout was buffered until process exit");

    let remaining = stream.collect::<Vec<_>>();
    assert!(remaining.iter().any(|event| {
        event.kind == EventKind::Stdout
            && String::from_utf8_lossy(&event.payload).contains("second")
    }));
    assert_eq!(
        remaining.last().unwrap().kind,
        EventKind::Terminal(TerminalStatus::Exited(0))
    );
}

#[test]
fn invalid_program_workspace_path_and_environment_are_rejected_before_spawn() {
    let root = workspace("reject");
    fs::create_dir(root.join("job")).unwrap();
    let executor = executor(&root);

    let mut invalid_program = request(&[]);
    invalid_program.program = root.join("not-allowed");
    assert_eq!(
        executor.execute(
            invalid_program,
            Duration::from_secs(1),
            CancellationToken::new()
        ),
        Err(ProcessError::ProgramDenied)
    );

    let mut escaped = request(&[]);
    escaped.working_directory = PathBuf::from("..");
    assert_eq!(
        executor.execute(escaped, Duration::from_secs(1), CancellationToken::new()),
        Err(ProcessError::WorkspaceEscape)
    );

    let mut invalid_environment = request(&[]);
    invalid_environment
        .environment
        .insert("MESH_DENIED".into(), "value".into());
    assert_eq!(
        executor.execute(
            invalid_environment,
            Duration::from_secs(1),
            CancellationToken::new()
        ),
        Err(ProcessError::EnvironmentDenied)
    );
}

#[test]
fn timeout_kills_the_process_tree_and_emits_one_terminal_event() {
    assert_tree_is_killed(false, TerminalStatus::TimedOut);
}

#[test]
fn cancellation_kills_the_process_tree_and_emits_one_terminal_event() {
    assert_tree_is_killed(true, TerminalStatus::Cancelled);
}

#[test]
fn timeout_still_kills_descendants_after_the_process_leader_exits() {
    let root = workspace("orphan-timeout");
    fs::create_dir(root.join("job")).unwrap();
    let marker = root.join("descendant-survived");
    let request = request(&[
        "--ignored",
        "--exact",
        "process_helper_spawns_descendant_and_exits",
        "--nocapture",
        "--",
        marker.to_str().unwrap(),
    ]);

    let events = executor(&root)
        .execute(
            request,
            Duration::from_millis(300),
            CancellationToken::new(),
        )
        .unwrap();
    thread::sleep(Duration::from_millis(900));

    assert!(
        !marker.exists(),
        "descendant survived process-tree termination"
    );
    assert_eq!(
        events.last().unwrap().kind,
        EventKind::Terminal(TerminalStatus::TimedOut)
    );
}

fn assert_tree_is_killed(cancel: bool, expected: TerminalStatus) {
    let root = workspace(if cancel { "cancel" } else { "timeout" });
    fs::create_dir(root.join("job")).unwrap();
    let marker = root.join("descendant-survived");
    let request = request(&[
        "--ignored",
        "--exact",
        "process_helper_spawns_descendant",
        "--nocapture",
        "--",
        marker.to_str().unwrap(),
    ]);
    let token = CancellationToken::new();
    if cancel {
        let trigger = token.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(150));
            trigger.cancel();
        });
    }

    let events = executor(&root)
        .execute(request, Duration::from_millis(300), token)
        .unwrap();
    thread::sleep(Duration::from_millis(900));

    assert!(
        !marker.exists(),
        "descendant survived process-tree termination"
    );
    assert_eq!(events.last().unwrap().kind, EventKind::Terminal(expected));
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event.kind, EventKind::Terminal(_)))
            .count(),
        1
    );
    assert_eq!(
        events
            .iter()
            .map(|event| event.sequence)
            .collect::<Vec<_>>(),
        (1..=events.len() as u64).collect::<Vec<_>>()
    );
}

#[test]
#[ignore]
fn process_helper_reports_context() {
    println!("allowed={}", env::var("MESH_ALLOWED").unwrap_or_default());
    println!(
        "parent_secret={}",
        env::var_os("MESH_SECRET_FROM_PARENT").is_some()
    );
    println!("cwd={}", env::current_dir().unwrap().display());
    eprintln!("helper-stderr");
}

#[test]
#[ignore]
fn process_helper_streams_before_exit() {
    println!("first");
    std::io::stdout().flush().unwrap();
    thread::sleep(Duration::from_millis(800));
    println!("second");
}

#[test]
#[ignore]
fn process_helper_spawns_descendant() {
    let marker = env::args().next_back().unwrap();
    let child = Command::new(env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "process_helper_delayed_marker",
            "--nocapture",
            "--",
            &marker,
        ])
        .spawn()
        .unwrap();
    let _ = child.wait_with_output();
}

#[test]
#[ignore]
fn process_helper_spawns_descendant_and_exits() {
    let marker = env::args().next_back().unwrap();
    let child = Command::new(env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "process_helper_delayed_marker",
            "--nocapture",
            "--",
            &marker,
        ])
        .spawn()
        .unwrap();
    drop(child);
}

#[test]
#[ignore]
fn process_helper_delayed_marker() {
    let marker = env::args().next_back().unwrap();
    thread::sleep(Duration::from_millis(700));
    fs::write(marker, b"survived").unwrap();
}
