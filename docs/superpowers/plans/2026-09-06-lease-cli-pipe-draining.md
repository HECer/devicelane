# Lease CLI Pipe Draining Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Remove the reproduced output-pipe deadlock from the lease integration test helper without weakening its five-second process deadline.

**Architecture:** Reuse the bounded concurrently draining test helper proven by the authenticated control. Route existing lease CLI calls through it; stdout and stderr readers start before polling child exit, and are joined after normal exit or timeout termination. No production process, protocol, timeout, or permissions change.

**Tech Stack:** Rust standard process/thread/I/O APIs; existing mutual TLS fixture.

AI-assisted plan and test development; no human-authorship claim.

## Acceptance criteria and scope

- Own only tests/network_device_leases.rs plus this plan. Preserve other dirty work.
- Existing real cli() entrypoint returns complete stdout/stderr and exit status for finite output, including the reproduced 128 KiB payload.
- Preserve five-second deadline and ten-millisecond polling; kill and reap timed-out child before joining readers and reporting timeout.
- Both stdout and stderr must be drained concurrently, never merely increase the pipe limit or process timeout.
- Keep actual TLS request/response validation, exact expected output comparison, bounded accept/socket operations and fixture join on scenario failure.
- Existing lease security, expiry, ownership and reconnect assertions remain unchanged.
- This fixes a test-harness deadlock. It is not proof of the cause of every historic CI timeout, nor a production transport or product readiness claim.
- SPEC then QUALITY review and fresh full network_device_leases tests, Clippy and formatting must pass before selective commit.

## Task 1: Regression evidence

- [x] Write the real authenticated CLI reproduction with successful concurrent-drain control; only test code was changed before observing RED.
- [x] Root independently ran the focused test: control exit 0 and stdout_bytes=131184; fully_flushed_replies=2; original helper timed out at five seconds. Test result 0 passed / 1 failed, 5.46s (tool chunk 034568). This is the expected behavioral failure, not a compilation failure.

Regression code:

```rust
#[test]
fn cli_drains_large_authenticated_events_output_before_waiting_for_exit() {
    let root = tempfile::tempdir().unwrap();
    let registry = root.path().join("registry");
    let client = root.path().join("client");
    pair(&registry, "registry", &client, "client");

    let payload = "x".repeat(128 * 1024);
    let response = Response {
        accepted: true,
        hosts: vec![],
        job_id: Some("large-events-job".into()),
        events: vec![NetworkEvent {
            sequence: 1,
            kind: "stdout".into(),
            payload: payload.clone(),
        }],
        audit: vec![],
        artifact: None,
        error: None,
        operation: None,
        apple_operation: None,
        cancel_jobs: vec![],
        artifact_metadata: None,
        artifact_chunk: None,
        confirmed_offset: None,
        lease_grant: None,
        lease_status: None,
    };
    let response_frame = serde_json::to_vec(&response).unwrap();
    let mut expected_stdout = response_frame.clone();
    expected_stdout.push(b'\n');

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let registry_transport = SecureTransport::load_or_create(&registry, "registry").unwrap();
    let fully_flushed_replies = Arc::new(AtomicUsize::new(0));
    let server_flushed_replies = Arc::clone(&fully_flushed_replies);
    let server = thread::spawn(move || {
        for _ in 0..2 {
            let deadline = Instant::now() + Duration::from_secs(5);
            let stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "fixture timed out accepting mesh-cli");
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("fixture failed accepting mesh-cli: {error}"),
                }
            };
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut stream = registry_transport.accept_tls(stream).unwrap();
            let mut request = String::new();
            BufReader::new(&mut stream).read_line(&mut request).unwrap();
            assert!(matches!(
                serde_json::from_str::<Request>(&request).unwrap(),
                Request::Events { ref job_id, after: 0 } if job_id == "large-events-job"
            ));
            stream.write_all(&response_frame).unwrap();
            stream.write_all(b"\n").unwrap();
            stream.flush().unwrap();
            server_flushed_replies.fetch_add(1, Ordering::SeqCst);
        }
    });

    let body = serde_json::json!({"job_id": "large-events-job", "after": 0});
    let scenario = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let control = cli_with_concurrent_drain(&address, &client, "events", &body);
        eprintln!(
            "control status={} stdout_bytes={}",
            control.status,
            control.stdout.len()
        );
        assert!(
            control.status.success(),
            "control mesh-cli failed: {}",
            String::from_utf8_lossy(&control.stderr)
        );
        assert_eq!(control.stdout, expected_stdout);
        let control_response: serde_json::Value = serde_json::from_slice(&control.stdout).unwrap();
        assert_eq!(control_response["events"][0]["payload"], payload);

        cli(&address, &client, "events", &body)
    }));
    let server_result = server.join();
    eprintln!(
        "fully_flushed_replies={}",
        fully_flushed_replies.load(Ordering::SeqCst)
    );
    if let Err(panic) = server_result {
        std::panic::resume_unwind(panic);
    }
    let output = match scenario {
        Ok(output) => output,
        Err(panic) => std::panic::resume_unwind(panic),
    };
    assert!(
        output.status.success(),
        "mesh-cli failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, expected_stdout);
}
```

The control implementation already added during reproduction:

```rust
fn cli_with_concurrent_drain<T: serde::Serialize>(
    address: &str,
    identity: &Path,
    command: &str,
    body: &T,
) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_mesh-cli"))
        .args([
            "--registry",
            address,
            "--identity",
            identity.to_str().unwrap(),
            command,
            "--json-request",
            &serde_json::to_string(body).unwrap(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let stdout_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        BufReader::new(stdout).read_to_end(&mut bytes).unwrap();
        bytes
    });
    let stderr_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        BufReader::new(stderr).read_to_end(&mut bytes).unwrap();
        bytes
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let status = child.wait().unwrap();
            let stdout = stdout_reader.join().unwrap();
            let stderr = stderr_reader.join().unwrap();
            panic!(
                "concurrently drained mesh-cli {command} timed out after five seconds; status={status}; stdout_bytes={}; stderr={}",
                stdout.len(),
                String::from_utf8_lossy(&stderr)
            );
        }
        thread::sleep(Duration::from_millis(10));
    };
    Output {
        status,
        stdout: stdout_reader.join().unwrap(),
        stderr: stderr_reader.join().unwrap(),
    }
}
```

## Task 2: Minimal correction

- [ ] Replace only the body of the existing cli() wrapper with this complete implementation; retain the control helper above unchanged:

```rust
fn cli<T: serde::Serialize>(address: &str, identity: &Path, command: &str, body: &T) -> Output {
    cli_with_concurrent_drain(address, identity, command, body)
}
```

The control and regression then exercise the same corrected routine. The recorded pre-fix RED distinguishes this from a test that only ever passed.

- [ ] Run focused regression:
```
cargo test -p devicelane --test network_device_leases cli_drains_large_authenticated_events_output_before_waiting_for_exit --locked --jobs 1 -- --nocapture
```
Expected: 1 passed, exact complete output, two fully flushed replies.
- [ ] Run all lease integration tests:
```
cargo test -p devicelane --test network_device_leases --locked --jobs 1
cargo clippy -p devicelane --test network_device_leases --locked --jobs 1 -- -D warnings
cargo fmt --all -- --check
git diff --check
```
Expected: 17 passed and all checks exit 0. Use RTK prefix; Windows VS2022 Developer PowerShell and target E:/CodexBuild/devicelane-task10-ci as in prior runs.
- [ ] Independent SPEC then QUALITY review of this scope. Resolve findings before commit.
- [ ] Root fresh verification, plus published-code baseline verification if frozen WIP could affect the regression. Audit this Markdown with audit-provenance; preserve disclosure and report unverifiable fields.
- [ ] Stage only tests/network_device_leases.rs and this plan, inspect staged diff, then commit and push feature branch:
```
git add tests/network_device_leases.rs docs/superpowers/plans/2026-09-06-lease-cli-pipe-draining.md
git diff --cached --check
git commit -m "test: drain lease CLI output while awaiting exit"
git push origin feat/speechwalker-remote-builds
```
No merge or deployment.

## QUALITY correction: protect both output streams

The initial authenticated fixture fills only stdout. Independent QUALITY review found that deferring stderr draining would therefore escape the new regression. This is an explicit acceptance-criterion gap, not a production behavior defect newly introduced by the wrapper.

- [ ] Extract the existing capture lifecycle unchanged into `bounded_cli_output(mut command: Command, label: &str) -> Output`; `cli_with_concurrent_drain` constructs the same command and delegates. Keep five seconds, both reader threads, kill/reap/join and full bytes. Rename only the diagnostic interpolation from command to label in the extracted function.

Replacement command-builder code:

```rust
fn cli_with_concurrent_drain<T: serde::Serialize>(
    address: &str, identity: &Path, command: &str, body: &T,
) -> Output {
    let mut process = Command::new(env!("CARGO_BIN_EXE_mesh-cli"));
    process.args([
        "--registry", address, "--identity", identity.to_str().unwrap(),
        command, "--json-request", &serde_json::to_string(body).unwrap(),
    ]);
    bounded_cli_output(process, command)
}
```

Complete extracted lifecycle (preserving timing, error paths and captures):

```rust
fn bounded_cli_output(mut command: Command, label: &str) -> Output {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let stdout_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        BufReader::new(stdout).read_to_end(&mut bytes).unwrap();
        bytes
    });
    let stderr_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        BufReader::new(stderr).read_to_end(&mut bytes).unwrap();
        bytes
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let status = child.wait().unwrap();
            let stdout = stdout_reader.join().unwrap();
            let stderr = stderr_reader.join().unwrap();
            panic!(
                "concurrently drained mesh-cli {label} timed out after five seconds; status={status}; stdout_bytes={}; stderr={}",
                stdout.len(),
                String::from_utf8_lossy(&stderr)
            );
        }
        thread::sleep(Duration::from_millis(10));
    };
    Output {
        status,
        stdout: stdout_reader.join().unwrap(),
        stderr: stderr_reader.join().unwrap(),
    }
}
```

- [ ] Add the following subprocess regression, using the test executable itself so no shell or external program dependency is added:

```rust
#[test]
fn cli_capture_drains_both_large_output_streams() {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.args(["--exact", "cli_pipe_output_child", "--ignored", "--nocapture"]);
    command.env("DEVICELANE_PIPE_TEST_CHILD", "1");
    let output = bounded_cli_output(command, "pipe-fixture");
    assert!(output.status.success());
    let marker = b"DEVICELANE_STDOUT_PAYLOAD\n";
    let positions: Vec<_> = output.stdout.windows(marker.len())
        .enumerate().filter_map(|(index, bytes)| (bytes == marker).then_some(index)).collect();
    assert_eq!(positions.len(), 1);
    assert_eq!(&output.stdout[positions[0] + marker.len()..], vec![b'o'; 128 * 1024]);
    assert_eq!(output.stderr, vec![b'e'; 128 * 1024]);
}
#[test]
#[ignore = "invoked as a bounded subprocess fixture"]
fn cli_pipe_output_child() {
    if std::env::var("DEVICELANE_PIPE_TEST_CHILD").as_deref() != Ok("1") {
        return;
    }
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(b"DEVICELANE_STDOUT_PAYLOAD\n").unwrap();
    stdout.write_all(&vec![b'o'; 128 * 1024]).unwrap();
    stdout.flush().unwrap();
    let mut stderr = std::io::stderr().lock();
    stderr.write_all(&vec![b'e'; 128 * 1024]).unwrap();
    stderr.flush().unwrap();
    std::process::exit(0);
}
```

- [ ] Negative mutation: defer stderr reader start until after exit polling; the new parent test must fail by bounded timeout. Restore both readers before exit polling; the new test must pass. Record as mutation verification of the extraction, not a claim that the previous helper was written test-first.
- [ ] Re-run both regressions and full suite (18 passed, one intentionally ignored child fixture expected), scoped Clippy, format/diff; then SPEC and QUALITY re-review. No staging before these gates.

## Final verification record

- Root independently confirmed the original authenticated RED: successful control returned exactly 131184 bytes, both TLS replies were fully flushed, but the original helper timed out after five seconds (034568).
- Implementer additionally tested a deliberate deferred-stderr mutation: the dual-pipe parent failed by timeout after 5.02 seconds. Restored early readers passed the dual-pipe test in 0.03 seconds and authenticated regression in 0.81 seconds.
- Root ran the resulting complete network_device_leases test executable: **18 passed, 0 failed, 1 ignored**, 63.78 seconds (953ba3). The ignored test is the child fixture; its parent explicitly executes it. The outer tool pipe remained open after the complete test summary, so no outer-wrapper exit code is asserted.
- Fresh root scoped Clippy returned exit 0 (4efbe4); workspace format check returned exit 0 (243cb9); diff check returned exit 0 (b7f8af).
- Independent final SPEC review passed; independent final QUALITY review closed the stderr coverage finding and reported scoped READY, with no remaining findings.
- Current CLI production WIP only changes the separate hardware-gate pagination path, not the events request/response printing path used by this regression (root inspected ec32ea). Other uncommitted transport work remains excluded from this change.
- CI for the preceding commit d8571d7 succeeded on Linux/macOS/npm but failed Windows: artifact publication reported stage=write, cause=response_timeout, followed by a rejected terminal event in forged_workspace_lease_and_grant_cannot_run_a_mutation_but_observer_reads_events (570526). This test-helper correction is not a fix claim for that distinct failure.
- The local Windows service is reachable but reports disconnected with no registry endpoint (7444f1); this remains product work, not something this test change resolves.
- AI-assisted disclosure is retained. Provenance scans of the plan found no supported embedded provenance and completed the local scan; cryptographic verification/trust and provider-keyed watermarks remain unknown without a verifier, policy and provider keys. TEXT metadata privacy is unsupported/unknown; absence of a signal is not evidence of human authorship.

Earlier unchecked execution items describe the historical plan; the completed verification and review gates are recorded above. Only selective staging/commit/push follows; no production deployment or broad readiness claim.
