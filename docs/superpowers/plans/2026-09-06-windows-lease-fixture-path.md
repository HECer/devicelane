# Windows lease fixture command resolution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make both Windows lease-test delay paths execute the intended system ping under the production executor's cleared environment.

**Architecture:** Preserve the existing seven-line fixture fix already present in the feature worktree, and add real-process regression coverage. First execute the regressions against the unmodified published fixture in the separate baseline worktree; only then bring the tests into the feature worktree and verify its absolute-path fix. No production permissions, transport timeouts, retry policy, or environment allowlist changes.

**Tech Stack:** Rust 2024, existing ProcessExecutor, tempfile, Windows cmd.exe/ping.exe.

AI-assisted engineering plan; not an authorship or cryptographic provenance claim.

## Evidence and acceptance criteria

- Root reproduced the bare command with ProcessStartInfo.EnvironmentVariables.Clear: cmd.exe /d /c ping.exe -n 1 127.0.0.1 exited 1, command not found (08d53f).
- Production ProcessExecutor clears child environment at src/lib.rs:811. The committed lease fixture uses bare ping in both delay and gate branches. Feature worktree already contains absolute SystemRoot/System32/ping.exe paths as uncommitted WIP.
- Both generated commands must retain quoted absolute system path, no PATH or environment relaxation.
- Actual ProcessExecutor regression tests must run both delay-only and gated fixtures with an empty environment, see successful terminal, no stderr and mutation-start/end marker.
- Delay test must not complete immediately. Gate test must remain incomplete until explicit release after observing mutation-start. Existing 5-second execution bound and process-group cleanup apply.
- Baseline RED must demonstrate the real fixture defect, not a compiler error. GREEN on the feature worktree must include the two regressions and full network_device_leases suite. Existing underlying CI lease/RPC timeouts remain separate unless evidence links them.
- Only tests/network_device_leases.rs and this plan may enter the commit. Frozen production WIP is excluded. Independent spec then quality reviews.

## Files

- Modify feature worktree tests/network_device_leases.rs: preserve existing 7-line fix, append two Windows tests and one helper.
- Temporarily add only regression tests to the separate detached worktree .worktrees/network-ci-035512d after its ongoing baseline test completes; do not change its original fixture before observing RED. This baseline copy and own target dir are diagnostic-only and not deployed.

### Task 1: Cover the existing fixture fix with real-process RED/GREEN

- [x] After root confirms baseline process terminal, add this exact regression code before fake_tool in baseline worktree. No helper fix yet.

```rust
#[cfg(windows)]
#[test]
fn windows_lease_fixture_delay_works_with_cleared_environment() {
    assert_windows_lease_fixture(false);
}

#[cfg(windows)]
#[test]
fn windows_lease_fixture_gate_works_with_cleared_environment() {
    assert_windows_lease_fixture(true);
}

#[cfg(windows)]
fn assert_windows_lease_fixture(gated: bool) {
    use device_development_mesh::process_execution::{
        CancellationToken, EventKind, ProcessExecutor, ProcessRequest, TerminalStatus,
    };
    let root = tempfile::tempdir().unwrap();
    let marker = root.path().join("fixture.log");
    let gate = root.path().join("release");
    let delay = if gated { Duration::ZERO } else { Duration::from_millis(1) };
    let tool = fake_tool(root.path(), "simctl", &marker, delay, gated.then_some(gate.as_path()));
    let executor = ProcessExecutor::new(root.path(), [tool.clone()], []).unwrap();
    let started = Instant::now();
    let events = thread::scope(|scope| {
        let release = gated.then(|| scope.spawn(|| {
            let deadline = Instant::now() + Duration::from_secs(5);
            while !std::fs::read_to_string(&marker).is_ok_and(|text| text.contains("mutation-start")) {
                assert!(Instant::now() < deadline, "fixture did not enter mutation");
                thread::sleep(Duration::from_millis(10));
            }
            thread::sleep(Duration::from_millis(200));
            assert!(!std::fs::read_to_string(&marker).unwrap().contains("mutation-end"),
                "fixture completed before explicit release");
            std::fs::write(&gate, b"release").unwrap();
        }));
        let events = executor.execute(
            ProcessRequest {
                program: tool,
                args: vec!["install".into(), DEVICE.into(), "build/App.app".into()],
                working_directory: ".".into(),
                environment: Default::default(),
            },
            Duration::from_secs(5),
            CancellationToken::new(),
        ).unwrap();
        if let Some(release) = release { release.join().unwrap(); }
        events
    });
    assert!(events.iter().any(|event| event.kind == EventKind::Terminal(TerminalStatus::Exited(0))),
        "fixture did not exit successfully");
    let stderr_bytes: usize = events.iter().filter(|event| event.kind == EventKind::Stderr)
        .map(|event| event.payload.len()).sum();
    assert_eq!(stderr_bytes, 0, "fixture wrote stderr with cleared environment");
    let marker = std::fs::read_to_string(marker).unwrap();
    assert!(marker.contains("mutation-start") && marker.contains("mutation-end"));
    if !gated {
        assert!(started.elapsed() >= Duration::from_millis(500), "fixture skipped its requested delay");
    }
}
```

- [x] Run baseline RED: cargo test -p devicelane --test network_device_leases windows_lease_fixture_ --locked --jobs 1. Both tests must fail because fixture emits stderr with no PATH. Record actual exit and assertion. Baseline target E:/CodexBuild/devicelane-network-ci-035512d.
- [x] Add same regression code to feature worktree, preserving its existing corrected fixture implementation:
```rust
let ping = PathBuf::from(std::env::var_os("SystemRoot").unwrap()).join("System32/ping.exe");
let delay_command = if mutation_delay.is_zero() {
    "rem no mutation delay".to_owned()
} else {
    let ping_count = mutation_delay.as_millis().div_ceil(1_000) + 1;
    format!("\"{}\" -n {ping_count} 127.0.0.1 >nul", ping.display())
};
let gate_command = mutation_gate.map_or_else(
    || "rem no mutation gate".to_owned(),
    |gate| {
        format!(
            ":wait_gate\r\nif not exist \"{}\" (\r\n  \"{}\" -n 2 127.0.0.1 >nul\r\n  goto wait_gate\r\n)",
            gate.display(), ping.display()
        )
    },
);
```
(The existing feature-worktree code is authoritative for Rust escaping; retain it unchanged.)
- [x] GREEN focused two tests then full network_device_leases (16 Windows tests), Clippy and workspace format/diff check. Do not convert unrelated failures to passes or enlarge network deadlines.
- [x] Independent spec review then quality review, close findings.
- [x] Root records evidence, read-only audits plan, stages only this plan plus tests/network_device_leases.rs, commits and pushes feature branch. No merge/deployment.

## Commands

Every shell command starts with rtk, login:false. Use the exact workspace as workdir. Baseline target differs from feature target; never run competing cargo invocations on one target.

```powershell
rtk proxy powershell -NoProfile -Command '$env:CARGO_TARGET_DIR="E:\CodexBuild\devicelane-network-ci-035512d"; Import-Module "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\Microsoft.VisualStudio.DevShell.dll"; Enter-VsDevShell -VsInstallPath "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools" -SkipAutomaticLocation -DevCmdArguments "-arch=x64 -host_arch=x64"; cargo test -p devicelane --test network_device_leases windows_lease_fixture_ --locked --jobs 1; exit $LASTEXITCODE'
```
For feature worktree use E:\CodexBuild\devicelane-task10-ci and remove filter for full suite. Same VS wrapper for cargo clippy -p devicelane --test network_device_leases --locked --jobs 1 -- -D warnings. Format only owned file with rustfmt --edition 2024, then rtk cargo fmt --all -- --check and rtk git diff --check.

## Execution evidence

- Published commit 035512d in separate detached worktree built with its own target in 3m47s; original 14 network_device_leases tests passed in 39.28s (root output `4c6fb1`). Actual baseline children were confirmed absent (`6cf069`) before test edits.
- Root independently reproduced bare ping lookup failure under a cleared environment: exit 1 (`08d53f`).
- Implementer reports targeted baseline RED: both new tests failed the zero-stderr assertion (delay 91 bytes, gate 23,569 bytes), 0 passed / 2 failed in 0.51s. Feature focused GREEN: 2 passed in 1.28s. The seven-line fix existed before this regression task; this is explicitly a baseline regression reproduction and verification of existing WIP, not a claim that its initial authorship followed test-first order.
- No claim that the bare-ping defect explains every sporadic CI lease/events timeout. The preceding published commit's Windows CI remains separately monitored.
- Initial read-only provenance scan completed, supported C2PA carrier not located; verification/trust UNKNOWN without conforming verifier/anchors, TEXT metadata privacy UNKNOWN, provider-keyed watermark checks unavailable. No marks removed; AI-assisted disclosure retained.

- Root final full feature-worktree network_device_leases: 16 passed, zero failed in 49.86s (`1afe2b`). Clippy warnings-denied exited 0 (`504c29`), workspace format exited 0 (`afec7a`), diff whitespace exited 0 (`5b7c50`).
- Independent SPEC PASS, then QUALITY READY with no open findings. Reviewer additionally executed focused two tests: 2 passed in 1.24s, format/diff clean.
- Latest published 035512d CI run 34015335724: Windows job 101437998321 failed the bridge test, 34 passed / 1 failed. New diagnostics report unexpected terminal while waiting for succeeded, rejection sequence 3 artifact_publish_failed (`f7450d`). The activity had already started and passed reconnection gates; this is a separate result-artifact publication failure, not proof of a lease fixture issue. macOS/Linux/npm completed successfully.
- Only test fixture changes and this plan are committed. Existing production transport/storage WIP remains excluded; no installed binaries, real identities, or remote configuration changed. The separate baseline worktree retains regression-only edits for reproducibility.
