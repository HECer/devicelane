# Bridge failure diagnostics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make failed process-bridge E2E runs report bounded registry rejection evidence instead of only an eventual waiting timeout.

**Architecture:** Test-only helpers read the fixture's exact `registry/vertical-slice.json` path on failure. They report only rejected event sequence numbers and restricted code strings; the data is explicitly an unverified diagnostic snapshot, never authorization evidence. Existing IPC/CLI/Tauri parity, deadline, cleanup, and restart gate remain intact.

**Tech Stack:** Rust 2024, serde_json, tempfile, existing Tauri bridge integration tests.

AI-assisted engineering plan. No authorship or cryptographic provenance claim.

## Acceptance criteria

1. Expected states still succeed first, including expected terminal states; unexpected Succeeded/Failed/Denied/Cancelled fail immediately, not after ten seconds.
2. On unexpected terminal or deadline failure, append registry fixture diagnostics. No diagnostic read on successful/pending polls.
3. Read at most 1 MiB + one sentinel byte from the exact fixture checkpoint; reject oversize, malformed, missing or unsupported input with a bounded message, no panic or raw content dump.
4. Report at most 16 rejected events, sequence as u64, payload only if nonempty, at most 128 bytes and solely ASCII lowercase letters, digits, underscore; otherwise `<redacted>`. Never show stdout, requests, paths, certificates, keys, or unrelated event payloads. State output is explicitly unverified, since no envelope hash validation occurs.
5. Tests use real temporary files and cover error-code visibility, non-rejected/other-field omission, code redaction, count/read bounds, malformed/missing input, terminal-state semantics.
6. Keep production files and existing unrelated work untouched. Keep 10-second deadline, 25-ms polling, process cleanup, and all existing assertions.
7. Observe substantive failing tests with inert helpers before implementation; then targeted tests, all bridge tests, package clippy and workspace format check pass. Independent spec and quality reviews precede commit.

## Files

- Create `desktop/src-tauri/tests/support/registry_diagnostics.rs`: bounded fixture reader, terminal predicate, unit tests.
- Modify `desktop/src-tauri/tests/bridge.rs`: include module and pass fixture identity to three waits.
- Update this plan with actual execution evidence after verification.

### Task 1: Test-only bounded failure evidence

- [x] Write tests first in the new module, initially use inert stubs returning `String::new()` and `false` for the two helpers. Include the module in bridge.rs so tests run. Tests:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture(value: serde_json::Value) -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("vertical-slice.json"), serde_json::to_vec(&value).unwrap()).unwrap();
        root
    }

    #[test]
    fn rejection_diagnostics_preserve_codes_without_other_payloads() {
        let root = fixture(json!({"schema_version": 1, "payload": {
            "private_key": "KEY_SECRET", "requests": {"secret": "REQUEST_SECRET"},
            "jobs": {"job-secret": [
                {"sequence": 1, "kind": "stdout", "payload": "output_secret"},
                {"sequence": 2, "kind": "rejected", "payload": "lease_validation_response_timeout"},
                {"sequence": 3, "kind": "rejected", "payload": "unsafe\nPAYLOAD_SECRET"}
            ]}
        }}));
        let report = registry_diagnostics(root.path());
        assert_eq!(report, "registry fixture (unverified): 2:lease_validation_response_timeout, 3:<redacted>");
        assert!(report.contains("unverified"));
        assert!(report.contains("2:lease_validation_response_timeout"));
        assert!(report.contains("3:<redacted>"));
        for omitted in ["KEY_SECRET", "REQUEST_SECRET", "output_secret", "PAYLOAD_SECRET", "job-secret"] {
            assert!(!report.contains(omitted), "{report}");
        }
    }

    #[test]
    fn rejection_diagnostics_bound_count_and_code_size() {
        let events: Vec<_> = (0..20).map(|sequence| json!({
            "sequence": sequence, "kind": "rejected", "payload": "a".repeat(129)
        })).collect();
        let root = fixture(json!({"schema_version": 1, "payload": {"jobs": {"job": events}}}));
        let report = registry_diagnostics(root.path());
        assert_eq!(report.matches("<redacted>").count(), 16);
        assert!(report.contains("truncated"));
        assert!(report.len() < 4096);
    }

    #[test]
    fn rejection_diagnostics_bound_file_and_handle_unavailable_input() {
        let root = tempfile::tempdir().unwrap();
        assert!(registry_diagnostics(root.path()).contains("unavailable"));
        let path = root.path().join("vertical-slice.json");
        std::fs::write(&path, b"{malformed").unwrap();
        assert!(registry_diagnostics(root.path()).contains("malformed"));
        std::fs::write(&path, vec![b' '; MAX_FIXTURE_BYTES + 1]).unwrap();
        assert!(registry_diagnostics(root.path()).contains("oversized"));
        std::fs::write(&path, br#"{"schema_version":2,"payload":{"jobs":{}}}"#).unwrap();
        assert!(registry_diagnostics(root.path()).contains("unsupported"));
        std::fs::write(&path, br#"{"schema_version":1,"payload":{"jobs":{}}}"#).unwrap();
        assert!(registry_diagnostics(root.path()).contains("no rejected events"));
    }

    #[test]
    fn terminal_wait_does_not_accept_wrong_terminal_or_reject_expected_state() {
        use ActivityState::*;
        for state in [Succeeded, Failed, Denied, Cancelled] {
            assert!(unexpected_terminal(state, "running"));
            assert!(!unexpected_terminal(state, &format!("{state:?}").to_uppercase()));
        }
        for state in [AwaitingApproval, Queued, Running, Reconnecting] {
            assert!(!unexpected_terminal(state, "succeeded"));
        }
    }
}
```

- [x] Run RED with the VS2022 environment below: `cargo test -p devicelane-desktop --test bridge support_registry_diagnostics --locked --jobs 1`. Expect four assertion failures, not compiler/toolchain failures.

- [x] Replace the inert helpers with this implementation. Keep tests in same module.

```rust
use device_development_mesh::dashboard::ActivityState;
use std::io::Read;
use std::path::Path;

const MAX_FIXTURE_BYTES: usize = 1024 * 1024;
const MAX_REJECTIONS: usize = 16;

pub(super) fn unexpected_terminal(state: ActivityState, expected: &str) -> bool {
    matches!(state, ActivityState::Succeeded | ActivityState::Failed | ActivityState::Denied | ActivityState::Cancelled)
        && !format!("{state:?}").eq_ignore_ascii_case(expected)
}

/// Best-effort, unverified evidence from an isolated E2E fixture only.
/// Never use this parser for registry recovery or authorization.
pub(super) fn registry_diagnostics(identity: &Path) -> String {
    const PREFIX: &str = "registry fixture (unverified): ";
    let read = || -> std::io::Result<Vec<u8>> {
        let file = std::fs::File::open(identity.join("vertical-slice.json"))?;
        let mut bytes = Vec::new();
        file.take((MAX_FIXTURE_BYTES + 1) as u64).read_to_end(&mut bytes)?;
        Ok(bytes)
    };
    let bytes = match read() {
        Ok(bytes) => bytes,
        Err(error) => return format!("{PREFIX}unavailable ({:?})", error.kind()),
    };
    if bytes.len() > MAX_FIXTURE_BYTES {
        return format!("{PREFIX}oversized");
    }
    let value: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(_) => return format!("{PREFIX}malformed"),
    };
    if value["schema_version"].as_u64() != Some(1) {
        return format!("{PREFIX}unsupported schema");
    }
    let Some(jobs) = value["payload"]["jobs"].as_object() else {
        return format!("{PREFIX}malformed jobs");
    };
    let mut codes = Vec::new();
    for events in jobs.values().filter_map(serde_json::Value::as_array) {
        for event in events {
            if event["kind"].as_str() != Some("rejected") {
                continue;
            }
            if codes.len() == MAX_REJECTIONS {
                return format!("{PREFIX}{}; truncated", codes.join(", "));
            }
            let sequence = event["sequence"].as_u64().map(|n| n.to_string()).unwrap_or_else(|| "?".into());
            let code = event["payload"].as_str().filter(|code| {
                !code.is_empty() && code.len() <= 128
                    && code.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            }).unwrap_or("<redacted>");
            codes.push(format!("{sequence}:{code}"));
        }
    }
    if codes.is_empty() {
        format!("{PREFIX}no rejected events")
    } else {
        format!("{PREFIX}{}", codes.join(", "))
    }
}
```

- [x] Wire into bridge.rs with this module declaration:
```rust
#[path = "support/registry_diagnostics.rs"]
mod support_registry_diagnostics;
```

Replace the three calls:
```rust
let running = wait_for_activity(&bridge, activity_id, "running", &registry_identity);
wait_for_activity(&bridge, activity_id, "reconnecting", &registry_identity);
let terminal = wait_for_activity(&bridge, activity_id, "succeeded", &registry_identity);
```

Replace helper body/signature:
```rust
fn wait_for_activity(
    bridge: &DesktopBridge<EndpointTransport>,
    activity_id: &str,
    expected: &str,
    registry_identity: &Path,
) -> DashboardSnapshot {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let snapshot = bridge.dashboard_snapshot(DashboardScope::Mesh).unwrap();
        let activity = snapshot.activities.iter().find(|activity| activity.activity_id.as_str() == activity_id);
        if activity.is_some_and(|activity| format!("{:?}", activity.state).eq_ignore_ascii_case(expected)) {
            return snapshot;
        }
        let unexpected_terminal = activity.is_some_and(|activity| {
            support_registry_diagnostics::unexpected_terminal(activity.state, expected)
        });
        if unexpected_terminal || Instant::now() >= deadline {
            let reason = if unexpected_terminal { "unexpected terminal state" } else { "timed out" };
            panic!(
                "{reason} waiting for {expected}; {}; last snapshot: {snapshot:?}",
                support_registry_diagnostics::registry_diagnostics(registry_identity)
            );
        }
        thread::sleep(Duration::from_millis(25));
    }
}
```

- [x] Run GREEN focused, then all bridge tests (expect 35), package clippy, workspace format, diff check. Use Rust edition 2024 formatting for owned files.

PowerShell shell commands must start with `rtk`, `login:false`. Cargo invocation:
```powershell
rtk proxy powershell -NoProfile -Command '$env:CARGO_TARGET_DIR="E:\CodexBuild\devicelane-task10-ci"; Import-Module "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\Microsoft.VisualStudio.DevShell.dll"; Enter-VsDevShell -VsInstallPath "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools" -SkipAutomaticLocation -DevCmdArguments "-arch=x64 -host_arch=x64"; cargo test -p devicelane-desktop --test bridge --locked --jobs 1; exit $LASTEXITCODE'
```
Use same wrapper for `cargo clippy -p devicelane-desktop --all-targets --locked --jobs 1 -- -D warnings`.
`rtk cargo fmt --all -- --check` and `rtk git diff --check` must pass.

- [x] Independent spec review, then quality review; fix findings and repeat required review.
- [x] Root audits this Markdown read-only, records evidence, stages only the three owned paths and commits `test: expose bounded registry rejection diagnostics in bridge E2E`. No deployment or merge. This is improved diagnosis, not a claimed fix for intermittent transport errors.

## Execution evidence

- Implementer reports substantive RED: all four diagnostic tests failed against inert stubs, Cargo exit 101, before implementation. Focused GREEN: four passed, exit 0; full bridge: 35 passed, exit 0. Its tool returned no chunk identifiers.
- Root independently ran all 35 bridge tests: 35 passed, zero failures in 5.47 seconds (output `49e6d5`). The actual test child was subsequently confirmed absent; the inherited outer shell pipe remained open.
- Root package Clippy with warnings denied exited 0 (`2857ac`); workspace format check exited 0 (`f32b67`); diff whitespace check exited 0 (`03d606`).
- Independent SPEC review passed. QUALITY found a minor test gap: uppercase stdout data would be redacted and could evade the omission assertions if the rejected-kind guard were removed. The test now requires an exact report with allowlist-valid stdout excluded; a temporary removed-guard mutation failed with leaked `1:output_secret` (exit 101), then the guard was restored. QUALITY re-review closed the finding and returned scoped READY, with no open Critical/Important/Minor findings.
- Initial read-only provenance scan completed and located no supported C2PA carrier. Verification/trust remain UNKNOWN without a conforming verifier/trust anchors; TEXT metadata privacy remains UNKNOWN, and keyed provider watermarks cannot be verified. No marks removed, AI-assisted disclosure retained.
- CI for the preceding commit d6690db: macOS/Linux/npm passed; Windows network_device_leases had 12 passes and two five-second CLI timeout failures (events and lease), run 34014277875 / job 101435264367. This test-diagnostics change does not claim to fix those failures.

- Final strengthened test independently rerun by root: four focused tests passed, exit 0 (`2cdc88`). Implementer reran all 35 bridge tests, Clippy and format after restoration; reviewer independently reran focused four and format/diff checks. Only the two test paths and this plan are included in the scoped commit; no installed binaries changed.
