# Artifact upload phase diagnostics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Identify which existing artifact upload phase and failure class caused the generic artifact_publish_failed result without exposing payloads or changing upload semantics.

**Architecture:** A small bin submodule formats one bounded JSON stderr line on a terminal publication failure. Existing publish_artifact catches the same Option failure branches and reports stage/cause before returning None. No new retries, deadlines, validations, protocol fields or persistence changes.

**Tech Stack:** Rust 2024, serde_json, std::io::Write, existing agent RPC.

AI-assisted engineering plan. No authorship or cryptographic provenance claim.

## Acceptance criteria

- Log only on terminal failed register/write RPC, missing registration metadata, or existing write-response error. Successful upload emits no new record.
- Preserve original return values and request ordering, byte chunks, hash calculation, three-attempt retry behavior, stable terminal artifact_publish_failed code, cancellation and time limits.
- Exact JSON keys: event, stage, cause, server_code. Stages register/write; RPC causes reflect all six current variants. Missing metadata and server rejection distinct.
- Known artifact server errors mapped to fixed allowlisted literals; unknown text replaced by unclassified_server_rejection, never logged raw. No identifiers, paths, payloads, certificates, keys or full request/response.
- Every diagnostic line is newline-terminated and under 256 bytes. Logging failure cannot panic or affect upload/retry outcome.
- Tests first with inert write_report, substantive failures, then implementation GREEN. Preserve unrelated frozen worktree changes.
- Independent spec and quality reviews. Root stages only new module, this plan and module/publish_artifact changes in parent, never the existing transport WIP.

## Files

- Create src/bin/mesh-agent/artifact_diagnostics.rs (subfolder avoids Cargo auto-bin discovery).
- Modify src/bin/mesh-agent.rs: add module declaration and only change publish_artifact.
- Plan is this Markdown.

### Task 1: Bounded formatter and failure-only integration

- [ ] Add the following tests first with Stage/Failure definitions and an inert write_report returning Ok(()); no logging implementation yet. Add module declaration after NAME:
```rust
#[path = "mesh-agent/artifact_diagnostics.rs"]
mod artifact_diagnostics;
```
The complete desired module follows; in RED use only its enums/tests and inert formatter. Record four failing assertions, not compiler errors.

```rust
use super::RpcError;
use std::io::{self, Write};

#[derive(Clone, Copy, Debug)]
pub(super) enum Stage { Register, Write }

pub(super) enum Failure<'a> {
    Rpc(RpcError),
    MissingMetadata,
    Server(&'a str),
}

pub(super) fn report(stage: Stage, failure: Failure<'_>) {
    // Logging is best effort and must never change upload/retry outcomes.
    let _ = write_report(&mut io::stderr().lock(), stage, failure);
}

fn write_report(writer: &mut impl Write, stage: Stage, failure: Failure<'_>) -> io::Result<()> {
    let stage = match stage { Stage::Register => "register", Stage::Write => "write" };
    let (cause, server_code) = match failure {
        Failure::Rpc(error) => (match error {
            RpcError::InvalidAddress => "invalid_address",
            RpcError::ConnectUnavailable => "connect_unavailable",
            RpcError::Tls => "tls",
            RpcError::Io => "io",
            RpcError::ResponseTimeout => "response_timeout",
            RpcError::Protocol => "protocol",
        }, None),
        Failure::MissingMetadata => ("missing_metadata", None),
        Failure::Server(code) => ("server_rejected", Some(match code {
            "artifact_access_denied" => "artifact_access_denied",
            "invalid_artifact_metadata" => "invalid_artifact_metadata",
            "persistence_failed" => "persistence_failed",
            "unknown_artifact" => "unknown_artifact",
            "artifact_metadata_mismatch" => "artifact_metadata_mismatch",
            "invalid_chunk_length" => "invalid_chunk_length",
            "chunk_hash_mismatch" => "chunk_hash_mismatch",
            "invalid_offset" => "invalid_offset",
            "chunk_conflict" => "chunk_conflict",
            "artifact_io" => "artifact_io",
            "artifact_hash_mismatch" => "artifact_hash_mismatch",
            _ => "unclassified_server_rejection",
        })),
    };
    let mut bytes = serde_json::to_vec(&serde_json::json!({
        "event": "artifact_publish_failed", "stage": stage,
        "cause": cause, "server_code": server_code,
    })).map_err(io::Error::other)?;
    bytes.push(b'\n');
    writer.write_all(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn record(stage: Stage, failure: Failure<'_>) -> serde_json::Value {
        let mut bytes = Vec::new();
        write_report(&mut bytes, stage, failure).unwrap();
        assert_eq!(bytes.iter().filter(|&&b| b == b'\n').count(), 1);
        assert_eq!(bytes.last(), Some(&b'\n'));
        assert!(bytes.len() < 256);
        serde_json::from_slice(&bytes).unwrap()
    }
    #[test]
    fn rpc_failures_preserve_stage_and_static_error_class() {
        for (error, cause) in [
            (RpcError::InvalidAddress, "invalid_address"),
            (RpcError::ConnectUnavailable, "connect_unavailable"),
            (RpcError::Tls, "tls"), (RpcError::Io, "io"),
            (RpcError::ResponseTimeout, "response_timeout"),
            (RpcError::Protocol, "protocol"),
        ] {
            for (stage, label) in [(Stage::Register, "register"), (Stage::Write, "write")] {
                assert_eq!(record(stage, Failure::Rpc(error.clone())), serde_json::json!({
                    "event":"artifact_publish_failed", "stage":label,
                    "cause":cause, "server_code":null,
                }));
            }
        }
    }
    #[test]
    fn server_errors_are_allowlisted_and_unknown_text_never_leaks() {
        for code in ["artifact_access_denied", "invalid_artifact_metadata", "persistence_failed",
            "unknown_artifact", "artifact_metadata_mismatch", "invalid_chunk_length",
            "chunk_hash_mismatch", "invalid_offset", "chunk_conflict", "artifact_io",
            "artifact_hash_mismatch"] {
            assert_eq!(record(Stage::Write, Failure::Server(code)), serde_json::json!({
                "event":"artifact_publish_failed", "stage":"write",
                "cause":"server_rejected", "server_code":code,
            }));
        }
        assert_eq!(record(Stage::Register, Failure::Server("SECRET\n/Users/private/key.pem")), serde_json::json!({
            "event":"artifact_publish_failed", "stage":"register",
            "cause":"server_rejected", "server_code":"unclassified_server_rejection",
        }));
    }
    #[test]
    fn absent_metadata_is_distinct_from_network_or_server_rejection() {
        assert_eq!(record(Stage::Register, Failure::MissingMetadata), serde_json::json!({
            "event":"artifact_publish_failed", "stage":"register",
            "cause":"missing_metadata", "server_code":null,
        }));
    }
    #[test]
    fn log_sink_failure_is_reported_without_panicking() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> { Err(io::ErrorKind::BrokenPipe.into()) }
            fn flush(&mut self) -> io::Result<()> { Ok(()) }
        }
        assert_eq!(write_report(&mut Broken, Stage::Write, Failure::Rpc(RpcError::Io))
            .unwrap_err().kind(), io::ErrorKind::BrokenPipe);
    }
}
```

- [ ] Run RED: cargo test -p devicelane --bin mesh-agent artifact_diagnostics --locked --jobs 1 (four substantive failures).
- [ ] Implement the formatter/report function above, then replace publish_artifact with:
```rust
fn publish_artifact(
    registry: &str, transport: &SecureTransport, job_id: &str,
    name: &str, media_type: &str, bytes: &[u8],
) -> Option<String> {
    publish_artifact_with(job_id, name, media_type, bytes,
        |request| rpc(registry, transport, request), artifact_diagnostics::report)
}

fn publish_artifact_with(
    job_id: &str, name: &str, media_type: &str, bytes: &[u8],
    mut call: impl FnMut(&Request) -> Result<Response, RpcError>,
    mut report: impl for<'a> FnMut(artifact_diagnostics::Stage, artifact_diagnostics::Failure<'a>),
) -> Option<String> {
    use artifact_diagnostics::{Failure, Stage};
    let sha256 = format!("{:x}", Sha256::digest(bytes));
    let registration = match retry_artifact_rpc(|| call(&Request::ArtifactRegister {
        job_id: job_id.into(), name: name.into(), media_type: media_type.into(),
        total_size: bytes.len() as u64, sha256: sha256.clone(),
    })) {
        Ok(response) => response,
        Err(error) => { report(Stage::Register, Failure::Rpc(error)); return None; }
    };
    let metadata = match registration.artifact_metadata {
        Some(metadata) => metadata,
        None => {
            report(Stage::Register, match registration.error.as_deref() {
                Some(code) => Failure::Server(code), None => Failure::MissingMetadata,
            });
            return None;
        }
    };
    for (index, chunk) in bytes.chunks(64 * 1024).enumerate() {
        let response = match retry_artifact_rpc(|| call(&Request::ArtifactWrite {
            artifact_id: metadata.id.clone(), offset: (index * 64 * 1024) as u64,
            total_size: bytes.len() as u64, sha256: sha256.clone(),
            chunk_sha256: format!("{:x}", Sha256::digest(chunk)), bytes: chunk.to_vec(),
        })) {
            Ok(response) => response,
            Err(error) => { report(Stage::Write, Failure::Rpc(error)); return None; }
        };
        if let Some(code) = response.error.as_deref() {
            report(Stage::Write, Failure::Server(code));
            return None;
        }
    }
    Some(metadata.id)
}
```

- [ ] Run focused GREEN four, then all mesh-agent unit tests and the existing real-TLS artifact_upload_replays_identical_requests_after_lost_responses regression. Run network_artifacts five integration tests. Preserve existing failures as failures.
- [ ] Run cargo clippy -p devicelane --bin mesh-agent --all-targets --locked --jobs 1 -- -D warnings; format only owned files with Rust edition 2024, then workspace format and diff checks.
- [ ] Independent SPEC then QUALITY review, address findings.
- [ ] Root audits plan read-only and commits only scoped changes. Parent is heavily dirty: use zero-context diff to select only module declaration and original publish_artifact line interval; verify staged diff excludes ProgressOutcome, write_rpc_request, write_progress_request, progress_batches and pre-existing WIP tests. Never stage entire parent. No deployment or merge.

## Commands

Use rtk prefix, login:false, feature worktree G:/NN-Developed/Dev-Tools/Windows-Mac-Iphone-Debug-Interface/.worktrees/speechwalker-remote-builds. VS2022 must be initialized in the same process as cargo:

```powershell
rtk proxy powershell -NoProfile -Command '$env:CARGO_TARGET_DIR="E:\CodexBuild\devicelane-task10-ci"; Import-Module "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\Microsoft.VisualStudio.DevShell.dll"; Enter-VsDevShell -VsInstallPath "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools" -SkipAutomaticLocation -DevCmdArguments "-arch=x64 -host_arch=x64"; cargo test -p devicelane --bin mesh-agent artifact_diagnostics --locked --jobs 1; exit $LASTEXITCODE'
```

## Evidence motivating this task

035512d CI run 34015335724 / Windows job101437998321 failed after Running/reconnection with stored rejected sequence3 artifact_publish_failed. Five direct Registry artifact tests pass on clean published baseline (ffd10d), and three agent artifact tests including real-TLS lost-response replay pass (9a487e). Current Option conversion hides whether registration RPC, registration response metadata, write RPC or write response failed. This diagnostics task is not a claim to fix the underlying CI failure.

## Quality review correction: exercise the publication boundary

The initial four tests only exercised the formatter. Removing every report call from publication would not fail them. Independent QUALITY classified this as an important integration-test gap; no completion claim is made until the following correction passes review.

- [ ] Extract the unchanged publication algorithm into the private injectable helper shown above; the real wrapper supplies the actual RPC and stderr reporter. No feature flag or environment switch. Add these two tests and helpers inside the diagnostic module's existing test module:

```rust
type UploadObservation = (Option<String>, Vec<Value>, Vec<Value>);

fn registration() -> super::super::Response {
    serde_json::from_value(json!({
        "accepted":true, "hosts":[], "artifact_metadata":{
            "id":"artifact-1", "job_id":"job-1", "name":"result.log",
            "media_type":"text/plain", "total_size":11,
            "sha256": format!("{:x}", <sha2::Sha256 as sha2::Digest>::digest(b"tool-output"))
        }
    })).unwrap()
}
fn reply(value: Value) -> super::super::Response {
    serde_json::from_value(value).unwrap()
}
fn capture_upload(script: Vec<Result<super::super::Response, super::super::RpcError>>) -> UploadObservation {
    let mut script: std::collections::VecDeque<_> = script.into();
    let mut requests = Vec::new();
    let mut records = Vec::new();
    let result = super::super::publish_artifact_with("job-1", "result.log", "text/plain", b"tool-output",
        |request| {
            requests.push(serde_json::to_value(request).unwrap());
            script.pop_front().expect("unexpected extra RPC")
        },
        |stage, failure| {
            let mut bytes = Vec::new();
            write_report(&mut bytes, stage, failure).unwrap();
            records.push(serde_json::from_slice(&bytes).unwrap());
        });
    assert!(script.is_empty(), "expected RPC was skipped");
    (result, requests, records)
}
#[test]
fn upload_failures_emit_one_final_record_at_the_actual_phase() {
    use super::super::RpcError::{Io, ResponseTimeout};
    let cases = [
        (vec![Err(Io)], "register", "io", None, 1, 0),
        (vec![Ok(reply(json!({"accepted":true,"hosts":[]})))], "register", "missing_metadata", None, 1, 0),
        (vec![Ok(reply(json!({"accepted":false,"hosts":[],"error":"invalid_artifact_metadata"})))],
            "register", "server_rejected", Some("invalid_artifact_metadata"), 1, 0),
        (vec![Ok(registration()), Err(Io)], "write", "io", None, 1, 1),
        (vec![Ok(registration()), Ok(reply(json!({"accepted":false,"hosts":[],"error":"artifact_io"})))],
            "write", "server_rejected", Some("artifact_io"), 1, 1),
        (vec![Err(ResponseTimeout), Err(ResponseTimeout), Err(ResponseTimeout)],
            "register", "response_timeout", None, 3, 0),
        (vec![Ok(registration()), Err(ResponseTimeout), Err(ResponseTimeout), Err(ResponseTimeout)],
            "write", "response_timeout", None, 1, 3),
    ];
    for (script, stage, cause, code, registers, writes) in cases {
        let (result, requests, records) = capture_upload(script);
        assert!(result.is_none());
        assert_eq!(records, vec![json!({"event":"artifact_publish_failed","stage":stage,
            "cause":cause,"server_code":code})]);
        assert_eq!(requests.len(), registers + writes);
        for (index, request) in requests.iter().enumerate() {
            assert_eq!(request["request"], if index < registers {"artifact_register"} else {"artifact_write"});
        }
    }
}
#[test]
fn successful_upload_is_silent_and_preserves_metadata_precedence() {
    for metadata_with_error in [false, true] {
        let mut metadata = registration();
        if metadata_with_error { metadata.error = Some("artifact_access_denied".into()); }
        let (result, requests, records) = capture_upload(vec![
            Ok(metadata), Ok(reply(json!({"accepted":true,"hosts":[],"confirmed_offset":11})))]);
        assert_eq!(result.as_deref(), Some("artifact-1"));
        assert!(records.is_empty());
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0]["request"], "artifact_register");
        assert_eq!(requests[1]["request"], "artifact_write");
        assert_eq!(requests[1]["offset"], 0);
        assert_eq!(requests[1]["bytes"], json!(b"tool-output".to_vec()));
    }
}
```

- [ ] Temporarily replace reporter execution with a no-op in the helper (apply_patch), run the two boundary tests: failure matrix must fail on absent records while silent-success control passes. Restore actual reports with apply_patch; record this as negative mutation verification, not a claim that initial extraction was authored test-first.
- [ ] Run all six diagnostic tests, full agent tests, existing artifact integration tests, format/Clippy checks, and independent QUALITY re-review. All earlier privacy, bounded logging and behavioral-preservation requirements remain in force.

## Verification checkpoint: final integration boundary coverage

AI-assisted implementation and verification; no human-authorship claim.

- Implementer negative mutation removed all four report calls: failure matrix failed, silent-success control passed. Restored implementation passed all six diagnostics tests.
- Root fresh feature-worktree run: 32 agent tests passed and all five `network_artifacts` tests passed (13.63 seconds for the latter), overall exit 0. This worktree still includes unrelated, uncommitted transport changes.
- Root mechanically copied only the diagnostics module and publication wrapper/helper into the separate published-code baseline. Its 19 agent tests passed, including the six diagnostics tests. This establishes no dependency on the frozen transport changes.
- Feature `cargo fmt --all -- --check`, `git diff --check`, and baseline owned-source rustfmt check all returned exit 0.
- Independent final SPEC review passed. Independent QUALITY review closed the missing publication-boundary coverage finding and reported scoped READY, with no remaining findings.
- Baseline `cargo clippy -p devicelane --bin mesh-agent --locked --jobs 1 -- -D warnings` completed with exit 0 (2m 41s). Selective staging follows these gates; no production deployment is authorized by this checkpoint.
- The baseline parent diff contains only the module declaration and publication wrapper/helper. It can provide a clean index-only patch later; do not stage the whole feature parent file.
- These results validate bounded failure diagnostics, not the cause or repair of the intermittent artifact-transfer failure, not the frozen transport changes, and not macOS runtime/UI readiness.
