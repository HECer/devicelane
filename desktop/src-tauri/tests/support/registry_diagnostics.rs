use device_development_mesh::dashboard::ActivityState;
use serde_json::Value;
use std::path::Path;

const MAX_FIXTURE_BYTES: usize = 1024 * 1024;
const MAX_REJECTIONS: usize = 16;
const PREFIX: &str = "registry fixture (unverified): ";

pub(super) fn unexpected_terminal(state: ActivityState, expected: &str) -> bool {
    matches!(
        state,
        ActivityState::Succeeded
            | ActivityState::Failed
            | ActivityState::Denied
            | ActivityState::Cancelled
    ) && !format!("{state:?}").eq_ignore_ascii_case(expected)
}

/// Best-effort isolated test evidence, not registry recovery, authentication, or security parsing.
pub(super) fn registry_diagnostics(identity: &Path) -> String {
    let file = match std::fs::File::open(identity.join("vertical-slice.json")) {
        Ok(file) => file,
        Err(error) => return format!("{PREFIX}unavailable ({:?})", error.kind()),
    };
    let mut bytes = Vec::new();
    let mut limited = std::io::Read::take(file, (MAX_FIXTURE_BYTES + 1) as u64);
    if let Err(error) = std::io::Read::read_to_end(&mut limited, &mut bytes) {
        return format!("{PREFIX}unavailable ({:?})", error.kind());
    }
    if bytes.len() > MAX_FIXTURE_BYTES {
        return format!("{PREFIX}oversized");
    }
    let value: Value = match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(_) => return format!("{PREFIX}malformed"),
    };
    if value["schema_version"].as_u64() != Some(1) {
        return format!("{PREFIX}unsupported schema");
    }
    let Some(jobs) = value["payload"]["jobs"].as_object() else {
        return format!("{PREFIX}malformed jobs");
    };

    let mut rejections = Vec::new();
    let mut truncated = false;
    for event in jobs.values().filter_map(Value::as_array).flatten() {
        if event["kind"].as_str() != Some("rejected") {
            continue;
        }
        if rejections.len() == MAX_REJECTIONS {
            truncated = true;
            break;
        }
        let sequence = event["sequence"]
            .as_u64()
            .map(|sequence| sequence.to_string())
            .unwrap_or_else(|| "?".to_owned());
        let code = event["payload"]
            .as_str()
            .filter(|code| {
                !code.is_empty()
                    && code.len() <= 128
                    && code.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'
                    })
            })
            .unwrap_or("<redacted>");
        rejections.push(format!("{sequence}:{code}"));
    }
    if rejections.is_empty() {
        format!("{PREFIX}no rejected events")
    } else if truncated {
        format!("{PREFIX}{}; truncated", rejections.join(", "))
    } else {
        format!("{PREFIX}{}", rejections.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::{registry_diagnostics, unexpected_terminal};
    use device_development_mesh::dashboard::ActivityState;
    use std::path::{Path, PathBuf};

    fn checkpoint(root: &Path) -> PathBuf {
        root.join("vertical-slice.json")
    }

    fn write_fixture(root: &Path, value: serde_json::Value) {
        std::fs::write(checkpoint(root), serde_json::to_vec(&value).unwrap()).unwrap();
    }

    #[test]
    fn rejection_diagnostics_preserve_codes_without_other_payloads() {
        let root = tempfile::tempdir().unwrap();
        write_fixture(
            root.path(),
            serde_json::json!({
                "schema_version": 1,
                "payload": {
                    "private_key": "KEY_SECRET",
                    "requests": { "secret": "REQUEST_SECRET" },
                    "jobs": {
                        "job-secret": [
                            { "sequence": 1, "kind": "stdout", "payload": "output_secret" },
                            { "sequence": 2, "kind": "rejected", "payload": "lease_validation_response_timeout" },
                            { "sequence": 3, "kind": "rejected", "payload": "unsafe\nPAYLOAD_SECRET" }
                        ]
                    }
                }
            }),
        );
        let report = registry_diagnostics(root.path());
        assert!(report.contains("unverified"));
        assert_eq!(
            report,
            "registry fixture (unverified): 2:lease_validation_response_timeout, 3:<redacted>"
        );
        assert!(report.contains("2:lease_validation_response_timeout"));
        assert!(report.contains("3:<redacted>"));
        for secret in [
            "KEY_SECRET",
            "REQUEST_SECRET",
            "output_secret",
            "PAYLOAD_SECRET",
            "job-secret",
        ] {
            assert!(!report.contains(secret));
        }
    }

    #[test]
    fn rejection_diagnostics_bound_count_and_code_size() {
        let root = tempfile::tempdir().unwrap();
        let events: Vec<_> = (0..20)
            .map(|sequence| {
                serde_json::json!({
                    "sequence": sequence,
                    "kind": "rejected",
                    "payload": "a".repeat(129),
                })
            })
            .collect();
        write_fixture(
            root.path(),
            serde_json::json!({
                "schema_version": 1,
                "payload": { "jobs": { "job-secret": events } }
            }),
        );
        let report = registry_diagnostics(root.path());
        assert_eq!(report.matches("<redacted>").count(), 16);
        assert!(report.contains("truncated"));
        assert!(report.len() < 4096);
    }

    #[test]
    fn rejection_diagnostics_bound_file_and_handle_unavailable_input() {
        const MAX_FIXTURE_BYTES: usize = 1024 * 1024;
        let root = tempfile::tempdir().unwrap();
        assert!(registry_diagnostics(root.path()).contains("unavailable"));
        std::fs::write(checkpoint(root.path()), b"{malformed").unwrap();
        assert!(registry_diagnostics(root.path()).contains("malformed"));
        std::fs::write(checkpoint(root.path()), vec![b' '; MAX_FIXTURE_BYTES + 1]).unwrap();
        assert!(registry_diagnostics(root.path()).contains("oversized"));
        write_fixture(
            root.path(),
            serde_json::json!({ "schema_version": 2, "payload": { "jobs": {} } }),
        );
        assert!(registry_diagnostics(root.path()).contains("unsupported"));
        write_fixture(
            root.path(),
            serde_json::json!({ "schema_version": 1, "payload": { "jobs": {} } }),
        );
        assert!(registry_diagnostics(root.path()).contains("no rejected events"));
    }

    #[test]
    fn terminal_wait_does_not_accept_wrong_terminal_or_reject_expected_state() {
        for state in [
            ActivityState::Succeeded,
            ActivityState::Failed,
            ActivityState::Denied,
            ActivityState::Cancelled,
        ] {
            assert!(unexpected_terminal(state, "running"));
            assert!(!unexpected_terminal(
                state,
                &format!("{:?}", state).to_uppercase()
            ));
        }
        for state in [
            ActivityState::AwaitingApproval,
            ActivityState::Queued,
            ActivityState::Running,
            ActivityState::Reconnecting,
        ] {
            assert!(!unexpected_terminal(state, "succeeded"));
        }
    }
}
