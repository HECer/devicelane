#[derive(Clone, Copy, Debug)]
pub(super) enum Stage {
    Register,
    Write,
}

pub(super) enum Failure<'a> {
    Rpc(super::RpcError),
    MissingMetadata,
    Server(&'a str),
}

pub(super) fn report(stage: Stage, failure: Failure<'_>) {
    // Diagnostics must never alter artifact publication outcomes.
    let _ = write_report(&mut std::io::stderr().lock(), stage, failure);
}

fn write_report(
    writer: &mut impl std::io::Write,
    stage: Stage,
    failure: Failure<'_>,
) -> std::io::Result<()> {
    let stage = match stage {
        Stage::Register => "register",
        Stage::Write => "write",
    };
    let (cause, server_code) = match failure {
        Failure::Rpc(error) => (
            match error {
                super::RpcError::InvalidAddress => "invalid_address",
                super::RpcError::ConnectUnavailable => "connect_unavailable",
                super::RpcError::Tls => "tls",
                super::RpcError::Io => "io",
                super::RpcError::ResponseTimeout => "response_timeout",
                super::RpcError::Protocol => "protocol",
            },
            None,
        ),
        Failure::MissingMetadata => ("missing_metadata", None),
        Failure::Server(code) => (
            "server_rejected",
            Some(match code {
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
            }),
        ),
    };
    let mut record = serde_json::to_vec(&serde_json::json!({
        "event": "artifact_publish_failed",
        "stage": stage,
        "cause": cause,
        "server_code": server_code,
    }))
    .map_err(std::io::Error::other)?;
    record.push(b'\n');
    writer.write_all(&record)
}

#[cfg(test)]
mod tests {
    use super::{Failure, Stage, write_report};
    use serde_json::{Value, json};
    use std::collections::VecDeque;
    use std::io::{self, Write};

    fn record(stage: Stage, failure: Failure<'_>) -> Value {
        let mut output = Vec::new();
        write_report(&mut output, stage, failure).unwrap();
        assert_eq!(output.iter().filter(|byte| **byte == b'\n').count(), 1);
        assert_eq!(output.last(), Some(&b'\n'));
        assert!(output.len() < 256);
        serde_json::from_slice(&output).unwrap()
    }

    #[test]
    fn rpc_failures_preserve_stage_and_static_error_class() {
        for (error, cause) in [
            (super::super::RpcError::InvalidAddress, "invalid_address"),
            (
                super::super::RpcError::ConnectUnavailable,
                "connect_unavailable",
            ),
            (super::super::RpcError::Tls, "tls"),
            (super::super::RpcError::Io, "io"),
            (super::super::RpcError::ResponseTimeout, "response_timeout"),
            (super::super::RpcError::Protocol, "protocol"),
        ] {
            for (stage, stage_label) in [(Stage::Register, "register"), (Stage::Write, "write")] {
                assert_eq!(
                    record(stage, Failure::Rpc(error.clone())),
                    json!({
                        "event": "artifact_publish_failed",
                        "stage": stage_label,
                        "cause": cause,
                        "server_code": null,
                    })
                );
            }
        }
    }

    #[test]
    fn server_errors_are_allowlisted_and_unknown_text_never_leaks() {
        for code in [
            "artifact_access_denied",
            "invalid_artifact_metadata",
            "persistence_failed",
            "unknown_artifact",
            "artifact_metadata_mismatch",
            "invalid_chunk_length",
            "chunk_hash_mismatch",
            "invalid_offset",
            "chunk_conflict",
            "artifact_io",
            "artifact_hash_mismatch",
        ] {
            assert_eq!(
                record(Stage::Write, Failure::Server(code)),
                json!({
                    "event": "artifact_publish_failed",
                    "stage": "write",
                    "cause": "server_rejected",
                    "server_code": code,
                })
            );
        }
        let unknown = "SECRET\n/Users/private/key.pem";
        let output = record(Stage::Register, Failure::Server(unknown));
        assert_eq!(
            output,
            json!({
                "event": "artifact_publish_failed",
                "stage": "register",
                "cause": "server_rejected",
                "server_code": "unclassified_server_rejection",
            })
        );
        assert!(!output.to_string().contains(unknown));
    }

    #[test]
    fn absent_metadata_is_distinct_from_network_or_server_rejection() {
        assert_eq!(
            record(Stage::Register, Failure::MissingMetadata),
            json!({
                "event": "artifact_publish_failed",
                "stage": "register",
                "cause": "missing_metadata",
                "server_code": null,
            })
        );
    }

    struct Broken;

    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn log_sink_failure_is_reported_without_panicking() {
        let error = write_report(
            &mut Broken,
            Stage::Write,
            Failure::Rpc(super::super::RpcError::Io),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    }

    fn response(value: Value) -> super::super::Response {
        serde_json::from_value(value).unwrap()
    }

    fn metadata(error: Option<&str>) -> super::super::Response {
        let mut value = json!({
            "accepted": true,
            "hosts": [],
            "artifact_metadata": {
                "id": "artifact-1",
                "job_id": "job-1",
                "name": "result.log",
                "media_type": "text/plain",
                "total_size": 11,
                "sha256": "8c59f55ddc11e8f0543c03e1b2d328a9153f6bdeeac96047072e756ceaf9501b",
            },
        });
        if let Some(error) = error {
            value["error"] = json!(error);
        }
        response(value)
    }

    fn write_success() -> super::super::Response {
        response(json!({"accepted": true, "hosts": [], "confirmed_offset": 11}))
    }

    fn run_publish(
        script: Vec<Result<super::super::Response, super::super::RpcError>>,
    ) -> (Option<String>, Vec<super::super::Request>, Vec<u8>) {
        let mut script = VecDeque::from(script);
        let mut requests = Vec::new();
        let mut output = Vec::new();
        let result = super::super::publish_artifact_with(
            "job-1",
            "result.log",
            "text/plain",
            b"tool-output",
            |request| {
                requests.push(request.clone());
                script.pop_front().expect("scripted RPC response")
            },
            |stage, failure| write_report(&mut output, stage, failure).unwrap(),
        );
        assert!(script.is_empty(), "all scripted responses must be consumed");
        (result, requests, output)
    }

    fn assert_requests(requests: &[super::super::Request], count: usize) {
        assert_eq!(requests.len(), count);
        assert!(matches!(
            requests.first(),
            Some(super::super::Request::ArtifactRegister {
                job_id,
                name,
                media_type,
                total_size: 11,
                ..
            }) if job_id == "job-1" && name == "result.log" && media_type == "text/plain"
        ));
        let first_write = requests
            .iter()
            .position(|request| matches!(request, super::super::Request::ArtifactWrite { .. }))
            .unwrap_or(requests.len());
        assert!(
            requests[..first_write]
                .iter()
                .all(|request| matches!(request, super::super::Request::ArtifactRegister { .. }))
        );
        assert!(
            requests[first_write..]
                .iter()
                .all(|request| matches!(request, super::super::Request::ArtifactWrite { .. }))
        );
    }

    fn assert_failure(
        script: Vec<Result<super::super::Response, super::super::RpcError>>,
        calls: usize,
        expected: Value,
    ) {
        let (result, requests, output) = run_publish(script);
        assert_eq!(result, None);
        assert_requests(&requests, calls);
        assert_eq!(output.iter().filter(|byte| **byte == b'\n').count(), 1);
        assert_eq!(serde_json::from_slice::<Value>(&output).unwrap(), expected);
    }

    #[test]
    fn publish_failure_matrix_reports_once_after_bounded_rpc_attempts() {
        assert_failure(
            vec![Err(super::super::RpcError::Io)],
            1,
            json!({"event":"artifact_publish_failed","stage":"register","cause":"io","server_code":null}),
        );
        assert_failure(
            vec![Ok(response(json!({"accepted":true,"hosts":[]})))],
            1,
            json!({"event":"artifact_publish_failed","stage":"register","cause":"missing_metadata","server_code":null}),
        );
        assert_failure(
            vec![Ok(response(
                json!({"accepted":false,"hosts":[],"error":"invalid_artifact_metadata"}),
            ))],
            1,
            json!({"event":"artifact_publish_failed","stage":"register","cause":"server_rejected","server_code":"invalid_artifact_metadata"}),
        );
        assert_failure(
            vec![Ok(metadata(None)), Err(super::super::RpcError::Io)],
            2,
            json!({"event":"artifact_publish_failed","stage":"write","cause":"io","server_code":null}),
        );
        assert_failure(
            vec![
                Ok(metadata(None)),
                Ok(response(
                    json!({"accepted":false,"hosts":[],"error":"artifact_io"}),
                )),
            ],
            2,
            json!({"event":"artifact_publish_failed","stage":"write","cause":"server_rejected","server_code":"artifact_io"}),
        );
        assert_failure(
            vec![
                Err(super::super::RpcError::ResponseTimeout),
                Err(super::super::RpcError::ResponseTimeout),
                Err(super::super::RpcError::ResponseTimeout),
            ],
            3,
            json!({"event":"artifact_publish_failed","stage":"register","cause":"response_timeout","server_code":null}),
        );
        assert_failure(
            vec![
                Ok(metadata(None)),
                Err(super::super::RpcError::ResponseTimeout),
                Err(super::super::RpcError::ResponseTimeout),
                Err(super::super::RpcError::ResponseTimeout),
            ],
            4,
            json!({"event":"artifact_publish_failed","stage":"write","cause":"response_timeout","server_code":null}),
        );
    }

    #[test]
    fn publish_success_matrix_has_no_diagnostics_and_preserves_metadata_with_error() {
        for registration in [metadata(None), metadata(Some("artifact_access_denied"))] {
            let (result, requests, output) =
                run_publish(vec![Ok(registration), Ok(write_success())]);
            assert_eq!(result.as_deref(), Some("artifact-1"));
            assert_requests(&requests, 2);
            assert!(output.is_empty());
        }
    }
}
