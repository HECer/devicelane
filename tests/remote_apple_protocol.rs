use device_development_mesh::remote_apple_protocol::{
    AppleAgent, AppleOperation, AppleRegistry, AppleRequest, ProtocolError, RemoteProtocolVersion,
};
use std::path::Path;
use std::sync::{Arc, Barrier};
use std::time::Duration;

fn request(operation: AppleOperation) -> AppleRequest {
    AppleRequest {
        version: RemoteProtocolVersion { major: 1, minor: 0 },
        request_id: "request-1".into(),
        idempotency_key: "retry-1".into(),
        capability: operation.capability().into(),
        workspace_path: "project".into(),
        device_id: operation.requires_device().then(|| "iphone-1".into()),
        lease_id: operation.requires_device().then(|| "lease-1".into()),
        operation,
    }
}

fn build_operation() -> AppleOperation {
    AppleOperation::BuildApp {
        container: "MeshApp.xcodeproj".into(),
        scheme: "MeshApp".into(),
        destination: "platform=iOS Simulator,id=sim-1".into(),
    }
}

#[test]
fn typed_versioned_requests_round_trip_without_a_raw_shell_field() {
    let operations = vec![
        AppleOperation::Discovery,
        AppleOperation::PhysicalDevice,
        AppleOperation::Diagnostics,
        AppleOperation::DiscoverProject {
            container: "MeshApp.xcodeproj".into(),
        },
        AppleOperation::DiscoverSimulator,
        AppleOperation::BuildApp {
            container: "MeshApp.xcodeproj".into(),
            scheme: "MeshApp".into(),
            destination: "platform=iOS Simulator,id=sim-1".into(),
        },
        AppleOperation::InstallApp {
            app_path: "build/MeshApp.app".into(),
        },
        AppleOperation::LaunchApp {
            bundle_id: "dev.mesh.app".into(),
        },
        AppleOperation::ReadAppLogs {
            bundle_id: "dev.mesh.app".into(),
        },
        AppleOperation::RunXcTest {
            container: "MeshApp.xcodeproj".into(),
            scheme: "MeshAppTests".into(),
            destination: "platform=iOS Simulator,id=sim-1".into(),
        },
        AppleOperation::HardwareGate {
            team_id: "ABCDE12345".into(),
        },
    ];

    for operation in operations {
        let original = request(operation);
        let json = serde_json::to_string(&original).unwrap();
        assert!(!json.contains("shell"));
        assert_eq!(
            serde_json::from_str::<AppleRequest>(&json).unwrap(),
            original
        );
    }
}

#[test]
fn typed_vertical_slice_parameters_are_validated() {
    let mut invalid = request(AppleOperation::BuildApp {
        container: "../outside.xcodeproj".into(),
        scheme: "MeshApp".into(),
        destination: "platform=iOS Simulator,id=sim-1".into(),
    });
    assert_eq!(
        device_development_mesh::remote_apple_protocol::validate_request_envelope(&invalid)
            .unwrap_err()
            .code(),
        "invalid_apple_parameter"
    );

    invalid.operation = AppleOperation::InstallApp {
        app_path: "/tmp/MeshApp.app".into(),
    };
    invalid.capability = invalid.operation.capability().into();
    invalid.device_id = Some("sim-1".into());
    invalid.lease_id = Some("lease-1".into());
    assert_eq!(
        device_development_mesh::remote_apple_protocol::validate_request_envelope(&invalid)
            .unwrap_err()
            .code(),
        "invalid_apple_parameter"
    );

    invalid.operation = AppleOperation::LaunchApp {
        bundle_id: "not a bundle id".into(),
    };
    invalid.capability = invalid.operation.capability().into();
    assert_eq!(
        device_development_mesh::remote_apple_protocol::validate_request_envelope(&invalid)
            .unwrap_err()
            .code(),
        "invalid_apple_parameter"
    );

    invalid.operation = AppleOperation::HardwareGate {
        team_id: "not-a-team".into(),
    };
    invalid.capability = invalid.operation.capability().into();
    assert_eq!(
        device_development_mesh::remote_apple_protocol::validate_request_envelope(&invalid)
            .unwrap_err()
            .code(),
        "invalid_apple_parameter"
    );
}

#[test]
fn validation_normalizes_unknown_and_unscoped_input() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("project")).unwrap();
    let agent = AppleAgent::new(
        root.path(),
        ["apple.discovery@1", "apple.device@1"],
        ["iphone-1"],
    )
    .unwrap();

    let cases = [
        (
            r#"{"version":{"major":2,"minor":0},"request_id":"r","idempotency_key":"i","capability":"apple.discovery@1","workspace_path":"project","operation":{"kind":"discovery"}}"#,
            "unsupported_version",
        ),
        (
            r#"{"version":{"major":1,"minor":1},"request_id":"r","idempotency_key":"i","capability":"apple.discovery@1","workspace_path":"project","operation":{"kind":"discovery"}}"#,
            "unsupported_version",
        ),
        (
            r#"{"version":{"major":1,"minor":0},"request_id":"r","idempotency_key":"i","capability":"apple.discovery@1","workspace_path":"project","operation":{"kind":"shell"}}"#,
            "unsupported_operation",
        ),
        (
            r#"{"version":{"major":1,"minor":0},"request_id":"r","idempotency_key":"i","capability":"apple.build@1","workspace_path":"project","operation":{"kind":"build"}}"#,
            "unsupported_operation",
        ),
    ];
    for (json, code) in cases {
        assert_eq!(agent.parse_and_validate(json).unwrap_err().code(), code);
    }

    let mut invalid = request(build_operation());
    assert_eq!(
        agent.validate(&invalid).unwrap_err().code(),
        "unsupported_capability"
    );
    invalid.operation = AppleOperation::Discovery;
    invalid.capability = "apple.discovery@1".into();
    invalid.workspace_path = "../outside".into();
    assert_eq!(
        agent.validate(&invalid).unwrap_err().code(),
        "workspace_path_denied"
    );
    invalid.workspace_path = "project".into();
    invalid.operation = AppleOperation::PhysicalDevice;
    invalid.capability = "apple.device@1".into();
    invalid.device_id = Some("missing".into());
    assert_eq!(
        agent.validate(&invalid).unwrap_err().code(),
        "unknown_device"
    );
    invalid.operation = AppleOperation::Discovery;
    invalid.capability = "apple.discovery@1".into();
    assert_eq!(
        agent.validate(&invalid).unwrap_err().code(),
        "unknown_device"
    );
    invalid.device_id = None;
    invalid.request_id.clear();
    assert_eq!(
        agent.validate(&invalid).unwrap_err().code(),
        "invalid_request"
    );
}

#[test]
fn accepted_jobs_are_immediate_idempotent_and_end_once() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("project")).unwrap();
    let agent = AppleAgent::new(
        root.path(),
        ["apple.build@1", "apple.discovery@1"],
        Vec::<String>::new(),
    )
    .unwrap();
    let registry = AppleRegistry::new(agent);
    let gate = Arc::new(Barrier::new(2));
    let worker_gate = gate.clone();

    let accepted = registry
        .submit(request(build_operation()), move |progress| {
            progress("compiling");
            worker_gate.wait();
            Ok("built".into())
        })
        .unwrap();
    assert!(!accepted.job_id().is_empty());
    let duplicate = registry
        .submit(request(build_operation()), |_| {
            panic!("duplicate request executed")
        })
        .unwrap();
    assert_eq!(duplicate.job_id(), accepted.job_id());
    let mut request_alias = request(build_operation());
    request_alias.idempotency_key = "retry-2".into();
    assert_eq!(
        registry
            .submit(request_alias, |_| panic!("request alias executed"))
            .unwrap()
            .job_id(),
        accepted.job_id()
    );
    let mut idempotency_alias = request(build_operation());
    idempotency_alias.request_id = "request-2".into();
    idempotency_alias.idempotency_key = "retry-2".into();
    assert_eq!(
        registry
            .submit(idempotency_alias, |_| panic!("idempotency alias executed"))
            .unwrap()
            .job_id(),
        accepted.job_id()
    );
    assert_eq!(
        registry
            .submit(request(AppleOperation::Discovery), |_| {
                panic!("conflicting request executed")
            })
            .unwrap_err()
            .code(),
        "idempotency_conflict"
    );

    let before_release = registry.events(accepted.job_id(), 0).unwrap();
    assert_eq!(before_release[0].sequence, 1);
    assert!(!before_release.iter().any(|event| event.terminal));
    gate.wait();

    let events = wait_for_terminal(&registry, accepted.job_id());
    assert_eq!(
        events
            .iter()
            .map(|event| event.sequence)
            .collect::<Vec<_>>(),
        (1..=events.len() as u64).collect::<Vec<_>>()
    );
    assert_eq!(events.iter().filter(|event| event.terminal).count(), 1);
    assert_eq!(events.last().unwrap().kind, "succeeded");
}

#[test]
fn phase_one_run_message_remains_deserializable() {
    let json = r#"{"request":"run","operation":{"principal_id":"p","host_id":"h","device_id":"d","workspace_id":"w","request_id":"r","manifest":[]}}"#;
    assert!(
        serde_json::from_str::<device_development_mesh::network_processes::Request>(json).is_ok()
    );
}

fn wait_for_terminal(
    registry: &AppleRegistry,
    job_id: &str,
) -> Vec<device_development_mesh::remote_apple_protocol::ProgressEvent> {
    for _ in 0..100 {
        let events = registry.events(job_id, 0).unwrap();
        if events.iter().any(|event| event.terminal) {
            return events;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("job did not finish");
}

#[test]
fn normalized_error_is_stable() {
    let error = ProtocolError::new("unsupported_version", "unsupported protocol version");
    assert_eq!(error.code(), "unsupported_version");
    assert_eq!(error.message(), "unsupported protocol version");
    assert!(!Path::new(error.code()).is_absolute());
}
