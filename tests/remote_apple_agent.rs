use device_development_mesh::process_execution::CancellationToken;
use device_development_mesh::remote_apple_agent::{
    AgentDiscovery, RemoteAppleAgent, RemoteAppleRegistry,
};
use device_development_mesh::remote_apple_protocol::{
    AppleOperation, AppleRequest, RemoteProtocolVersion,
};
use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::time::Duration;

fn request(operation: AppleOperation) -> AppleRequest {
    AppleRequest {
        version: RemoteProtocolVersion { major: 1, minor: 0 },
        request_id: "request-1".into(),
        idempotency_key: "retry-1".into(),
        capability: operation.capability().into(),
        workspace_path: "project".into(),
        device_id: operation.requires_device().then(|| "iphone-1".into()),
        operation,
    }
}

#[test]
fn registry_dispatches_typed_job_unchanged_and_only_agent_executes_it() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("project")).unwrap();
    let discovery = Arc::new(Mutex::new(AgentDiscovery {
        capabilities: HashSet::from(["apple.build@1".into()]),
        devices: HashSet::new(),
    }));
    let executions = Arc::new(AtomicUsize::new(0));
    let received = Arc::new(Mutex::new(None));
    let agent = RemoteAppleAgent::new(
        root.path(),
        {
            let discovery = discovery.clone();
            move || discovery.lock().unwrap().clone()
        },
        {
            let executions = executions.clone();
            let received = received.clone();
            move |request, cancellation: CancellationToken, progress: &dyn Fn(&str)| {
                executions.fetch_add(1, Ordering::SeqCst);
                *received.lock().unwrap() = Some(request.clone());
                progress("compiling");
                while !cancellation.is_cancelled() {
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err("cancelled".into())
            }
        },
    )
    .unwrap();
    let registry = RemoteAppleRegistry::new(agent);
    let original = request(AppleOperation::Build);

    let accepted = registry.submit(original.clone()).unwrap();
    let duplicate = registry.submit(original.clone()).unwrap();
    assert_eq!(accepted.job_id(), duplicate.job_id());
    for _ in 0..100 {
        if executions.load(Ordering::SeqCst) == 1 {
            break;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(executions.load(Ordering::SeqCst), 1);
    assert_eq!(received.lock().unwrap().as_ref(), Some(&original));

    let progress = registry.events(accepted.job_id(), 1).unwrap();
    assert_eq!(progress[0].payload, "compiling");
    registry.cancel(accepted.job_id()).unwrap();
    let terminal = wait_for_terminal(&registry, accepted.job_id());
    assert_eq!(terminal.last().unwrap().kind, "cancelled");
    assert_eq!(executions.load(Ordering::SeqCst), 1);
}

#[test]
fn agent_refreshes_discovery_and_rechecks_scope_immediately_before_execution() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("project")).unwrap();
    let discovery = Arc::new(Mutex::new(AgentDiscovery {
        capabilities: HashSet::from(["apple.device@1".into()]),
        devices: HashSet::from(["iphone-1".into()]),
    }));
    let gate = Arc::new(Barrier::new(2));
    let discovery_gate = gate.clone();
    let agent = RemoteAppleAgent::new(
        root.path(),
        {
            let discovery = discovery.clone();
            move || {
                discovery_gate.wait();
                discovery.lock().unwrap().clone()
            }
        },
        |_, _, _| panic!("revoked device reached AppleToolRunner"),
    )
    .unwrap();
    let registry = RemoteAppleRegistry::new(agent);
    let submitter = std::thread::spawn(move || {
        registry
            .submit(request(AppleOperation::PhysicalDevice))
            .unwrap_err()
            .code()
            .to_owned()
    });
    discovery.lock().unwrap().devices.clear();
    gate.wait();
    assert_eq!(submitter.join().unwrap(), "unknown_device");

    let json = r#"{"version":{"major":1,"minor":0},"request_id":"r","idempotency_key":"i","capability":"apple.build@1","workspace_path":"project","operation":{"kind":"shell","path":"/bin/sh"}}"#;
    assert!(serde_json::from_str::<AppleRequest>(json).is_err());
}

fn wait_for_terminal(
    registry: &RemoteAppleRegistry,
    job_id: &str,
) -> Vec<device_development_mesh::remote_apple_protocol::ProgressEvent> {
    for _ in 0..100 {
        let events = registry.events(job_id, 0).unwrap();
        if events.iter().any(|event| event.terminal) {
            return events;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    panic!("job did not finish");
}
