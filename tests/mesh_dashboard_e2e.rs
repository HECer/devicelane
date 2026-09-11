use device_development_mesh::dashboard::audit::{AuditStore, Redactor, RetentionPolicy};
use device_development_mesh::dashboard::event_log::EventJournal;
use device_development_mesh::dashboard::policy::PolicyEngine;
use device_development_mesh::dashboard::service::DashboardService;
use device_development_mesh::dashboard::topology::TopologyProjector;
use device_development_mesh::dashboard::{ActivityId, DashboardScope, HostId};
use device_development_mesh::local_ipc::{
    ConnectionState, DaemonRole, DaemonSnapshot, DaemonState, LocalEndpoint, LocalProtocolVersion,
    LocalRequest, LocalResponse, local_endpoint, send_local_request, serve_local,
};
use std::fs;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

struct DaemonFixture {
    _root: tempfile::TempDir,
    endpoint: LocalEndpoint,
}

fn daemon_fixture() -> DaemonFixture {
    #[cfg(windows)]
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(1);
    let root = tempfile::tempdir().unwrap();
    let runtime = root.path().join("runtime");
    fs::create_dir_all(&runtime).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
    }
    #[cfg(windows)]
    let listen = format!(
        r"\\.\pipe\devicelane-mesh-failure-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    #[cfg(unix)]
    let listen = runtime
        .canonicalize()
        .unwrap()
        .join("mesh-failure.sock")
        .display()
        .to_string();
    let endpoint = local_endpoint(&runtime, &listen).unwrap();
    let audit = AuditStore::open(
        root.path().join("audit"),
        RetentionPolicy::default(),
        Redactor::default(),
    )
    .unwrap();
    let mut daemon = DaemonState::new(
        DaemonSnapshot {
            public_identity: "mac-agent".into(),
            daemon_version: "test".into(),
            os: std::env::consts::OS.into(),
            architecture: std::env::consts::ARCH.into(),
            role: DaemonRole::Agent,
            endpoint: listen,
            connection: ConnectionState::Disconnected,
            local_protocol: LocalProtocolVersion::CURRENT,
            remote_protocol: "1.0".into(),
            warnings: Vec::new(),
            remote_access_paused: false,
            autostart: false,
            log_location: root.path().display().to_string(),
            features: vec!["dashboard_v1".into()],
        },
        Vec::new(),
    );
    daemon.enable_dashboard(DashboardService::new(
        HostId::parse("mac-agent").unwrap(),
        TopologyProjector::new(),
        EventJournal::new(1, 0),
        Arc::new(Mutex::new(audit)),
        PolicyEngine::new(),
    ));
    let server_endpoint = endpoint.clone();
    thread::spawn(move || {
        let _ = serve_local(&server_endpoint, Arc::new(Mutex::new(daemon)));
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    while send_local_request(
        &endpoint,
        &LocalRequest::Status {
            version: LocalProtocolVersion::CURRENT,
        },
    )
    .is_err()
    {
        assert!(Instant::now() < deadline, "daemon did not start");
        thread::sleep(Duration::from_millis(20));
    }
    DaemonFixture {
        _root: root,
        endpoint,
    }
}

#[test]
fn remote_execution_without_a_negotiated_authenticated_runtime_fails_closed() {
    let fixture = daemon_fixture();
    let activity_id = ActivityId::parse("offline-preapproval-activity").unwrap();
    let response = send_local_request(
        &fixture.endpoint,
        &LocalRequest::StartRemoteExecution {
            version: LocalProtocolVersion::CURRENT,
            activity_id: activity_id.clone(),
            workspace_path: "project".into(),
            request_id: "request-1".into(),
            app_path: "build/App.app".into(),
        },
    )
    .unwrap();
    assert_eq!(
        response,
        LocalResponse::Error {
            code: "feature_unavailable".into(),
            message: "dashboard feature was not negotiated".into(),
        }
    );
    let LocalResponse::DashboardSnapshot(snapshot) = send_local_request(
        &fixture.endpoint,
        &LocalRequest::DashboardSnapshot {
            version: LocalProtocolVersion::CURRENT,
            scope: DashboardScope::Local,
        },
    )
    .unwrap() else {
        panic!("dashboard snapshot missing")
    };
    assert!(
        snapshot
            .activities
            .iter()
            .all(|activity| activity.activity_id != activity_id),
        "an unavailable runtime must not synthesize activity transitions"
    );
}

#[test]
fn old_local_agent_version_is_rejected_before_execution() {
    let request = LocalRequest::StartRemoteExecution {
        version: LocalProtocolVersion { major: 0, minor: 9 },
        activity_id: ActivityId::parse("old-agent-activity").unwrap(),
        workspace_path: "project".into(),
        request_id: "request-1".into(),
        app_path: "build/App.app".into(),
    };
    assert_eq!(
        request.validate(),
        Err(device_development_mesh::local_ipc::LocalProtocolError::IncompatibleVersion)
    );
}
