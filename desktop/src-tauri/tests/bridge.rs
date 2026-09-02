use device_development_mesh::dashboard::event_log::EventRead;
use device_development_mesh::dashboard::{
    ApprovalDecision, DashboardScope, DashboardSnapshot, EventCursor, SubscriberId,
};
use device_development_mesh::local_ipc::{
    ConnectionState, DaemonRole, DaemonSnapshot, LocalProtocolVersion, LocalRequest, LocalResponse,
};
use devicelane_desktop::{
    DaemonTransport, DesktopBridge, JavaScriptWire, RepairProcess, WireEventCursor, repair_spec,
    run_smoke_probe_with_transport, sha256_file, validate_bundle_asset,
};
use std::ffi::OsString;
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

struct FakeTransport {
    requests: Arc<Mutex<Vec<LocalRequest>>>,
    response: LocalResponse,
}

#[test]
fn installed_desktop_smoke_probe_uses_the_same_typed_bridge() {
    let transport = FakeTransport {
        requests: Arc::new(Mutex::new(vec![])),
        response: LocalResponse::Snapshot(snapshot()),
    };
    let encoded = run_smoke_probe_with_transport(transport).unwrap();
    let decoded: DaemonSnapshot = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded, snapshot());
}

struct FakeRepairProcess {
    calls: Mutex<usize>,
}

impl RepairProcess for FakeRepairProcess {
    fn execute(&self, _spec: &devicelane_desktop::RepairSpec) -> Result<(), String> {
        *self.calls.lock().unwrap() += 1;
        Ok(())
    }
}

impl DaemonTransport for FakeTransport {
    fn send(&self, request: LocalRequest) -> Result<LocalResponse, String> {
        self.requests.lock().unwrap().push(request);
        Ok(self.response.clone())
    }
}

fn snapshot() -> DaemonSnapshot {
    DaemonSnapshot {
        public_identity: "mac-agent".into(),
        daemon_version: "0.1.0-service".into(),
        os: "macOS".into(),
        architecture: "arm64".into(),
        role: DaemonRole::Agent,
        endpoint: "local".into(),
        connection: ConnectionState::Connected,
        local_protocol: LocalProtocolVersion::CURRENT,
        remote_protocol: "mesh/1".into(),
        warnings: vec!["warning".into()],
        remote_access_paused: false,
        autostart: true,
        log_location: "/logs/service.log".into(),
        features: Vec::new(),
    }
}

#[test]
fn status_maps_the_wire_snapshot_to_the_typed_desktop_contract() {
    let transport = FakeTransport {
        requests: Arc::new(Mutex::new(vec![])),
        response: LocalResponse::Snapshot(snapshot()),
    };
    let bridge = DesktopBridge::new(transport);

    let status = bridge.status().unwrap();

    assert_eq!(status, snapshot());
    assert_eq!(status.public_identity, "mac-agent");
    assert_eq!(status.endpoint, "local");
    assert_eq!(status.remote_protocol, "mesh/1");
    assert_eq!(status.daemon_version, "0.1.0-service");
}

#[test]
fn controls_send_only_versioned_local_ipc_requests() {
    let requests = Arc::new(Mutex::new(vec![]));
    let transport = FakeTransport {
        requests: Arc::clone(&requests),
        response: LocalResponse::Acknowledged,
    };
    let bridge = DesktopBridge::new(transport);

    bridge.pause().unwrap();
    bridge.resume().unwrap();
    bridge.set_autostart(false).unwrap();

    assert_eq!(
        *requests.lock().unwrap(),
        vec![
            LocalRequest::PauseRemoteAccess {
                version: LocalProtocolVersion::CURRENT
            },
            LocalRequest::ResumeRemoteAccess {
                version: LocalProtocolVersion::CURRENT
            },
            LocalRequest::SetAutostart {
                version: LocalProtocolVersion::CURRENT,
                enabled: false
            },
        ]
    );
}

#[test]
fn daemon_errors_remain_errors_at_the_command_boundary() {
    let transport = FakeTransport {
        requests: Arc::new(Mutex::new(vec![])),
        response: LocalResponse::Error {
            code: "unauthorized".into(),
            message: "wrong user".into(),
        },
    };
    let bridge = DesktopBridge::new(transport);

    assert_eq!(
        bridge.pause().unwrap_err(),
        "daemon error (unauthorized): wrong user"
    );
}

#[test]
fn dashboard_bridge_uses_typed_versioned_requests_and_preserves_resync_details() {
    let requests = Arc::new(Mutex::new(vec![]));
    let resync = EventRead::ResyncRequired {
        oldest_available: EventCursor {
            epoch: u64::MAX,
            sequence: u64::MAX - 1,
        },
        snapshot_revision: u64::MAX - 2,
    };
    let bridge = DesktopBridge::new(FakeTransport {
        requests: Arc::clone(&requests),
        response: LocalResponse::ActivityEvents(resync.clone()),
    });

    let response = bridge
        .activity_events(
            DashboardScope::Local,
            EventCursor {
                epoch: 0,
                sequence: 0,
            },
            100,
        )
        .unwrap();

    assert_eq!(response, resync);
    assert_eq!(
        *requests.lock().unwrap(),
        vec![LocalRequest::ActivityEvents {
            version: LocalProtocolVersion::CURRENT,
            scope: DashboardScope::Local,
            cursor: EventCursor {
                epoch: 0,
                sequence: 0
            },
            limit: 100,
        }]
    );
}

#[test]
fn dashboard_snapshot_bridge_uses_the_typed_scope_and_response() {
    let requests = Arc::new(Mutex::new(vec![]));
    let snapshot = DashboardSnapshot {
        revision: 7,
        generated_at_ms: 42,
        scope: DashboardScope::Mesh,
        hosts: vec![],
        activities: vec![],
        leases: vec![],
        pending_approvals: vec![],
        warnings: vec![],
    };
    let bridge = DesktopBridge::new(FakeTransport {
        requests: Arc::clone(&requests),
        response: LocalResponse::DashboardSnapshot(snapshot.clone()),
    });

    assert_eq!(
        bridge.dashboard_snapshot(DashboardScope::Mesh).unwrap(),
        snapshot
    );
    assert_eq!(
        *requests.lock().unwrap(),
        vec![LocalRequest::DashboardSnapshot {
            version: LocalProtocolVersion::CURRENT,
            scope: DashboardScope::Mesh,
        }]
    );
}

#[test]
fn management_bridge_uses_approval_ids_without_exposing_nonces_or_access_credentials() {
    let requests = Arc::new(Mutex::new(vec![]));
    let bridge = DesktopBridge::new(FakeTransport {
        requests: Arc::clone(&requests),
        response: LocalResponse::ApprovalDecided {
            decision: ApprovalDecision::AllowOnce,
            created_rule: None,
        },
    });

    bridge
        .decide_pending_approval("approval-42", ApprovalDecision::AllowOnce)
        .unwrap();

    let encoded = serde_json::to_string(&requests.lock().unwrap()[0]).unwrap();
    assert!(encoded.contains("approval-42"));
    assert!(!encoded.contains("nonce"));
    assert!(!encoded.contains("principal_id"));
    assert!(!encoded.contains("identity"));
}

#[test]
fn management_bridge_preserves_daemon_error_codes() {
    let bridge = DesktopBridge::new(FakeTransport {
        requests: Arc::new(Mutex::new(vec![])),
        response: LocalResponse::Error {
            code: "revision_conflict".into(),
            message: "rule changed".into(),
        },
    });

    assert_eq!(
        bridge.delete_policy_rule("rule-1", 7).unwrap_err(),
        "daemon error (revision_conflict): rule changed"
    );
}

#[test]
fn dashboard_acknowledgement_parses_decimal_cursor_without_javascript_precision_loss() {
    let requests = Arc::new(Mutex::new(vec![]));
    let bridge = DesktopBridge::new(FakeTransport {
        requests: Arc::clone(&requests),
        response: LocalResponse::Acknowledged,
    });
    let cursor = WireEventCursor {
        epoch: u64::MAX.to_string(),
        sequence: (u64::MAX - 1).to_string(),
    };

    bridge
        .acknowledge_events("desktop-ui", cursor.try_into().unwrap())
        .unwrap();

    assert_eq!(
        *requests.lock().unwrap(),
        vec![LocalRequest::AcknowledgeEvents {
            version: LocalProtocolVersion::CURRENT,
            subscriber_id: SubscriberId::parse("desktop-ui").unwrap(),
            cursor: EventCursor {
                epoch: u64::MAX,
                sequence: u64::MAX - 1
            },
        }]
    );
}

#[test]
fn javascript_dashboard_wire_serializes_every_u64_as_an_exact_decimal_string() {
    let wire = serde_json::to_value(JavaScriptWire(EventRead::ResyncRequired {
        oldest_available: EventCursor {
            epoch: u64::MAX,
            sequence: u64::MAX - 1,
        },
        snapshot_revision: u64::MAX - 2,
    }))
    .unwrap();

    assert_eq!(wire["oldest_available"]["epoch"], u64::MAX.to_string());
    assert_eq!(
        wire["oldest_available"]["sequence"],
        (u64::MAX - 1).to_string()
    );
    assert_eq!(wire["snapshot_revision"], (u64::MAX - 2).to_string());
}

#[test]
fn javascript_dashboard_wire_keeps_cursor_and_limit_recovery_variants_structured() {
    let cursor_ahead = serde_json::to_value(JavaScriptWire(EventRead::CursorAhead {
        newest_available: EventCursor {
            epoch: u64::MAX,
            sequence: u64::MAX - 1,
        },
    }))
    .unwrap();
    let limit = serde_json::to_value(JavaScriptWire(EventRead::LimitExceeded)).unwrap();

    assert_eq!(cursor_ahead["result"], "cursor_ahead");
    assert_eq!(
        cursor_ahead["newest_available"]["epoch"],
        u64::MAX.to_string()
    );
    assert_eq!(limit["result"], "limit_exceeded");
}

#[test]
fn repair_uses_only_fixed_platform_programs_and_arguments() {
    let root = Path::new("/trusted/resources");
    let linux_binary = Path::new("/trusted/bin/devicelane-service");
    let linux = repair_spec("linux", root, linux_binary).unwrap();
    assert_eq!(linux.program, Path::new("/bin/sh"));
    assert_eq!(
        linux.arguments,
        [root.join("scripts/setup-linux.sh"), "--repair".into()]
    );

    assert_eq!(linux.service_binary, linux_binary);

    let windows_binary = Path::new(r"C:\trusted\bin\devicelane-service.exe");
    let windows = repair_spec("windows", root, windows_binary).unwrap();
    assert_eq!(
        windows.program,
        Path::new(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
    );
    let expected: Vec<OsString> = vec![
        "-NoProfile".into(),
        "-NonInteractive".into(),
        "-ExecutionPolicy".into(),
        "Bypass".into(),
        "-File".into(),
        root.join("scripts").join("setup-windows.ps1").into(),
        "--service-repair".into(),
    ];
    assert_eq!(windows.arguments, expected);
    assert_eq!(windows.service_binary, windows_binary);
}

#[test]
fn fake_process_executes_a_validated_repair_spec_once() {
    let process = FakeRepairProcess {
        calls: Mutex::new(0),
    };
    let spec = devicelane_desktop::RepairSpec {
        program: "/bin/sh".into(),
        arguments: vec!["setup-linux.sh".into(), "--repair".into()],
        service_binary: "/trusted/devicelane-service".into(),
    };

    process.execute(&spec).unwrap();

    assert_eq!(*process.calls.lock().unwrap(), 1);
}

#[test]
fn bundle_assets_reject_outside_missing_and_non_file_paths() {
    let root = std::env::temp_dir().join(format!("devicelane-assets-{}", std::process::id()));
    let outside = std::env::temp_dir().join(format!("devicelane-outside-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("directory")).unwrap();
    fs::write(&outside, b"outside").unwrap();
    assert!(
        validate_bundle_asset(&root, &outside, &sha256_file(&outside).unwrap())
            .unwrap_err()
            .contains("outside")
    );
    assert!(
        validate_bundle_asset(&root, &root.join("missing"), "00")
            .unwrap_err()
            .contains("unavailable")
    );
    assert!(
        validate_bundle_asset(&root, &root.join("directory"), "00")
            .unwrap_err()
            .contains("regular file")
    );
    fs::remove_dir_all(root).unwrap();
    fs::remove_file(outside).unwrap();
}

#[test]
fn bundle_asset_integrity_accepts_exact_hash_and_rejects_changes() {
    let root = std::env::temp_dir().join(format!("devicelane-integrity-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let asset = root.join("setup.sh");
    fs::write(&asset, b"trusted").unwrap();
    let hash = sha256_file(&asset).unwrap();
    assert_eq!(
        validate_bundle_asset(&root, &asset, &hash).unwrap(),
        asset.canonicalize().unwrap()
    );
    fs::write(&asset, b"changed").unwrap();
    assert!(
        validate_bundle_asset(&root, &asset, &hash)
            .unwrap_err()
            .contains("integrity")
    );
    fs::remove_dir_all(root).unwrap();
}

#[cfg(any(unix, windows))]
#[test]
fn bundle_assets_reject_symbolic_links() {
    let root = std::env::temp_dir().join(format!("devicelane-links-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let target = root.join("target");
    let link = root.join("link");
    fs::write(&target, b"trusted").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&target, &link).unwrap();
    #[cfg(windows)]
    if std::os::windows::fs::symlink_file(&target, &link).is_err() {
        fs::remove_dir_all(root).unwrap();
        return;
    }
    assert!(
        validate_bundle_asset(&root, &link, &sha256_file(&target).unwrap())
            .unwrap_err()
            .contains("link")
    );
    fs::remove_dir_all(root).unwrap();
}

#[cfg(windows)]
#[test]
fn hanging_repair_child_is_killed_and_reaped_at_the_deadline() {
    let spec = devicelane_desktop::RepairSpec {
        program: r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".into(),
        arguments: vec![
            "-NoProfile".into(),
            "-Command".into(),
            "Start-Sleep -Seconds 30".into(),
        ],
        service_binary: std::env::current_exe().unwrap(),
    };
    let started = Instant::now();
    let error = devicelane_desktop::execute_repair_process(&spec, Duration::from_millis(100), 1024)
        .unwrap_err();
    assert!(error.contains("timed out"));
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[cfg(windows)]
#[test]
fn oversized_repair_stderr_is_drained_but_diagnostic_is_bounded() {
    let spec = devicelane_desktop::RepairSpec {
        program: r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".into(),
        arguments: vec![
            "-NoProfile".into(),
            "-Command".into(),
            "$x='x'*200000; [Console]::Error.Write($x); exit 7".into(),
        ],
        service_binary: std::env::current_exe().unwrap(),
    };
    let error = devicelane_desktop::execute_repair_process(&spec, Duration::from_secs(5), 1024)
        .unwrap_err();
    assert!(error.contains("output truncated"));
    assert!(error.len() < 1200);
}
