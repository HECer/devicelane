use device_development_mesh::apple_diagnostics::{
    AppleDiagnosticError, DapCommand, DapEvent, DebugBinding, DebugSession, TraceKind, TracePlan,
    register_diagnostic_artifacts,
};
use device_development_mesh::artifacts::ArtifactStore;
use device_development_mesh::authorization::{PolicyEngine, Role};
use std::fs;
use std::time::Duration;
use tempfile::tempdir;

fn authorized_policy(
    lifetime: Duration,
) -> (
    PolicyEngine,
    device_development_mesh::authorization::LeaseId,
) {
    let mut policy = PolicyEngine::new();
    policy.grant("debugger", Role::Operator, "apple.debug@1");
    let lease = policy
        .acquire_lease("iphone-1", "debugger", lifetime)
        .unwrap();
    (policy, lease)
}

#[test]
fn lldb_dap_supports_the_controlled_debug_lifecycle() {
    let (mut policy, lease) = authorized_policy(Duration::from_secs(30));
    let mut session = DebugSession::open(
        "session-28",
        "debugger",
        "iphone-1",
        lease,
        DebugBinding::Loopback,
        &mut policy,
    )
    .unwrap();

    let commands = [
        DapCommand::Launch("Mesh.app".into()),
        DapCommand::Attach(42),
        DapCommand::Breakpoint("Sources/App.swift".into(), 12),
        DapCommand::Continue,
        DapCommand::Pause,
        DapCommand::Stack,
        DapCommand::Variables(7),
        DapCommand::Disconnect,
    ];
    let events = commands
        .into_iter()
        .map(|command| session.execute(command, &mut policy).unwrap())
        .collect::<Vec<_>>();

    assert_eq!(
        events,
        vec![
            DapEvent::Launched,
            DapEvent::Attached,
            DapEvent::BreakpointSet,
            DapEvent::Continued,
            DapEvent::Paused,
            DapEvent::Stack(vec!["main".into()]),
            DapEvent::Variables(vec![("self".into(), "Mesh.App".into())]),
            DapEvent::Disconnected,
        ]
    );
    assert_eq!(session.session_id(), "session-28");
    assert!(session.is_terminated());
}

#[test]
fn debug_endpoints_are_private_and_stop_after_revoke_or_timeout() {
    let (mut policy, lease) = authorized_policy(Duration::from_secs(30));
    assert_eq!(
        DebugSession::open(
            "session",
            "debugger",
            "iphone-1",
            lease,
            DebugBinding::Public,
            &mut policy,
        ),
        Err(AppleDiagnosticError::PublicEndpointDenied)
    );
    let mut session = DebugSession::open(
        "session",
        "debugger",
        "iphone-1",
        lease,
        DebugBinding::EncryptedSessionChannel,
        &mut policy,
    )
    .unwrap();
    policy.revoke_lease(lease);
    assert_eq!(
        session.execute(DapCommand::Pause, &mut policy),
        Err(AppleDiagnosticError::LeaseInactive)
    );
    assert!(session.is_terminated());

    let (mut expired_policy, expired_lease) = authorized_policy(Duration::ZERO);
    assert_eq!(
        DebugSession::open(
            "session",
            "debugger",
            "iphone-1",
            expired_lease,
            DebugBinding::Loopback,
            &mut expired_policy,
        ),
        Err(AppleDiagnosticError::LeaseInactive)
    );
}

#[test]
fn trace_plans_enforce_kind_target_duration_workspace_and_resource_limit() {
    let root = tempdir().unwrap();
    for kind in [
        TraceKind::Cpu,
        TraceKind::Memory,
        TraceKind::Energy,
        TraceKind::Network,
    ] {
        let plan = TracePlan {
            kind,
            target: "iphone-1".into(),
            duration: Duration::from_secs(10),
            output: "Diagnostics/run.trace".into(),
            max_megabytes: 128,
        };
        let arguments = plan.arguments(root.path()).unwrap();
        assert!(arguments.contains(&"record".into()));
        assert!(
            arguments.contains(
                &root
                    .path()
                    .join("Diagnostics/run.trace")
                    .to_string_lossy()
                    .into_owned()
            )
        );
    }

    for invalid in [
        TracePlan {
            kind: TraceKind::Cpu,
            target: "".into(),
            duration: Duration::from_secs(10),
            output: "Diagnostics/run.trace".into(),
            max_megabytes: 128,
        },
        TracePlan {
            kind: TraceKind::Cpu,
            target: "iphone-1".into(),
            duration: Duration::ZERO,
            output: "Diagnostics/run.trace".into(),
            max_megabytes: 128,
        },
        TracePlan {
            kind: TraceKind::Cpu,
            target: "iphone-1".into(),
            duration: Duration::from_secs(10),
            output: "../run.trace".into(),
            max_megabytes: 128,
        },
        TracePlan {
            kind: TraceKind::Cpu,
            target: "iphone-1".into(),
            duration: Duration::from_secs(10),
            output: "Diagnostics/run.trace".into(),
            max_megabytes: 0,
        },
    ] {
        assert_eq!(
            invalid.arguments(root.path()),
            Err(AppleDiagnosticError::InvalidTracePlan)
        );
    }
}

#[test]
fn registers_trace_symbol_crash_and_diagnostics_with_stable_repairs() {
    let root = tempdir().unwrap();
    let output = root.path().join("output");
    fs::create_dir(&output).unwrap();
    for name in ["run.trace", "Mesh.dSYM"] {
        fs::create_dir(output.join(name)).unwrap();
        fs::write(output.join(name).join("payload"), name.as_bytes()).unwrap();
    }
    for name in ["Mesh.crash", "diagnostics.log"] {
        fs::write(output.join(name), name.as_bytes()).unwrap();
    }
    let mut store = ArtifactStore::new(root.path().join("artifacts")).unwrap();
    let artifacts =
        register_diagnostic_artifacts(&output, "job-28", "session-28", &mut store, 100, 200)
            .unwrap();
    assert_eq!(artifacts.len(), 4);
    for artifact in artifacts {
        assert!(
            !store
                .read("session-28", &artifact.sha256, 100)
                .unwrap()
                .is_empty()
        );
    }

    assert_eq!(
        TracePlan::template_available(TraceKind::Cpu, &[]),
        Err(AppleDiagnosticError::MissingTemplate {
            repair: "install_xcode_instruments_templates"
        })
    );
    assert_eq!(
        DebugSession::require_symbols(None),
        Err(AppleDiagnosticError::MissingSymbols {
            repair: "build_and_upload_matching_dsym"
        })
    );
}
