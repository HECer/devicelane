use device_development_mesh::connection_config::ConnectionConfig;
use device_development_mesh::dashboard::audit::{AuditStore, Redactor, RetentionPolicy};
use device_development_mesh::dashboard::event_log::EventJournal;
use device_development_mesh::dashboard::managed_policy::{
    ManagedPolicyStore, PolicyAdminTrustStore,
};
use device_development_mesh::dashboard::service::DashboardService;
use device_development_mesh::dashboard::topology::TopologyProjector;
use device_development_mesh::dashboard::{HostId, policy::PolicyEngine};
use device_development_mesh::local_ipc::{
    ConnectionState, DaemonRole, DaemonSnapshot, DaemonState, DiagnosticItem, LocalProtocolVersion,
    RemoteExecutionConfig, local_endpoint, platform_autostart_enabled, serve_local,
    start_registry_inventory_observer, validate_state_paths,
};
use device_development_mesh::registry_runtime::{
    RegistryRecoveryPolicy, RegistryRuntime, RegistryRuntimeConfig,
};
use device_development_mesh::secure_transport::SecureTransport;
use device_development_mesh::state_paths::{
    prepare_private_state_directory, validate_private_state_directory,
};
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Default)]
struct Args {
    identity: PathBuf,
    runtime_dir: PathBuf,
    role: String,
    registry: String,
    registry_listen: Option<SocketAddr>,
    listen: String,
    agent_peers: Vec<String>,
    log_dir: PathBuf,
    foreground: bool,
    managed_policy: Option<PathBuf>,
    policy_admin_trust: Option<PathBuf>,
    policy_admin_sids: Vec<String>,
}

fn requested_log_dir() -> Option<PathBuf> {
    let mut args = std::env::args_os().skip(1);
    while let Some(argument) = args.next() {
        if argument == "--log-dir" {
            return args.next().map(PathBuf::from);
        }
    }
    None
}

fn persist_startup_error(error: &str) {
    let Some(log_dir) = requested_log_dir() else {
        return;
    };
    if !log_dir.is_absolute() {
        return;
    }
    #[cfg(windows)]
    let log_dir_is_allowed = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .map(|local_app_data| {
            local_app_data
                .join("DeviceLane")
                .join("service")
                .join("logs")
        })
        .is_some_and(|expected| expected == log_dir && log_dir.is_dir());
    #[cfg(not(windows))]
    let log_dir_is_allowed = validate_private_state_directory(&log_dir).is_ok();
    if !log_dir_is_allowed {
        return;
    }
    let path = log_dir.join("startup-error.log");
    let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    else {
        return;
    };
    use std::io::Write;
    let _ = writeln!(file, "{error}");
}

fn parse_args() -> Result<Args, String> {
    let mut parsed = Args::default();
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        if flag == "--foreground" {
            parsed.foreground = true;
            continue;
        }
        let value = args
            .next()
            .ok_or_else(|| format!("missing value for {flag}"))?;
        match flag.as_str() {
            "--identity" => parsed.identity = value.into(),
            "--runtime-dir" => parsed.runtime_dir = value.into(),
            "--role" => parsed.role = value,
            "--registry" => parsed.registry = value,
            "--registry-listen" => {
                parsed.registry_listen = Some(registry_listener_address(&value)?)
            }
            "--listen" => parsed.listen = value,
            "--agent-peer" => parsed.agent_peers.push(value),
            "--log-dir" => parsed.log_dir = value.into(),
            "--managed-policy" => parsed.managed_policy = Some(value.into()),
            "--policy-admin-trust" => parsed.policy_admin_trust = Some(value.into()),
            "--policy-admin-sid" => parsed.policy_admin_sids.push(value),
            _ => return Err(format!("unknown argument: {flag}")),
        }
    }
    if parsed.role.is_empty() {
        return Err("--role is required".into());
    }
    if !matches!(parsed.role.as_str(), "workstation" | "agent" | "registry") {
        return Err("invalid --role".into());
    }
    if parsed.role == "agent" && (parsed.registry.is_empty() || parsed.agent_peers.is_empty()) {
        return Err("--registry and --agent-peer are required for remote roles".into());
    }
    if parsed.role == "registry" && parsed.registry_listen.is_none() {
        return Err("--registry-listen is required for the registry role".into());
    }
    if parsed.role != "registry" && parsed.registry_listen.is_some() {
        return Err("--registry-listen requires the registry role".into());
    }
    if parsed.managed_policy.is_some() != parsed.policy_admin_trust.is_some() {
        return Err("--managed-policy and --policy-admin-trust must be configured together".into());
    }
    validate_state_paths([
        parsed.identity.as_path(),
        parsed.runtime_dir.as_path(),
        parsed.log_dir.as_path(),
    ])
    .map_err(|error| error.to_string())?;
    Ok(parsed)
}

fn registry_listener_address(value: &str) -> Result<SocketAddr, String> {
    let address: SocketAddr = value
        .parse()
        .map_err(|_| "invalid --registry-listen".to_owned())?;
    let allowed_v4 =
        |ip: std::net::Ipv4Addr| ip.is_loopback() || ip.is_private() || ip.is_link_local();
    let allowed = match address {
        SocketAddr::V4(address) => allowed_v4(*address.ip()),
        SocketAddr::V6(address) => {
            let ip = address.ip();
            if let Some(ipv4) = ip.to_ipv4_mapped() {
                allowed_v4(ipv4)
            } else {
                ip.is_loopback()
                    || ip.is_unique_local()
                    || (ip.is_unicast_link_local() && address.scope_id() != 0)
            }
        }
    };
    allowed
        .then_some(address)
        .ok_or_else(|| "--registry-listen requires a numeric private or loopback address".into())
}

fn run() -> Result<(), String> {
    let mut args = parse_args()?;
    // Resolve all selected directories read-only before any endpoint preparation
    // or state mutation, retaining the resolved paths for every later consumer.
    args.identity =
        validate_private_state_directory(&args.identity).map_err(|error| error.to_string())?;
    args.runtime_dir =
        validate_private_state_directory(&args.runtime_dir).map_err(|error| error.to_string())?;
    args.log_dir =
        validate_private_state_directory(&args.log_dir).map_err(|error| error.to_string())?;
    #[cfg(unix)]
    if !args.listen.is_empty() {
        let requested = std::path::Path::new(&args.listen);
        let parent = requested.parent().ok_or("invalid local endpoint")?;
        if !requested.is_absolute()
            || validate_private_state_directory(parent).map_err(|error| error.to_string())?
                != args.runtime_dir
        {
            return Err("invalid local endpoint".into());
        }
        args.listen = args
            .runtime_dir
            .join(requested.file_name().ok_or("invalid local endpoint")?)
            .to_str()
            .ok_or("invalid local endpoint")?
            .to_owned();
    }
    #[cfg(windows)]
    local_endpoint(&args.runtime_dir, &args.listen).map_err(|error| error.to_string())?;
    let role = match args.role.as_str() {
        "workstation" => DaemonRole::Workstation,
        "agent" => DaemonRole::Agent,
        "registry" => DaemonRole::Registry,
        _ => return Err("invalid --role".into()),
    };
    // Reserve the normal endpoint before identity creation or store writes.
    let registry_listener = args
        .registry_listen
        .map(TcpListener::bind)
        .transpose()
        .map_err(|error| format!("cannot bind registry listener: {error}"))?;
    args.identity =
        prepare_private_state_directory(&args.identity).map_err(|error| error.to_string())?;
    args.runtime_dir =
        prepare_private_state_directory(&args.runtime_dir).map_err(|error| error.to_string())?;
    args.log_dir =
        prepare_private_state_directory(&args.log_dir).map_err(|error| error.to_string())?;
    let endpoint =
        local_endpoint(&args.runtime_dir, &args.listen).map_err(|error| error.to_string())?;
    let registry_transport = registry_listener
        .as_ref()
        .map(|_| {
            SecureTransport::load_or_create(&args.identity, "registry")
                .map(Arc::new)
                .map_err(|error| format!("cannot load registry identity: {error:?}"))
        })
        .transpose()?;
    let public_identity = if let Some(transport) = &registry_transport {
        transport
            .identity_id()
            .map_err(|error| format!("invalid registry identity: {error:?}"))?
    } else {
        args.identity
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("devicelane")
            .to_owned()
    };
    let local_host_id =
        HostId::parse(public_identity.clone()).map_err(|error| error.to_string())?;
    let connection = if args.registry.is_empty() {
        ConnectionConfig::load(&args.identity)
    } else {
        ConnectionConfig::new(&args.registry, "registry").map(Some)
    };
    // This first slice serves seeded normal trust only; it does not advertise pairing.
    let _registry_runtime = match (registry_listener, registry_transport) {
        (Some(listener), Some(transport)) => Some(
            RegistryRuntime::start(RegistryRuntimeConfig {
                listener,
                transport,
                state_root: args.identity.join("registry-state"),
                offline_after: Duration::from_secs(10),
                agent_peers: args.agent_peers.iter().cloned().collect(),
                recovery_policy: RegistryRecoveryPolicy::Reject,
            })
            .map_err(|error| format!("cannot start registry: {error}"))?,
        ),
        _ => None,
    };
    let mut diagnostics = vec![DiagnosticItem {
        code: "ready".into(),
        message: "local daemon is ready".into(),
        healthy: true,
    }];
    let mut warnings = Vec::new();
    if connection.is_err() {
        warnings.push("connection_configuration_invalid".into());
        diagnostics.push(DiagnosticItem {
            code: "connection_configuration_invalid".into(),
            message: "Mesh connection settings could not be loaded. Local service remains available; repair connection settings.".into(),
            healthy: false,
        });
    }
    let mut daemon_state = DaemonState::new_with_platform_lifecycle(
        DaemonSnapshot {
            public_identity: public_identity.clone(),
            daemon_version: env!("CARGO_PKG_VERSION").into(),
            os: std::env::consts::OS.into(),
            architecture: std::env::consts::ARCH.into(),
            role,
            endpoint: args.listen.clone(),
            connection: ConnectionState::Disconnected,
            local_protocol: LocalProtocolVersion::CURRENT,
            remote_protocol: "1.0".into(),
            warnings,
            remote_access_paused: false,
            // Querying the platform scheduler can start a cold PowerShell process
            // on Windows. The service must bind IPC before that optional status
            // refresh completes.
            autostart: false,
            log_location: args.log_dir.display().to_string(),
            features: vec![
                "dashboard_v1".into(),
                "activity_events".into(),
                "policy_rules".into(),
                "audit_query_export".into(),
            ],
        },
        diagnostics,
    );
    let mut policy_engine = PolicyEngine::new();
    if let (Some(policy_path), Some(trust_path)) = (
        args.managed_policy.as_deref(),
        args.policy_admin_trust.as_deref(),
    ) {
        let trust = PolicyAdminTrustStore::load(trust_path, args.policy_admin_sids.clone())
            .map_err(|error| format!("invalid policy admin trust store: {error:?}"))?;
        let managed = ManagedPolicyStore::load(policy_path, &trust)
            .map_err(|error| format!("invalid managed policy store: {error:?}"))?;
        policy_engine
            .add_verified_managed_rules(managed)
            .map_err(|error| format!("invalid managed policy rules: {error:?}"))?;
    }
    let audit = AuditStore::open(
        args.log_dir.join("audit"),
        RetentionPolicy::default(),
        Redactor::default(),
    )
    .map_err(|error| format!("cannot open dashboard audit: {error}"))?;
    let mut topology = TopologyProjector::new();
    let observed_at_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock predates Unix epoch".to_owned())?
        .as_millis()
        .min(u64::MAX as u128) as u64;
    topology
        .observe_local(
            1,
            observed_at_ms,
            device_development_mesh::network_processes::HostSnapshot {
                id: public_identity.clone(),
                operating_system: std::env::consts::OS.into(),
                architecture: std::env::consts::ARCH.into(),
                status: "online".into(),
                capabilities: Vec::new(),
                devices: Vec::new(),
            },
        )
        .map_err(|error| format!("cannot initialize local host: {error}"))?;
    daemon_state.enable_dashboard(
        DashboardService::new_persistent(
            local_host_id,
            topology,
            EventJournal::new(1, 0),
            Arc::new(Mutex::new(audit)),
            policy_engine,
        )
        .map_err(|error| format!("cannot restore dashboard activities: {}", error.code()))?,
    );
    daemon_state
        .configure_connection_storage(args.identity.clone())
        .map_err(|error| error.to_string())?;
    if let Ok(Some(connection)) = connection {
        daemon_state.enable_remote_execution(RemoteExecutionConfig {
            registry_address: connection.registry_address().into(),
            registry_peer_id: connection.registry_peer_id().into(),
            identity_path: args.identity,
            client_id: public_identity,
        });
    }
    let state = Arc::new(Mutex::new(daemon_state));
    if let Some(runtime) = &_registry_runtime {
        state
            .lock()
            .map_err(|_| "daemon state lock poisoned".to_owned())?
            .attach_registry_status(runtime.status());
    }
    start_registry_inventory_observer(&state);
    let autostart_state = Arc::clone(&state);
    let _ = std::thread::Builder::new()
        .name("autostart-status".into())
        .spawn(move || {
            let enabled = platform_autostart_enabled();
            if let Ok(mut daemon_state) = autostart_state.lock() {
                daemon_state.set_autostart_status(enabled);
            }
        });
    if args.foreground {
        eprintln!("devicelane-service: listening on {}", args.listen);
    }
    serve_local(&endpoint, state).map_err(|error| error.to_string())
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("--print-executable-path") {
        match std::env::current_exe() {
            Ok(path) => println!("{}", path.display()),
            Err(error) => {
                eprintln!("devicelane-service: cannot resolve executable path: {error}");
                std::process::exit(2);
            }
        }
        return;
    }
    if let Err(error) = run() {
        eprintln!("devicelane-service: {error}");
        persist_startup_error(&error);
        std::process::exit(2);
    }
}
