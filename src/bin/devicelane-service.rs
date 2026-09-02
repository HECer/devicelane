use device_development_mesh::dashboard::{HostId, policy::PolicyEngine};
use device_development_mesh::local_ipc::{
    ConnectionState, DaemonRole, DaemonSnapshot, DaemonState, DiagnosticItem, LocalProtocolVersion,
    local_endpoint, platform_autostart_enabled, serve_local, validate_state_paths,
};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct Args {
    identity: PathBuf,
    runtime_dir: PathBuf,
    role: String,
    registry: String,
    listen: String,
    agent_peer: String,
    log_dir: PathBuf,
    foreground: bool,
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
            "--listen" => parsed.listen = value,
            "--agent-peer" => parsed.agent_peer = value,
            "--log-dir" => parsed.log_dir = value.into(),
            _ => return Err(format!("unknown argument: {flag}")),
        }
    }
    if parsed.role.is_empty() {
        return Err("--role is required".into());
    }
    if parsed.role != "workstation" && (parsed.registry.is_empty() || parsed.agent_peer.is_empty())
    {
        return Err("--registry and --agent-peer are required for remote roles".into());
    }
    validate_state_paths([
        parsed.identity.as_path(),
        parsed.runtime_dir.as_path(),
        parsed.log_dir.as_path(),
    ])
    .map_err(|error| error.to_string())?;
    Ok(parsed)
}

fn run() -> Result<(), String> {
    let args = parse_args()?;
    // State path validation deliberately precedes endpoint creation/binding.
    let endpoint =
        local_endpoint(&args.runtime_dir, &args.listen).map_err(|error| error.to_string())?;
    let role = match args.role.as_str() {
        "workstation" => DaemonRole::Workstation,
        "agent" => DaemonRole::Agent,
        "registry" => DaemonRole::Registry,
        _ => return Err("invalid --role".into()),
    };
    let public_identity = args
        .identity
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("devicelane")
        .to_owned();
    let local_host_id =
        HostId::parse(public_identity.clone()).map_err(|error| error.to_string())?;
    let mut daemon_state = DaemonState::new_with_platform_lifecycle(
        DaemonSnapshot {
            public_identity,
            daemon_version: env!("CARGO_PKG_VERSION").into(),
            os: std::env::consts::OS.into(),
            architecture: std::env::consts::ARCH.into(),
            role,
            endpoint: args.listen.clone(),
            connection: ConnectionState::Disconnected,
            local_protocol: LocalProtocolVersion::CURRENT,
            remote_protocol: "1.0".into(),
            warnings: Vec::new(),
            remote_access_paused: false,
            autostart: platform_autostart_enabled(),
            log_location: args.log_dir.display().to_string(),
        },
        vec![DiagnosticItem {
            code: "ready".into(),
            message: "local daemon is ready".into(),
            healthy: true,
        }],
    );
    daemon_state.enable_dashboard_policy(local_host_id, PolicyEngine::new());
    let state = Arc::new(Mutex::new(daemon_state));
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
        std::process::exit(2);
    }
}
