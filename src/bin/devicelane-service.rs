use device_development_mesh::local_ipc::{local_endpoint, validate_state_paths};
use std::path::PathBuf;

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
    if parsed.role.is_empty() || parsed.registry.is_empty() || parsed.agent_peer.is_empty() {
        return Err("--role, --registry, and --agent-peer are required".into());
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
    #[cfg(unix)]
    {
        let _listener = device_development_mesh::local_ipc::bind_local(&endpoint)
            .map_err(|error| error.to_string())?;
        if args.foreground {
            loop {
                std::thread::park();
            }
        }
    }
    #[cfg(windows)]
    {
        // The named-pipe endpoint is consumed by the Windows service host. Keeping it typed
        // prevents an accidental TCP fallback in this transport-neutral service bootstrap.
        let _endpoint = endpoint;
        if args.foreground {
            loop {
                std::thread::park();
            }
        }
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("devicelane-service: {error}");
        std::process::exit(2);
    }
}
