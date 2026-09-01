use device_development_mesh::local_ipc::{
    LocalEndpoint, LocalProtocolVersion, LocalRequest, LocalResponse, local_endpoint,
    send_local_request,
};
use std::path::PathBuf;

const HELP: &str = "DeviceLane unified client\n\nUsage:\n  devicelane status --local [--json] [--endpoint ENDPOINT]\n  devicelane remote-access <pause|resume> --local [--json] [--endpoint ENDPOINT]\n  devicelane diagnostics --local [--json] [--endpoint ENDPOINT]";

struct Args {
    request: LocalRequest,
    endpoint: Option<String>,
    json: bool,
    message: &'static str,
}

fn parse_args() -> Result<Option<Args>, String> {
    let values: Vec<String> = std::env::args().skip(1).collect();
    if values
        .iter()
        .any(|value| value == "--help" || value == "-h")
    {
        match values.first().map(String::as_str) {
            Some("status") => {
                println!("Usage: devicelane status --local [--json] [--endpoint ENDPOINT]")
            }
            Some("diagnostics") => {
                println!("Usage: devicelane diagnostics --local [--json] [--endpoint ENDPOINT]")
            }
            Some("remote-access") => println!(
                "Usage: devicelane remote-access <pause|resume> --local [--json] [--endpoint ENDPOINT]"
            ),
            _ => println!("{HELP}"),
        }
        return Ok(None);
    }
    if matches!(values.as_slice(), [flag] if flag == "--version" || flag == "-V") {
        println!("devicelane {}", env!("CARGO_PKG_VERSION"));
        return Ok(None);
    }
    let (mut positional, mut endpoint, mut json, mut local) = (Vec::new(), None, false, false);
    let mut index = 0;
    while index < values.len() {
        match values[index].as_str() {
            "--local" if !local => local = true,
            "--json" if !json => json = true,
            "--endpoint" if endpoint.is_none() => {
                index += 1;
                let value = values
                    .get(index)
                    .filter(|value| !value.starts_with('-'))
                    .ok_or("missing value for --endpoint")?;
                endpoint = Some(value.clone());
            }
            value if value.starts_with('-') => return Err(format!("unknown flag: {value}")),
            value => positional.push(value.to_owned()),
        }
        index += 1;
    }
    if !local {
        return Err("local commands require --local".into());
    }
    let version = LocalProtocolVersion::CURRENT;
    let (request, message) = match positional
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["status"] => (LocalRequest::Status { version }, "status received"),
        ["remote-access", "pause"] => (
            LocalRequest::PauseRemoteAccess { version },
            "remote access paused",
        ),
        ["remote-access", "resume"] => (
            LocalRequest::ResumeRemoteAccess { version },
            "remote access resumed",
        ),
        ["diagnostics"] => (
            LocalRequest::Diagnostics { version },
            "diagnostics received",
        ),
        _ => return Err(format!("invalid command\n\n{HELP}")),
    };
    Ok(Some(Args {
        request,
        endpoint,
        json,
        message,
    }))
}

fn default_runtime_dir() -> Result<PathBuf, String> {
    #[cfg(windows)]
    {
        std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .map(|p| p.join("DeviceLane").join("runtime"))
            .ok_or_else(|| "LOCALAPPDATA is unavailable".into())
    }
    #[cfg(unix)]
    {
        std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .map(|p| p.join("devicelane"))
            .ok_or_else(|| "XDG_RUNTIME_DIR is unavailable".into())
    }
}

fn resolve_endpoint(explicit: Option<&str>) -> Result<LocalEndpoint, String> {
    #[cfg(windows)]
    let runtime = default_runtime_dir()?;
    #[cfg(unix)]
    let runtime = match explicit {
        Some(value) => std::path::Path::new(value)
            .parent()
            .ok_or("--endpoint must have a parent directory")?
            .to_owned(),
        None => default_runtime_dir()?,
    };
    local_endpoint(&runtime, explicit.unwrap_or("")).map_err(|e| e.to_string())
}

fn text(response: &LocalResponse, acknowledged: &str) -> Result<String, String> {
    match response {
        LocalResponse::Snapshot(s) => Ok(format!(
            "{} ({:?}) - {:?}{}",
            s.public_identity,
            s.role,
            s.connection,
            if s.remote_access_paused {
                " [remote access paused]"
            } else {
                ""
            }
        )),
        LocalResponse::Diagnostics(items) => Ok(items
            .iter()
            .map(|i| {
                format!(
                    "{}: {}",
                    if i.healthy { "ok" } else { "warning" },
                    i.message
                )
            })
            .collect::<Vec<_>>()
            .join("\n")),
        LocalResponse::Acknowledged => Ok(acknowledged.into()),
        LocalResponse::Error { code, message } => Err(format!("daemon error ({code}): {message}")),
    }
}

fn run() -> Result<(), String> {
    let Some(args) = parse_args()? else {
        return Ok(());
    };
    let response = match resolve_endpoint(args.endpoint.as_deref()).and_then(|endpoint| {
        send_local_request(&endpoint, &args.request).map_err(|e| e.to_string())
    }) {
        Ok(response) => response,
        Err(message) if args.json => {
            let response = LocalResponse::Error {
                code: "local_ipc_error".into(),
                message: message.clone(),
            };
            println!(
                "{}",
                serde_json::to_string(&response).map_err(|e| e.to_string())?
            );
            return Err(message);
        }
        Err(message) => return Err(message),
    };
    if args.json {
        println!(
            "{}",
            serde_json::to_string(&response).map_err(|e| e.to_string())?
        );
        if let LocalResponse::Error { code, message } = response {
            return Err(format!("daemon error ({code}): {message}"));
        }
    } else {
        println!("{}", text(&response, args.message)?);
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("devicelane: {error}");
        std::process::exit(2);
    }
}
