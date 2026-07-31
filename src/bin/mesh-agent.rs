use device_development_mesh::{
    apple_discovery::{AppleDiscovery, Availability},
    network_processes::{DeviceSnapshot, HostSnapshot, Request, Response},
    preflight::{AppleTool, AppleToolRunner},
    process_execution::{CancellationToken, EventKind},
    remote_apple_protocol::AppleAgent,
    secure_transport::SecureTransport,
};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    io::{BufRead, BufReader, Write},
    net::TcpStream,
    process::Command,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};
const NAME: &str = "mesh-agent";
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if metadata(&args) {
        return;
    }
    if args.first().map(String::as_str) == Some("pair") {
        let mut identity =
            SecureTransport::load_or_create(value(&args, "--identity"), "agent").unwrap();
        let mut reader = BufReader::new(TcpStream::connect(value(&args, "--address")).unwrap());
        let mut challenge = String::new();
        reader.read_line(&mut challenge).unwrap();
        let challenge: serde_json::Value = serde_json::from_str(&challenge).unwrap();
        serde_json::to_writer(reader.get_mut(), &serde_json::json!({"code": challenge["code"], "certificate": identity.certificate_der()})).unwrap();
        reader.get_mut().write_all(b"\n").unwrap();
        let mut response = String::new();
        reader.read_line(&mut response).unwrap();
        let response: serde_json::Value = serde_json::from_str(&response).unwrap();
        let certificate: Vec<u8> = serde_json::from_value(response["certificate"].clone()).unwrap();
        identity.trust("registry", &certificate).unwrap();
        return;
    }
    if args.first().map(String::as_str) == Some("execute") {
        let mut input = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut input).unwrap();
        let files: Vec<device_development_mesh::network_processes::ManifestUpload> =
            serde_json::from_str(&input).unwrap();
        let workspace = std::env::temp_dir().join(format!("mesh-agent-job-{}", std::process::id()));
        std::fs::create_dir_all(&workspace).unwrap();
        for file in &files {
            let path = std::path::Path::new(&file.path);
            assert!(
                !path.is_absolute()
                    && path
                        .components()
                        .all(|part| matches!(part, std::path::Component::Normal(_)))
            );
            let destination = workspace.join(path);
            std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
            std::fs::write(destination, file.contents.as_bytes()).unwrap();
        }
        println!("manifest_files={}", files.len());
        std::fs::remove_dir_all(workspace).unwrap();
        return;
    }
    let registry = value(&args, "--registry");
    let transport =
        Arc::new(SecureTransport::load_or_create(value(&args, "--identity"), "agent").unwrap());
    let interval = Duration::from_millis(value(&args, "--heartbeat-ms").parse().unwrap());
    let workspace_root = std::path::PathBuf::from(
        optional_value(&args, "--workspace-root")
            .unwrap_or_else(|| std::env::temp_dir().to_string_lossy().into_owned()),
    );
    std::fs::create_dir_all(&workspace_root).unwrap();
    let workspace_root = std::fs::canonicalize(workspace_root).unwrap();
    let xcodebuild = optional_value(&args, "--xcodebuild");
    let devicectl = optional_value(&args, "--devicectl");
    let simctl = optional_value(&args, "--simctl");
    let legacy_capabilities = values(&args, "--capability");
    let legacy_devices: Vec<_> = values(&args, "--device")
        .into_iter()
        .filter_map(|binding| parse_device_binding(&binding))
        .collect();
    let running = Arc::new(Mutex::new(HashMap::<String, CancellationToken>::new()));
    let mut host = HostSnapshot {
        id: value(&args, "--id"),
        operating_system: value(&args, "--os"),
        architecture: value(&args, "--arch"),
        status: "online".into(),
        capabilities: Vec::new(),
        devices: Vec::new(),
    };
    loop {
        let (mut capabilities, mut devices) =
            discover(&workspace_root, &xcodebuild, &devicectl, &simctl);
        capabilities.extend(legacy_capabilities.iter().cloned());
        capabilities.sort();
        capabilities.dedup();
        for device in &legacy_devices {
            if !devices.iter().any(|current| current.id == device.id) {
                devices.push(device.clone());
            }
        }
        host.capabilities = capabilities;
        host.devices = devices;
        if let Ok(stream) = TcpStream::connect(&registry) {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
            if let Ok(mut stream) = transport.connect_tls(stream, "registry") {
                let _ =
                    serde_json::to_writer(&mut stream, &Request::Heartbeat { host: host.clone() });
                let _ = stream.write_all(b"\n");
                let mut line = String::new();
                let _ = BufReader::new(&mut stream).read_line(&mut line);
                if let Ok(response) = serde_json::from_str::<Response>(&line) {
                    for job_id in response.cancel_jobs {
                        if let Some(token) = running.lock().unwrap().get(&job_id) {
                            token.cancel();
                        }
                    }
                    if let (Some(job_id), Some(operation)) =
                        (response.job_id.clone(), response.operation)
                    {
                        let workspace = workspace_root.join(&host.id).join(&operation.workspace_id);
                        std::fs::create_dir_all(&workspace).unwrap();
                        for file in &operation.manifest {
                            let destination = workspace.join(&file.path);
                            std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
                            std::fs::write(destination, file.contents.as_bytes()).unwrap();
                        }
                        let artifact = format!("manifest_files={}", operation.manifest.len());
                        let output = if cfg!(windows) {
                            Command::new("cmd")
                                .args(["/C", "echo", &artifact])
                                .current_dir(&workspace)
                                .output()
                                .unwrap()
                        } else {
                            Command::new("printf")
                                .args(["%s\\n", &artifact])
                                .current_dir(&workspace)
                                .output()
                                .unwrap()
                        };
                        complete(&registry, &transport, job_id, artifact, output);
                    }
                    if let (Some(job_id), Some(operation), Some(tool)) = (
                        response.job_id,
                        response.apple_operation,
                        xcodebuild.clone(),
                    ) && !running.lock().unwrap().contains_key(&job_id)
                    {
                        start_apple_job(
                            registry.clone(),
                            Arc::clone(&transport),
                            workspace_root.join(&host.id),
                            job_id,
                            operation,
                            tool,
                            devicectl.clone(),
                            simctl.clone(),
                            Arc::clone(&running),
                        );
                    }
                }
            }
        }
        thread::sleep(interval)
    }
}

fn discover(
    workspace: &std::path::Path,
    tool: &Option<String>,
    devicectl: &Option<String>,
    simctl: &Option<String>,
) -> (Vec<String>, Vec<DeviceSnapshot>) {
    let capabilities = tool
        .as_ref()
        .filter(|path| tool_output(path, "-version"))
        .map(|_| {
            vec![
                "apple.preflight@1".into(),
                "apple.tool@1".into(),
                "apple.build@1".into(),
                "apple.project@1".into(),
                "apple.xctest@1".into(),
                "apple.diagnostics@1".into(),
            ]
        })
        .unwrap_or_default();
    if let (Some(devicectl), Some(simctl)) = (devicectl, simctl)
        && let Ok(runner) = AppleToolRunner::new(
            workspace,
            [
                (AppleTool::Devicectl, devicectl.into()),
                (AppleTool::Simctl, simctl.into()),
            ],
        )
        && let Ok(snapshots) = AppleDiscovery::discover(&runner, ".", Duration::from_secs(2))
    {
        let mut discovered_capabilities = capabilities;
        for snapshot in &snapshots {
            discovered_capabilities.extend(snapshot.capabilities.iter().cloned());
            if snapshot.connection
                == device_development_mesh::apple_discovery::Connection::Simulator
            {
                discovered_capabilities.push("apple.simulator@1".into());
            } else if snapshot.availability == Availability::Available {
                discovered_capabilities.push("apple.device@1".into());
            }
        }
        discovered_capabilities.sort();
        discovered_capabilities.dedup();
        let devices = snapshots
            .into_iter()
            .map(|snapshot| DeviceSnapshot {
                id: snapshot.id,
                platform: snapshot.platform,
                state: match snapshot.availability {
                    Availability::Available => "connected",
                    Availability::Locked => "locked",
                    Availability::Unavailable => "detached",
                    Availability::RuntimeMissing => "runtime_missing",
                }
                .into(),
            })
            .collect();
        return (discovered_capabilities, devices);
    }
    (capabilities, Vec::new())
}

fn tool_output(path: &str, argument: &str) -> bool {
    #[cfg(windows)]
    let mut command = if matches!(
        std::path::Path::new(path)
            .extension()
            .and_then(|extension| extension.to_str()),
        Some("cmd" | "bat")
    ) {
        let mut command = Command::new("cmd.exe");
        command.args(["/D", "/C", path]);
        command
    } else {
        Command::new(path)
    };
    #[cfg(not(windows))]
    let mut command = Command::new(path);
    command
        .arg(argument)
        .output()
        .is_ok_and(|output| output.status.success())
}

#[allow(clippy::too_many_arguments)]
fn start_apple_job(
    registry: String,
    transport: Arc<SecureTransport>,
    host_workspace: std::path::PathBuf,
    job_id: String,
    operation: device_development_mesh::remote_apple_protocol::AppleRequest,
    tool: String,
    devicectl: Option<String>,
    simctl: Option<String>,
    running: Arc<Mutex<HashMap<String, CancellationToken>>>,
) {
    let cancellation = CancellationToken::new();
    running
        .lock()
        .unwrap()
        .insert(job_id.clone(), cancellation.clone());
    send_apple_progress(
        &registry,
        &transport,
        &job_id,
        vec![network_event(1, "started", "")],
        false,
    );
    thread::spawn(move || {
        let (capabilities, devices) =
            discover(&host_workspace, &Some(tool.clone()), &devicectl, &simctl);
        let capabilities: HashSet<_> = capabilities.into_iter().collect();
        let devices: HashSet<_> = devices
            .into_iter()
            .filter(|device| device.state == "connected")
            .map(|device| device.id)
            .collect();
        let workspace = host_workspace.join(&operation.workspace_path);
        let valid = AppleAgent::new(
            &host_workspace,
            capabilities.iter().cloned(),
            devices.iter().cloned(),
        )
        .and_then(|agent| agent.validate(&operation))
        .is_ok()
            && lease_is_active(&host_workspace, &operation)
            && std::fs::canonicalize(&workspace)
                .ok()
                .is_some_and(|path| path.starts_with(&host_workspace));
        let (selected_tool, arguments) = match operation.operation {
            device_development_mesh::remote_apple_protocol::AppleOperation::Discovery => {
                (AppleTool::Devicectl, vec!["list".into(), "devices".into()])
            }
            device_development_mesh::remote_apple_protocol::AppleOperation::Project => {
                (AppleTool::Xcodebuild, vec!["-list".into()])
            }
            device_development_mesh::remote_apple_protocol::AppleOperation::Build => {
                (AppleTool::Xcodebuild, vec!["build".into()])
            }
            device_development_mesh::remote_apple_protocol::AppleOperation::Simulator => {
                (AppleTool::Simctl, vec!["list".into(), "devices".into()])
            }
            device_development_mesh::remote_apple_protocol::AppleOperation::PhysicalDevice => {
                (AppleTool::Devicectl, vec!["list".into(), "devices".into()])
            }
            device_development_mesh::remote_apple_protocol::AppleOperation::XcTest => {
                (AppleTool::Xcodebuild, vec!["test".into()])
            }
            device_development_mesh::remote_apple_protocol::AppleOperation::Diagnostics => {
                (AppleTool::Xcodebuild, vec!["-version".into()])
            }
        };
        let mut configured_tools = vec![(AppleTool::Xcodebuild, tool.into())];
        if let Some(path) = devicectl {
            configured_tools.push((AppleTool::Devicectl, path.into()));
        }
        if let Some(path) = simctl {
            configured_tools.push((AppleTool::Simctl, path.into()));
        }
        let mut events = Vec::new();
        let mut artifact_bytes = Vec::new();
        let mut succeeded = false;
        if valid
            && let Ok(runner) = AppleToolRunner::new(&host_workspace, configured_tools)
            && let Ok(process_events) = runner.execute(
                selected_tool,
                arguments,
                &operation.workspace_path,
                HashMap::new(),
                Duration::from_secs(60),
                cancellation.clone(),
            )
        {
            succeeded = process_events.last().is_some_and(|event| {
                matches!(
                    event.kind,
                    EventKind::Terminal(
                        device_development_mesh::process_execution::TerminalStatus::Exited(0)
                    )
                )
            });
            for event in process_events {
                if event.kind == EventKind::Stdout {
                    artifact_bytes.extend_from_slice(&event.payload);
                    events.push(network_event(
                        events.len() as u64 + 2,
                        "stdout",
                        &String::from_utf8_lossy(&event.payload),
                    ));
                }
            }
        }
        let artifact_id = succeeded
            .then(|| publish_artifact(&registry, &transport, &job_id, &artifact_bytes))
            .flatten()
            .unwrap_or_default();
        events.push(network_event(
            events.len() as u64 + 2,
            if cancellation.is_cancelled() {
                "cancelled"
            } else if succeeded {
                "completed"
            } else {
                "rejected"
            },
            &artifact_id,
        ));
        while !send_apple_progress(&registry, &transport, &job_id, events.clone(), true) {
            thread::sleep(Duration::from_millis(100));
        }
        running.lock().unwrap().remove(&job_id);
    });
}

fn publish_artifact(
    registry: &str,
    transport: &SecureTransport,
    job_id: &str,
    bytes: &[u8],
) -> Option<String> {
    let sha256 = format!("{:x}", Sha256::digest(bytes));
    let metadata = rpc(
        registry,
        transport,
        &Request::ArtifactRegister {
            job_id: job_id.into(),
            name: "apple-tool-output.log".into(),
            media_type: "text/plain".into(),
            total_size: bytes.len() as u64,
            sha256: sha256.clone(),
        },
    )?
    .artifact_metadata?;
    for (index, chunk) in bytes.chunks(64 * 1024).enumerate() {
        let response = rpc(
            registry,
            transport,
            &Request::ArtifactWrite {
                artifact_id: metadata.id.clone(),
                offset: (index * 64 * 1024) as u64,
                total_size: bytes.len() as u64,
                sha256: sha256.clone(),
                chunk_sha256: format!("{:x}", Sha256::digest(chunk)),
                bytes: chunk.to_vec(),
            },
        )?;
        if response.error.is_some() {
            return None;
        }
    }
    Some(metadata.id)
}

fn rpc(registry: &str, transport: &SecureTransport, request: &Request) -> Option<Response> {
    let stream = TcpStream::connect(registry).ok()?;
    let mut stream = transport.connect_tls(stream, "registry").ok()?;
    serde_json::to_writer(&mut stream, request).ok()?;
    stream.write_all(b"\n").ok()?;
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line).ok()?;
    serde_json::from_str(&line).ok()
}

fn lease_is_active(
    workspace: &std::path::Path,
    operation: &device_development_mesh::remote_apple_protocol::AppleRequest,
) -> bool {
    if !operation.operation.requires_device() {
        return operation.lease_id.is_none();
    }
    let (Some(device_id), Some(lease_id)) = (&operation.device_id, &operation.lease_id) else {
        return false;
    };
    if !valid_component(device_id) || !valid_component(lease_id) {
        return false;
    }
    workspace
        .join(".leases")
        .join(device_id)
        .join(lease_id)
        .is_file()
}

fn valid_component(value: &str) -> bool {
    !value.is_empty()
        && std::path::Path::new(value)
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
}

fn network_event(
    sequence: u64,
    kind: &str,
    payload: &str,
) -> device_development_mesh::network_processes::NetworkEvent {
    device_development_mesh::network_processes::NetworkEvent {
        sequence,
        kind: kind.into(),
        payload: payload.into(),
    }
}

fn send_apple_progress(
    registry: &str,
    transport: &SecureTransport,
    job_id: &str,
    events: Vec<device_development_mesh::network_processes::NetworkEvent>,
    terminal: bool,
) -> bool {
    for _ in 0..20 {
        if let Ok(stream) = TcpStream::connect(registry)
            && let Ok(mut stream) = transport.connect_tls(stream, "registry")
            && serde_json::to_writer(
                &mut stream,
                &Request::AppleProgress {
                    job_id: job_id.into(),
                    events: events.clone(),
                    terminal,
                },
            )
            .is_ok()
            && stream.write_all(b"\n").is_ok()
        {
            let mut response = String::new();
            if BufReader::new(stream).read_line(&mut response).is_ok() {
                return true;
            }
        }
        thread::sleep(Duration::from_millis(10));
    }
    false
}

fn complete(
    registry: &str,
    transport: &SecureTransport,
    job_id: String,
    artifact: String,
    output: std::process::Output,
) {
    let events = vec![
        device_development_mesh::network_processes::NetworkEvent {
            sequence: 1,
            kind: "started".into(),
            payload: String::new(),
        },
        device_development_mesh::network_processes::NetworkEvent {
            sequence: 2,
            kind: "stdout".into(),
            payload: String::from_utf8_lossy(&output.stdout).into_owned(),
        },
        device_development_mesh::network_processes::NetworkEvent {
            sequence: 3,
            kind: "exit".into(),
            payload: output.status.code().unwrap_or(-1).to_string(),
        },
    ];
    let mut payload = serde_json::to_vec(&Request::Complete {
        job_id,
        artifact,
        events,
    })
    .unwrap();
    payload.push(b'\n');
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Ok(stream) = TcpStream::connect(registry) {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
            if let Ok(mut stream) = transport.connect_tls(stream, "registry")
                && stream.write_all(&payload).is_ok()
            {
                let mut response = String::new();
                if BufReader::new(stream).read_line(&mut response).is_ok()
                    && serde_json::from_str::<Response>(&response)
                        .is_ok_and(|response| response.accepted)
                {
                    return;
                }
            }
        }
        if Instant::now() >= deadline {
            return;
        }
        thread::sleep(Duration::from_millis(25));
    }
}
fn value(a: &[String], n: &str) -> String {
    optional_value(a, n).unwrap()
}
fn optional_value(a: &[String], n: &str) -> Option<String> {
    a.iter()
        .position(|v| v == n)
        .and_then(|i| a.get(i + 1))
        .cloned()
}

fn values(a: &[String], n: &str) -> Vec<String> {
    a.windows(2)
        .filter(|pair| pair[0] == n)
        .map(|pair| pair[1].clone())
        .collect()
}

fn parse_device_binding(binding: &str) -> Option<DeviceSnapshot> {
    let mut fields = binding.splitn(3, ':');
    let id = fields.next()?;
    let platform = fields.next()?;
    let state = fields.next()?;
    (!id.is_empty() && !platform.is_empty() && !state.is_empty()).then(|| DeviceSnapshot {
        id: id.into(),
        platform: platform.into(),
        state: state.into(),
    })
}
fn metadata(a: &[String]) -> bool {
    if a == ["--help"] {
        println!(
            "{NAME} --registry ADDRESS --identity DIRECTORY --id ID --os OS --arch ARCH --capability NAME --device ID:PLATFORM:STATE --heartbeat-ms MILLISECONDS"
        );
        true
    } else if a == ["--version"] {
        println!("{NAME} {}", env!("CARGO_PKG_VERSION"));
        true
    } else {
        false
    }
}
