use device_development_mesh::{
    apple_discovery::{AppleDiscovery, Availability},
    network_processes::{DeviceSnapshot, HostSnapshot, LeaseGrant, Request, Response},
    preflight::{AppleTool, AppleToolRunner},
    process_execution::{
        CancellationToken, EventKind, ProcessError, ProcessExecutor, ProcessRequest,
    },
    remote_apple_protocol::AppleAgent,
    secure_transport::SecureTransport,
};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    io::{BufRead, BufReader, Write},
    net::{TcpStream, ToSocketAddrs},
    process::Command,
    sync::{Arc, Condvar, Mutex},
    thread,
    time::{Duration, Instant},
};
const NAME: &str = "mesh-agent";
const DEFAULT_PEER_ID: &str = "agent";
const REGISTRY_RPC_TIMEOUT: Duration = Duration::from_millis(250);
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let peer_id = optional_value(&args, "--peer-id").unwrap_or_else(|| DEFAULT_PEER_ID.into());
    if metadata(&args) {
        return;
    }
    if args.first().map(String::as_str) == Some("peer-id") {
        let identity =
            SecureTransport::load_or_create(value(&args, "--identity"), &peer_id).unwrap();
        println!("{}", identity.identity_id().unwrap());
        return;
    }
    if args.first().map(String::as_str) == Some("pair") {
        let mut identity =
            SecureTransport::load_or_create(value(&args, "--identity"), &peer_id).unwrap();
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
        Arc::new(SecureTransport::load_or_create(value(&args, "--identity"), &peer_id).unwrap());
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
    let xcresulttool = optional_value(&args, "--xcresulttool");
    let xctrace = optional_value(&args, "--xctrace");
    let lldb_dap = optional_value(&args, "--lldb-dap");
    let hardware_gate = optional_value(&args, "--hardware-gate");
    let controlled_home = std::env::var("HOME").ok().filter(|home| {
        let path = std::path::Path::new(home);
        path.is_absolute() && path.is_dir()
    });
    let legacy_capabilities = values(&args, "--capability");
    let legacy_devices: Vec<_> = values(&args, "--device")
        .into_iter()
        .filter_map(|binding| parse_device_binding(&binding))
        .collect();
    let running = Arc::new(Mutex::new(HashMap::<String, CancellationToken>::new()));
    let device_writers = Arc::new((Mutex::new(HashSet::<String>::new()), Condvar::new()));
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
        if hardware_gate
            .as_ref()
            .is_some_and(|path| std::path::Path::new(path).is_file())
            && capabilities.iter().any(|value| value == "apple.device@1")
        {
            capabilities.push("apple.hardware-gate@1".into());
        }
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
                            xcresulttool.clone(),
                            xctrace.clone(),
                            lldb_dap.clone(),
                            hardware_gate.clone(),
                            peer_id.clone(),
                            controlled_home.clone(),
                            host.capabilities.clone(),
                            host.devices.clone(),
                            Arc::clone(&running),
                            Arc::clone(&device_writers),
                            response.lease_grant,
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
    xcresulttool: Option<String>,
    xctrace: Option<String>,
    lldb_dap: Option<String>,
    hardware_gate: Option<String>,
    peer_id: String,
    controlled_home: Option<String>,
    capabilities: Vec<String>,
    devices: Vec<DeviceSnapshot>,
    running: Arc<Mutex<HashMap<String, CancellationToken>>>,
    device_writers: Arc<(Mutex<HashSet<String>>, Condvar)>,
    lease_grant: Option<device_development_mesh::network_processes::LeaseGrant>,
) {
    let cancellation = CancellationToken::new();
    running
        .lock()
        .unwrap()
        .insert(job_id.clone(), cancellation.clone());
    if !send_apple_progress(
        &registry,
        &transport,
        &job_id,
        vec![network_event(1, "started", "")],
        false,
    ) {
        running.lock().unwrap().remove(&job_id);
        return;
    }
    thread::spawn(move || {
        let capabilities: HashSet<_> = capabilities.into_iter().collect();
        let devices: HashSet<_> = devices
            .into_iter()
            .filter(|device| device.state == "connected")
            .map(|device| device.id)
            .collect();
        let workspace = host_workspace.join(&operation.workspace_path);
        if matches!(
            operation.operation,
            device_development_mesh::remote_apple_protocol::AppleOperation::HardwareGate { .. }
        ) {
            let _ = std::fs::create_dir_all(&workspace);
        }
        let validation_error = if let Err(code) =
            validate_lease_grant(&operation, &job_id, lease_grant.as_ref(), &transport)
        {
            Some(code.to_owned())
        } else if let Err(error) = AppleAgent::new(
            &host_workspace,
            capabilities.iter().cloned(),
            devices.iter().cloned(),
        )
        .and_then(|agent| agent.validate(&operation))
        {
            Some(error.code().to_owned())
        } else if !std::fs::canonicalize(&workspace)
            .ok()
            .is_some_and(|path| path.starts_with(&host_workspace))
        {
            Some("workspace_path_denied".to_owned())
        } else {
            None
        };
        let (selected_tool, arguments) = match &operation.operation {
            device_development_mesh::remote_apple_protocol::AppleOperation::Discovery => {
                (AppleTool::Devicectl, vec!["list".into(), "devices".into()])
            }
            device_development_mesh::remote_apple_protocol::AppleOperation::PhysicalDevice => {
                (AppleTool::Devicectl, vec!["list".into(), "devices".into()])
            }
            device_development_mesh::remote_apple_protocol::AppleOperation::Diagnostics => {
                (AppleTool::Xcodebuild, vec!["-version".into()])
            }
            device_development_mesh::remote_apple_protocol::AppleOperation::DiscoverProject {
                container,
            } => (
                AppleTool::Xcodebuild,
                vec!["-project".into(), container.clone(), "-list".into()],
            ),
            device_development_mesh::remote_apple_protocol::AppleOperation::DiscoverSimulator => {
                (AppleTool::Simctl, vec!["list".into(), "devices".into()])
            }
            device_development_mesh::remote_apple_protocol::AppleOperation::BuildApp {
                container,
                scheme,
                destination,
            } => (
                AppleTool::Xcodebuild,
                vec![
                    "-project".into(),
                    container.clone(),
                    "-scheme".into(),
                    scheme.clone(),
                    "-destination".into(),
                    destination.clone(),
                    "build".into(),
                ],
            ),
            device_development_mesh::remote_apple_protocol::AppleOperation::InstallApp {
                app_path,
            } => (
                AppleTool::Simctl,
                vec![
                    "install".into(),
                    operation.device_id.clone().unwrap(),
                    app_path.clone(),
                ],
            ),
            device_development_mesh::remote_apple_protocol::AppleOperation::LaunchApp {
                bundle_id,
            } => (
                AppleTool::Simctl,
                vec![
                    "launch".into(),
                    operation.device_id.clone().unwrap(),
                    bundle_id.clone(),
                ],
            ),
            device_development_mesh::remote_apple_protocol::AppleOperation::ReadAppLogs {
                bundle_id,
            } => (
                AppleTool::Simctl,
                vec![
                    "spawn".into(),
                    operation.device_id.clone().unwrap(),
                    "log".into(),
                    "show".into(),
                    "--predicate".into(),
                    format!("subsystem == '{bundle_id}'"),
                ],
            ),
            device_development_mesh::remote_apple_protocol::AppleOperation::RunXcTest {
                container,
                scheme,
                destination,
            } => (
                AppleTool::Xcodebuild,
                vec![
                    "-project".into(),
                    container.clone(),
                    "-scheme".into(),
                    scheme.clone(),
                    "-destination".into(),
                    destination.clone(),
                    "test".into(),
                ],
            ),
            device_development_mesh::remote_apple_protocol::AppleOperation::HardwareGate {
                ..
            } => (AppleTool::Xcodebuild, Vec::new()),
        };
        let mut configured_tools = vec![(AppleTool::Xcodebuild, tool.into())];
        if let Some(path) = devicectl {
            configured_tools.push((AppleTool::Devicectl, path.into()));
        }
        if let Some(path) = simctl {
            configured_tools.push((AppleTool::Simctl, path.into()));
        }
        if let Some(path) = xcresulttool {
            configured_tools.push((AppleTool::Xcresulttool, path.into()));
        }
        if let Some(path) = xctrace {
            configured_tools.push((AppleTool::Xctrace, path.into()));
        }
        if let Some(path) = lldb_dap {
            configured_tools.push((AppleTool::LldbDap, path.into()));
        }
        let mut events = Vec::new();
        let mut artifact_bytes = Vec::new();
        let mut succeeded = false;
        let mut rejection_code = validation_error;
        if rejection_code.is_none()
            && let Ok(runner) = AppleToolRunner::new(&host_workspace, configured_tools)
        {
            let writer_device = operation
                .operation
                .mutates_device()
                .then(|| operation.device_id.clone().unwrap());
            if let Some(device_id) = &writer_device {
                let (writers, available) = &*device_writers;
                let mut writers = writers.lock().unwrap();
                while writers.contains(device_id) {
                    writers = available.wait(writers).unwrap();
                }
                writers.insert(device_id.clone());
            }
            let lease_validation_error = writer_device.as_ref().and_then(|_| {
                let Some(grant) = lease_grant.as_ref() else {
                    return Some("lease_grant_missing".into());
                };
                validate_lease_with_retry(
                    || match rpc(
                        &registry,
                        &transport,
                        &Request::Lease {
                            operation:
                                device_development_mesh::network_processes::LeaseRequest::Validate {
                                    grant: grant.clone(),
                                },
                        },
                    ) {
                        Ok(response) if response.lease_status.as_deref() == Some("active") => {
                            Ok(())
                        }
                        Ok(response) => Err(LeaseValidationError::ServerDenied(
                            response.error.unwrap_or_else(|| "lease_inactive".into()),
                        )),
                        Err(RpcError::ConnectUnavailable) => {
                            Err(LeaseValidationError::ConnectUnavailable)
                        }
                        Err(RpcError::InvalidAddress) => Err(LeaseValidationError::InvalidAddress),
                        Err(RpcError::Tls) => Err(LeaseValidationError::Tls),
                        Err(RpcError::Io) => Err(LeaseValidationError::Io),
                        Err(RpcError::Protocol) => Err(LeaseValidationError::Protocol),
                    },
                    Duration::from_millis(850),
                )
                .err()
                .map(|error| error.code().to_owned())
            });
            if lease_validation_error.is_none() {
                let execution = if matches!(
                    operation.operation,
                    device_development_mesh::remote_apple_protocol::AppleOperation::HardwareGate { .. }
                ) {
                    let team_id = match &operation.operation {
                        device_development_mesh::remote_apple_protocol::AppleOperation::HardwareGate { team_id } => team_id.clone(),
                        _ => unreachable!(),
                    };
                    let gate = hardware_gate.as_ref().ok_or(
                        device_development_mesh::process_execution::ProcessError::ProgramDenied,
                    );
                    gate.and_then(|gate| {
                        let home = controlled_home.clone().ok_or(
                            device_development_mesh::process_execution::ProcessError::EnvironmentDenied,
                        )?;
                        ProcessExecutor::new(
                            &host_workspace,
                            [gate.into()],
                            ["HOME", "PATH"],
                        )?
                        .execute(
                            ProcessRequest {
                                program: gate.into(),
                                args: vec![
                                    "--device".into(),
                                    operation.device_id.clone().unwrap(),
                                    "--team".into(),
                                    team_id,
                                    "--output".into(),
                                    workspace
                                        .join("hardware-gates")
                                        .to_string_lossy()
                                        .into_owned(),
                                    "--job-id".into(),
                                    job_id.clone(),
                                    "--agent-peer".into(),
                                    peer_id.clone(),
                                    "--archive-stdout".into(),
                                ],
                                working_directory: operation.workspace_path.clone().into(),
                                environment: HashMap::from([
                                    ("HOME".into(), home),
                                    ("PATH".into(), "/usr/bin:/bin".into()),
                                ]),
                            },
                            Duration::from_secs(30 * 60),
                            cancellation.clone(),
                        )
                    })
                } else {
                    runner.execute(
                        selected_tool,
                        arguments,
                        &operation.workspace_path,
                        HashMap::new(),
                        Duration::from_secs(60),
                        cancellation.clone(),
                    )
                };
                match execution {
                    Ok(process_events) => {
                        succeeded = process_events.last().is_some_and(|event| {
                            matches!(
                        event.kind,
                        EventKind::Terminal(
                            device_development_mesh::process_execution::TerminalStatus::Exited(0)
                        )
                    )
                        });
                        if !succeeded {
                            rejection_code = Some("tool_failed".into());
                        }
                        for event in process_events {
                            if event.kind == EventKind::Stdout {
                                artifact_bytes.extend_from_slice(&event.payload);
                                if !matches!(
                            operation.operation,
                            device_development_mesh::remote_apple_protocol::AppleOperation::HardwareGate { .. }
                        ) {
                                    events.push(network_event(
                                        events.len() as u64 + 2,
                                        "stdout",
                                        &String::from_utf8_lossy(&event.payload),
                                    ));
                                }
                            } else if event.kind == EventKind::Stderr {
                                events.push(network_event(
                                    events.len() as u64 + 2,
                                    "stderr",
                                    &String::from_utf8_lossy(&event.payload),
                                ));
                            }
                        }
                    }
                    Err(error) => {
                        rejection_code = Some(process_error_code(error).into());
                    }
                }
            } else {
                rejection_code = lease_validation_error;
            }
            if let Some(device_id) = writer_device {
                let (writers, available) = &*device_writers;
                writers.lock().unwrap().remove(&device_id);
                available.notify_all();
            }
        } else if rejection_code.is_none() {
            rejection_code = Some("tool_configuration_invalid".into());
        }
        let (artifact_name, artifact_media_type) = if matches!(
            operation.operation,
            device_development_mesh::remote_apple_protocol::AppleOperation::HardwareGate { .. }
        ) {
            ("mac-hardware-gate.tar.gz", "application/gzip")
        } else {
            ("apple-tool-output.log", "text/plain")
        };
        let artifact_id = succeeded
            .then(|| {
                publish_artifact(
                    &registry,
                    &transport,
                    &job_id,
                    artifact_name,
                    artifact_media_type,
                    &artifact_bytes,
                )
            })
            .flatten()
            .unwrap_or_default();
        let terminal_payload = if cancellation.is_cancelled() {
            "cancelled"
        } else if succeeded {
            artifact_id.as_str()
        } else {
            rejection_code.as_deref().unwrap_or("tool_failed")
        };
        events.push(network_event(
            events.len() as u64 + 2,
            if cancellation.is_cancelled() {
                "cancelled"
            } else if succeeded {
                "completed"
            } else {
                "rejected"
            },
            terminal_payload,
        ));
        while !send_apple_progress(&registry, &transport, &job_id, events.clone(), true) {
            thread::sleep(Duration::from_millis(100));
        }
        running.lock().unwrap().remove(&job_id);
    });
}

fn validate_lease_grant(
    operation: &device_development_mesh::remote_apple_protocol::AppleRequest,
    job_id: &str,
    grant: Option<&LeaseGrant>,
    transport: &SecureTransport,
) -> Result<(), &'static str> {
    if !operation.operation.mutates_device() {
        return Ok(());
    }
    let grant = grant.ok_or("lease_grant_missing")?;
    if grant.job_id != job_id {
        return Err("lease_grant_job_mismatch");
    }
    if operation.device_id.as_deref() != Some(&grant.device_id) {
        return Err("lease_grant_device_mismatch");
    }
    if operation.lease_id.as_deref() != Some(&grant.lease_id) {
        return Err("lease_grant_id_mismatch");
    }
    transport
        .verify_peer_signature("registry", &grant.signed_payload(), &grant.signature)
        .map_err(|_| "lease_grant_signature_invalid")
}

fn validate_lease_with_retry(
    mut validate: impl FnMut() -> Result<(), LeaseValidationError>,
    total_timeout: Duration,
) -> Result<(), LeaseValidationError> {
    let deadline = Instant::now() + total_timeout;
    for attempt in 0..3 {
        match validate() {
            Ok(()) => return Ok(()),
            Err(LeaseValidationError::ConnectUnavailable) => {
                if attempt == 2 || Instant::now() >= deadline {
                    return Err(LeaseValidationError::ConnectUnavailable);
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!()
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum RpcError {
    InvalidAddress,
    ConnectUnavailable,
    Tls,
    Io,
    Protocol,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum LeaseValidationError {
    ConnectUnavailable,
    InvalidAddress,
    Tls,
    Io,
    Protocol,
    ServerDenied(String),
}

impl LeaseValidationError {
    fn code(&self) -> &'static str {
        match self {
            Self::ConnectUnavailable => "lease_validation_unavailable",
            Self::InvalidAddress => "lease_validation_address_invalid",
            Self::Tls => "lease_validation_tls_failed",
            Self::Io => "lease_validation_io_failed",
            Self::Protocol => "lease_validation_protocol_failed",
            Self::ServerDenied(error) if error == "lease_inactive" => "lease_inactive",
            Self::ServerDenied(error) if error == "lease_validation_access_denied" => {
                "lease_validation_access_denied"
            }
            Self::ServerDenied(_) => "lease_validation_denied",
        }
    }
}

fn publish_artifact(
    registry: &str,
    transport: &SecureTransport,
    job_id: &str,
    name: &str,
    media_type: &str,
    bytes: &[u8],
) -> Option<String> {
    let sha256 = format!("{:x}", Sha256::digest(bytes));
    let metadata = rpc(
        registry,
        transport,
        &Request::ArtifactRegister {
            job_id: job_id.into(),
            name: name.into(),
            media_type: media_type.into(),
            total_size: bytes.len() as u64,
            sha256: sha256.clone(),
        },
    )
    .ok()?
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
        )
        .ok()?;
        if response.error.is_some() {
            return None;
        }
    }
    Some(metadata.id)
}

fn rpc(
    registry: &str,
    transport: &SecureTransport,
    request: &Request,
) -> Result<Response, RpcError> {
    let stream = registry_stream(registry)?;
    let mut stream = transport
        .connect_tls(stream, "registry")
        .map_err(|_| RpcError::Tls)?;
    serde_json::to_writer(&mut stream, request).map_err(|_| RpcError::Protocol)?;
    stream.write_all(b"\n").map_err(|_| RpcError::Io)?;
    let mut line = String::new();
    BufReader::new(stream)
        .read_line(&mut line)
        .map_err(|_| RpcError::Io)?;
    serde_json::from_str(&line).map_err(|_| RpcError::Protocol)
}

fn registry_stream(registry: &str) -> Result<TcpStream, RpcError> {
    let addresses = registry
        .to_socket_addrs()
        .map_err(|_| RpcError::InvalidAddress)?;
    for address in addresses {
        if let Ok(stream) = TcpStream::connect_timeout(&address, REGISTRY_RPC_TIMEOUT) {
            stream
                .set_read_timeout(Some(REGISTRY_RPC_TIMEOUT))
                .map_err(|_| RpcError::Io)?;
            stream
                .set_write_timeout(Some(REGISTRY_RPC_TIMEOUT))
                .map_err(|_| RpcError::Io)?;
            return Ok(stream);
        }
    }
    Err(RpcError::ConnectUnavailable)
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

fn process_error_code(error: ProcessError) -> &'static str {
    match error {
        ProcessError::ProgramDenied => "program_denied",
        ProcessError::WorkspaceEscape => "workspace_path_denied",
        ProcessError::EnvironmentDenied => "environment_denied",
        ProcessError::Io => "tool_io_failed",
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
        if let Ok(stream) = registry_stream(registry)
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
            if BufReader::new(stream).read_line(&mut response).is_ok()
                && progress_acknowledged(&response)
            {
                return true;
            }
        }
        thread::sleep(Duration::from_millis(10));
    }
    false
}

fn progress_acknowledged(response: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(response)
        .ok()
        .and_then(|value| value["accepted"].as_bool())
        == Some(true)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_ack_requires_an_accepted_registry_response() {
        assert!(progress_acknowledged(
            r#"{"accepted":true,"hosts":[],"events":[],"audit":[],"cancel_jobs":[]}"#
        ));
        assert!(!progress_acknowledged(
            r#"{"accepted":false,"hosts":[],"events":[],"audit":[],"cancel_jobs":[],"error":"persistence_failed"}"#
        ));
        assert!(!progress_acknowledged("not-json"));
    }

    #[test]
    fn process_rejections_have_stable_actionable_codes() {
        assert_eq!(
            [
                ProcessError::ProgramDenied,
                ProcessError::WorkspaceEscape,
                ProcessError::EnvironmentDenied,
                ProcessError::Io,
            ]
            .map(process_error_code),
            [
                "program_denied",
                "workspace_path_denied",
                "environment_denied",
                "tool_io_failed",
            ]
        );
    }

    #[test]
    fn lease_grant_rejections_identify_the_exact_safe_category() {
        use device_development_mesh::remote_apple_protocol::{
            AppleOperation, AppleRequest, RemoteProtocolVersion,
        };

        let root = tempfile::tempdir().unwrap();
        let registry =
            SecureTransport::load_or_create(root.path().join("registry"), "registry").unwrap();
        let mut agent =
            SecureTransport::load_or_create(root.path().join("agent"), "agent").unwrap();
        agent.trust("registry", registry.certificate_der()).unwrap();
        let operation = AppleRequest {
            version: RemoteProtocolVersion { major: 1, minor: 0 },
            request_id: "request-1".into(),
            idempotency_key: "idempotency-1".into(),
            capability: "apple.simulator@1".into(),
            workspace_path: "project".into(),
            device_id: Some("sim-1".into()),
            lease_id: Some("lease-1".into()),
            operation: AppleOperation::InstallApp {
                app_path: "build/App.app".into(),
            },
        };
        let mut valid = LeaseGrant {
            lease_id: "lease-1".into(),
            device_id: "sim-1".into(),
            client_id: "client-1".into(),
            job_id: "job-1".into(),
            expires_at_ms: 30_000,
            signature: Vec::new(),
        };
        valid.signature = registry.sign(&valid.signed_payload()).unwrap();

        assert_eq!(
            validate_lease_grant(&operation, "job-1", None, &agent),
            Err("lease_grant_missing")
        );
        let mut wrong_job = valid.clone();
        wrong_job.job_id = "job-2".into();
        assert_eq!(
            validate_lease_grant(&operation, "job-1", Some(&wrong_job), &agent),
            Err("lease_grant_job_mismatch")
        );
        let mut wrong_device = valid.clone();
        wrong_device.device_id = "sim-2".into();
        assert_eq!(
            validate_lease_grant(&operation, "job-1", Some(&wrong_device), &agent),
            Err("lease_grant_device_mismatch")
        );
        let mut wrong_lease = valid.clone();
        wrong_lease.lease_id = "lease-2".into();
        assert_eq!(
            validate_lease_grant(&operation, "job-1", Some(&wrong_lease), &agent),
            Err("lease_grant_id_mismatch")
        );
        let mut bad_signature = valid.clone();
        bad_signature.signature = vec![0; valid.signature.len()];
        assert_eq!(
            validate_lease_grant(&operation, "job-1", Some(&bad_signature), &agent),
            Err("lease_grant_signature_invalid")
        );
        assert_eq!(
            validate_lease_grant(&operation, "job-1", Some(&valid), &agent),
            Ok(())
        );
    }

    #[test]
    fn lease_validation_retries_only_transport_unavailability() {
        let mut transient_attempts = 0;
        assert_eq!(
            validate_lease_with_retry(
                || {
                    transient_attempts += 1;
                    if transient_attempts < 3 {
                        Err(LeaseValidationError::ConnectUnavailable)
                    } else {
                        Ok(())
                    }
                },
                Duration::from_millis(100),
            ),
            Ok(())
        );
        assert_eq!(transient_attempts, 3);

        for error in [
            LeaseValidationError::InvalidAddress,
            LeaseValidationError::Tls,
            LeaseValidationError::Io,
            LeaseValidationError::Protocol,
            LeaseValidationError::ServerDenied("lease_inactive".into()),
            LeaseValidationError::ServerDenied("lease_validation_unavailable".into()),
        ] {
            let mut attempts = 0;
            assert_eq!(
                validate_lease_with_retry(
                    || {
                        attempts += 1;
                        Err(error.clone())
                    },
                    Duration::from_millis(100),
                ),
                Err(error)
            );
            assert_eq!(attempts, 1);
        }
    }

    #[test]
    fn registry_rpc_returns_when_the_tls_peer_stalls() {
        let root = tempfile::tempdir().unwrap();
        let registry =
            SecureTransport::load_or_create(root.path().join("registry"), "registry").unwrap();
        let mut agent =
            SecureTransport::load_or_create(root.path().join("agent"), "agent").unwrap();
        agent.trust("registry", registry.certificate_der()).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let stalled_peer = thread::spawn(move || {
            let (_stream, _) = listener.accept().unwrap();
            thread::sleep(Duration::from_millis(900));
        });

        let started = Instant::now();
        assert!(matches!(
            rpc(&address, &agent, &Request::List),
            Err(RpcError::Tls)
        ));
        assert!(
            started.elapsed() < Duration::from_millis(700),
            "stalled registry held the device writer for {:?}",
            started.elapsed()
        );
        stalled_peer.join().unwrap();
    }

    #[test]
    fn registry_rpc_classifies_connect_unavailability() {
        let root = tempfile::tempdir().unwrap();
        let agent = SecureTransport::load_or_create(root.path().join("agent"), "agent").unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        drop(listener);

        let started = Instant::now();
        assert!(matches!(
            rpc(&address, &agent, &Request::List),
            Err(RpcError::ConnectUnavailable)
        ));
        assert!(started.elapsed() < Duration::from_millis(700));
    }

    #[test]
    fn registry_rpc_classifies_malformed_authenticated_response_as_protocol_error() {
        let root = tempfile::tempdir().unwrap();
        let mut registry =
            SecureTransport::load_or_create(root.path().join("registry"), "registry").unwrap();
        let mut agent =
            SecureTransport::load_or_create(root.path().join("agent"), "agent").unwrap();
        registry.trust("agent", agent.certificate_der()).unwrap();
        agent.trust("registry", registry.certificate_der()).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let malformed_peer = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = registry.accept_tls(stream).unwrap();
            let mut request = String::new();
            BufReader::new(&mut stream).read_line(&mut request).unwrap();
            stream.write_all(b"not-json\n").unwrap();
        });

        assert!(matches!(
            rpc(&address, &agent, &Request::List),
            Err(RpcError::Protocol)
        ));
        malformed_peer.join().unwrap();
    }
}
