use device_development_mesh::network_processes::{
    AuditRecord, HostSnapshot, NetworkEvent, Request, Response, RunRequest,
};
use device_development_mesh::secure_transport::SecureTransport;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs,
    io::{BufRead, BufReader, Write},
    net::{TcpListener, TcpStream},
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

const NAME: &str = "mesh-registry";

struct Entry {
    host: HostSnapshot,
    heartbeat: Instant,
}

#[derive(Default, serde::Deserialize, serde::Serialize)]
struct DurableState {
    requests: HashMap<String, String>,
    jobs: HashMap<String, Vec<NetworkEvent>>,
    artifacts: HashMap<String, String>,
    audit: Vec<AuditRecord>,
    #[serde(skip)]
    recovery_error: Option<String>,
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if metadata(&args) {
        return;
    }
    if args.first().map(String::as_str) == Some("pair") {
        pair(&args);
        return;
    }
    let identity = PathBuf::from(value(&args, "--identity"));
    let transport = Arc::new(SecureTransport::load_or_create(&identity, "registry").unwrap());
    let listener = TcpListener::bind(value(&args, "--listen")).unwrap();
    let offline = Duration::from_millis(value(&args, "--offline-after-ms").parse().unwrap());
    let entries = Arc::new(Mutex::new(HashMap::new()));
    let state_path = identity.join("vertical-slice.json");
    let state = Arc::new(Mutex::new(load_state(&state_path)));
    for stream in listener.incoming() {
        let (transport, entries, state, state_path) = (
            Arc::clone(&transport),
            Arc::clone(&entries),
            Arc::clone(&state),
            state_path.clone(),
        );
        thread::spawn(move || {
            handle(
                stream.unwrap(),
                &transport,
                offline,
                entries,
                state,
                &state_path,
            )
        });
    }
}

fn handle(
    stream: TcpStream,
    transport: &SecureTransport,
    offline: Duration,
    entries: Arc<Mutex<HashMap<String, Entry>>>,
    state: Arc<Mutex<DurableState>>,
    state_path: &Path,
) {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let Ok(mut stream) = transport.accept_tls(stream) else {
        return;
    };
    let mut line = String::new();
    if BufReader::new(&mut stream).read_line(&mut line).is_err() {
        return;
    }
    let Ok(request) = serde_json::from_str(&line) else {
        return;
    };
    let response = match request {
        Request::Heartbeat { mut host } => {
            host.status = "online".into();
            entries.lock().unwrap().insert(
                host.id.clone(),
                Entry {
                    host,
                    heartbeat: Instant::now(),
                },
            );
            response()
        }
        Request::List => {
            let now = Instant::now();
            let mut hosts: Vec<_> = entries
                .lock()
                .unwrap()
                .values()
                .map(|entry| {
                    let mut host = entry.host.clone();
                    host.status = if now.duration_since(entry.heartbeat) >= offline {
                        "offline"
                    } else {
                        "online"
                    }
                    .into();
                    host
                })
                .collect();
            hosts.sort_by(|a, b| a.id.cmp(&b.id));
            Response {
                hosts,
                ..response()
            }
        }
        Request::Run { operation } => {
            let mut state = state.lock().unwrap();
            if let Some(error) = &state.recovery_error {
                Response {
                    accepted: false,
                    error: Some(error.clone()),
                    ..response()
                }
            } else {
                run(operation, &mut state, state_path)
            }
        }
        Request::Events { job_id, after } => {
            let state = state.lock().unwrap();
            if let Some(error) = &state.recovery_error {
                return write_response(
                    &mut stream,
                    Response {
                        accepted: false,
                        error: Some(error.clone()),
                        ..response()
                    },
                );
            }
            Response {
                job_id: Some(job_id.clone()),
                events: state
                    .jobs
                    .get(&job_id)
                    .into_iter()
                    .flatten()
                    .filter(|event| event.sequence > after)
                    .cloned()
                    .collect(),
                audit: state
                    .audit
                    .iter()
                    .filter(|event| event.job_id == job_id)
                    .cloned()
                    .collect(),
                artifact: state.artifacts.get(&job_id).cloned(),
                ..response()
            }
        }
    };
    let _ = serde_json::to_writer(&mut stream, &response);
    let _ = stream.write_all(b"\n");
}

fn run(operation: RunRequest, state: &mut DurableState, state_path: &Path) -> Response {
    if let Some(job_id) = state.requests.get(&operation.request_id).cloned() {
        return job_response(state, job_id);
    }
    if !valid_id(&operation.host_id) || !valid_id(&operation.workspace_id) {
        return Response {
            accepted: false,
            ..response()
        };
    }
    let job_id = format!("job-{:x}", Sha256::digest(operation.request_id.as_bytes()));
    for file in &operation.manifest {
        let path = Path::new(&file.path);
        assert!(
            !path.is_absolute()
                && path
                    .components()
                    .all(|part| matches!(part, Component::Normal(_)))
        );
    }
    let agent = std::env::current_exe()
        .unwrap()
        .with_file_name(if cfg!(windows) {
            "mesh-agent.exe"
        } else {
            "mesh-agent"
        });
    let mut child = Command::new(agent)
        .arg("execute")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(&operation.manifest).unwrap())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    let artifact = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let events = vec![
        NetworkEvent {
            sequence: 1,
            kind: "started".into(),
            payload: String::new(),
        },
        NetworkEvent {
            sequence: 2,
            kind: "stdout".into(),
            payload: String::from_utf8_lossy(&output.stdout).into_owned(),
        },
        NetworkEvent {
            sequence: 3,
            kind: "exit".into(),
            payload: output.status.code().unwrap_or(-1).to_string(),
        },
    ];
    state.requests.insert(operation.request_id, job_id.clone());
    state.jobs.insert(job_id.clone(), events);
    state.artifacts.insert(job_id.clone(), artifact);
    state.audit.push(AuditRecord {
        principal_id: operation.principal_id,
        host_id: operation.host_id,
        device_id: operation.device_id,
        workspace_id: operation.workspace_id,
        job_id: job_id.clone(),
        result: if output.status.success() {
            "succeeded"
        } else {
            "failed"
        }
        .into(),
    });
    fs::write(state_path, serde_json::to_vec(state).unwrap()).unwrap();
    job_response(state, job_id)
}

fn job_response(state: &DurableState, job_id: String) -> Response {
    let artifact = state.artifacts.get(&job_id).cloned();
    Response {
        events: state.jobs.get(&job_id).cloned().unwrap_or_default(),
        audit: state
            .audit
            .iter()
            .filter(|event| event.job_id == job_id)
            .cloned()
            .collect(),
        job_id: Some(job_id),
        artifact,
        ..response()
    }
}

fn response() -> Response {
    Response {
        accepted: true,
        hosts: vec![],
        job_id: None,
        events: vec![],
        audit: vec![],
        artifact: None,
        error: None,
    }
}
fn write_response(stream: &mut impl Write, response: Response) {
    let _ = serde_json::to_writer(&mut *stream, &response);
    let _ = stream.write_all(b"\n");
}
fn pair(args: &[String]) {
    let mut identity =
        SecureTransport::load_or_create(value(args, "--identity"), "registry").unwrap();
    let listener = TcpListener::bind(value(args, "--listen")).unwrap();
    let (stream, _) = listener.accept().unwrap();
    let mut reader = BufReader::new(stream);
    let code = identity.issue_pairing_code(Duration::from_secs(10));
    serde_json::to_writer(reader.get_mut(), &serde_json::json!({"code": code})).unwrap();
    reader.get_mut().write_all(b"\n").unwrap();
    let mut request = String::new();
    reader.read_line(&mut request).unwrap();
    let request: serde_json::Value = serde_json::from_str(&request).unwrap();
    let certificate: Vec<u8> = serde_json::from_value(request["certificate"].clone()).unwrap();
    identity
        .accept_pairing(
            request["code"].as_str().unwrap(),
            &certificate,
            Duration::ZERO,
        )
        .unwrap();
    serde_json::to_writer(
        reader.get_mut(),
        &serde_json::json!({"certificate": identity.certificate_der()}),
    )
    .unwrap();
    reader.get_mut().write_all(b"\n").unwrap();
}
fn valid_id(value: &str) -> bool {
    let path = Path::new(value);
    !value.is_empty()
        && !path.is_absolute()
        && path
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
}
fn load_state(path: &Path) -> DurableState {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|_| DurableState {
            recovery_error: Some("recovery_state_corrupt".into()),
            ..DurableState::default()
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => DurableState::default(),
        Err(_) => DurableState {
            recovery_error: Some("recovery_state_unreadable".into()),
            ..DurableState::default()
        },
    }
}
fn value(args: &[String], name: &str) -> String {
    args.iter()
        .position(|v| v == name)
        .and_then(|i| args.get(i + 1))
        .unwrap()
        .clone()
}
fn metadata(args: &[String]) -> bool {
    if args == ["--help"] {
        println!("{NAME} --listen ADDRESS --identity DIRECTORY --offline-after-ms MILLISECONDS");
        true
    } else if args == ["--version"] {
        println!("{NAME} {}", env!("CARGO_PKG_VERSION"));
        true
    } else {
        false
    }
}
