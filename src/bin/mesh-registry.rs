use device_development_mesh::controller_session::issue_mesh_approval;
use device_development_mesh::network_processes::{
    ArtifactChunk, AuditRecord, HostSnapshot, LeaseGrant, LeaseRequest, NetworkArtifactMetadata,
    NetworkEvent, Request, Response, RunRequest,
};
use device_development_mesh::remote_apple_protocol::{AppleRequest, validate_request_envelope};
use device_development_mesh::secure_transport::SecureTransport;
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fs::{self, OpenOptions},
    io::{BufRead, BufReader, Read, Seek, SeekFrom, Write},
    net::{TcpListener, TcpStream},
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
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
    pending: HashMap<String, RunRequest>,
    apple_pending: HashMap<String, AppleRequest>,
    apple_requests: HashMap<String, String>,
    apple_operations: HashMap<String, AppleRequest>,
    apple_hosts: HashMap<String, String>,
    #[serde(default)]
    job_clients: HashMap<String, String>,
    #[serde(default)]
    job_agents: HashMap<String, String>,
    #[serde(default)]
    host_peers: HashMap<String, String>,
    #[serde(default)]
    device_peers: HashMap<String, String>,
    #[serde(default)]
    dispatched: HashSet<String>,
    #[serde(default)]
    acknowledged: HashSet<String>,
    #[serde(default)]
    cancelled: HashSet<String>,
    #[serde(skip)]
    recovery_error: Option<String>,
}

const MAX_ARTIFACT_CHUNK: u64 = 64 * 1024;

#[derive(serde::Deserialize, serde::Serialize)]
struct PersistedJson {
    schema_version: u32,
    generation: u64,
    sha256: String,
    payload: serde_json::Value,
}

#[derive(Clone, serde::Deserialize, serde::Serialize)]
struct NetworkArtifact {
    metadata: NetworkArtifactMetadata,
    participants: HashSet<String>,
    confirmed_offset: u64,
    published: bool,
}

struct NetworkArtifacts {
    root: PathBuf,
    index_path: PathBuf,
    entries: HashMap<String, NetworkArtifact>,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct DeviceLease {
    id: String,
    device_id: String,
    client_id: String,
    expires_at_ms: u64,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct WaitingLease {
    device_id: String,
    client_id: String,
    lifetime_ms: u64,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct DeviceWriter {
    job_id: String,
}

#[derive(Default, serde::Deserialize, serde::Serialize)]
struct LeaseBook {
    next_id: u64,
    active: HashMap<String, DeviceLease>,
    waiting: Vec<WaitingLease>,
    writers: HashMap<String, DeviceWriter>,
    pending_release: HashSet<String>,
    pending_detach: HashSet<String>,
    #[serde(skip)]
    path: PathBuf,
}

impl LeaseBook {
    fn load(path: PathBuf) -> Self {
        let mut leases: Self = load_json_with_fallback(&path)
            .expect("device lease state is corrupt or unreadable")
            .unwrap_or_default();
        leases.path = path;
        leases.expire();
        let _ = leases.persist();
        leases
    }

    fn persist(&self) -> std::io::Result<()> {
        atomic_write_json(&self.path, self)
    }

    fn expire(&mut self) {
        let now = unix_time_ms();
        let expired: Vec<_> = self
            .active
            .iter()
            .filter(|(_, lease)| now >= lease.expires_at_ms)
            .map(|(device, _)| device.clone())
            .collect();
        for device in expired {
            self.release_device(&device);
        }
    }

    fn release_device(&mut self, device_id: &str) {
        if self.writers.contains_key(device_id) {
            self.pending_release.insert(device_id.into());
            return;
        }
        self.release_device_now(device_id);
    }

    fn force_release_device(&mut self, device_id: &str) {
        self.writers.remove(device_id);
        self.pending_release.remove(device_id);
        self.pending_detach.remove(device_id);
        self.release_device_now(device_id);
    }

    fn detach_inventory(&mut self, device_id: &str) {
        if self.writers.contains_key(device_id) {
            self.pending_detach.insert(device_id.into());
        }
        self.release_device(device_id);
    }

    fn release_device_now(&mut self, device_id: &str) {
        self.active.remove(device_id);
        if let Some(index) = self
            .waiting
            .iter()
            .position(|waiting| waiting.device_id == device_id)
        {
            let waiting = self.waiting.remove(index);
            self.insert(
                waiting.device_id,
                waiting.client_id,
                Duration::from_millis(waiting.lifetime_ms),
            );
        }
    }

    fn insert(&mut self, device_id: String, client_id: String, lifetime: Duration) -> String {
        self.next_id += 1;
        let id = format!("lease-{}", self.next_id);
        self.active.insert(
            device_id.clone(),
            DeviceLease {
                id: id.clone(),
                device_id,
                client_id,
                expires_at_ms: unix_time_ms().saturating_add(lifetime.as_millis() as u64),
            },
        );
        id
    }
}

fn reconcile_runtime_state(state: &mut DurableState, leases: &mut LeaseBook) -> bool {
    let orphaned: Vec<_> = leases
        .writers
        .iter()
        .filter(|(_, writer)| {
            !state.acknowledged.contains(&writer.job_id)
                || !state.apple_pending.contains_key(&writer.job_id)
        })
        .map(|(device_id, _)| device_id.clone())
        .collect();
    for device_id in &orphaned {
        leases.writers.remove(device_id);
        if leases.pending_release.remove(device_id) {
            leases.release_device(device_id);
        }
        if leases.pending_detach.remove(device_id) {
            state.device_peers.remove(device_id);
        }
    }
    !orphaned.is_empty()
}

fn restore_acknowledged_writer(
    state: &DurableState,
    leases: &mut LeaseBook,
    job_id: &str,
) -> Result<bool, &'static str> {
    let Some(operation) = state.apple_pending.get(job_id) else {
        return Err("unknown_job");
    };
    if !operation.operation.mutates_device() {
        return Ok(false);
    }
    leases.expire();
    let (Some(device_id), Some(lease_id), Some(client_id)) = (
        operation.device_id.as_ref(),
        operation.lease_id.as_ref(),
        state.job_clients.get(job_id),
    ) else {
        return Err("lease_inactive");
    };
    let valid = leases
        .active
        .get(device_id)
        .is_some_and(|lease| &lease.id == lease_id && &lease.client_id == client_id);
    if !valid {
        return Err("lease_inactive");
    }
    match leases.writers.get(device_id) {
        Some(writer) if writer.job_id == job_id => Ok(false),
        Some(_) => Err("device_writer_busy"),
        None => {
            leases.writers.insert(
                device_id.clone(),
                DeviceWriter {
                    job_id: job_id.into(),
                },
            );
            Ok(true)
        }
    }
}

impl NetworkArtifacts {
    fn new(root: PathBuf) -> Self {
        fs::create_dir_all(&root).unwrap();
        let index_path = root.join("index.json");
        let entries = load_json_with_fallback(&index_path)
            .expect("artifact index is corrupt or unreadable")
            .unwrap_or_default();
        Self {
            root,
            index_path,
            entries,
        }
    }

    fn persist(&self) -> std::io::Result<()> {
        atomic_write_json(&self.index_path, &self.entries)
    }

    fn path(&self, id: &str) -> PathBuf {
        self.root.join(format!("{id}.partial"))
    }
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
    let configured_agents = values(&args, "--agent-peer");
    let agent_peers = Arc::new(if configured_agents.is_empty() {
        HashSet::from(["agent".into()])
    } else {
        configured_agents.into_iter().collect()
    });
    let entries = Arc::new(Mutex::new(HashMap::new()));
    let state_path = identity.join("vertical-slice.json");
    let mut loaded_state = load_state(&state_path);
    let artifacts = Arc::new(Mutex::new(NetworkArtifacts::new(
        identity.join("artifacts"),
    )));
    let mut loaded_leases = LeaseBook::load(identity.join("device-leases.json"));
    if reconcile_runtime_state(&mut loaded_state, &mut loaded_leases) {
        persist_state(&state_path, &loaded_state)
            .expect("registry recovery state persistence failed");
        loaded_leases
            .persist()
            .expect("registry recovery lease persistence failed");
    }
    let state = Arc::new(Mutex::new(loaded_state));
    let leases = Arc::new(Mutex::new(loaded_leases));
    for stream in listener.incoming() {
        let (transport, entries, state, artifacts, leases, agent_peers, state_path) = (
            Arc::clone(&transport),
            Arc::clone(&entries),
            Arc::clone(&state),
            Arc::clone(&artifacts),
            Arc::clone(&leases),
            Arc::clone(&agent_peers),
            state_path.clone(),
        );
        thread::spawn(move || {
            handle(
                stream.unwrap(),
                &transport,
                offline,
                entries,
                state,
                artifacts,
                leases,
                agent_peers,
                &state_path,
            )
        });
    }
}

#[allow(clippy::too_many_arguments)]
fn handle(
    stream: TcpStream,
    transport: &SecureTransport,
    offline: Duration,
    entries: Arc<Mutex<HashMap<String, Entry>>>,
    state: Arc<Mutex<DurableState>>,
    artifacts: Arc<Mutex<NetworkArtifacts>>,
    leases: Arc<Mutex<LeaseBook>>,
    agent_peers: Arc<HashSet<String>>,
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
    let Some(peer_certificate) = stream
        .conn
        .peer_certificates()
        .and_then(|items| items.first())
    else {
        return;
    };
    let Ok(peer_id) = transport.peer_id(peer_certificate.as_ref()) else {
        return;
    };
    loop {
        let mut line = String::new();
        let read = BufReader::new(&mut stream)
            .take(512 * 1024)
            .read_line(&mut line);
        if !matches!(read, Ok(bytes) if bytes > 0) {
            return;
        }
        let Ok(request) = serde_json::from_str(&line) else {
            return;
        };
        if let Some(error) = state.lock().unwrap().recovery_error.clone()
            && !read_only_during_recovery(&request)
        {
            return write_response(&mut stream, error_response(&error));
        }
        let response = match request {
            Request::Heartbeat { mut host } => {
                if !agent_peers.contains(&peer_id) {
                    return write_response(&mut stream, error_response("agent_access_denied"));
                }
                let connected: HashSet<_> = host
                    .devices
                    .iter()
                    .filter(|device| device.state == "connected")
                    .map(|device| device.id.clone())
                    .collect();
                {
                    let mut state = state.lock().unwrap();
                    if state
                        .host_peers
                        .get(&host.id)
                        .is_some_and(|owner| owner != &peer_id)
                        || connected.iter().any(|device| {
                            state
                                .device_peers
                                .get(device)
                                .is_some_and(|owner| owner != &peer_id)
                        })
                    {
                        return write_response(
                            &mut stream,
                            error_response("agent_identity_mismatch"),
                        );
                    }
                    let detached: Vec<_> = state
                        .device_peers
                        .iter()
                        .filter(|(device, owner)| {
                            *owner == &peer_id && !connected.contains(*device)
                        })
                        .map(|(device, _)| device.clone())
                        .collect();
                    state.host_peers.insert(host.id.clone(), peer_id.clone());
                    for device in &connected {
                        state.device_peers.insert(device.clone(), peer_id.clone());
                    }
                    let mut leases = leases.lock().unwrap();
                    for device in &connected {
                        leases.pending_detach.remove(device);
                    }
                    for device in &detached {
                        let writer_active = leases.writers.contains_key(device);
                        leases.detach_inventory(device);
                        if !writer_active {
                            state.device_peers.remove(device);
                        }
                    }
                    if leases.persist().is_err() {
                        return write_response(&mut stream, error_response("persistence_failed"));
                    }
                }
                {
                    let mut leases = leases.lock().unwrap();
                    leases.expire();
                    if leases.persist().is_err() {
                        return write_response(&mut stream, error_response("persistence_failed"));
                    }
                }
                host.status = "online".into();
                let host_id = host.id.clone();
                entries.lock().unwrap().insert(
                    host.id.clone(),
                    Entry {
                        host: host.clone(),
                        heartbeat: Instant::now(),
                    },
                );
                let mut response = response();
                let mut state = state.lock().unwrap();
                if let Some((job_id, operation)) = state
                    .pending
                    .iter()
                    .find(|(job_id, operation)| {
                        operation.host_id == host_id && !state.dispatched.contains(*job_id)
                    })
                    .map(|(job_id, operation)| (job_id.clone(), operation.clone()))
                {
                    state.dispatched.insert(job_id.clone());
                    response.operation = Some(operation);
                    response.job_id = Some(job_id);
                }
                if let Some((job_id, operation)) = state
                    .apple_pending
                    .iter()
                    .find(|(job_id, _)| {
                        state.apple_hosts.get(*job_id) == Some(&host_id)
                            && !state.acknowledged.contains(*job_id)
                            && state.apple_pending.get(*job_id).is_none_or(|operation| {
                                !operation.operation.mutates_device()
                                    || operation.device_id.as_ref().is_none_or(|device_id| {
                                        leases
                                            .lock()
                                            .unwrap()
                                            .writers
                                            .get(device_id)
                                            .is_none_or(|writer| &writer.job_id == *job_id)
                                    })
                            })
                    })
                    .map(|(job_id, operation)| (job_id.clone(), operation.clone()))
                {
                    response.apple_operation = Some(operation);
                    response.job_id = Some(job_id);
                    let mut dispatch = true;
                    if let Some(request) = response.apple_operation.as_ref()
                        && request.operation.mutates_device()
                        && let (Some(device_id), Some(lease_id)) =
                            (request.device_id.as_ref(), request.lease_id.as_ref())
                    {
                        let mut leases = leases.lock().unwrap();
                        leases.expire();
                        if let Some(lease) = leases.active.get(device_id)
                            && &lease.id == lease_id
                            && state.job_clients.get(response.job_id.as_ref().unwrap())
                                == Some(&lease.client_id)
                        {
                            let mut grant = LeaseGrant {
                                lease_id: lease.id.clone(),
                                device_id: lease.device_id.clone(),
                                client_id: lease.client_id.clone(),
                                job_id: response.job_id.clone().unwrap(),
                                expires_at_ms: lease.expires_at_ms.saturating_sub(unix_time_ms()),
                                signature: Vec::new(),
                            };
                            grant.signature = transport.sign(&grant.signed_payload()).unwrap();
                            leases.writers.insert(
                                device_id.clone(),
                                DeviceWriter {
                                    job_id: response.job_id.clone().unwrap(),
                                },
                            );
                            if leases.persist().is_err() {
                                return write_response(
                                    &mut stream,
                                    error_response("persistence_failed"),
                                );
                            }
                            response.lease_grant = Some(grant);
                        } else {
                            let rejected_job = response.job_id.clone().unwrap();
                            response.apple_operation = None;
                            state.apple_pending.remove(&rejected_job);
                            state
                                .jobs
                                .entry(rejected_job)
                                .or_default()
                                .push(NetworkEvent {
                                    sequence: 1,
                                    kind: "rejected".into(),
                                    payload: "lease_inactive".into(),
                                });
                            dispatch = false;
                        }
                    }
                    if dispatch {
                        state.dispatched.insert(response.job_id.clone().unwrap());
                    }
                }
                response.cancel_jobs = state.cancelled.iter().cloned().collect();
                if persist_state(state_path, &state).is_err() {
                    if let Some(job_id) = response.job_id.as_ref() {
                        state.dispatched.remove(job_id);
                        let mut leases = leases.lock().unwrap();
                        reconcile_runtime_state(&mut state, &mut leases);
                        let _ = leases.persist();
                    }
                    return write_response(&mut stream, error_response("persistence_failed"));
                }
                response
            }
            Request::Complete {
                job_id,
                artifact,
                events,
            } => {
                let mut state = state.lock().unwrap();
                if let Some(operation) = state.pending.remove(&job_id) {
                    let succeeded = events
                        .last()
                        .is_some_and(|event| event.kind == "exit" && event.payload == "0");
                    state.jobs.insert(job_id.clone(), events);
                    state.artifacts.insert(job_id.clone(), artifact);
                    state.audit.push(AuditRecord {
                        principal_id: operation.principal_id,
                        host_id: operation.host_id,
                        device_id: operation.device_id,
                        workspace_id: operation.workspace_id,
                        job_id,
                        result: if succeeded { "succeeded" } else { "failed" }.into(),
                    });
                    persist_state(state_path, &state).unwrap();
                }
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
            Request::AuthenticateDashboardAccess {
                claim,
                client_signature,
            } => {
                if agent_peers.contains(&peer_id) {
                    return write_response(
                        &mut stream,
                        error_response("controller_identity_required"),
                    );
                }
                match issue_mesh_approval(
                    transport,
                    &peer_id,
                    claim,
                    &client_signature,
                    unix_time_ms(),
                    60_000,
                ) {
                    Ok(assertion) => Response {
                        accepted: true,
                        events: vec![NetworkEvent {
                            sequence: 1,
                            kind: "authenticated_dashboard_access".into(),
                            payload: serde_json::to_string(&assertion).unwrap(),
                        }],
                        ..response()
                    },
                    Err(_) => error_response("mesh_identity_mismatch"),
                }
            }
            Request::Run { operation } => {
                if let Some(error) = &state.lock().unwrap().recovery_error {
                    Response {
                        accepted: false,
                        error: Some(error.clone()),
                        ..response()
                    }
                } else {
                    run(operation, &state, state_path)
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
            Request::AppleRun { operation } => {
                if let Err(error) = validate_request_envelope(&operation) {
                    return write_response(
                        &mut stream,
                        Response {
                            accepted: false,
                            error: Some(error.code().into()),
                            ..response()
                        },
                    );
                }
                if operation.operation.mutates_device() {
                    let mut leases = leases.lock().unwrap();
                    leases.expire();
                    let active = operation.device_id.as_ref().is_some_and(|device_id| {
                        leases.active.get(device_id).is_some_and(|lease| {
                            operation.lease_id.as_ref() == Some(&lease.id)
                                && lease.client_id == peer_id
                        })
                    });
                    if leases.persist().is_err() {
                        return write_response(&mut stream, error_response("persistence_failed"));
                    }
                    if !active {
                        return write_response(&mut stream, error_response("lease_inactive"));
                    }
                }
                let mut state = state.lock().unwrap();
                let job_id =
                    if let Some(job_id) = state.apple_requests.get(&operation.idempotency_key) {
                        if state
                            .apple_operations
                            .get(&operation.idempotency_key)
                            .is_some_and(|existing| existing != &operation)
                        {
                            return write_response(
                                &mut stream,
                                Response {
                                    accepted: false,
                                    error: Some("idempotency_conflict".into()),
                                    ..response()
                                },
                            );
                        }
                        job_id.clone()
                    } else {
                        let target = entries
                            .lock()
                            .unwrap()
                            .values()
                            .find(|entry| {
                                entry.host.capabilities.contains(&operation.capability)
                                    && operation.device_id.as_ref().is_none_or(|device_id| {
                                        entry.host.devices.iter().any(|device| {
                                            &device.id == device_id && device.state == "connected"
                                        })
                                    })
                            })
                            .map(|entry| entry.host.id.clone());
                        let Some(target) = target else {
                            return write_response(
                                &mut stream,
                                Response {
                                    accepted: false,
                                    error: Some("no_eligible_host".into()),
                                    ..response()
                                },
                            );
                        };
                        let job_id = format!(
                            "apple-{:x}",
                            Sha256::digest(operation.idempotency_key.as_bytes())
                        );
                        state
                            .apple_requests
                            .insert(operation.idempotency_key.clone(), job_id.clone());
                        state
                            .apple_operations
                            .insert(operation.idempotency_key.clone(), operation.clone());
                        state.apple_pending.insert(job_id.clone(), operation);
                        state.apple_hosts.insert(job_id.clone(), target);
                        state.job_clients.insert(job_id.clone(), peer_id.clone());
                        if let Some(agent) = state
                            .apple_hosts
                            .get(&job_id)
                            .and_then(|host| state.host_peers.get(host))
                            .cloned()
                        {
                            state.job_agents.insert(job_id.clone(), agent);
                        }
                        state.jobs.insert(job_id.clone(), Vec::new());
                        persist_state(state_path, &state).unwrap();
                        job_id
                    };
                Response {
                    job_id: Some(job_id),
                    ..response()
                }
            }
            Request::AppleProgress {
                job_id,
                events,
                terminal,
            } => {
                let mut state = state.lock().unwrap();
                if state.job_agents.get(&job_id) != Some(&peer_id) {
                    return write_response(
                        &mut stream,
                        error_response("apple_progress_access_denied"),
                    );
                }
                let restored_writer = if terminal {
                    false
                } else {
                    let mut leases = leases.lock().unwrap();
                    match restore_acknowledged_writer(&state, &mut leases, &job_id) {
                        Ok(restored) => {
                            if leases.persist().is_err() {
                                return write_response(
                                    &mut stream,
                                    error_response("persistence_failed"),
                                );
                            }
                            restored
                        }
                        Err(error) => {
                            let _ = leases.persist();
                            return write_response(&mut stream, error_response(error));
                        }
                    }
                };
                let existing = state.jobs.entry(job_id.clone()).or_default();
                for event in events {
                    if !existing
                        .iter()
                        .any(|current| current.sequence == event.sequence)
                    {
                        existing.push(event);
                    }
                }
                if !terminal {
                    state.acknowledged.insert(job_id.clone());
                }
                if terminal {
                    let mut leases = leases.lock().unwrap();
                    let finished_devices: Vec<_> = leases
                        .writers
                        .iter()
                        .filter(|(_, writer)| writer.job_id == job_id)
                        .map(|(device, _)| device.clone())
                        .collect();
                    for device in finished_devices {
                        leases.writers.remove(&device);
                        if leases.pending_release.remove(&device) {
                            leases.release_device(&device);
                        }
                        if leases.pending_detach.remove(&device) {
                            state.device_peers.remove(&device);
                        }
                    }
                    state.apple_pending.remove(&job_id);
                    state.cancelled.remove(&job_id);
                }
                if persist_state(state_path, &state).is_err() {
                    if restored_writer {
                        let mut leases = leases.lock().unwrap();
                        leases.writers.retain(|_, writer| writer.job_id != job_id);
                        let _ = leases.persist();
                    }
                    return write_response(&mut stream, error_response("persistence_failed"));
                }
                if terminal && leases.lock().unwrap().persist().is_err() {
                    return write_response(&mut stream, error_response("persistence_failed"));
                }
                response()
            }
            Request::AppleCancel { job_id } => {
                let mut state = state.lock().unwrap();
                if state.job_clients.get(&job_id) != Some(&peer_id) {
                    error_response("apple_cancel_access_denied")
                } else if state.apple_pending.contains_key(&job_id) {
                    if state.dispatched.contains(&job_id) {
                        state.cancelled.insert(job_id);
                    } else {
                        state.apple_pending.remove(&job_id);
                        state.jobs.entry(job_id).or_default().push(NetworkEvent {
                            sequence: 1,
                            kind: "cancelled".into(),
                            payload: String::new(),
                        });
                    }
                    persist_state(state_path, &state).unwrap();
                    response()
                } else {
                    Response {
                        accepted: false,
                        error: Some("unknown_job".into()),
                        ..response()
                    }
                }
            }
            Request::ArtifactRegister {
                job_id,
                name,
                media_type,
                total_size,
                sha256,
            } => {
                let state = state.lock().unwrap();
                let host_peer = state.job_agents.get(&job_id);
                if host_peer != Some(&peer_id) {
                    error_response("artifact_access_denied")
                } else if total_size == 0
                    || sha256.len() != 64
                    || !valid_id(&name)
                    || media_type.is_empty()
                {
                    error_response("invalid_artifact_metadata")
                } else {
                    let id = format!(
                        "{:x}",
                        Sha256::digest(format!("{job_id}\0{name}\0{sha256}").as_bytes())
                    );
                    let mut participants = HashSet::from([peer_id.clone()]);
                    if let Some(client) = state.job_clients.get(&job_id) {
                        participants.insert(client.clone());
                    }
                    drop(state);
                    let metadata = NetworkArtifactMetadata {
                        id: id.clone(),
                        job_id,
                        name,
                        media_type,
                        total_size,
                        sha256,
                    };
                    let mut artifacts = artifacts.lock().unwrap();
                    artifacts
                        .entries
                        .entry(id)
                        .and_modify(|entry| entry.participants.extend(participants.clone()))
                        .or_insert_with(|| NetworkArtifact {
                            metadata: metadata.clone(),
                            participants,
                            confirmed_offset: 0,
                            published: false,
                        });
                    if artifacts.persist().is_err() {
                        error_response("persistence_failed")
                    } else {
                        Response {
                            artifact_metadata: Some(metadata),
                            ..response()
                        }
                    }
                }
            }
            Request::ArtifactWrite {
                artifact_id,
                offset,
                total_size,
                sha256,
                chunk_sha256,
                bytes,
            } => write_artifact(
                &mut artifacts.lock().unwrap(),
                &peer_id,
                &artifact_id,
                offset,
                ArtifactWrite {
                    total_size,
                    sha256: &sha256,
                    chunk_sha256: &chunk_sha256,
                    bytes: &bytes,
                },
            ),
            Request::ArtifactRead {
                artifact_id,
                offset,
                length,
                total_size,
                sha256,
            } => read_artifact(
                &artifacts.lock().unwrap(),
                &peer_id,
                &artifact_id,
                offset,
                length,
                total_size,
                &sha256,
            ),
            Request::ArtifactInfo { artifact_id } => {
                let artifacts = artifacts.lock().unwrap();
                let Some(entry) = artifacts.entries.get(&artifact_id) else {
                    return write_response(&mut stream, error_response("unknown_artifact"));
                };
                if !entry.participants.contains(&peer_id) {
                    error_response("artifact_access_denied")
                } else if !entry.published {
                    error_response("artifact_not_published")
                } else {
                    Response {
                        artifact_metadata: Some(entry.metadata.clone()),
                        ..response()
                    }
                }
            }
            Request::Lease { operation } => {
                let mut state = state.lock().unwrap();
                let mut leases = leases.lock().unwrap();
                let response = lease(
                    operation,
                    &peer_id,
                    &agent_peers,
                    &mut state.device_peers,
                    &mut leases,
                    transport,
                );
                if leases.persist().is_err() || persist_state(state_path, &state).is_err() {
                    error_response("persistence_failed")
                } else {
                    response
                }
            }
        };
        let _ = serde_json::to_writer(&mut stream, &response);
        if stream.write_all(b"\n").is_err() || stream.flush().is_err() {
            return;
        }
    }
}

fn read_only_during_recovery(request: &Request) -> bool {
    matches!(
        request,
        Request::List
            | Request::Events { .. }
            | Request::ArtifactRead { .. }
            | Request::ArtifactInfo { .. }
    )
}

fn lease(
    operation: LeaseRequest,
    peer_id: &str,
    agent_peers: &HashSet<String>,
    device_peers: &mut HashMap<String, String>,
    leases: &mut LeaseBook,
    transport: &SecureTransport,
) -> Response {
    leases.expire();
    let result = match operation {
        LeaseRequest::Acquire {
            device_id,
            lifetime_ms,
        } => {
            if leases.active.contains_key(&device_id) {
                return error_response("device_already_leased");
            }
            let id = leases.insert(
                device_id.clone(),
                peer_id.into(),
                Duration::from_millis(lifetime_ms),
            );
            (id, "acquired")
        }
        LeaseRequest::Queue {
            device_id,
            lifetime_ms,
        } => {
            if let Some(active) = leases.active.get(&device_id) {
                if active.client_id == peer_id {
                    (active.id.clone(), "acquired")
                } else {
                    if !leases.waiting.iter().any(|waiting| {
                        waiting.device_id == device_id && waiting.client_id == peer_id
                    }) {
                        leases.waiting.push(WaitingLease {
                            device_id,
                            client_id: peer_id.into(),
                            lifetime_ms,
                        });
                    }
                    return Response {
                        lease_status: Some("queued".into()),
                        ..response()
                    };
                }
            } else {
                let id = leases.insert(
                    device_id,
                    peer_id.into(),
                    Duration::from_millis(lifetime_ms),
                );
                (id, "acquired")
            }
        }
        LeaseRequest::Renew {
            lease_id,
            lifetime_ms,
        } => {
            let Some(lease) = leases
                .active
                .values_mut()
                .find(|lease| lease.id == lease_id && lease.client_id == peer_id)
            else {
                return error_response("lease_inactive");
            };
            lease.expires_at_ms = unix_time_ms().saturating_add(lifetime_ms);
            (lease.id.clone(), "renewed")
        }
        LeaseRequest::Release { lease_id } => {
            let Some(device) = leases
                .active
                .values()
                .find(|lease| lease.id == lease_id && lease.client_id == peer_id)
                .map(|lease| lease.device_id.clone())
            else {
                return error_response("lease_inactive");
            };
            leases.release_device(&device);
            return Response {
                lease_status: Some("released".into()),
                ..response()
            };
        }
        LeaseRequest::Revoke { lease_id } => {
            let Some(device) = leases
                .active
                .values()
                .find(|lease| lease.id == lease_id && lease.client_id == peer_id)
                .map(|lease| lease.device_id.clone())
            else {
                return error_response("lease_inactive");
            };
            leases.release_device(&device);
            return Response {
                lease_status: Some("revoked".into()),
                ..response()
            };
        }
        LeaseRequest::Validate { grant } => {
            if !agent_peers.contains(peer_id)
                || device_peers.get(&grant.device_id).map(String::as_str) != Some(peer_id)
            {
                return error_response("lease_validation_access_denied");
            }
            let active = leases.active.get(&grant.device_id).is_some_and(|lease| {
                lease.id == grant.lease_id && lease.client_id == grant.client_id
            });
            return if active {
                Response {
                    lease_status: Some("active".into()),
                    ..response()
                }
            } else {
                error_response("lease_inactive")
            };
        }
        LeaseRequest::Disconnect => {
            let devices: Vec<_> = leases
                .active
                .values()
                .filter(|lease| lease.client_id == peer_id)
                .map(|lease| lease.device_id.clone())
                .collect();
            leases
                .waiting
                .retain(|waiting| waiting.client_id != peer_id);
            for device in devices {
                leases.release_device(&device);
            }
            return Response {
                lease_status: Some("disconnected".into()),
                ..response()
            };
        }
        LeaseRequest::AgentDetach { device_id } => {
            if !agent_peers.contains(peer_id)
                || device_peers.get(&device_id).map(String::as_str) != Some(peer_id)
            {
                return error_response("agent_detach_access_denied");
            }
            leases.force_release_device(&device_id);
            device_peers.remove(&device_id);
            return Response {
                lease_status: Some("detached".into()),
                ..response()
            };
        }
    };
    let lease = leases
        .active
        .values()
        .find(|lease| lease.id == result.0)
        .unwrap();
    let mut grant = LeaseGrant {
        lease_id: lease.id.clone(),
        device_id: lease.device_id.clone(),
        client_id: lease.client_id.clone(),
        job_id: String::new(),
        expires_at_ms: lease.expires_at_ms.saturating_sub(unix_time_ms()),
        signature: Vec::new(),
    };
    grant.signature = transport.sign(&grant.signed_payload()).unwrap();
    Response {
        lease_grant: Some(grant),
        lease_status: Some(result.1.into()),
        ..response()
    }
}

fn run(operation: RunRequest, shared: &Mutex<DurableState>, state_path: &Path) -> Response {
    let mut state = shared.lock().unwrap();
    if let Some(job_id) = state.requests.get(&operation.request_id).cloned() {
        return job_response(&state, job_id);
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
    state
        .requests
        .insert(operation.request_id.clone(), job_id.clone());
    state.pending.insert(job_id.clone(), operation);
    persist_state(state_path, &state).unwrap();
    drop(state);
    // Keep the legacy synchronous manifest RPC tolerant of a busy development
    // host. New Apple jobs are accepted asynchronously and do not use this wait.
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if let Some(response) = {
            let state = shared.lock().unwrap();
            state
                .jobs
                .contains_key(&job_id)
                .then(|| job_response(&state, job_id.clone()))
        } {
            return response;
        }
        thread::sleep(Duration::from_millis(10));
    }
    Response {
        accepted: false,
        job_id: Some(job_id),
        error: Some("agent_timeout".into()),
        ..response()
    }
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
        operation: None,
        apple_operation: None,
        cancel_jobs: vec![],
        artifact_metadata: None,
        artifact_chunk: None,
        confirmed_offset: None,
        lease_grant: None,
        lease_status: None,
    }
}

fn error_response(error: &str) -> Response {
    Response {
        accepted: false,
        error: Some(error.into()),
        ..response()
    }
}

struct ArtifactWrite<'a> {
    total_size: u64,
    sha256: &'a str,
    chunk_sha256: &'a str,
    bytes: &'a [u8],
}

fn write_artifact(
    store: &mut NetworkArtifacts,
    peer_id: &str,
    artifact_id: &str,
    offset: u64,
    write: ArtifactWrite<'_>,
) -> Response {
    let Some(entry) = store.entries.get(artifact_id) else {
        return error_response("unknown_artifact");
    };
    if !entry.participants.contains(peer_id) {
        return error_response("artifact_access_denied");
    }
    if write.total_size != entry.metadata.total_size || write.sha256 != entry.metadata.sha256 {
        return error_response("artifact_metadata_mismatch");
    }
    if write.bytes.is_empty()
        || write.bytes.len() as u64 > MAX_ARTIFACT_CHUNK
        || offset.saturating_add(write.bytes.len() as u64) > write.total_size
    {
        return error_response("invalid_chunk_length");
    }
    if format!("{:x}", Sha256::digest(write.bytes)) != write.chunk_sha256 {
        return error_response("chunk_hash_mismatch");
    }
    let path = store.path(artifact_id);
    if offset < entry.confirmed_offset {
        if offset + write.bytes.len() as u64 > entry.confirmed_offset {
            return error_response("invalid_offset");
        }
        let mut existing = vec![0; write.bytes.len()];
        let read_matches = OpenOptions::new()
            .read(true)
            .open(path)
            .and_then(|mut file| {
                file.seek(SeekFrom::Start(offset))?;
                file.read_exact(&mut existing)
            })
            .is_ok()
            && existing == write.bytes;
        return if read_matches {
            Response {
                confirmed_offset: Some(entry.confirmed_offset),
                ..response()
            }
        } else {
            error_response("chunk_conflict")
        };
    }
    if offset != entry.confirmed_offset {
        return error_response("invalid_offset");
    }
    let mut file = match OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&path)
    {
        Ok(file) => file,
        Err(_) => return error_response("artifact_io"),
    };
    if file.seek(SeekFrom::Start(offset)).is_err()
        || file.write_all(write.bytes).is_err()
        || file.set_len(offset + write.bytes.len() as u64).is_err()
        || file.sync_all().is_err()
    {
        return error_response("artifact_io");
    }
    let next_offset = entry.confirmed_offset + write.bytes.len() as u64;
    if next_offset == entry.metadata.total_size {
        let Ok(aggregate_hash) = hash_file(&path) else {
            return error_response("artifact_io");
        };
        if aggregate_hash != entry.metadata.sha256 {
            if OpenOptions::new()
                .write(true)
                .open(&path)
                .and_then(|file| file.set_len(entry.confirmed_offset))
                .is_err()
            {
                return error_response("artifact_io");
            }
            return error_response("artifact_hash_mismatch");
        }
    }
    let entry = store.entries.get_mut(artifact_id).unwrap();
    entry.confirmed_offset = next_offset;
    if next_offset == entry.metadata.total_size {
        entry.published = true;
    }
    let confirmed_offset = entry.confirmed_offset;
    if store.persist().is_err() {
        error_response("persistence_failed")
    } else {
        Response {
            confirmed_offset: Some(confirmed_offset),
            ..response()
        }
    }
}

fn hash_file(path: &Path) -> std::io::Result<String> {
    let mut file = OpenOptions::new().read(true).open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; MAX_ARTIFACT_CHUNK as usize];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn read_artifact(
    store: &NetworkArtifacts,
    peer_id: &str,
    artifact_id: &str,
    offset: u64,
    length: u64,
    total_size: u64,
    sha256: &str,
) -> Response {
    let Some(entry) = store.entries.get(artifact_id) else {
        return error_response("unknown_artifact");
    };
    if !entry.participants.contains(peer_id) {
        return error_response("artifact_access_denied");
    }
    if !entry.published {
        return error_response("artifact_not_published");
    }
    if total_size != entry.metadata.total_size || sha256 != entry.metadata.sha256 {
        return error_response("artifact_metadata_mismatch");
    }
    if length == 0 || length > MAX_ARTIFACT_CHUNK || offset >= total_size {
        return error_response("invalid_offset");
    }
    let read_length = length.min(total_size - offset) as usize;
    let mut bytes = vec![0; read_length];
    let result = OpenOptions::new()
        .read(true)
        .open(store.path(artifact_id))
        .and_then(|mut file| {
            file.seek(SeekFrom::Start(offset))?;
            file.read_exact(&mut bytes)
        });
    if result.is_err() {
        return error_response("artifact_io");
    }
    Response {
        artifact_chunk: Some(ArtifactChunk {
            offset,
            total_size,
            sha256: sha256.into(),
            bytes,
        }),
        ..response()
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

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn atomic_write_json(path: &Path, value: &impl serde::Serialize) -> std::io::Result<()> {
    let payload = serde_json::to_value(value)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    let payload_bytes = serde_json::to_vec(&payload)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    let generation = persisted_generation(path)?.saturating_add(1);
    let envelope = PersistedJson {
        schema_version: 1,
        generation,
        sha256: format!("{:x}", Sha256::digest(&payload_bytes)),
        payload,
    };
    let bytes = serde_json::to_vec(&envelope)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    atomic_write(path, &bytes)
}

fn persisted_generation(path: &Path) -> std::io::Result<u64> {
    match fs::read(path) {
        Ok(bytes) => return serialized_generation(&bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let mut latest = 0;
    for (candidate, may_be_partial) in [
        (sidecar_path(path, ".next"), true),
        (sidecar_path(path, ".retired"), false),
        (sidecar_path(path, ".previous"), false),
    ] {
        match fs::read(candidate) {
            Ok(bytes) => match serialized_generation(&bytes) {
                Ok(generation) => latest = latest.max(generation),
                Err(_) if may_be_partial => {}
                Err(error) => return Err(error),
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(latest)
}

fn serialized_generation(bytes: &[u8]) -> std::io::Result<u64> {
    match serde_json::from_slice::<PersistedJson>(bytes) {
        Ok(envelope) => {
            validate_envelope(&envelope)?;
            Ok(envelope.generation)
        }
        Err(_) if serde_json::from_slice::<serde_json::Value>(bytes).is_ok() => Ok(0),
        Err(error) => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, error)),
    }
}

fn validate_envelope(envelope: &PersistedJson) -> std::io::Result<()> {
    if envelope.schema_version != 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unsupported persistence schema",
        ));
    }
    let payload = serde_json::to_vec(&envelope.payload)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    if format!("{:x}", Sha256::digest(payload)) != envelope.sha256 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "persistence checksum mismatch",
        ));
    }
    Ok(())
}

fn atomic_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let staged = sidecar_path(path, ".next");
    let previous = sidecar_path(path, ".previous");
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&staged)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);

    let retired = sidecar_path(path, ".retired");
    match fs::remove_file(&retired) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    match durable_rename(path, &retired) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    durable_rename(&staged, path)?;
    sync_parent(path)?;
    if retired.exists() {
        match fs::remove_file(&previous) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        durable_rename(&retired, &previous)?;
        sync_parent(path)?;
    }
    Ok(())
}

#[cfg(unix)]
fn sync_parent(path: &Path) -> std::io::Result<()> {
    std::fs::File::open(path.parent().unwrap_or_else(|| Path::new(".")))?.sync_all()
}

#[cfg(not(windows))]
fn durable_rename(from: &Path, to: &Path) -> std::io::Result<()> {
    fs::rename(from, to)
}

#[cfg(windows)]
fn durable_rename(from: &Path, to: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;

    unsafe extern "system" {
        fn MoveFileExW(
            existing_file_name: *const u16,
            new_file_name: *const u16,
            flags: u32,
        ) -> i32;
    }
    let from: Vec<_> = from.as_os_str().encode_wide().chain(Some(0)).collect();
    let to: Vec<_> = to.as_os_str().encode_wide().chain(Some(0)).collect();
    const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x8;
    let result = unsafe {
        MoveFileExW(
            from.as_ptr(),
            to.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(unix))]
fn sync_parent(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

fn parse_persisted<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> std::io::Result<T> {
    if let Ok(envelope) = serde_json::from_slice::<PersistedJson>(bytes) {
        validate_envelope(&envelope)?;
        serde_json::from_value(envelope.payload)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
    } else {
        serde_json::from_slice(bytes)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
    }
}

fn load_json_with_fallback<T: serde::de::DeserializeOwned>(
    path: &Path,
) -> std::io::Result<Option<T>> {
    match fs::read(path) {
        Ok(bytes) => return parse_persisted(&bytes).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let mut candidates = Vec::new();
    for (candidate, may_be_partial) in [
        (sidecar_path(path, ".next"), true),
        (sidecar_path(path, ".retired"), false),
        (sidecar_path(path, ".previous"), false),
    ] {
        match fs::read(candidate) {
            Ok(bytes) => match serialized_generation(&bytes) {
                Ok(generation) => candidates.push((generation, bytes)),
                Err(_) if may_be_partial => {}
                Err(error) => return Err(error),
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    candidates.sort_by_key(|(generation, _)| *generation);
    candidates
        .pop()
        .map(|(_, bytes)| parse_persisted(&bytes).map(Some))
        .unwrap_or(Ok(None))
}

fn persist_state(path: &Path, state: &DurableState) -> std::io::Result<()> {
    if state.recovery_error.is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "refusing to overwrite corrupt registry state",
        ));
    }
    atomic_write_json(path, state)
}

fn load_state(path: &Path) -> DurableState {
    match load_json_with_fallback(path) {
        Ok(Some(state)) => state,
        Ok(None) => DurableState::default(),
        Err(error) if error.kind() == std::io::ErrorKind::InvalidData => DurableState {
            recovery_error: Some("recovery_state_corrupt".into()),
            ..DurableState::default()
        },
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

fn values(args: &[String], name: &str) -> Vec<String> {
    args.windows(2)
        .filter(|pair| pair[0] == name)
        .map(|pair| pair[1].clone())
        .collect()
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

#[cfg(test)]
mod tests {
    use super::*;

    fn lease_with_waiter_and_writer() -> LeaseBook {
        let mut leases = LeaseBook::default();
        leases.insert("sim-1".into(), "client-a".into(), Duration::from_secs(30));
        leases.waiting.push(WaitingLease {
            device_id: "sim-1".into(),
            client_id: "client-b".into(),
            lifetime_ms: Duration::from_secs(30).as_millis() as u64,
        });
        leases.writers.insert(
            "sim-1".into(),
            DeviceWriter {
                job_id: "job-1".into(),
            },
        );
        leases
    }

    #[test]
    fn active_writer_reservation_does_not_expire_before_terminal_progress() {
        let mut leases = LeaseBook::default();
        leases.writers.insert(
            "sim-1".into(),
            DeviceWriter {
                job_id: "job-1".into(),
            },
        );
        thread::sleep(Duration::from_millis(5));

        leases.expire();

        assert!(
            leases.writers.contains_key("sim-1"),
            "wall-clock expiry opened a second writer before terminal progress"
        );
    }

    #[test]
    fn inventory_detach_defers_lease_promotion_until_terminal_progress() {
        let mut leases = lease_with_waiter_and_writer();

        leases.detach_inventory("sim-1");

        assert_eq!(leases.active["sim-1"].client_id, "client-a");
        assert_eq!(leases.waiting[0].client_id, "client-b");
        assert!(leases.writers.contains_key("sim-1"));
    }

    #[test]
    fn explicit_agent_detach_clears_a_stale_writer_and_promotes_the_waiter() {
        let root = tempfile::tempdir().unwrap();
        let transport = SecureTransport::load_or_create(root.path(), "registry").unwrap();
        let mut leases = lease_with_waiter_and_writer();
        let agents = HashSet::from(["agent".into()]);
        let mut devices = HashMap::from([("sim-1".into(), "agent".into())]);

        let response = lease(
            LeaseRequest::AgentDetach {
                device_id: "sim-1".into(),
            },
            "agent",
            &agents,
            &mut devices,
            &mut leases,
            &transport,
        );

        assert_eq!(response.lease_status.as_deref(), Some("detached"));
        assert!(!leases.writers.contains_key("sim-1"));
        assert_eq!(leases.active["sim-1"].client_id, "client-b");
    }

    #[test]
    fn durable_state_fails_closed_instead_of_rolling_back_a_corrupt_current_snapshot() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("state.json");
        let mut first = DurableState::default();
        first.requests.insert("request-1".into(), "job-1".into());
        persist_state(&path, &first).unwrap();

        let mut second = DurableState::default();
        second.requests.insert("request-2".into(), "job-2".into());
        persist_state(&path, &second).unwrap();
        fs::write(&path, b"incomplete").unwrap();

        let recovered = load_state(&path);
        assert_eq!(
            recovered.recovery_error.as_deref(),
            Some("recovery_state_corrupt")
        );
        assert!(persist_state(&path, &recovered).is_err());
    }

    #[test]
    fn durable_state_recovers_the_newest_snapshot_from_an_interrupted_rename() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("state.json");
        let mut state = DurableState::default();
        state.requests.insert("request-1".into(), "job-1".into());
        persist_state(&path, &state).unwrap();
        let retired = sidecar_path(&path, ".retired");
        fs::rename(&path, &retired).unwrap();

        let recovered = load_state(&path);

        assert_eq!(recovered.requests.get("request-1"), Some(&"job-1".into()));
        assert!(recovered.recovery_error.is_none());
    }

    #[test]
    fn durable_state_uses_a_synced_next_generation_after_a_second_rename_crash() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("state.json");
        let mut first = DurableState::default();
        first.requests.insert("request-1".into(), "job-1".into());
        persist_state(&path, &first).unwrap();
        let mut second = DurableState::default();
        second.requests.insert("request-2".into(), "job-2".into());
        persist_state(&path, &second).unwrap();
        let retired = sidecar_path(&path, ".retired");
        fs::rename(&path, &retired).unwrap();

        let mut third = DurableState::default();
        third.requests.insert("request-3".into(), "job-3".into());
        let payload = serde_json::to_value(&third).unwrap();
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let next = PersistedJson {
            schema_version: 1,
            generation: 3,
            sha256: format!("{:x}", Sha256::digest(payload_bytes)),
            payload,
        };
        fs::write(
            sidecar_path(&path, ".next"),
            serde_json::to_vec(&next).unwrap(),
        )
        .unwrap();
        fs::remove_file(retired).unwrap();

        let recovered = load_state(&path);

        assert_eq!(recovered.requests.get("request-3"), Some(&"job-3".into()));
        assert!(!recovered.requests.contains_key("request-1"));
    }

    #[test]
    fn dispatch_and_cancel_fences_survive_serialization() {
        let state = DurableState {
            dispatched: HashSet::from(["apple-1".into()]),
            acknowledged: HashSet::from(["apple-1".into()]),
            cancelled: HashSet::from(["apple-1".into()]),
            ..DurableState::default()
        };

        let recovered: DurableState =
            serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();

        assert!(recovered.dispatched.contains("apple-1"));
        assert!(recovered.acknowledged.contains("apple-1"));
        assert!(recovered.cancelled.contains("apple-1"));
    }

    #[test]
    fn lease_writer_fences_survive_registry_storage_reload() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("leases.json");
        let mut leases = LeaseBook::load(path.clone());
        leases.insert("sim-1".into(), "client-a".into(), Duration::from_secs(30));
        leases.waiting.push(WaitingLease {
            device_id: "sim-1".into(),
            client_id: "client-b".into(),
            lifetime_ms: 30_000,
        });
        leases.writers.insert(
            "sim-1".into(),
            DeviceWriter {
                job_id: "apple-1".into(),
            },
        );
        leases.pending_release.insert("sim-1".into());
        leases.persist().unwrap();

        let recovered = LeaseBook::load(path);

        assert_eq!(recovered.active["sim-1"].client_id, "client-a");
        assert_eq!(recovered.waiting[0].client_id, "client-b");
        assert_eq!(recovered.writers["sim-1"].job_id, "apple-1");
        assert!(recovered.pending_release.contains("sim-1"));
    }

    #[test]
    fn restart_reconciliation_rolls_back_a_writer_that_was_never_dispatched() {
        let mut state = DurableState::default();
        state.apple_pending.insert(
            "apple-1".into(),
            AppleRequest {
                version: device_development_mesh::remote_apple_protocol::RemoteProtocolVersion {
                    major: 1,
                    minor: 0,
                },
                request_id: "request-1".into(),
                idempotency_key: "key-1".into(),
                capability: "apple.simulator@1".into(),
                workspace_path: "workspace".into(),
                device_id: Some("sim-1".into()),
                lease_id: Some("lease-1".into()),
                operation:
                    device_development_mesh::remote_apple_protocol::AppleOperation::LaunchApp {
                        bundle_id: "dev.mesh.App".into(),
                    },
            },
        );
        let mut leases = LeaseBook::default();
        leases.writers.insert(
            "sim-1".into(),
            DeviceWriter {
                job_id: "apple-1".into(),
            },
        );

        assert!(reconcile_runtime_state(&mut state, &mut leases));
        assert!(!leases.writers.contains_key("sim-1"));
    }

    #[test]
    fn restart_reconciliation_releases_a_writer_after_terminal_state_won() {
        let mut state = DurableState::default();
        state.dispatched.insert("apple-1".into());
        let mut leases = LeaseBook::default();
        leases.writers.insert(
            "sim-1".into(),
            DeviceWriter {
                job_id: "apple-1".into(),
            },
        );

        assert!(reconcile_runtime_state(&mut state, &mut leases));
        assert!(!leases.writers.contains_key("sim-1"));
    }

    #[test]
    fn delayed_started_ack_revalidates_the_lease_and_restores_the_writer_fence() {
        let mut leases = LeaseBook::default();
        let lease_id = leases.insert("sim-1".into(), "client-a".into(), Duration::from_secs(30));
        let mut state = DurableState::default();
        state
            .job_clients
            .insert("apple-1".into(), "client-a".into());
        state.apple_pending.insert(
            "apple-1".into(),
            AppleRequest {
                version: device_development_mesh::remote_apple_protocol::RemoteProtocolVersion {
                    major: 1,
                    minor: 0,
                },
                request_id: "request-1".into(),
                idempotency_key: "key-1".into(),
                capability: "apple.simulator@1".into(),
                workspace_path: "workspace".into(),
                device_id: Some("sim-1".into()),
                lease_id: Some(lease_id),
                operation:
                    device_development_mesh::remote_apple_protocol::AppleOperation::LaunchApp {
                        bundle_id: "dev.mesh.App".into(),
                    },
            },
        );

        assert_eq!(
            restore_acknowledged_writer(&state, &mut leases, "apple-1"),
            Ok(true)
        );
        assert_eq!(leases.writers["sim-1"].job_id, "apple-1");
    }

    #[test]
    fn recovery_mode_classifies_every_mutating_request_as_fail_closed() {
        assert!(read_only_during_recovery(&Request::List));
        assert!(read_only_during_recovery(&Request::Events {
            job_id: "job-1".into(),
            after: 0,
        }));
        assert!(read_only_during_recovery(&Request::ArtifactInfo {
            artifact_id: "artifact-1".into(),
        }));
        assert!(!read_only_during_recovery(&Request::Heartbeat {
            host: HostSnapshot {
                id: "mac-1".into(),
                operating_system: "macos".into(),
                architecture: "arm64".into(),
                status: "online".into(),
                capabilities: Vec::new(),
                devices: Vec::new(),
            },
        }));
        assert!(!read_only_during_recovery(&Request::AppleCancel {
            job_id: "job-1".into(),
        }));
        assert!(!read_only_during_recovery(&Request::Lease {
            operation: LeaseRequest::Disconnect,
        }));
    }
}
