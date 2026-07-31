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
    pending: HashMap<String, RunRequest>,
    apple_pending: HashMap<String, AppleRequest>,
    apple_requests: HashMap<String, String>,
    apple_operations: HashMap<String, AppleRequest>,
    apple_hosts: HashMap<String, String>,
    #[serde(default)]
    job_clients: HashMap<String, String>,
    #[serde(default)]
    job_agents: HashMap<String, String>,
    #[serde(skip)]
    host_peers: HashMap<String, String>,
    #[serde(skip)]
    device_peers: HashMap<String, String>,
    #[serde(skip)]
    dispatched: HashSet<String>,
    #[serde(skip)]
    cancelled: HashSet<String>,
    #[serde(skip)]
    recovery_error: Option<String>,
}

const MAX_ARTIFACT_CHUNK: u64 = 64 * 1024;

struct NetworkArtifact {
    metadata: NetworkArtifactMetadata,
    participants: HashSet<String>,
    confirmed_offset: u64,
    published: bool,
}

struct NetworkArtifacts {
    root: PathBuf,
    entries: HashMap<String, NetworkArtifact>,
}

struct DeviceLease {
    id: String,
    device_id: String,
    client_id: String,
    expires: Instant,
}

struct WaitingLease {
    device_id: String,
    client_id: String,
    lifetime: Duration,
}

struct DeviceWriter {
    job_id: String,
}

#[derive(Default)]
struct LeaseBook {
    next_id: u64,
    active: HashMap<String, DeviceLease>,
    waiting: Vec<WaitingLease>,
    writers: HashMap<String, DeviceWriter>,
    pending_release: HashSet<String>,
    pending_detach: HashSet<String>,
}

impl LeaseBook {
    fn expire(&mut self) {
        let expired: Vec<_> = self
            .active
            .iter()
            .filter(|(_, lease)| Instant::now() >= lease.expires)
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
            self.insert(waiting.device_id, waiting.client_id, waiting.lifetime);
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
                expires: Instant::now() + lifetime,
            },
        );
        id
    }
}

impl NetworkArtifacts {
    fn new(root: PathBuf) -> Self {
        fs::create_dir_all(&root).unwrap();
        Self {
            root,
            entries: HashMap::new(),
        }
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
    let state = Arc::new(Mutex::new(load_state(&state_path)));
    let artifacts = Arc::new(Mutex::new(NetworkArtifacts::new(
        identity.join("artifacts"),
    )));
    let leases = Arc::new(Mutex::new(LeaseBook::default()));
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
    let mut line = String::new();
    if BufReader::new(&mut stream)
        .take(512 * 1024)
        .read_line(&mut line)
        .is_err()
    {
        return;
    }
    let Ok(request) = serde_json::from_str(&line) else {
        return;
    };
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
                    return write_response(&mut stream, error_response("agent_identity_mismatch"));
                }
                let detached: Vec<_> = state
                    .device_peers
                    .iter()
                    .filter(|(device, owner)| *owner == &peer_id && !connected.contains(*device))
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
            }
            leases.lock().unwrap().expire();
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
                        && !state.dispatched.contains(*job_id)
                        && state.apple_pending.get(*job_id).is_none_or(|operation| {
                            !operation.operation.mutates_device()
                                || operation.device_id.as_ref().is_none_or(|device_id| {
                                    !leases.lock().unwrap().writers.contains_key(device_id)
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
                            expires_at_ms: lease
                                .expires
                                .saturating_duration_since(Instant::now())
                                .as_millis() as u64,
                            signature: Vec::new(),
                        };
                        grant.signature = transport.sign(&grant.signed_payload()).unwrap();
                        leases.writers.insert(
                            device_id.clone(),
                            DeviceWriter {
                                job_id: response.job_id.clone().unwrap(),
                            },
                        );
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
                fs::write(state_path, serde_json::to_vec(&*state).unwrap()).unwrap();
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
                        operation.lease_id.as_ref() == Some(&lease.id) && lease.client_id == peer_id
                    })
                });
                if !active {
                    return write_response(&mut stream, error_response("lease_inactive"));
                }
            }
            let mut state = state.lock().unwrap();
            let job_id = if let Some(job_id) = state.apple_requests.get(&operation.idempotency_key)
            {
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
                fs::write(state_path, serde_json::to_vec(&*state).unwrap()).unwrap();
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
                return write_response(&mut stream, error_response("apple_progress_access_denied"));
            }
            let existing = state.jobs.entry(job_id.clone()).or_default();
            for event in events {
                if !existing
                    .iter()
                    .any(|current| current.sequence == event.sequence)
                {
                    existing.push(event);
                }
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
            fs::write(state_path, serde_json::to_vec(&*state).unwrap()).unwrap();
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
                fs::write(state_path, serde_json::to_vec(&*state).unwrap()).unwrap();
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
                artifacts
                    .lock()
                    .unwrap()
                    .entries
                    .entry(id)
                    .or_insert_with(|| NetworkArtifact {
                        metadata: metadata.clone(),
                        participants,
                        confirmed_offset: 0,
                        published: false,
                    });
                Response {
                    artifact_metadata: Some(metadata),
                    ..response()
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
            lease(
                operation,
                &peer_id,
                &agent_peers,
                &mut state.device_peers,
                &mut leases.lock().unwrap(),
                transport,
            )
        }
    };
    let _ = serde_json::to_writer(&mut stream, &response);
    let _ = stream.write_all(b"\n");
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
                            lifetime: Duration::from_millis(lifetime_ms),
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
            lease.expires = Instant::now() + Duration::from_millis(lifetime_ms);
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
        expires_at_ms: lease
            .expires
            .saturating_duration_since(Instant::now())
            .as_millis() as u64,
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
    fs::write(state_path, serde_json::to_vec(&*state).unwrap()).unwrap();
    drop(state);
    // Keep the legacy synchronous manifest RPC tolerant of a busy development
    // host. New Apple jobs are accepted asynchronously and do not use this wait.
    for _ in 0..1500 {
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
    let mut file = match OpenOptions::new().create(true).append(true).open(&path) {
        Ok(file) => file,
        Err(_) => return error_response("artifact_io"),
    };
    if file.write_all(write.bytes).is_err() {
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
    Response {
        confirmed_offset: Some(entry.confirmed_offset),
        ..response()
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
            lifetime: Duration::from_secs(30),
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
}
