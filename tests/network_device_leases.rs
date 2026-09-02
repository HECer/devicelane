use device_development_mesh::{
    network_processes::{
        DeviceSnapshot, HostSnapshot, LeaseGrant, LeaseRequest, NetworkEvent, Request,
    },
    remote_apple_protocol::{AppleOperation, AppleRequest, RemoteProtocolVersion},
    secure_transport::SecureTransport,
};
use std::{
    io::{BufRead, BufReader, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::{Mutex, MutexGuard},
    thread,
    time::{Duration, Instant},
};

const DEVICE: &str = "sim-1";
static NETWORK_TEST_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn lease_rpc_covers_acquire_renew_queue_release_revoke_and_one_writer() {
    let harness = Harness::start(Duration::ZERO);

    let first = lease(
        &harness.address,
        &harness.client_a,
        &LeaseRequest::Acquire {
            device_id: DEVICE.into(),
            lifetime_ms: 30_000,
        },
    );
    assert_eq!(first["lease_status"], "acquired");
    let first_id = grant_id(&first);
    assert_eq!(first["lease_grant"]["client_id"], "client-a");

    let conflicting = lease(
        &harness.address,
        &harness.client_b,
        &LeaseRequest::Acquire {
            device_id: DEVICE.into(),
            lifetime_ms: 30_000,
        },
    );
    assert_eq!(conflicting["error"], "device_already_leased");

    let renewed = lease(
        &harness.address,
        &harness.client_a,
        &LeaseRequest::Renew {
            lease_id: first_id.clone(),
            lifetime_ms: 30_000,
        },
    );
    assert_eq!(renewed["lease_status"], "renewed");
    assert_eq!(grant_id(&renewed), first_id);

    let queued = lease(
        &harness.address,
        &harness.client_b,
        &LeaseRequest::Queue {
            device_id: DEVICE.into(),
            lifetime_ms: 30_000,
        },
    );
    assert_eq!(queued["lease_status"], "queued");
    assert!(queued["lease_grant"].is_null());

    let released = lease(
        &harness.address,
        &harness.client_a,
        &LeaseRequest::Release { lease_id: first_id },
    );
    assert_eq!(released["lease_status"], "released");

    let promoted_b = lease(
        &harness.address,
        &harness.client_b,
        &LeaseRequest::Queue {
            device_id: DEVICE.into(),
            lifetime_ms: 30_000,
        },
    );
    assert_eq!(promoted_b["lease_status"], "acquired");
    assert_eq!(promoted_b["lease_grant"]["client_id"], "client-b");
    let second_id = grant_id(&promoted_b);

    let queued_a = lease(
        &harness.address,
        &harness.client_a,
        &LeaseRequest::Queue {
            device_id: DEVICE.into(),
            lifetime_ms: 30_000,
        },
    );
    assert_eq!(queued_a["lease_status"], "queued");

    let revoked = lease(
        &harness.address,
        &harness.client_b,
        &LeaseRequest::Revoke {
            lease_id: second_id,
        },
    );
    assert_eq!(revoked["lease_status"], "revoked");

    let promoted_a = lease(
        &harness.address,
        &harness.client_a,
        &LeaseRequest::Queue {
            device_id: DEVICE.into(),
            lifetime_ms: 30_000,
        },
    );
    assert_eq!(promoted_a["lease_status"], "acquired");
    assert_eq!(promoted_a["lease_grant"]["client_id"], "client-a");
}

#[test]
fn disconnect_and_expiry_promote_the_next_paired_client_in_order() {
    let harness = Harness::start(Duration::ZERO);
    let first = acquire(&harness, &harness.client_a, 30_000);

    assert_eq!(
        lease(
            &harness.address,
            &harness.client_b,
            &LeaseRequest::Queue {
                device_id: DEVICE.into(),
                lifetime_ms: 30_000,
            },
        )["lease_status"],
        "queued"
    );
    assert_eq!(
        lease(
            &harness.address,
            &harness.client_a,
            &LeaseRequest::Disconnect,
        )["lease_status"],
        "disconnected"
    );

    let promoted_b = current_grant(&harness, &harness.client_b);
    assert_eq!(promoted_b["lease_grant"]["client_id"], "client-b");
    assert_ne!(grant_id(&promoted_b), grant_id(&first));
    let promoted_b_id = grant_id(&promoted_b);

    assert_eq!(
        lease(
            &harness.address,
            &harness.client_a,
            &LeaseRequest::Queue {
                device_id: DEVICE.into(),
                lifetime_ms: 30_000,
            },
        )["lease_status"],
        "queued"
    );
    assert_eq!(
        lease(
            &harness.address,
            &harness.client_b,
            &LeaseRequest::Renew {
                lease_id: promoted_b_id,
                lifetime_ms: 75,
            },
        )["lease_status"],
        "renewed"
    );

    thread::sleep(Duration::from_millis(125));
    let promoted_a = current_grant(&harness, &harness.client_a);
    assert_eq!(promoted_a["lease_grant"]["client_id"], "client-a");
}

#[test]
fn registry_restart_preserves_the_active_lease_and_fifo_waiters() {
    let mut harness = Harness::start(Duration::ZERO);
    let first = acquire(&harness, &harness.client_a, 30_000);
    let first_id = grant_id(&first);

    for identity in [&harness.client_b, &harness.client_c] {
        let queued = lease(
            &harness.address,
            identity,
            &LeaseRequest::Queue {
                device_id: DEVICE.into(),
                lifetime_ms: 30_000,
            },
        );
        assert_eq!(queued["lease_status"], "queued", "{queued}");
    }

    harness._registry.kill().unwrap();
    harness._registry.wait().unwrap();
    harness._registry = start_registry(&harness.address, &harness._root.path().join("registry"));
    wait_for_host(&harness.address, &harness.client_a);

    let forged = cli_json(
        &harness.address,
        &harness.client_c,
        "apple-run",
        &apple_request("forged-after-restart", &first_id),
    );
    assert_eq!(forged["accepted"], false, "{forged}");
    assert_eq!(forged["error"], "lease_inactive", "{forged}");

    let renewed = lease(
        &harness.address,
        &harness.client_a,
        &LeaseRequest::Renew {
            lease_id: first_id.clone(),
            lifetime_ms: 30_000,
        },
    );
    assert_eq!(renewed["lease_status"], "renewed", "{renewed}");
    assert_eq!(grant_id(&renewed), first_id);

    let released = lease(
        &harness.address,
        &harness.client_a,
        &LeaseRequest::Release {
            lease_id: first_id.clone(),
        },
    );
    assert_eq!(released["lease_status"], "released", "{released}");

    let still_queued_c = lease(
        &harness.address,
        &harness.client_c,
        &LeaseRequest::Queue {
            device_id: DEVICE.into(),
            lifetime_ms: 30_000,
        },
    );
    assert_eq!(still_queued_c["lease_status"], "queued", "{still_queued_c}");
    assert!(still_queued_c["lease_grant"].is_null(), "{still_queued_c}");

    let promoted_b = current_grant(&harness, &harness.client_b);
    assert_eq!(promoted_b["lease_grant"]["client_id"], "client-b");
    assert_ne!(grant_id(&promoted_b), first_id);

    let reused = cli_json(
        &harness.address,
        &harness.client_a,
        "apple-run",
        &apple_request("reused-after-release", &first_id),
    );
    assert_eq!(reused["accepted"], false, "{reused}");
    assert_eq!(reused["error"], "lease_inactive", "{reused}");
}

#[test]
fn paired_client_cannot_issue_agent_detach() {
    let harness = Harness::start(Duration::ZERO);
    let owned = acquire(&harness, &harness.client_a, 30_000);

    let unauthorized = lease(
        &harness.address,
        &harness.client_b,
        &LeaseRequest::AgentDetach {
            device_id: DEVICE.into(),
        },
    );
    assert_eq!(
        unauthorized["accepted"], false,
        "a paired client detached an agent-owned device: {unauthorized}"
    );

    let still_owned = lease(
        &harness.address,
        &harness.client_a,
        &LeaseRequest::Renew {
            lease_id: grant_id(&owned),
            lifetime_ms: 30_000,
        },
    );
    assert_eq!(still_owned["lease_status"], "renewed");
}

#[test]
fn authorized_agent_detach_promotes_the_waiting_client() {
    let harness = Harness::start(Duration::ZERO);
    acquire(&harness, &harness.client_a, 30_000);
    assert_eq!(
        lease(
            &harness.address,
            &harness.client_b,
            &LeaseRequest::Queue {
                device_id: DEVICE.into(),
                lifetime_ms: 30_000,
            },
        )["lease_status"],
        "queued"
    );

    let detached = lease(
        &harness.address,
        &harness.agent,
        &LeaseRequest::AgentDetach {
            device_id: DEVICE.into(),
        },
    );
    assert_eq!(detached["lease_status"], "detached");

    let promoted = current_grant(&harness, &harness.client_b);
    assert_eq!(promoted["lease_grant"]["client_id"], "client-b");
}

#[test]
fn agent_detach_recovers_a_writer_after_terminal_progress_is_lost() {
    let mut harness = Harness::start_gated();
    let owned = acquire(&harness, &harness.client_a, 30_000);
    assert_eq!(
        lease(
            &harness.address,
            &harness.client_b,
            &LeaseRequest::Queue {
                device_id: DEVICE.into(),
                lifetime_ms: 30_000,
            },
        )["lease_status"],
        "queued"
    );
    let job = cli_json(
        &harness.address,
        &harness.client_a,
        "apple-run",
        &apple_request("lost-terminal", &grant_id(&owned)),
    );
    let job_id = job["job_id"].as_str().unwrap().to_owned();
    wait_for_mutation(
        &mut harness,
        "mutation-start",
        "mutating tool start",
        true,
        Some(&job_id),
    );
    harness._registry.kill().unwrap();
    harness._registry.wait().unwrap();
    std::fs::write(
        harness.mutation_gate.as_ref().unwrap(),
        b"release mutation\n",
    )
    .unwrap();
    wait_for_mutation(
        &mut harness,
        "mutation-end",
        "tool completion while terminal delivery is unavailable",
        false,
        None,
    );
    harness._agent.kill().unwrap();
    harness._agent.wait().unwrap();
    harness._registry = start_registry(&harness.address, &harness._root.path().join("registry"));
    wait_for_listener(&harness.address);
    let snapshot = cli_json(
        &harness.address,
        &harness.client_a,
        "events",
        &serde_json::json!({"job_id": job_id, "after": 0}),
    );
    assert_eq!(snapshot["accepted"], true, "{snapshot}");
    assert_eq!(snapshot["job_id"], job_id, "{snapshot}");
    assert!(
        snapshot["events"].as_array().is_none_or(|events| {
            events.iter().all(|event| {
                !matches!(
                    event["kind"].as_str(),
                    Some("completed" | "rejected" | "cancelled")
                )
            })
        }),
        "agent delivered a terminal event before the detach recovery boundary: {snapshot}"
    );

    let detached_inventory = rpc(
        &harness.address,
        &harness.agent,
        &Request::Heartbeat {
            host: HostSnapshot {
                id: "mac-1".into(),
                operating_system: "macos".into(),
                architecture: "aarch64".into(),
                status: "online".into(),
                capabilities: vec!["apple.simulator@1".into()],
                devices: Vec::new(),
            },
        },
    );
    assert_eq!(detached_inventory["accepted"], true, "{detached_inventory}");
    let detached = lease(
        &harness.address,
        &harness.agent,
        &LeaseRequest::AgentDetach {
            device_id: DEVICE.into(),
        },
    );
    assert_eq!(detached["lease_status"], "detached", "{detached}");
    assert_eq!(
        current_grant(&harness, &harness.client_b)["lease_grant"]["client_id"],
        "client-b"
    );
}

#[test]
fn heartbeat_from_another_agent_cannot_detach_the_lease_owners_device() {
    let harness = Harness::start(Duration::ZERO);
    let owned = acquire(&harness, &harness.client_a, 30_000);

    let heartbeat = rpc(
        &harness.address,
        &harness.agent_b,
        &Request::Heartbeat {
            host: HostSnapshot {
                id: "mac-2".into(),
                operating_system: "macos".into(),
                architecture: "aarch64".into(),
                status: "online".into(),
                capabilities: vec!["apple.simulator@1".into()],
                devices: vec![DeviceSnapshot {
                    id: "sim-2".into(),
                    platform: "ios".into(),
                    state: "connected".into(),
                }],
            },
        },
    );
    assert_eq!(heartbeat["accepted"], true, "{heartbeat}");

    let still_owned = lease(
        &harness.address,
        &harness.client_a,
        &LeaseRequest::Renew {
            lease_id: grant_id(&owned),
            lifetime_ms: 30_000,
        },
    );
    assert_eq!(
        still_owned["lease_status"], "renewed",
        "another agent's inventory detached this device: {still_owned}"
    );
}

#[test]
fn registry_restart_preserves_the_authenticated_host_and_device_owner() {
    let mut harness = Harness::start(Duration::ZERO);
    harness._agent.kill().unwrap();
    harness._agent.wait().unwrap();
    harness._registry.kill().unwrap();
    harness._registry.wait().unwrap();
    harness._registry = start_registry(&harness.address, &harness._root.path().join("registry"));
    wait_for_listener(&harness.address);

    let takeover = rpc(
        &harness.address,
        &harness.agent_b,
        &Request::Heartbeat {
            host: HostSnapshot {
                id: "mac-1".into(),
                operating_system: "macos".into(),
                architecture: "aarch64".into(),
                status: "online".into(),
                capabilities: vec!["apple.simulator@1".into()],
                devices: vec![DeviceSnapshot {
                    id: DEVICE.into(),
                    platform: "ios-simulator".into(),
                    state: "connected".into(),
                }],
            },
        },
    );

    assert_eq!(
        takeover["accepted"], false,
        "a second trusted agent took over persisted host/device IDs: {takeover}"
    );
    assert_eq!(takeover["error"], "agent_identity_mismatch", "{takeover}");
}

#[test]
fn detached_device_without_a_writer_can_migrate_to_another_agent() {
    let mut harness = Harness::start(Duration::ZERO);
    harness._agent.kill().unwrap();
    harness._agent.wait().unwrap();
    let detached = rpc(
        &harness.address,
        &harness.agent,
        &Request::Heartbeat {
            host: HostSnapshot {
                id: "mac-1".into(),
                operating_system: "macos".into(),
                architecture: "aarch64".into(),
                status: "online".into(),
                capabilities: vec!["apple.simulator@1".into()],
                devices: Vec::new(),
            },
        },
    );
    assert_eq!(detached["accepted"], true, "{detached}");

    let migrated = rpc(
        &harness.address,
        &harness.agent_b,
        &Request::Heartbeat {
            host: HostSnapshot {
                id: "mac-2".into(),
                operating_system: "macos".into(),
                architecture: "aarch64".into(),
                status: "online".into(),
                capabilities: vec!["apple.simulator@1".into()],
                devices: vec![DeviceSnapshot {
                    id: DEVICE.into(),
                    platform: "ios".into(),
                    state: "connected".into(),
                }],
            },
        },
    );
    assert_eq!(
        migrated["accepted"], true,
        "detached device remained bound to the old agent: {migrated}"
    );
}

#[test]
fn reconnected_device_keeps_its_agent_owner_after_writer_terminal() {
    let mut harness = Harness::start_with_heartbeat(Duration::from_millis(2_000), 4_000);
    let owned = acquire(&harness, &harness.client_a, 30_000);
    let job = cli_json(
        &harness.address,
        &harness.client_a,
        "apple-run",
        &apple_request("transient-detach", &grant_id(&owned)),
    );
    wait_for_mutation(
        &mut harness,
        "mutation-start",
        "mutating tool start",
        true,
        job["job_id"].as_str(),
    );
    for devices in [
        Vec::new(),
        vec![DeviceSnapshot {
            id: DEVICE.into(),
            platform: "ios".into(),
            state: "connected".into(),
        }],
    ] {
        assert_eq!(
            rpc(
                &harness.address,
                &harness.agent,
                &Request::Heartbeat {
                    host: HostSnapshot {
                        id: "mac-1".into(),
                        operating_system: "macos".into(),
                        architecture: "aarch64".into(),
                        status: "online".into(),
                        capabilities: vec!["apple.simulator@1".into()],
                        devices,
                    },
                },
            )["accepted"],
            true
        );
    }
    wait_for_terminal(
        &harness.address,
        &harness.client_a,
        job["job_id"].as_str().unwrap(),
    );
    harness._agent.kill().unwrap();
    harness._agent.wait().unwrap();

    let takeover = rpc(
        &harness.address,
        &harness.agent_b,
        &Request::Heartbeat {
            host: HostSnapshot {
                id: "mac-2".into(),
                operating_system: "macos".into(),
                architecture: "aarch64".into(),
                status: "online".into(),
                capabilities: vec!["apple.simulator@1".into()],
                devices: vec![DeviceSnapshot {
                    id: DEVICE.into(),
                    platform: "ios".into(),
                    state: "connected".into(),
                }],
            },
        },
    );
    assert_eq!(
        takeover["accepted"], false,
        "reconnect lost the live device owner after terminal progress: {takeover}"
    );
}

#[test]
fn paired_client_cannot_publish_an_agent_heartbeat() {
    let harness = Harness::start(Duration::ZERO);

    let forged = rpc(
        &harness.address,
        &harness.client_b,
        &Request::Heartbeat {
            host: HostSnapshot {
                id: "forged-mac".into(),
                operating_system: "macos".into(),
                architecture: "aarch64".into(),
                status: "online".into(),
                capabilities: vec!["apple.simulator@1".into()],
                devices: vec![DeviceSnapshot {
                    id: "forged-device".into(),
                    platform: "ios".into(),
                    state: "connected".into(),
                }],
            },
        },
    );

    assert_eq!(forged["accepted"], false, "{forged}");
}

#[test]
fn forged_workspace_lease_and_grant_cannot_run_a_mutation_but_observer_reads_events() {
    let harness = Harness::start(Duration::ZERO);

    let forged = apple_request("forged", "forged-lease");
    let rejected = cli_json(&harness.address, &harness.client_a, "apple-run", &forged);
    assert_eq!(rejected["accepted"], false);
    assert_eq!(rejected["error"], "lease_inactive");
    assert_eq!(mutation_lines(&harness.marker), Vec::<String>::new());

    let owned = acquire(&harness, &harness.client_a, 30_000);
    let legitimate = cli_json(
        &harness.address,
        &harness.client_a,
        "apple-run",
        &apple_request("legitimate", &grant_id(&owned)),
    );
    let job_id = legitimate["job_id"].as_str().unwrap();
    let terminal = wait_for_terminal(&harness.address, &harness.client_b, job_id);
    assert_eq!(
        terminal["kind"], "completed",
        "observer could not read the legitimate job terminal event: {terminal}"
    );
    assert_eq!(
        mutation_lines(&harness.marker),
        ["mutation-start", "mutation-end"]
    );
}

#[test]
fn expired_writer_finishes_before_the_promoted_writer_starts() {
    let harness = Harness::start(Duration::from_millis(5_000));
    let first = acquire(&harness, &harness.client_a, 30_000);
    let first_id = grant_id(&first);
    let first_job = cli_json(
        &harness.address,
        &harness.client_a,
        "apple-run",
        &apple_request("slow-a", &first_id),
    )["job_id"]
        .as_str()
        .unwrap()
        .to_owned();
    wait_until("first mutating tool start", || {
        mutation_lines(&harness.marker)
            .iter()
            .filter(|line| *line == "mutation-start")
            .count()
            == 1
    });
    assert_eq!(
        lease(
            &harness.address,
            &harness.client_b,
            &LeaseRequest::Queue {
                device_id: DEVICE.into(),
                lifetime_ms: 30_000,
            },
        )["lease_status"],
        "queued"
    );

    let renewed = lease(
        &harness.address,
        &harness.client_a,
        &LeaseRequest::Renew {
            lease_id: first_id,
            lifetime_ms: 2_000,
        },
    );
    assert_eq!(renewed["lease_status"], "renewed", "{renewed}");

    thread::sleep(Duration::from_millis(2_050));
    let promoted = wait_for_current_grant(&harness, &harness.client_b);
    let second_job = cli_json(
        &harness.address,
        &harness.client_b,
        "apple-run",
        &apple_request("slow-b", &grant_id(&promoted)),
    )["job_id"]
        .as_str()
        .unwrap()
        .to_owned();
    wait_for_terminal(&harness.address, &harness.client_a, &first_job);
    wait_for_terminal(&harness.address, &harness.client_b, &second_job);

    assert_eq!(
        mutation_lines(&harness.marker),
        [
            "mutation-start",
            "mutation-end",
            "mutation-start",
            "mutation-end"
        ],
        "two mutating tools overlapped after lease expiry"
    );
}

#[test]
fn observer_cannot_cancel_or_publish_progress_for_another_clients_job() {
    let harness = Harness::start(Duration::from_millis(650));
    let owned = acquire(&harness, &harness.client_a, 30_000);
    let accepted = cli_json(
        &harness.address,
        &harness.client_a,
        "apple-run",
        &apple_request("owned-job", &grant_id(&owned)),
    );
    let job_id = accepted["job_id"].as_str().unwrap().to_owned();

    wait_until("owned mutating tool start", || {
        mutation_lines(&harness.marker).contains(&"mutation-start".into())
    });
    let cancelled = rpc(
        &harness.address,
        &harness.client_b,
        &Request::AppleCancel {
            job_id: job_id.clone(),
        },
    );
    assert_eq!(
        cancelled["accepted"], false,
        "observer cancelled another client's job: {cancelled}"
    );

    let forged_progress = rpc(
        &harness.address,
        &harness.client_b,
        &Request::AppleProgress {
            job_id,
            events: vec![NetworkEvent {
                sequence: 999,
                kind: "completed".into(),
                payload: "forged".into(),
            }],
            terminal: true,
        },
    );
    assert_eq!(
        forged_progress["accepted"], false,
        "observer published progress for another client's job: {forged_progress}"
    );
}

struct Harness {
    _root: tempfile::TempDir,
    address: String,
    client_a: PathBuf,
    client_b: PathBuf,
    client_c: PathBuf,
    agent: PathBuf,
    agent_b: PathBuf,
    marker: PathBuf,
    mutation_gate: Option<PathBuf>,
    _registry: ChildGuard,
    _agent: ChildGuard,
    _network_test_lock: MutexGuard<'static, ()>,
}

impl Harness {
    fn start(mutation_delay: Duration) -> Self {
        Self::start_with_options(mutation_delay, 50, false)
    }

    fn start_with_heartbeat(mutation_delay: Duration, heartbeat_ms: u64) -> Self {
        Self::start_with_options(mutation_delay, heartbeat_ms, false)
    }

    fn start_gated() -> Self {
        Self::start_with_options(Duration::ZERO, 50, true)
    }

    fn start_with_options(
        mutation_delay: Duration,
        heartbeat_ms: u64,
        gate_mutation: bool,
    ) -> Self {
        let network_test_lock = NETWORK_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let root = tempfile::tempdir().unwrap();
        let address = free_address();
        let registry = root.path().join("registry");
        let agent = root.path().join("agent");
        let agent_b = root.path().join("agent-b");
        let client_a = root.path().join("client-a");
        let client_b = root.path().join("client-b");
        let client_c = root.path().join("client-c");
        pair(&registry, "registry", &agent, "agent");
        pair(&registry, "registry", &agent_b, "agent-b");
        pair(&registry, "registry", &client_a, "client-a");
        pair(&registry, "registry", &client_b, "client-b");
        pair(&registry, "registry", &client_c, "client-c");

        let workspace_root = root.path().join("workspaces");
        let project = workspace_root.join("mac-1/project");
        std::fs::create_dir_all(project.join(".leases")).unwrap();
        let marker = root.path().join("apple-tools.log");
        let mutation_gate = root.path().join("mutation-release");
        let gate = gate_mutation.then_some(mutation_gate.as_path());
        let xcodebuild = fake_tool(root.path(), "xcodebuild", &marker, mutation_delay, gate);
        let devicectl = fake_tool(root.path(), "devicectl", &marker, mutation_delay, gate);
        let simctl = fake_tool(root.path(), "simctl", &marker, mutation_delay, gate);

        let client_transport = SecureTransport::load_or_create(&client_a, "client-a").unwrap();
        let mut forged_grant = LeaseGrant {
            lease_id: "forged-lease".into(),
            device_id: DEVICE.into(),
            client_id: "client-a".into(),
            job_id: "forged-job".into(),
            expires_at_ms: u64::MAX,
            signature: Vec::new(),
        };
        forged_grant.signature = client_transport
            .sign(&forged_grant.signed_payload())
            .unwrap();
        std::fs::write(
            project.join("lease-grant.json"),
            serde_json::to_vec(&forged_grant).unwrap(),
        )
        .unwrap();
        std::fs::write(
            project.join(".leases").join(DEVICE),
            b"forged-lease\nclient-a\n",
        )
        .unwrap();

        let registry_process = start_registry(&address, &registry);
        let agent_process = spawn(
            env!("CARGO_BIN_EXE_mesh-agent"),
            &[
                "--registry",
                &address,
                "--identity",
                agent.to_str().unwrap(),
                "--id",
                "mac-1",
                "--os",
                "macos",
                "--arch",
                "aarch64",
                "--workspace-root",
                workspace_root.to_str().unwrap(),
                "--xcodebuild",
                xcodebuild.to_str().unwrap(),
                "--devicectl",
                devicectl.to_str().unwrap(),
                "--simctl",
                simctl.to_str().unwrap(),
                "--heartbeat-ms",
                &heartbeat_ms.to_string(),
                "--capability",
                "apple.simulator@1",
                "--device",
                "sim-1:ios:connected",
            ],
        );
        wait_for_host(&address, &client_a);

        Self {
            _root: root,
            address,
            client_a,
            client_b,
            client_c,
            agent,
            agent_b,
            marker,
            mutation_gate: gate_mutation.then_some(mutation_gate),
            _registry: registry_process,
            _agent: agent_process,
            _network_test_lock: network_test_lock,
        }
    }
}

fn acquire(harness: &Harness, identity: &Path, lifetime_ms: u64) -> serde_json::Value {
    let response = lease(
        &harness.address,
        identity,
        &LeaseRequest::Acquire {
            device_id: DEVICE.into(),
            lifetime_ms,
        },
    );
    assert_eq!(response["lease_status"], "acquired", "{response}");
    response
}

fn current_grant(harness: &Harness, identity: &Path) -> serde_json::Value {
    let response = lease(
        &harness.address,
        identity,
        &LeaseRequest::Queue {
            device_id: DEVICE.into(),
            lifetime_ms: 30_000,
        },
    );
    assert_eq!(response["lease_status"], "acquired", "{response}");
    response
}

fn wait_for_current_grant(harness: &Harness, identity: &Path) -> serde_json::Value {
    let mut response = serde_json::Value::Null;
    wait_until("lease promotion", || {
        response = lease(
            &harness.address,
            identity,
            &LeaseRequest::Queue {
                device_id: DEVICE.into(),
                lifetime_ms: 30_000,
            },
        );
        response["lease_status"] == "acquired"
    });
    response
}

fn grant_id(response: &serde_json::Value) -> String {
    response["lease_grant"]["lease_id"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn lease(address: &str, identity: &Path, request: &LeaseRequest) -> serde_json::Value {
    cli_json(address, identity, "lease", request)
}

fn apple_request(suffix: &str, lease_id: &str) -> AppleRequest {
    AppleRequest {
        version: RemoteProtocolVersion { major: 1, minor: 0 },
        request_id: format!("request-{suffix}"),
        idempotency_key: format!("idempotency-{suffix}"),
        capability: "apple.simulator@1".into(),
        workspace_path: "project".into(),
        device_id: Some(DEVICE.into()),
        lease_id: Some(lease_id.into()),
        operation: AppleOperation::InstallApp {
            app_path: "build/MeshApp.app".into(),
        },
    }
}

fn wait_for_terminal(address: &str, identity: &Path, job_id: &str) -> serde_json::Value {
    let mut terminal = None;
    wait_until("terminal event", || {
        terminal = cli_json(
            address,
            identity,
            "events",
            &serde_json::json!({"job_id": job_id, "after": 0}),
        )["events"]
            .as_array()
            .and_then(|events| {
                events
                    .iter()
                    .find(|event| {
                        matches!(
                            event["kind"].as_str(),
                            Some("completed" | "rejected" | "cancelled")
                        )
                    })
                    .cloned()
            });
        terminal.is_some()
    });
    terminal.unwrap()
}

fn mutation_lines(marker: &Path) -> Vec<String> {
    std::fs::read_to_string(marker)
        .unwrap_or_default()
        .lines()
        .filter(|line| line.starts_with("mutation-"))
        .map(str::to_owned)
        .collect()
}

fn wait_for_mutation(
    harness: &mut Harness,
    expected: &str,
    label: &str,
    registry_should_run: bool,
    job_id: Option<&str>,
) {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut next_event_probe = Instant::now();
    let mut last_event_snapshot = serde_json::Value::Null;
    loop {
        let markers = mutation_lines(&harness.marker);
        let agent_status = harness._agent.try_wait().unwrap();
        let registry_status = harness._registry.try_wait().unwrap();
        assert!(
            agent_status.is_none(),
            "agent exited before {label}; agent_status={agent_status:?}; registry_status={registry_status:?}; markers={markers:?}"
        );
        assert_eq!(
            registry_status.is_none(),
            registry_should_run,
            "registry state changed before {label}; agent_status={agent_status:?}; registry_status={registry_status:?}; markers={markers:?}"
        );
        if markers.iter().any(|line| line == expected) {
            return;
        }
        if let Some(job_id) = job_id
            && Instant::now() >= next_event_probe
        {
            let output = cli(
                &harness.address,
                &harness.client_a,
                "events",
                &serde_json::json!({"job_id": job_id, "after": 0}),
            );
            assert!(
                output.status.success(),
                "event probe failed before {label}; status={}; stderr={}; markers={markers:?}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
            last_event_snapshot = serde_json::from_slice(&output.stdout).unwrap();
            let terminal = last_event_snapshot["events"].as_array().and_then(|events| {
                events.iter().find(|event| {
                    matches!(
                        event["kind"].as_str(),
                        Some("completed" | "rejected" | "cancelled")
                    )
                })
            });
            assert!(
                terminal.is_none(),
                "job terminated before {label}; terminal={terminal:?}; snapshot={last_event_snapshot}; markers={markers:?}"
            );
            next_event_probe = Instant::now() + Duration::from_millis(250);
        }
        if Instant::now() >= deadline {
            let hosts = Command::new(env!("CARGO_BIN_EXE_mesh-cli"))
                .args([
                    "--registry",
                    &harness.address,
                    "--identity",
                    harness.client_a.to_str().unwrap(),
                    "list",
                    "--json",
                ])
                .output()
                .unwrap();
            panic!(
                "timed out waiting for {label}; agent_status={agent_status:?}; registry_status={registry_status:?}; markers={markers:?}; last_event_snapshot={last_event_snapshot}; host_status={}; host_stdout={}; host_stderr={}",
                hosts.status,
                String::from_utf8_lossy(&hosts.stdout),
                String::from_utf8_lossy(&hosts.stderr)
            );
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn start_registry(address: &str, identity: &Path) -> ChildGuard {
    spawn(
        env!("CARGO_BIN_EXE_mesh-registry"),
        &[
            "--listen",
            address,
            "--identity",
            identity.to_str().unwrap(),
            "--offline-after-ms",
            "5000",
            "--agent-peer",
            "agent",
            "--agent-peer",
            "agent-b",
        ],
    )
}

fn fake_tool(
    root: &Path,
    name: &str,
    marker: &Path,
    mutation_delay: Duration,
    mutation_gate: Option<&Path>,
) -> PathBuf {
    #[cfg(windows)]
    {
        let path = root.join(format!("{name}.cmd"));
        let delay_command = if mutation_delay.is_zero() {
            "rem no mutation delay".to_owned()
        } else {
            let ping_count = mutation_delay.as_millis().div_ceil(1_000) + 1;
            format!("ping.exe -n {ping_count} 127.0.0.1 >nul")
        };
        let gate_command = mutation_gate.map_or_else(
            || "rem no mutation gate".to_owned(),
            |gate| {
                format!(
                    ":wait_gate\r\nif not exist \"{}\" (\r\n  ping.exe -n 2 127.0.0.1 >nul\r\n  goto wait_gate\r\n)",
                    gate.display()
                )
            },
        );
        std::fs::write(
            &path,
            format!(
                "@echo off\r\nif \"{name}\"==\"simctl\" if \"%1\"==\"install\" goto mutation\r\nif \"%1\"==\"-version\" goto version\r\nif \"{name}\"==\"devicectl\" if \"%1\"==\"list\" goto devices\r\nif \"{name}\"==\"simctl\" if \"%1\"==\"list\" goto simulators\r\necho tool-output {name} %*\r\nexit /b 0\r\n:mutation\r\necho mutation-start>>\"{}\"\r\n{}\r\n{}\r\necho mutation-end>>\"{}\"\r\necho installed\r\nexit /b 0\r\n:version\r\necho Xcode 16\r\nexit /b 0\r\n:devices\r\necho {{\"result\":{{\"devices\":[]}}}}\r\nexit /b 0\r\n:simulators\r\necho {{\"devices\":{{\"com.apple.CoreSimulator.SimRuntime.iOS-17-0\":[{{\"udid\":\"sim-1\",\"name\":\"iPhone\",\"state\":\"Booted\",\"isAvailable\":true}}]}}}}\r\nexit /b 0\r\n",
                marker.display(),
                gate_command,
                delay_command,
                marker.display()
            ),
        )
        .unwrap();
        path
    }
    #[cfg(not(windows))]
    {
        use std::os::unix::fs::PermissionsExt;
        let path = root.join(name);
        let gate_command = mutation_gate.map_or_else(String::new, |gate| {
            format!(
                "  while [ ! -f '{}' ]; do sleep 0.05; done\n",
                gate.display()
            )
        });
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\nif [ '{name}' = simctl ] && [ \"$1\" = install ]; then\n  echo mutation-start >> '{}'\n{}  sleep {}\n  echo mutation-end >> '{}'\n  echo installed\n  exit 0\nfi\n[ \"$1\" = -version ] && echo 'Xcode 16' && exit 0\n[ '{name}' = devicectl ] && [ \"$1\" = list ] && echo '{{\"result\":{{\"devices\":[]}}}}' && exit 0\n[ '{name}' = simctl ] && [ \"$1\" = list ] && echo '{{\"devices\":{{\"com.apple.CoreSimulator.SimRuntime.iOS-17-0\":[{{\"udid\":\"sim-1\",\"name\":\"iPhone\",\"state\":\"Booted\",\"isAvailable\":true}}]}}}}' && exit 0\necho \"tool-output {name} $*\"\n",
                marker.display(),
                gate_command,
                mutation_delay.as_secs_f64(),
                marker.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }
}

fn cli<T: serde::Serialize>(address: &str, identity: &Path, command: &str, body: &T) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_mesh-cli"))
        .args([
            "--registry",
            address,
            "--identity",
            identity.to_str().unwrap(),
            command,
            "--json-request",
            &serde_json::to_string(body).unwrap(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let output = child.wait_with_output().unwrap();
            panic!(
                "mesh-cli {command} timed out after five seconds; status={}; stderr={}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
        }
        thread::sleep(Duration::from_millis(10));
    }
    child.wait_with_output().unwrap()
}

fn cli_json<T: serde::Serialize>(
    address: &str,
    identity: &Path,
    command: &str,
    body: &T,
) -> serde_json::Value {
    let output = cli(address, identity, command, body);
    assert!(
        output.status.success(),
        "mesh-cli failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn rpc(address: &str, identity: &Path, request: &Request) -> serde_json::Value {
    let transport = SecureTransport::load_or_create(identity, "test-peer").unwrap();
    let stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut stream = transport.connect_tls(stream, "registry").unwrap();
    serde_json::to_writer(&mut stream, request).unwrap();
    stream.write_all(b"\n").unwrap();
    let mut response = String::new();
    BufReader::new(stream).read_line(&mut response).unwrap();
    serde_json::from_str(&response).unwrap()
}

fn wait_for_host(address: &str, identity: &Path) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let output = Command::new(env!("CARGO_BIN_EXE_mesh-cli"))
            .args([
                "--registry",
                address,
                "--identity",
                identity.to_str().unwrap(),
                "list",
                "--json",
            ])
            .output()
            .unwrap();
        let snapshot = serde_json::from_slice::<serde_json::Value>(&output.stdout).ok();
        if output.status.success()
            && snapshot.as_ref().is_some_and(|hosts| {
                hosts.as_array().is_some_and(|hosts| {
                    hosts
                        .iter()
                        .any(|host| host["id"] == "mac-1" && host["status"] == "online")
                })
            })
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "registry never exposed online mac-1; status={}; stderr={}; snapshot={snapshot:?}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        thread::sleep(Duration::from_millis(25));
    }
}

fn wait_for_listener(address: &str) {
    wait_until("registry listener", || TcpStream::connect(address).is_ok());
}

fn wait_until(label: &str, mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !condition() {
        assert!(Instant::now() < deadline, "timed out waiting for {label}");
        thread::sleep(Duration::from_millis(25));
    }
}

fn pair(registry: &Path, registry_id: &str, peer: &Path, peer_id: &str) {
    let mut left = SecureTransport::load_or_create(registry, registry_id).unwrap();
    let mut right = SecureTransport::load_or_create(peer, peer_id).unwrap();
    let code = left.issue_pairing_code(Duration::from_secs(10));
    left.accept_pairing(&code, right.certificate_der(), Duration::ZERO)
        .unwrap();
    right.trust(registry_id, left.certificate_der()).unwrap();
}

fn free_address() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().to_string()
}

fn spawn(path: &str, args: &[&str]) -> ChildGuard {
    ChildGuard(
        Command::new(path)
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    )
}

struct ChildGuard(Child);

impl std::ops::Deref for ChildGuard {
    type Target = Child;

    fn deref(&self) -> &Child {
        &self.0
    }
}

impl std::ops::DerefMut for ChildGuard {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.0
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
