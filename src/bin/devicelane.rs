use device_development_mesh::controller_session::{
    ControllerSessionAssertion, MeshApprovalAssertion, issue_controller_session,
    sign_mesh_access_claim, verify_controller_session,
};
use device_development_mesh::dashboard::{
    audit::AuditFilter, event_log::EventRead, policy::AccessRequest, service::AdminMutation, *,
};
use device_development_mesh::local_ipc::{
    LocalEndpoint, LocalProtocolVersion, LocalRequest, LocalResponse, local_endpoint,
    send_local_request,
};
use device_development_mesh::network_processes::{
    Request as MeshRequest, Response as MeshResponse,
};
use device_development_mesh::secure_transport::SecureTransport;
use std::{
    collections::BTreeMap,
    fs,
    io::{self, BufRead, BufReader, Write},
    net::TcpStream,
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const HELP: &str = "DeviceLane unified client\n\nUsage:\n  devicelane status --local [--json] [--endpoint ENDPOINT]\n  devicelane remote-access <pause|resume> --local\n  devicelane diagnostics --local\n  devicelane mesh <status|watch> --local [--scope local|mesh]\n  devicelane activities <list|watch|cancel> --local [--cursor EPOCH:SEQUENCE] [--limit 1..256]\n  devicelane approvals <list|request|decide> --local [typed access options]\n  devicelane policy <list|put|delete> --local [typed rule options]\n  devicelane audit <list|export> --local [filters]\n\nGrant flow:\n  approvals request --activity-id ID --principal-id ID --source-host-id ID --target-host-id ID --operation OP --resource RESOURCE\n  approvals decide --nonce NONCE [same exact access flags] --decision allow_once|allow_and_remember|deny_once|deny_and_block\n  Exact policy mutation: approvals request --admin-mutation policy_put [same typed rule flags as policy put]\n  then approvals list, approvals decide --approval-id ID --decision allow_once, and invoke the exact policy put before expiry.\n\nAdministrative operations: devicelane.policy.put, devicelane.policy.delete, devicelane.activity.cancel.\nResources: workspace_read, workspace_write, artifact_upload, artifact_download, device_lease, application_install, application_launch, debugger, signing, microphone, screen_capture, network_endpoint, device_lane_policy, device_lane_service.";
const ADMIN_HELP: &str = "Admin grants: devicelane.policy.put -> device_lane_policy; devicelane.policy.delete -> device_lane_policy; devicelane.activity.cancel -> device_lane_service; devicelane.service.pause -> device_lane_service; devicelane.service.resume -> device_lane_service. Exact deletion flow: approvals request --admin-mutation policy_delete --rule-id ID --expected-revision REV; approvals list; approvals decide --approval-id ID --decision allow_once; policy delete --rule-id ID --expected-revision REV.";

#[derive(Default)]
struct P {
    pos: Vec<String>,
    f: BTreeMap<String, Vec<String>>,
    local: bool,
    json: bool,
    endpoint: Option<String>,
}
enum Watch {
    No,
    Mesh(DashboardScope),
    Activities(EventCursor, usize),
}
struct Args {
    request: LocalRequest,
    endpoint: Option<String>,
    json: bool,
    message: &'static str,
    watch: Watch,
}

fn raw(v: &[String]) -> Result<P, String> {
    let mut p = P::default();
    let mut i = 0;
    while i < v.len() {
        match v[i].as_str() {
            "--local" => p.local = true,
            "--json" => p.json = true,
            x if x.starts_with("--") => {
                let boolean = matches!(
                    x,
                    "--physical-device"
                        | "--user-present"
                        | "--require-user-presence"
                        | "--enabled"
                        | "--match-device-exact"
                        | "--match-resources-exact"
                );
                let n = if boolean {
                    "true".into()
                } else {
                    i += 1;
                    v.get(i)
                        .filter(|x| !x.starts_with('-'))
                        .cloned()
                        .ok_or_else(|| format!("missing value for {x}"))?
                };
                if x == "--endpoint" {
                    if p.endpoint.replace(n).is_some() {
                        return Err("duplicate --endpoint".into());
                    }
                } else {
                    p.f.entry(x.into()).or_default().push(n)
                }
            }
            x if x.starts_with('-') => return Err(format!("unknown flag: {x}")),
            x => p.pos.push(x.into()),
        }
        i += 1
    }
    Ok(p)
}
fn one<'a>(p: &'a P, k: &str) -> Result<Option<&'a str>, String> {
    match p.f.get(k).map(Vec::as_slice) {
        None => Ok(None),
        Some([v]) => Ok(Some(v)),
        Some(_) => Err(format!("duplicate {k}")),
    }
}
fn req<'a>(p: &'a P, k: &str) -> Result<&'a str, String> {
    one(p, k)?.ok_or_else(|| format!("missing required {k}"))
}
fn num(p: &P, k: &str, d: u64) -> Result<u64, String> {
    one(p, k)?.map_or(Ok(d), |x| x.parse().map_err(|_| format!("invalid {k}")))
}
fn lim(p: &P) -> Result<usize, String> {
    let n = num(p, "--limit", 100)? as usize;
    (1..=256)
        .contains(&n)
        .then_some(n)
        .ok_or("--limit must be between 1 and 256".into())
}
fn en<T: serde::de::DeserializeOwned>(s: &str, k: &str) -> Result<T, String> {
    serde_json::from_value(serde_json::Value::String(s.into()))
        .map_err(|_| format!("invalid value for {k}: {s}"))
}
fn id<T>(s: &str, f: impl FnOnce(String) -> Result<T, ValidationError>) -> Result<T, String> {
    f(s.to_owned()).map_err(|e| e.to_string())
}
fn cur(p: &P) -> Result<EventCursor, String> {
    let Some(s) = one(p, "--cursor")? else {
        return Ok(EventCursor {
            epoch: 1,
            sequence: 0,
        });
    };
    let (a, b) = s.split_once(':').ok_or("--cursor must be EPOCH:SEQUENCE")?;
    Ok(EventCursor {
        epoch: a.parse().map_err(|_| "invalid cursor")?,
        sequence: b.parse().map_err(|_| "invalid cursor")?,
    })
}
fn resources(p: &P) -> Result<Vec<ResourceClass>, String> {
    p.f.get("--resource")
        .into_iter()
        .flatten()
        .map(|x| en(x, "--resource"))
        .collect()
}
fn access(p: &P) -> Result<AccessRequest, String> {
    let r = resources(p)?;
    if r.is_empty() {
        return Err("at least one --resource is required".into());
    }
    Ok(AccessRequest {
        activity_id: id(req(p, "--activity-id")?, ActivityId::parse)?,
        principal_id: id(req(p, "--principal-id")?, PrincipalId::parse)?,
        source_host_id: id(req(p, "--source-host-id")?, HostId::parse)?,
        target_host_id: id(req(p, "--target-host-id")?, HostId::parse)?,
        device_id: one(p, "--device-id")?
            .map(|x| id(x, DeviceId::parse))
            .transpose()?,
        operation: id(req(p, "--operation")?, OperationId::parse)?,
        resources: r,
        physical_device: p.f.contains_key("--physical-device"),
        user_present: p.f.contains_key("--user-present"),
    })
}
fn filter(p: &P) -> Result<AuditFilter, String> {
    Ok(AuditFilter {
        from_ms: one(p, "--from-ms")?
            .map(str::parse)
            .transpose()
            .map_err(|_| "invalid --from-ms")?,
        through_ms: one(p, "--through-ms")?
            .map(str::parse)
            .transpose()
            .map_err(|_| "invalid --through-ms")?,
        principal_id: one(p, "--principal-id")?
            .map(|x| id(x, PrincipalId::parse))
            .transpose()?,
        source_host_id: one(p, "--source-host-id")?
            .map(|x| id(x, HostId::parse))
            .transpose()?,
        target_host_id: one(p, "--target-host-id")?
            .map(|x| id(x, HostId::parse))
            .transpose()?,
        device_id: one(p, "--device-id")?
            .map(|x| id(x, DeviceId::parse))
            .transpose()?,
        operation: one(p, "--operation")?
            .map(|x| id(x, OperationId::parse))
            .transpose()?,
        resource: one(p, "--resource")?
            .map(|x| en(x, "--resource"))
            .transpose()?,
        decision: one(p, "--decision")?
            .map(|x| en(x, "--decision"))
            .transpose()?,
        result: one(p, "--result")?
            .map(|x| en::<AuditResult>(x, "--result"))
            .transpose()?,
    })
}
fn rule(p: &P) -> Result<PolicyRule, String> {
    let x = PolicyRule {
        id: id(req(p, "--rule-id")?, RuleId::parse)?,
        revision: num(p, "--revision", 1)?,
        effect: en(req(p, "--effect")?, "--effect")?,
        principal_id: one(p, "--principal-id")?
            .map(|x| id(x, PrincipalId::parse))
            .transpose()?,
        source_host_id: one(p, "--source-host-id")?
            .map(|x| id(x, HostId::parse))
            .transpose()?,
        target_host_id: one(p, "--target-host-id")?
            .map(|x| id(x, HostId::parse))
            .transpose()?,
        device_id: one(p, "--device-id")?
            .map(|x| id(x, DeviceId::parse))
            .transpose()?,
        operation: one(p, "--operation")?
            .map(|x| id(x, OperationId::parse))
            .transpose()?,
        resources: resources(p)?,
        expires_at_ms: one(p, "--expires-at-ms")?
            .map(str::parse)
            .transpose()
            .map_err(|_| "invalid expiry")?,
        require_user_presence: p.f.contains_key("--require-user-presence"),
        user_presence: None,
        physical_device: None,
        match_device_exact: p.f.contains_key("--match-device-exact"),
        match_resources_exact: p.f.contains_key("--match-resources-exact"),
        enabled: p.f.contains_key("--enabled"),
        origin: one(p, "--origin")?.map_or(Ok(PolicyOrigin::User), |x| en(x, "--origin"))?,
    };
    x.validate().map_err(|e| e.to_string())?;
    Ok(x)
}

fn admin_mutation(p: &P) -> Result<AdminMutation, String> {
    match req(p, "--admin-mutation")? {
        "policy_put" => {
            let rule = rule(p)?;
            Ok(AdminMutation::PolicyPut {
                expected_revision: rule.revision.saturating_sub(1),
                rule,
            })
        }
        "policy_delete" => Ok(AdminMutation::PolicyDelete {
            rule_id: id(req(p, "--rule-id")?, RuleId::parse)?,
            expected_revision: num(p, "--expected-revision", 0)?,
        }),
        value => Err(format!("invalid value for --admin-mutation: {value}")),
    }
}

fn reject_foreign_flags(p: &P, command: &[&str]) -> Result<(), String> {
    let allowed: &[&str] = match command {
        ["mesh", _] => &["--scope"],
        ["activities", "list" | "watch"] => &["--cursor", "--limit"],
        ["activities", "cancel"] => &["--activity-id"],
        ["approvals", "list"]
        | ["policy", "list"]
        | ["status"]
        | ["diagnostics"]
        | ["remote-access", _] => &[],
        ["approvals", "request"] => &[
            "--lifetime-ms",
            "--admin-mutation",
            "--expected-revision",
            "--activity-id",
            "--principal-id",
            "--source-host-id",
            "--target-host-id",
            "--device-id",
            "--operation",
            "--resource",
            "--physical-device",
            "--user-present",
            "--rule-id",
            "--revision",
            "--effect",
            "--expires-at-ms",
            "--require-user-presence",
            "--match-device-exact",
            "--match-resources-exact",
            "--enabled",
            "--origin",
        ],
        ["approvals", "decide"] => &[
            "--nonce",
            "--approval-id",
            "--decision",
            "--activity-id",
            "--principal-id",
            "--source-host-id",
            "--target-host-id",
            "--device-id",
            "--operation",
            "--resource",
            "--physical-device",
            "--user-present",
        ],
        ["policy", "put"] => &[
            "--rule-id",
            "--revision",
            "--effect",
            "--principal-id",
            "--source-host-id",
            "--target-host-id",
            "--device-id",
            "--operation",
            "--resource",
            "--expires-at-ms",
            "--require-user-presence",
            "--match-device-exact",
            "--match-resources-exact",
            "--enabled",
            "--origin",
        ],
        ["policy", "delete"] => &["--rule-id", "--expected-revision"],
        ["audit", "list"] => &[
            "--from-ms",
            "--through-ms",
            "--principal-id",
            "--source-host-id",
            "--target-host-id",
            "--device-id",
            "--operation",
            "--resource",
            "--decision",
            "--result",
            "--cursor",
            "--limit",
        ],
        ["audit", "export"] => &[
            "--from-ms",
            "--through-ms",
            "--principal-id",
            "--source-host-id",
            "--target-host-id",
            "--device-id",
            "--operation",
            "--resource",
            "--decision",
            "--result",
        ],
        _ => &[],
    };
    if let Some(flag) = p.f.keys().find(|flag| !allowed.contains(&flag.as_str())) {
        return Err(format!("{flag} is not valid for {}", command.join(" ")));
    }
    Ok(())
}

fn parse() -> Result<Option<Args>, String> {
    let v: Vec<_> = std::env::args().skip(1).collect();
    if v.iter().any(|x| x == "--help" || x == "-h") {
        println!(
            "{HELP}\n\n{ADMIN_HELP}\n\nAll commands use authenticated local IPC and require --local. No raw JSON or shell input is accepted."
        );
        return Ok(None);
    }
    if matches!(v.as_slice(),[x] if x=="-V"||x=="--version") {
        println!("devicelane {}", env!("CARGO_PKG_VERSION"));
        return Ok(None);
    }
    let p = raw(&v)?;
    if !p.local {
        return Err("local commands require --local".into());
    }
    let z = LocalProtocolVersion::CURRENT;
    let c: Vec<_> = p.pos.iter().map(String::as_str).collect();
    reject_foreign_flags(&p, &c)?;
    let (r, m, w) = match c.as_slice() {
        ["status"] => (
            LocalRequest::Status { version: z },
            "status received",
            Watch::No,
        ),
        ["diagnostics"] => (
            LocalRequest::Diagnostics { version: z },
            "diagnostics received",
            Watch::No,
        ),
        ["remote-access", "pause"] => (
            LocalRequest::PauseRemoteAccess { version: z },
            "remote access paused",
            Watch::No,
        ),
        ["remote-access", "resume"] => (
            LocalRequest::ResumeRemoteAccess { version: z },
            "remote access resumed",
            Watch::No,
        ),
        ["mesh", a @ ("status" | "watch")] => {
            let s = one(&p, "--scope")?.map_or(Ok(DashboardScope::Mesh), |x| en(x, "--scope"))?;
            (
                LocalRequest::DashboardSnapshot {
                    version: z,
                    scope: s,
                },
                "mesh status received",
                if *a == "watch" {
                    Watch::Mesh(s)
                } else {
                    Watch::No
                },
            )
        }
        ["activities", a @ ("list" | "watch")] => {
            let (c, l) = (cur(&p)?, lim(&p)?);
            (
                LocalRequest::ActivityEvents {
                    version: z,
                    scope: DashboardScope::Local,
                    cursor: c,
                    limit: l,
                },
                "activity events received",
                if *a == "watch" {
                    Watch::Activities(c, l)
                } else {
                    Watch::No
                },
            )
        }
        ["activities", "cancel"] => (
            LocalRequest::CancelActivity {
                version: z,
                activity_id: id(req(&p, "--activity-id")?, ActivityId::parse)?,
            },
            "activity cancellation requested",
            Watch::No,
        ),
        ["approvals", "list"] => (
            LocalRequest::PendingApprovals { version: z },
            "pending approvals received",
            Watch::No,
        ),
        ["approvals", "request"] => {
            let lifetime_ms = num(&p, "--lifetime-ms", 300000)?.min(300000);
            let request = if p.f.contains_key("--admin-mutation") {
                for incompatible in ["--activity-id", "--physical-device", "--user-present"] {
                    if p.f.contains_key(incompatible) {
                        return Err(format!("{incompatible} is not valid with --admin-mutation"));
                    }
                }
                LocalRequest::RequestAdminMutationApproval {
                    version: z,
                    mutation: admin_mutation(&p)?,
                    lifetime_ms,
                }
            } else {
                LocalRequest::RequestApproval {
                    version: z,
                    access: access(&p)?,
                    lifetime_ms,
                }
            };
            (request, "approval requested", Watch::No)
        }
        ["approvals", "decide"] => {
            let decision = en(req(&p, "--decision")?, "--decision")?;
            let request = if let Some(approval_id) = one(&p, "--approval-id")? {
                for incompatible in [
                    "--nonce",
                    "--activity-id",
                    "--principal-id",
                    "--source-host-id",
                    "--target-host-id",
                    "--device-id",
                    "--operation",
                    "--resource",
                    "--physical-device",
                    "--user-present",
                ] {
                    if p.f.contains_key(incompatible) {
                        return Err(format!("{incompatible} is not valid with --approval-id"));
                    }
                }
                LocalRequest::DecidePendingApproval {
                    version: z,
                    approval_id: id(approval_id, ApprovalId::parse)?,
                    decision,
                }
            } else {
                LocalRequest::DecideApproval {
                    version: z,
                    nonce: req(&p, "--nonce")?.into(),
                    access: access(&p)?,
                    decision,
                }
            };
            (request, "approval decided", Watch::No)
        }
        ["policy", "list"] => (
            LocalRequest::PolicyRules { version: z },
            "policy rules received",
            Watch::No,
        ),
        ["policy", "put"] => (
            LocalRequest::PutPolicyRule {
                version: z,
                rule: rule(&p)?,
            },
            "policy rule stored",
            Watch::No,
        ),
        ["policy", "delete"] => {
            let rule_id = id(req(&p, "--rule-id")?, RuleId::parse)?;
            let request = match one(&p, "--expected-revision")? {
                Some(_) => LocalRequest::DeletePolicyRuleIfRevision {
                    version: z,
                    rule_id,
                    expected_revision: num(&p, "--expected-revision", 0)?,
                },
                None => LocalRequest::DeletePolicyRule {
                    version: z,
                    rule_id,
                },
            };
            (request, "policy rule deleted", Watch::No)
        }
        ["audit", "list"] => (
            LocalRequest::AuditQuery {
                version: z,
                filter: filter(&p)?,
                cursor: one(&p, "--cursor")?.map(|_| cur(&p)).transpose()?,
                limit: lim(&p)?,
            },
            "audit records received",
            Watch::No,
        ),
        ["audit", "export"] => (
            LocalRequest::AuditExport {
                version: z,
                filter: filter(&p)?,
            },
            "audit exported",
            Watch::No,
        ),
        _ => return Err(format!("invalid command\n\n{HELP}")),
    };
    Ok(Some(Args {
        request: r,
        endpoint: p.endpoint,
        json: p.json,
        message: m,
        watch: w,
    }))
}

fn runtime() -> Result<PathBuf, String> {
    #[cfg(windows)]
    {
        std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .map(|p| p.join("DeviceLane/runtime"))
            .ok_or("LOCALAPPDATA unavailable".into())
    }
    #[cfg(unix)]
    {
        std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .map(|p| p.join("devicelane"))
            .ok_or("XDG_RUNTIME_DIR unavailable".into())
    }
}
fn endpoint(x: Option<&str>) -> Result<LocalEndpoint, String> {
    #[cfg(windows)]
    let r = runtime()?;
    #[cfg(unix)]
    let r = match x {
        Some(v) => std::path::Path::new(v)
            .parent()
            .ok_or("endpoint parent missing")?
            .into(),
        None => runtime()?,
    };
    local_endpoint(&r, x.unwrap_or("")).map_err(|e| e.to_string())
}
fn json(x: &impl serde::Serialize) -> io::Result<()> {
    let mut o = io::stdout().lock();
    serde_json::to_writer(&mut o, x).map_err(io::Error::other)?;
    o.write_all(b"\n")?;
    o.flush()
}
fn human(r: &LocalResponse, m: &str) -> Result<String, String> {
    match r {
        LocalResponse::Snapshot(s) => Ok(format!(
            "{} - role {:?}, connection {:?}, remote access {}",
            s.public_identity,
            s.role,
            s.connection,
            if s.remote_access_paused {
                "paused"
            } else {
                "active"
            }
        )),
        LocalResponse::DashboardSnapshot(s) => Ok(s
            .hosts
            .iter()
            .map(|h| {
                format!(
                    "{}: {:?}, last seen {}",
                    h.display_name,
                    h.presence,
                    match h.freshness {
                        Freshness::Stale { last_seen_at_ms } => last_seen_at_ms.to_string(),
                        Freshness::Live => "now".into(),
                        Freshness::Unknown => "unknown".into(),
                    }
                )
            })
            .collect::<Vec<_>>()
            .join("\n")),
        LocalResponse::ActivityEvents(EventRead::Events { events, .. }) => Ok(events
            .iter()
            .map(|e| format!("{}: {:?}", e.activity_id, e.state))
            .collect::<Vec<_>>()
            .join("\n")),
        LocalResponse::PendingApprovals(values) => Ok(values
            .iter()
            .map(|a| {
                format!(
                    "{}: {:?} {} -> {}, operation {}, resources {:?}, expires {}",
                    a.id,
                    a.risk,
                    a.source_host_id,
                    a.target_host_id,
                    a.operation,
                    a.resources,
                    a.expires_at_ms
                )
            })
            .collect::<Vec<_>>()
            .join("\n")),
        LocalResponse::PolicyRules(values) => Ok(values
            .iter()
            .map(|r| {
                format!(
                    "{} rev {}: {:?}, operation {:?}, resources {:?}, enabled {}, expires {:?}",
                    r.id,
                    r.revision,
                    r.effect,
                    r.operation,
                    r.resources,
                    r.enabled,
                    r.expires_at_ms
                )
            })
            .collect::<Vec<_>>()
            .join("\n")),
        LocalResponse::AuditRecords(page) => Ok(page
            .items
            .iter()
            .map(|r| {
                format!(
                    "{}: {:?} {:?}, {} -> {}, operation {}, resources {:?}",
                    r.sequence,
                    r.result,
                    r.decision,
                    r.source_host_id,
                    r.target_host_id,
                    r.operation,
                    r.resources
                )
            })
            .collect::<Vec<_>>()
            .join("\n")),
        LocalResponse::ApprovalCreated {
            nonce,
            expires_at_ms,
        } => Ok(format!(
            "approval requested: nonce {nonce}, expires {expires_at_ms}"
        )),
        LocalResponse::ApprovalDecided {
            decision,
            created_rule,
        } => Ok(format!(
            "approval decided: {:?}, created rule {:?}",
            decision,
            created_rule.as_ref().map(|r| &r.id)
        )),
        LocalResponse::Cancellation { cancelled } => Ok(format!(
            "activity state: {}",
            if *cancelled { "cancelled" } else { "unchanged" }
        )),
        LocalResponse::RuleDeleted { deleted } => Ok(format!(
            "policy rule {}",
            if *deleted { "deleted" } else { "not found" }
        )),
        LocalResponse::AuditExport(export) => Ok(format!(
            "audit export: {} records, hash {}",
            export.records.len(),
            export.manifest.records_sha256
        )),
        LocalResponse::Error { code, message } => Err(format!("daemon error ({code}): {message}")),
        LocalResponse::Diagnostics(v) => Ok(v
            .iter()
            .map(|x| x.message.clone())
            .collect::<Vec<_>>()
            .join("\n")),
        _ => Ok(m.into()),
    }
}
fn send(e: &LocalEndpoint, r: &LocalRequest) -> Result<LocalResponse, String> {
    send_local_request(e, r).map_err(|x| x.to_string())
}
fn structured_watch_error(message: &str) -> Result<(), String> {
    json(&LocalResponse::Error {
        code: "local_ipc_error".into(),
        message: message.into(),
    })
    .map_err(|error| error.to_string())
}
enum WatchFailure {
    Transport(String),
    Daemon { code: String, message: String },
    Protocol(String),
}
impl WatchFailure {
    fn message(&self) -> String {
        match self {
            Self::Transport(message) | Self::Protocol(message) => message.clone(),
            Self::Daemon { code, message } => format!("daemon error ({code}): {message}"),
        }
    }
}
fn watch_activity(
    e: &LocalEndpoint,
    mut c: EventCursor,
    l: usize,
    j: bool,
) -> Result<(), WatchFailure> {
    let z = LocalProtocolVersion::CURRENT;
    let s = SubscriberId::parse(format!("cli-{}", std::process::id()))
        .map_err(|x| WatchFailure::Protocol(x.to_string()))?;
    loop {
        match send(
            e,
            &LocalRequest::ActivityEvents {
                version: z,
                scope: DashboardScope::Local,
                cursor: c,
                limit: l,
            },
        )
        .map_err(WatchFailure::Transport)?
        {
            LocalResponse::ActivityEvents(EventRead::Events {
                events,
                next_cursor,
            }) => {
                for x in &events {
                    let w = if j {
                        json(x)
                    } else {
                        writeln!(io::stdout(), "{}: {:?}", x.activity_id, x.state)
                    };
                    if let Err(q) = w {
                        return if q.kind() == io::ErrorKind::BrokenPipe {
                            Ok(())
                        } else {
                            Err(WatchFailure::Transport(q.to_string()))
                        };
                    }
                }
                if events.is_empty() {
                    std::thread::sleep(Duration::from_millis(500))
                } else {
                    match send(
                        e,
                        &LocalRequest::AcknowledgeEvents {
                            version: z,
                            subscriber_id: s.clone(),
                            cursor: next_cursor,
                        },
                    )
                    .map_err(WatchFailure::Transport)?
                    {
                        LocalResponse::Acknowledged => c = next_cursor,
                        LocalResponse::Error { code, message } => {
                            return Err(WatchFailure::Daemon { code, message });
                        }
                        _ => return Err(WatchFailure::Protocol("unexpected acknowledge".into())),
                    }
                }
            }
            LocalResponse::ActivityEvents(EventRead::CursorAhead { .. }) => {
                return Err(WatchFailure::Daemon {
                    code: "cursor_ahead".into(),
                    message: "activity cursor is ahead of the available stream".into(),
                });
            }
            LocalResponse::ActivityEvents(EventRead::ResyncRequired { .. }) => {
                return Err(WatchFailure::Daemon {
                    code: "resync_required".into(),
                    message: "activity cursor requires a fresh snapshot".into(),
                });
            }
            LocalResponse::ActivityEvents(EventRead::LimitExceeded) => {
                return Err(WatchFailure::Daemon {
                    code: "limit_exceeded".into(),
                    message: "activity page exceeds the safe size limit".into(),
                });
            }
            LocalResponse::Error { code, message } => {
                return Err(WatchFailure::Daemon { code, message });
            }
            _ => return Err(WatchFailure::Protocol("unexpected response".into())),
        }
    }
}
fn run() -> Result<(), String> {
    let Some(a) = parse()? else { return Ok(()) };
    let e = match endpoint(a.endpoint.as_deref()) {
        Ok(x) => x,
        Err(m) if a.json => {
            json(&LocalResponse::Error {
                code: "local_ipc_error".into(),
                message: m.clone(),
            })
            .map_err(|e| e.to_string())?;
            return Err(m);
        }
        Err(m) => return Err(m),
    };
    match a.watch {
        Watch::Activities(c, l) => {
            let result = watch_activity(&e, c, l, a.json);
            return match result {
                Ok(()) => Ok(()),
                Err(WatchFailure::Daemon { code, message }) => {
                    if a.json {
                        json(&LocalResponse::Error {
                            code: code.clone(),
                            message: message.clone(),
                        })
                        .map_err(|e| e.to_string())?;
                    }
                    Err(format!("daemon error ({code}): {message}"))
                }
                Err(error) => {
                    let message = error.message();
                    if a.json {
                        structured_watch_error(&message)?;
                    }
                    Err(message)
                }
            };
        }
        Watch::Mesh(s) => loop {
            let r = match send(
                &e,
                &LocalRequest::DashboardSnapshot {
                    version: LocalProtocolVersion::CURRENT,
                    scope: s,
                },
            ) {
                Ok(response) => response,
                Err(message) => {
                    if a.json {
                        structured_watch_error(&message)?;
                    }
                    return Err(message);
                }
            };
            if let LocalResponse::Error { code, message } = &r {
                if a.json {
                    json(&r).map_err(|e| e.to_string())?;
                }
                return Err(format!("daemon error ({code}): {message}"));
            }
            if a.json {
                json(&r).map_err(|e| e.to_string())?
            } else {
                println!("{}", human(&r, a.message)?)
            }
            std::thread::sleep(Duration::from_secs(1))
        },
        Watch::No => {}
    }
    let r = match send(&e, &a.request) {
        Ok(x) => x,
        Err(m) if a.json => {
            json(&LocalResponse::Error {
                code: "local_ipc_error".into(),
                message: m.clone(),
            })
            .map_err(|e| e.to_string())?;
            return Err(m);
        }
        Err(m) => return Err(m),
    };
    if a.json {
        json(&r).map_err(|e| e.to_string())?;
        if let LocalResponse::Error { code, message } = r {
            return Err(format!("daemon error ({code}): {message}"));
        }
    } else {
        println!("{}", human(&r, a.message)?)
    }
    Ok(())
}
fn main() {
    let raw_args: Vec<String> = std::env::args().skip(1).collect();
    if raw_args
        .iter()
        .any(|argument| argument == "--mesh-registry")
    {
        if let Err(error) = mesh_approval_command(&raw_args) {
            eprintln!("devicelane: {error}");
            std::process::exit(2)
        }
        return;
    }
    if raw_args.first().map(String::as_str) == Some("controller-session") {
        if let Err(error) = controller_session_command(&raw_args) {
            eprintln!("devicelane: {error}");
            std::process::exit(2)
        }
        return;
    }
    if let Err(e) = run() {
        eprintln!("devicelane: {e}");
        std::process::exit(2)
    }
}

fn mesh_approval_command(args: &[String]) -> Result<(), String> {
    let parsed = raw(args)?;
    if parsed.pos != ["approvals", "request"] || !parsed.local || !parsed.json {
        return Err("mesh approval requires `approvals request --local --json`".into());
    }
    if parsed.f.contains_key("--principal-id") || parsed.f.contains_key("--source-host-id") {
        return Err(
            "mesh_identity_mismatch: principal and source are derived from the authenticated mesh peer"
                .into(),
        );
    }
    let identity_path = PathBuf::from(req(&parsed, "--mesh-identity")?);
    if !identity_path.join("certificate.der").is_file()
        || !identity_path.join("private-key.der").is_file()
    {
        return Err("mesh_identity_missing: use an existing paired Windows identity".into());
    }
    let transport = SecureTransport::load_or_create(&identity_path, "windows-client")
        .map_err(|_| "mesh_identity_invalid".to_owned())?;
    let peer_id = transport
        .identity_id()
        .map_err(|_| "mesh_identity_invalid".to_owned())?;
    let access = AccessRequest {
        activity_id: id(req(&parsed, "--activity-id")?, ActivityId::parse)?,
        principal_id: id(&peer_id, PrincipalId::parse)?,
        source_host_id: id(&peer_id, HostId::parse)?,
        target_host_id: id(req(&parsed, "--target-host-id")?, HostId::parse)?,
        device_id: one(&parsed, "--device-id")?
            .map(|value| id(value, DeviceId::parse))
            .transpose()?,
        operation: id(req(&parsed, "--operation")?, OperationId::parse)?,
        resources: resources(&parsed)?,
        physical_device: parsed.f.contains_key("--physical-device"),
        user_present: parsed.f.contains_key("--user-present"),
    };
    let (claim, client_signature) = sign_mesh_access_claim(&transport, access)
        .map_err(|_| "mesh_identity_invalid".to_owned())?;
    let registry = req(&parsed, "--mesh-registry")?;
    let stream =
        TcpStream::connect(registry).map_err(|_| "mesh_registry_unavailable".to_owned())?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
    let mut stream = transport
        .connect_tls(stream, "registry")
        .map_err(|_| "mesh_authentication_failed".to_owned())?;
    serde_json::to_writer(
        &mut stream,
        &MeshRequest::AuthenticateDashboardAccess {
            claim,
            client_signature,
        },
    )
    .map_err(|_| "mesh_protocol_failed".to_owned())?;
    stream
        .write_all(b"\n")
        .map_err(|_| "mesh_protocol_failed".to_owned())?;
    let mut line = String::new();
    BufReader::new(stream)
        .read_line(&mut line)
        .map_err(|_| "mesh_protocol_failed".to_owned())?;
    let response: MeshResponse =
        serde_json::from_str(&line).map_err(|_| "mesh_protocol_failed".to_owned())?;
    if !response.accepted {
        return Err(response
            .error
            .unwrap_or_else(|| "mesh_identity_mismatch".into()));
    }
    let assertion: MeshApprovalAssertion = response
        .events
        .iter()
        .find(|event| event.kind == "authenticated_dashboard_access")
        .and_then(|event| serde_json::from_str(&event.payload).ok())
        .ok_or_else(|| "mesh_session_assertion_missing".to_owned())?;
    let response = send_local_request(
        &endpoint(parsed.endpoint.as_deref())?,
        &LocalRequest::RequestAuthenticatedApproval {
            version: LocalProtocolVersion::CURRENT,
            assertion,
            lifetime_ms: num(&parsed, "--lifetime-ms", 300_000)?,
        },
    )
    .map_err(|error| error.to_string())?;
    json(&response).map_err(|error| error.to_string())?;
    if let LocalResponse::Error { code, message } = response {
        return Err(format!("daemon error ({code}): {message}"));
    }
    Ok(())
}

fn controller_session_value<'a>(args: &'a [String], name: &str) -> Result<&'a str, String> {
    let index = args
        .iter()
        .position(|value| value == name)
        .ok_or_else(|| format!("missing required {name}"))?;
    args.get(index + 1)
        .map(String::as_str)
        .ok_or_else(|| format!("missing value for {name}"))
}

fn controller_session_command(args: &[String]) -> Result<(), String> {
    let action = args.get(1).map(String::as_str).unwrap_or_default();
    let identity_path = PathBuf::from(controller_session_value(args, "--identity")?);
    if !identity_path.join("certificate.der").is_file()
        || !identity_path.join("private-key.der").is_file()
    {
        return Err("controller_session_identity_missing: use an existing paired identity".into());
    }
    let identity = SecureTransport::load_or_create(&identity_path, "controller")
        .map_err(|_| "controller_session_identity_invalid".to_owned())?;
    let endpoint = controller_session_value(args, "--mesh-controller")?;
    let challenge = controller_session_value(args, "--challenge")?;
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "controller_session_clock_invalid".to_owned())?
        .as_millis() as u64;
    match action {
        "issue" => {
            let lifetime_ms = args
                .iter()
                .position(|value| value == "--lifetime-ms")
                .and_then(|index| args.get(index + 1))
                .map_or(Ok(60_000), |value| value.parse::<u64>())
                .map_err(|_| "invalid --lifetime-ms".to_owned())?;
            let assertion =
                issue_controller_session(&identity, endpoint, challenge, now_ms, lifetime_ms)
                    .map_err(|error| format!("controller_session_issue_failed: {error:?}"))?;
            json(&assertion).map_err(|error| error.to_string())
        }
        "verify" => {
            let assertion: ControllerSessionAssertion = serde_json::from_slice(
                &fs::read(controller_session_value(args, "--assertion")?)
                    .map_err(|_| "controller_session_assertion_unreadable".to_owned())?,
            )
            .map_err(|_| "controller_session_assertion_invalid".to_owned())?;
            let verified = verify_controller_session(
                &identity,
                &assertion,
                endpoint,
                controller_session_value(args, "--controller-peer-id")?,
                challenge,
                now_ms,
            )
            .map_err(|error| format!("controller_session_verification_failed: {error:?}"))?;
            json(&verified).map_err(|error| error.to_string())
        }
        _ => Err("controller-session requires issue or verify".into()),
    }
}
