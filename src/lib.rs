pub mod protocol {
    use prost::{Enumeration, Message};

    #[derive(Clone, Copy, PartialEq, Eq, Message)]
    pub struct ProtocolVersion {
        #[prost(uint32, tag = "1")]
        pub major: u32,
        #[prost(uint32, tag = "2")]
        pub minor: u32,
    }

    #[derive(Clone, PartialEq, Message)]
    pub struct Host {
        #[prost(message, optional, tag = "1")]
        pub version: Option<ProtocolVersion>,
        #[prost(string, tag = "2")]
        pub id: String,
        #[prost(string, tag = "3")]
        pub operating_system: String,
        #[prost(string, tag = "4")]
        pub architecture: String,
    }

    #[derive(Clone, PartialEq, Message)]
    pub struct Device {
        #[prost(message, optional, tag = "1")]
        pub version: Option<ProtocolVersion>,
        #[prost(string, tag = "2")]
        pub id: String,
        #[prost(string, tag = "3")]
        pub host_id: String,
        #[prost(string, tag = "4")]
        pub platform: String,
        #[prost(string, tag = "5")]
        pub state: String,
    }

    #[derive(Clone, PartialEq, Message)]
    pub struct Capability {
        #[prost(message, optional, tag = "1")]
        pub version: Option<ProtocolVersion>,
        #[prost(string, tag = "2")]
        pub name: String,
        #[prost(uint32, tag = "3")]
        pub revision: u32,
    }

    #[derive(Clone, PartialEq, Message)]
    pub struct Job {
        #[prost(message, optional, tag = "1")]
        pub version: Option<ProtocolVersion>,
        #[prost(string, tag = "2")]
        pub id: String,
        #[prost(string, tag = "3")]
        pub capability: String,
        #[prost(string, tag = "4")]
        pub state: String,
    }

    #[derive(Clone, PartialEq, Message)]
    pub struct Event {
        #[prost(message, optional, tag = "1")]
        pub version: Option<ProtocolVersion>,
        #[prost(string, tag = "2")]
        pub job_id: String,
        #[prost(uint64, tag = "3")]
        pub sequence: u64,
        #[prost(string, tag = "4")]
        pub kind: String,
        #[prost(bytes = "vec", tag = "5")]
        pub payload: Vec<u8>,
    }

    #[derive(Clone, PartialEq, Message)]
    pub struct Artifact {
        #[prost(message, optional, tag = "1")]
        pub version: Option<ProtocolVersion>,
        #[prost(string, tag = "2")]
        pub id: String,
        #[prost(string, tag = "3")]
        pub job_id: String,
        #[prost(string, tag = "4")]
        pub sha256: String,
        #[prost(uint64, tag = "5")]
        pub size_bytes: u64,
        #[prost(string, tag = "6")]
        pub media_type: String,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Enumeration)]
    pub enum RetryClass {
        Never = 0,
        Immediate = 1,
        Backoff = 2,
        AfterRepair = 3,
    }

    #[derive(Clone, PartialEq, Message)]
    pub struct RepairAction {
        #[prost(string, tag = "1")]
        pub description: String,
        #[prost(string, optional, tag = "2")]
        pub command: Option<String>,
    }

    #[derive(Clone, PartialEq, Message)]
    struct WireError {
        #[prost(string, tag = "1")]
        code: String,
        #[prost(string, tag = "2")]
        message: String,
        #[prost(enumeration = "RetryClass", tag = "3")]
        retry_class: i32,
        #[prost(message, optional, tag = "4")]
        repair_action: Option<RepairAction>,
    }

    #[derive(Clone, Debug, PartialEq)]
    pub struct Error {
        code: String,
        message: String,
        retry_class: RetryClass,
        repair_action: Option<RepairAction>,
    }

    impl Error {
        pub fn new(
            code: impl Into<String>,
            message: impl Into<String>,
            retry_class: RetryClass,
            repair_action: Option<RepairAction>,
        ) -> Result<Self, &'static str> {
            let code = code.into();
            let message = message.into();
            if code.is_empty() {
                return Err("error code must not be empty");
            }
            if message.is_empty() {
                return Err("error message must not be empty");
            }
            Ok(Self {
                code,
                message,
                retry_class,
                repair_action,
            })
        }

        pub fn encode_to_vec(&self) -> Vec<u8> {
            WireError {
                code: self.code.clone(),
                message: self.message.clone(),
                retry_class: self.retry_class.into(),
                repair_action: self.repair_action.clone(),
            }
            .encode_to_vec()
        }

        pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
            let wire = WireError::decode(bytes).map_err(|_| "invalid error encoding")?;
            let retry_class =
                RetryClass::try_from(wire.retry_class).map_err(|_| "unknown retry class")?;
            Self::new(wire.code, wire.message, retry_class, wire.repair_action)
        }

        pub fn code(&self) -> &str {
            &self.code
        }

        pub fn message(&self) -> &str {
            &self.message
        }

        pub fn retry_class(&self) -> RetryClass {
            self.retry_class
        }

        pub fn repair_action(&self) -> Option<&RepairAction> {
            self.repair_action.as_ref()
        }
    }
}

pub mod identity {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    static NEXT_ID: AtomicU64 = AtomicU64::new(1);

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Certificate {
        machine_id: String,
        fingerprint: String,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum AuditEvent {
        PairingSucceeded { peer_id: String },
        PairingRejected { reason: &'static str },
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum PairingError {
        InvalidCode,
        CodeExpired,
        CodeReused,
        TlsRequired,
        UntrustedPeer,
        InvalidCertificate,
    }

    struct PairingCode {
        value: String,
        lifetime: Duration,
        consumed: bool,
    }

    pub struct MachineIdentity {
        id: String,
        certificate: Certificate,
        pairing_code: Option<PairingCode>,
        trusted: HashMap<String, Certificate>,
        audit: Vec<AuditEvent>,
    }

    impl MachineIdentity {
        pub fn new(id: impl Into<String>) -> Result<Self, PairingError> {
            let id = id.into();
            if id.is_empty() {
                return Err(PairingError::InvalidCertificate);
            }
            let nonce = NEXT_ID.fetch_add(1, Ordering::Relaxed);
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            Ok(Self {
                certificate: Certificate {
                    machine_id: id.clone(),
                    fingerprint: format!("{now:032x}{nonce:016x}"),
                },
                id,
                pairing_code: None,
                trusted: HashMap::new(),
                audit: Vec::new(),
            })
        }

        pub fn certificate(&self) -> &Certificate {
            &self.certificate
        }

        pub fn issue_pairing_code(&mut self, lifetime: Duration) -> String {
            let nonce = NEXT_ID.fetch_add(1, Ordering::Relaxed);
            let value = format!("{:06}", nonce % 1_000_000);
            self.pairing_code = Some(PairingCode {
                value: value.clone(),
                lifetime,
                consumed: false,
            });
            value
        }

        pub fn accept_pairing(
            &mut self,
            code: &str,
            peer: &Certificate,
            elapsed: Duration,
        ) -> Result<Certificate, PairingError> {
            let result: Result<(), (PairingError, &'static str)> = match self.pairing_code.as_mut()
            {
                Some(pairing) if pairing.value != code => {
                    Err((PairingError::InvalidCode, "invalid_code"))
                }
                Some(pairing) if pairing.consumed => Err((PairingError::CodeReused, "code_reused")),
                Some(pairing) if elapsed > pairing.lifetime => {
                    Err((PairingError::CodeExpired, "code_expired"))
                }
                Some(pairing) => {
                    pairing.consumed = true;
                    self.trusted.insert(peer.machine_id.clone(), peer.clone());
                    self.audit.push(AuditEvent::PairingSucceeded {
                        peer_id: peer.machine_id.clone(),
                    });
                    return Ok(self.certificate.clone());
                }
                None => Err((PairingError::InvalidCode, "invalid_code")),
            };
            let (error, reason) = result.unwrap_err();
            self.audit.push(AuditEvent::PairingRejected { reason });
            Err(error)
        }

        pub fn trust(
            &mut self,
            peer_id: &str,
            certificate: &Certificate,
        ) -> Result<(), PairingError> {
            if peer_id != certificate.machine_id || certificate.fingerprint.is_empty() {
                return Err(PairingError::InvalidCertificate);
            }
            self.trusted.insert(peer_id.to_owned(), certificate.clone());
            Ok(())
        }

        pub fn mutual_tls_with(&self, peer: &MachineIdentity) -> Result<(), PairingError> {
            match self.trusted.get(&peer.id) {
                Some(certificate) if certificate == peer.certificate() => Ok(()),
                _ => Err(PairingError::UntrustedPeer),
            }
        }

        pub fn accept_unencrypted(&self, _peer_id: &str) -> Result<(), PairingError> {
            Err(PairingError::TlsRequired)
        }

        pub fn audit_log(&self) -> &[AuditEvent] {
            &self.audit
        }
    }
}

pub mod discovery {
    use std::collections::HashMap;
    use std::time::Duration;

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct CapabilitySnapshot {
        pub capabilities: Vec<String>,
        pub toolchains: Vec<String>,
    }

    pub struct AgentHeartbeat {
        pub agent_id: String,
        pub operating_system: String,
        pub architecture: String,
        pub snapshot: CapabilitySnapshot,
    }

    pub struct Agent {
        heartbeat: AgentHeartbeat,
    }

    impl Agent {
        pub fn new(heartbeat: AgentHeartbeat) -> Self {
            Self { heartbeat }
        }

        pub fn start(self, registry: &mut Registry, now: Duration) {
            registry.record_heartbeat(self.heartbeat, now);
        }
    }

    struct AgentRecord {
        heartbeat: AgentHeartbeat,
        last_seen: Duration,
        snapshot_revision: u64,
    }

    pub struct Registry {
        heartbeat_window: Duration,
        agents: HashMap<String, AgentRecord>,
    }

    impl Registry {
        pub fn new(heartbeat_window: Duration) -> Self {
            Self {
                heartbeat_window,
                agents: HashMap::new(),
            }
        }

        pub fn record_heartbeat(&mut self, heartbeat: AgentHeartbeat, now: Duration) {
            let revision = self
                .agents
                .get(&heartbeat.agent_id)
                .map(|record| {
                    record.snapshot_revision
                        + u64::from(record.heartbeat.snapshot != heartbeat.snapshot)
                })
                .unwrap_or(1);
            self.agents.insert(
                heartbeat.agent_id.clone(),
                AgentRecord {
                    heartbeat,
                    last_seen: now,
                    snapshot_revision: revision,
                },
            );
        }

        pub fn snapshot_revision(&self, agent_id: &str) -> Option<u64> {
            self.agents
                .get(agent_id)
                .map(|record| record.snapshot_revision)
        }

        pub fn cli_agents(&self, now: Duration) -> String {
            self.agents
                .values()
                .map(|record| {
                    let agent = &record.heartbeat;
                    let status = if now.saturating_sub(record.last_seen) >= self.heartbeat_window {
                        "offline"
                    } else {
                        "online"
                    };
                    format!(
                        "{} {} {} {} {} revision={} {status}",
                        agent.agent_id,
                        agent.operating_system,
                        agent.architecture,
                        agent.snapshot.capabilities.join(","),
                        agent.snapshot.toolchains.join(","),
                        record.snapshot_revision
                    )
                })
                .collect::<Vec<_>>()
                .join("\n")
        }
    }
}

pub mod authorization {
    use std::collections::{HashMap, HashSet};
    use std::time::{Duration, Instant};

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub enum Role {
        Operator,
        Observer,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Operation<'a> {
        ReadLogs,
        StartProcess { device_id: &'a str },
        InstallDevice { device_id: &'a str },
    }

    impl Operation<'_> {
        fn capability(&self) -> &str {
            match self {
                Self::ReadLogs => "logs.read",
                Self::StartProcess { .. } => "process.start",
                Self::InstallDevice { .. } => "device.install",
            }
        }

        fn device_id(&self) -> Option<&str> {
            match self {
                Self::ReadLogs => None,
                Self::StartProcess { device_id } | Self::InstallDevice { device_id } => {
                    Some(device_id)
                }
            }
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum AuthorizationError {
        CapabilityDenied,
        DeviceAlreadyLeased,
        LeaseInactive,
        ObserverReadOnly,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct LeaseId(u64);

    struct Lease {
        device_id: String,
        holder: String,
        expires_at: Instant,
        revoked: bool,
    }

    struct Principal {
        role: Role,
        capabilities: HashSet<String>,
    }

    pub struct PolicyEngine {
        principals: HashMap<String, Principal>,
        leases: HashMap<LeaseId, Lease>,
        next_lease_id: u64,
    }

    impl PolicyEngine {
        pub fn new() -> Self {
            Self {
                principals: HashMap::new(),
                leases: HashMap::new(),
                next_lease_id: 1,
            }
        }

        pub fn grant(
            &mut self,
            actor: impl Into<String>,
            role: Role,
            capability: impl Into<String>,
        ) {
            let principal = self.principals.entry(actor.into()).or_insert(Principal {
                role,
                capabilities: HashSet::new(),
            });
            principal.role = role;
            principal.capabilities.insert(capability.into());
        }

        pub fn acquire_lease(
            &mut self,
            device_id: &str,
            holder: &str,
            lifetime: Duration,
        ) -> Result<LeaseId, AuthorizationError> {
            if self.principals.get(holder).map(|principal| principal.role) != Some(Role::Operator) {
                return Err(AuthorizationError::ObserverReadOnly);
            }
            let now = Instant::now();
            if self.leases.values().any(|lease| {
                lease.device_id == device_id && !lease.revoked && now < lease.expires_at
            }) {
                return Err(AuthorizationError::DeviceAlreadyLeased);
            }
            let id = LeaseId(self.next_lease_id);
            self.next_lease_id += 1;
            self.leases.insert(
                id,
                Lease {
                    device_id: device_id.to_owned(),
                    holder: holder.to_owned(),
                    expires_at: now + lifetime,
                    revoked: false,
                },
            );
            Ok(id)
        }

        pub fn revoke_lease(&mut self, lease_id: LeaseId) {
            if let Some(lease) = self.leases.get_mut(&lease_id) {
                lease.revoked = true;
            }
        }

        pub fn lease_is_active(&self, lease_id: LeaseId) -> bool {
            let now = Instant::now();
            self.leases
                .get(&lease_id)
                .is_some_and(|lease| !lease.revoked && now < lease.expires_at)
        }

        pub fn execute<T>(
            &mut self,
            actor: &str,
            operation: Operation<'_>,
            lease_id: Option<LeaseId>,
            adapter: impl FnOnce() -> T,
        ) -> Result<T, AuthorizationError> {
            let Some(principal) = self.principals.get(actor) else {
                return Err(AuthorizationError::CapabilityDenied);
            };
            if !principal.capabilities.contains(operation.capability()) {
                return Err(AuthorizationError::CapabilityDenied);
            }
            let device_id = operation.device_id();
            if principal.role == Role::Observer && device_id.is_some() {
                return Err(AuthorizationError::ObserverReadOnly);
            }
            if let Some(device_id) = device_id {
                let Some(lease_id) = lease_id else {
                    return Err(AuthorizationError::LeaseInactive);
                };
                let now = Instant::now();
                let active_for_device = self.leases.get(&lease_id).is_some_and(|lease| {
                    lease.device_id == device_id
                        && lease.holder == actor
                        && !lease.revoked
                        && now < lease.expires_at
                });
                if !active_for_device {
                    return Err(AuthorizationError::LeaseInactive);
                }
            }
            Ok(adapter())
        }
    }

    impl Default for PolicyEngine {
        fn default() -> Self {
            Self::new()
        }
    }
}

pub mod workspace {
    use cap_std::ambient_authority;
    use cap_std::fs::Dir;
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;
    use std::fs;
    use std::fs::OpenOptions;
    use std::io::{ErrorKind, Write};
    use std::path::{Component, Path, PathBuf};

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum WorkspaceError {
        PathEscape,
        WriteLeaseConflict,
        WriteLeaseRequired,
        Io,
    }

    pub struct ManifestEntry {
        path: PathBuf,
        contents: Vec<u8>,
    }

    impl ManifestEntry {
        pub fn new(path: impl Into<PathBuf>, contents: Vec<u8>) -> Self {
            Self {
                path: path.into(),
                contents,
            }
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    pub struct ManifestHash {
        path: String,
        sha256: String,
    }

    impl ManifestHash {
        pub fn path(&self) -> &str {
            &self.path
        }

        pub fn sha256(&self) -> &str {
            &self.sha256
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    pub struct Manifest {
        entries: Vec<ManifestHash>,
    }

    impl Manifest {
        pub fn entries(&self) -> &[ManifestHash] {
            &self.entries
        }
    }

    pub struct WorkspaceManager {
        root: PathBuf,
        root_dir: Dir,
        write_leases: HashMap<(String, String), String>,
    }

    impl WorkspaceManager {
        pub fn new(root: impl AsRef<Path>) -> Result<Self, WorkspaceError> {
            fs::create_dir_all(root.as_ref()).map_err(|_| WorkspaceError::Io)?;
            let root = fs::canonicalize(root.as_ref()).map_err(|_| WorkspaceError::Io)?;
            let root_dir = Dir::open_ambient_dir(&root, ambient_authority())
                .map_err(|_| WorkspaceError::Io)?;
            Ok(Self {
                root,
                root_dir,
                write_leases: HashMap::new(),
            })
        }

        pub fn acquire_write_lease(
            &mut self,
            agent_id: &str,
            session_id: &str,
            client_id: &str,
        ) -> Result<(), WorkspaceError> {
            validate_agent_name(agent_id)?;
            validate_name(session_id)?;
            let key = (agent_id.to_owned(), session_id.to_owned());
            if self
                .write_leases
                .get(&key)
                .is_some_and(|holder| holder != client_id)
            {
                return Err(WorkspaceError::WriteLeaseConflict);
            }
            let session = self.root.join(agent_id).join(session_id);
            fs::create_dir_all(&session).map_err(|_| WorkspaceError::Io)?;
            if !fs::canonicalize(&session)
                .map_err(|_| WorkspaceError::Io)?
                .starts_with(&self.root)
            {
                return Err(WorkspaceError::PathEscape);
            }
            let lease = self.root.join(".leases").join(agent_id).join(session_id);
            fs::create_dir_all(lease.parent().unwrap()).map_err(|_| WorkspaceError::Io)?;
            match OpenOptions::new().write(true).create_new(true).open(&lease) {
                Ok(mut file) => file
                    .write_all(client_id.as_bytes())
                    .map_err(|_| WorkspaceError::Io)?,
                Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                    if fs::read_to_string(&lease).map_err(|_| WorkspaceError::Io)? != client_id {
                        return Err(WorkspaceError::WriteLeaseConflict);
                    }
                }
                Err(_) => return Err(WorkspaceError::Io),
            }
            self.write_leases.insert(key, client_id.to_owned());
            Ok(())
        }

        pub fn upload_manifest(
            &self,
            agent_id: &str,
            session_id: &str,
            client_id: &str,
            entries: Vec<ManifestEntry>,
        ) -> Result<Manifest, WorkspaceError> {
            validate_agent_name(agent_id)?;
            validate_name(session_id)?;
            if self
                .write_leases
                .get(&(agent_id.to_owned(), session_id.to_owned()))
                .map(String::as_str)
                != Some(client_id)
            {
                return Err(WorkspaceError::WriteLeaseRequired);
            }
            let session = fs::canonicalize(self.root.join(agent_id).join(session_id))
                .map_err(|_| WorkspaceError::Io)?;
            let session_dir = self
                .root_dir
                .open_dir(Path::new(agent_id).join(session_id))
                .map_err(|_| WorkspaceError::PathEscape)?;
            let mut hashes = Vec::with_capacity(entries.len());
            for entry in entries {
                validate_relative_path(&entry.path)?;
                let destination = session.join(&entry.path);
                let mut ancestor = destination.parent().ok_or(WorkspaceError::PathEscape)?;
                while !ancestor.exists() {
                    ancestor = ancestor.parent().ok_or(WorkspaceError::PathEscape)?;
                }
                if !fs::canonicalize(ancestor)
                    .map_err(|_| WorkspaceError::Io)?
                    .starts_with(&session)
                {
                    return Err(WorkspaceError::PathEscape);
                }
                if fs::symlink_metadata(&destination)
                    .is_ok_and(|metadata| metadata.file_type().is_symlink())
                {
                    return Err(WorkspaceError::PathEscape);
                }
                session_dir
                    .create_dir_all(entry.path.parent().unwrap())
                    .map_err(|_| WorkspaceError::PathEscape)?;
                session_dir
                    .write(&entry.path, &entry.contents)
                    .map_err(|_| WorkspaceError::PathEscape)?;
                hashes.push(ManifestHash {
                    path: entry.path.to_string_lossy().replace('\\', "/"),
                    sha256: format!("{:x}", Sha256::digest(&entry.contents)),
                });
            }
            Ok(Manifest { entries: hashes })
        }
    }

    fn validate_name(name: &str) -> Result<(), WorkspaceError> {
        validate_relative_path(Path::new(name))
    }

    fn validate_agent_name(name: &str) -> Result<(), WorkspaceError> {
        if name.eq_ignore_ascii_case(".leases") {
            return Err(WorkspaceError::PathEscape);
        }
        validate_name(name)
    }

    fn validate_relative_path(path: &Path) -> Result<(), WorkspaceError> {
        if path.as_os_str().is_empty()
            || path.is_absolute()
            || path
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(WorkspaceError::PathEscape);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn workspace_package_is_available() {
        assert_eq!(env!("CARGO_PKG_NAME"), "device-development-mesh");
    }
}
