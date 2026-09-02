pub use crate::dashboard::model::LeaseState;
use crate::dashboard::{
    ConnectionPath, DashboardDevice, DashboardHost, DashboardLease, DashboardScope,
    DashboardSnapshot, DeviceId, Freshness, HostId, LeaseId, MAX_COLLECTION_ITEMS, MAX_ID_BYTES,
    MAX_TEXT_BYTES, Presence, SafeCode, TrustState,
};
use crate::network_processes::{DeviceSnapshot, HostSnapshot};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;

#[derive(Clone, Debug)]
pub struct DeviceDetails {
    pub id: String,
    pub display_name: String,
    pub capabilities: Vec<String>,
    pub permissions: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct RegistryHost {
    pub snapshot: HostSnapshot,
    pub display_name: String,
    pub trust: TrustState,
    pub connection_path: ConnectionPath,
    pub permissions: Vec<String>,
    pub devices: Vec<DeviceDetails>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TopologyErrorKind {
    InvalidField,
    InvalidTrust,
    InvalidConnectionPath,
    UnauthenticatedRegistry,
    InvalidRegistryEpoch,
    LimitExceeded,
    RevisionExhausted,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TopologyError {
    kind: TopologyErrorKind,
    field: &'static str,
    value: String,
}

impl TopologyError {
    pub fn kind(&self) -> TopologyErrorKind {
        self.kind
    }

    pub fn field(&self) -> &'static str {
        self.field
    }
}

impl fmt::Display for TopologyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid {}: {}", self.field, self.value)
    }
}

impl std::error::Error for TopologyError {}

#[derive(Clone, Debug)]
struct StoredHost {
    dashboard: DashboardHost,
    last_seen_at_ms: u64,
    is_local: bool,
}

#[derive(Clone, Debug)]
struct StoredLease {
    owner_host_id: HostId,
    device_id: DeviceId,
    state: LeaseState,
}

#[derive(Default)]
pub struct TopologyProjector {
    hosts: BTreeMap<HostId, StoredHost>,
    leases: BTreeMap<String, StoredLease>,
    local_host_id: Option<HostId>,
    local_revision: Option<u64>,
    registry_revision: Option<u64>,
    registry_authenticated: bool,
    authenticated_registry: Option<(String, u64)>,
    revision: u64,
}

impl TopologyProjector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn new_at_revision(revision: u64) -> Self {
        Self {
            revision,
            ..Self::default()
        }
    }

    pub fn connect_registry(
        &mut self,
        session_id: impl Into<String>,
        epoch: u64,
        authenticated: bool,
    ) -> Result<(), TopologyError> {
        let session_id = session_id.into();
        if !authenticated {
            self.preflight_revision()?;
            self.registry_authenticated = false;
            self.mark_all_remote_stale();
            self.commit_revision();
            return Ok(());
        }
        validate_identifier("registry_session_id", &session_id)?;
        let is_new_epoch = match &self.authenticated_registry {
            None => true,
            Some((stored_session, stored_epoch)) if stored_session == &session_id => {
                if epoch < *stored_epoch {
                    return Err(error(
                        TopologyErrorKind::InvalidRegistryEpoch,
                        "registry_epoch",
                        epoch.to_string(),
                    ));
                }
                epoch > *stored_epoch
            }
            Some((_, stored_epoch)) => {
                if epoch <= *stored_epoch {
                    return Err(error(
                        TopologyErrorKind::InvalidRegistryEpoch,
                        "registry_epoch",
                        epoch.to_string(),
                    ));
                }
                true
            }
        };
        if is_new_epoch {
            self.preflight_revision()?;
            self.registry_revision = None;
            self.authenticated_registry = Some((session_id, epoch));
        } else {
            self.preflight_revision()?;
        }
        self.registry_authenticated = true;
        self.commit_revision();
        Ok(())
    }

    pub fn disconnect_registry(&mut self, _detected_at_ms: u64) -> Result<(), TopologyError> {
        self.preflight_revision()?;
        self.registry_authenticated = false;
        self.mark_all_remote_stale();
        self.commit_revision();
        Ok(())
    }

    pub fn observe_local(
        &mut self,
        source_revision: u64,
        observed_at_ms: u64,
        snapshot: HostSnapshot,
    ) -> Result<(), TopologyError> {
        if self
            .local_revision
            .is_some_and(|stored| source_revision <= stored)
        {
            return Ok(());
        }
        let host_id = parse_host_id(&snapshot.id)?;
        let freshness = if self.hosts.contains_key(&host_id) {
            Freshness::Live
        } else {
            Freshness::Unknown
        };
        let dashboard = project_host(
            snapshot,
            None,
            TrustState::Local,
            ConnectionPath::Local,
            Vec::new(),
            freshness,
            observed_at_ms,
        )?;
        self.preflight_revision()?;
        if let Some(previous_local) = self.local_host_id.replace(host_id.clone()) {
            if previous_local != host_id {
                self.hosts.remove(&previous_local);
            }
        }
        self.hosts.insert(
            host_id,
            StoredHost {
                dashboard,
                last_seen_at_ms: observed_at_ms,
                is_local: true,
            },
        );
        self.local_revision = Some(source_revision);
        self.commit_revision();
        Ok(())
    }

    pub fn observe_registry(
        &mut self,
        source_revision: u64,
        observed_at_ms: u64,
        authenticated: bool,
        hosts: Vec<RegistryHost>,
    ) -> Result<(), TopologyError> {
        if !authenticated || !self.registry_authenticated {
            self.preflight_revision()?;
            self.registry_authenticated = false;
            self.mark_all_remote_stale();
            self.commit_revision();
            if hosts.is_empty() {
                return Ok(());
            }
            return Err(error(
                TopologyErrorKind::UnauthenticatedRegistry,
                "registry",
                "registry snapshot requires an authenticated session".into(),
            ));
        }
        ensure_limit("hosts", hosts.len())?;
        let local_slots = usize::from(self.local_host_id.is_some());
        ensure_limit("hosts", hosts.len() + local_slots)?;
        if self
            .registry_revision
            .is_some_and(|stored| source_revision <= stored)
        {
            return Ok(());
        }
        let mut projected = Vec::with_capacity(hosts.len());
        for host in hosts {
            if host.trust == TrustState::Local {
                return Err(error(
                    TopologyErrorKind::InvalidTrust,
                    "trust",
                    "remote hosts cannot claim local trust".into(),
                ));
            }
            if !matches!(
                host.connection_path,
                ConnectionPath::Direct | ConnectionPath::Registry
            ) {
                return Err(error(
                    TopologyErrorKind::InvalidConnectionPath,
                    "connection_path",
                    format!("{:?}", host.connection_path),
                ));
            }
            let host_id = parse_host_id(&host.snapshot.id)?;
            if self.local_host_id.as_ref() == Some(&host_id) {
                continue;
            }
            let freshness = if self.hosts.contains_key(&host_id) {
                Freshness::Live
            } else {
                Freshness::Unknown
            };
            let dashboard = project_host(
                host.snapshot,
                Some((host.display_name, host.devices)),
                host.trust,
                host.connection_path,
                host.permissions,
                freshness,
                observed_at_ms,
            )?;
            projected.push((host_id, dashboard));
        }
        self.preflight_revision()?;
        let observed_ids: HashSet<_> = projected.iter().map(|(id, _)| id.clone()).collect();
        let absent_ids: Vec<_> = self
            .hosts
            .iter()
            .filter(|(id, host)| !host.is_local && !observed_ids.contains(*id))
            .map(|(id, _)| id.clone())
            .collect();
        for id in absent_ids {
            self.mark_host_stale(&id);
        }
        for (host_id, dashboard) in projected {
            self.hosts.insert(
                host_id,
                StoredHost {
                    dashboard,
                    last_seen_at_ms: observed_at_ms,
                    is_local: false,
                },
            );
        }
        self.prune_absent_hosts(&observed_ids);
        self.registry_revision = Some(source_revision);
        self.registry_authenticated = authenticated;
        self.commit_revision();
        Ok(())
    }

    pub fn mark_disconnected(
        &mut self,
        host_id: &HostId,
        _detected_at_ms: u64,
    ) -> Result<(), TopologyError> {
        if !self.hosts.contains_key(host_id) {
            return Ok(());
        }
        self.preflight_revision()?;
        self.mark_host_stale(host_id);
        self.commit_revision();
        Ok(())
    }

    pub fn snapshot(&self, generated_at_ms: u64) -> DashboardSnapshot {
        let mut hosts: Vec<_> = self.hosts.values().collect();
        hosts.sort_by(|left, right| {
            right
                .is_local
                .cmp(&left.is_local)
                .then_with(|| left.dashboard.id.cmp(&right.dashboard.id))
        });
        DashboardSnapshot {
            revision: self.revision,
            generated_at_ms,
            scope: if self.registry_authenticated {
                DashboardScope::Mesh
            } else {
                DashboardScope::Local
            },
            hosts: hosts
                .into_iter()
                .map(|host| host.dashboard.clone())
                .collect(),
            activities: Vec::new(),
            leases: self
                .leases
                .iter()
                .map(|(id, lease)| DashboardLease {
                    id: LeaseId::parse(id.clone()).expect("stored lease IDs are validated"),
                    owner_host_id: lease.owner_host_id.clone(),
                    device_id: lease.device_id.clone(),
                    state: lease.state,
                })
                .collect(),
            pending_approvals: Vec::new(),
            warnings: Vec::new(),
        }
    }

    pub fn track_active_lease(
        &mut self,
        lease_id: impl Into<String>,
        owner_host_id: impl Into<String>,
        device_id: impl Into<String>,
    ) -> Result<(), TopologyError> {
        let lease_id = lease_id.into();
        validate_identifier("lease_id", &lease_id)?;
        let owner_host_id = parse_host_id(&owner_host_id.into())?;
        let device_id = DeviceId::parse(device_id.into())
            .map_err(|error| invalid("device_id", error.to_string()))?;
        let state = if self.host_is_connected(&owner_host_id) {
            LeaseState::Active
        } else {
            LeaseState::Uncertain
        };
        let stale_to_remove =
            if !self.leases.contains_key(&lease_id) && self.leases.len() >= MAX_COLLECTION_ITEMS {
                self.leases
                    .iter()
                    .find(|(_, lease)| lease.state == LeaseState::Uncertain)
                    .map(|(id, _)| id.clone())
            } else {
                None
            };
        if !self.leases.contains_key(&lease_id) && stale_to_remove.is_none() {
            ensure_limit("leases", self.leases.len() + 1)?;
        }
        self.preflight_revision()?;
        if let Some(stale_id) = stale_to_remove {
            self.leases.remove(&stale_id);
        }
        self.leases.insert(
            lease_id,
            StoredLease {
                owner_host_id,
                device_id,
                state,
            },
        );
        self.commit_revision();
        Ok(())
    }

    pub fn lease_state(&self, lease_id: &str) -> Option<LeaseState> {
        self.leases.get(lease_id).map(|lease| lease.state)
    }

    pub fn lease_authorizable(&self, lease_id: &str) -> bool {
        self.leases.get(lease_id).is_some_and(|lease| {
            lease.state == LeaseState::Active
                && self.host_is_live(&lease.owner_host_id)
                && self.host_owns_device(&lease.owner_host_id, &lease.device_id)
                && self.host_is_authorized(&lease.owner_host_id)
        })
    }

    fn host_is_live(&self, host_id: &HostId) -> bool {
        self.hosts.get(host_id).is_some_and(|host| {
            host.dashboard.freshness == Freshness::Live
                && host.dashboard.presence == Presence::Online
        })
    }

    fn host_is_connected(&self, host_id: &HostId) -> bool {
        self.hosts.get(host_id).is_some_and(|host| {
            !matches!(host.dashboard.freshness, Freshness::Stale { .. })
                && host.dashboard.presence != Presence::Offline
        })
    }

    fn host_owns_device(&self, host_id: &HostId, device_id: &DeviceId) -> bool {
        self.hosts.get(host_id).is_some_and(|host| {
            host.dashboard.devices.iter().any(|device| {
                device.id == *device_id
                    && device.host_id == *host_id
                    && device.presence == Presence::Online
                    && device.freshness == Freshness::Live
            })
        })
    }

    fn host_is_authorized(&self, host_id: &HostId) -> bool {
        self.hosts.get(host_id).is_some_and(|host| {
            if host.is_local {
                self.local_host_id.as_ref() == Some(host_id)
                    && host.dashboard.trust == TrustState::Local
            } else {
                self.registry_authenticated && host.dashboard.trust == TrustState::Trusted
            }
        })
    }

    fn mark_all_remote_stale(&mut self) {
        let ids: Vec<_> = self
            .hosts
            .iter()
            .filter(|(_, host)| !host.is_local)
            .map(|(id, _)| id.clone())
            .collect();
        for id in ids {
            self.mark_host_stale(&id);
        }
    }

    fn prune_absent_hosts(&mut self, observed_ids: &HashSet<HostId>) {
        if self.hosts.len() <= MAX_COLLECTION_ITEMS {
            return;
        }
        let candidates: Vec<_> = self
            .hosts
            .iter()
            .filter(|(id, host)| !host.is_local && !observed_ids.contains(*id))
            .map(|(id, host)| (host.last_seen_at_ms, id.clone()))
            .collect();
        let mut candidates = candidates;
        candidates.sort();
        for (_, id) in candidates {
            if self.hosts.len() <= MAX_COLLECTION_ITEMS {
                break;
            }
            self.hosts.remove(&id);
        }
    }

    fn mark_host_stale(&mut self, host_id: &HostId) {
        let Some(host) = self.hosts.get_mut(host_id) else {
            return;
        };
        host.dashboard.presence = Presence::Offline;
        host.dashboard.freshness = Freshness::Stale {
            last_seen_at_ms: host.last_seen_at_ms,
        };
        for device in &mut host.dashboard.devices {
            device.presence = Presence::Offline;
            device.freshness = Freshness::Stale {
                last_seen_at_ms: host.last_seen_at_ms,
            };
        }
        for lease in self.leases.values_mut() {
            if lease.owner_host_id == *host_id && lease.state == LeaseState::Active {
                lease.state = LeaseState::Uncertain;
            }
        }
    }

    fn preflight_revision(&self) -> Result<(), TopologyError> {
        self.revision.checked_add(1).map(|_| ()).ok_or_else(|| {
            error(
                TopologyErrorKind::RevisionExhausted,
                "revision",
                self.revision.to_string(),
            )
        })
    }

    fn commit_revision(&mut self) {
        self.revision += 1;
    }
}

fn project_host(
    snapshot: HostSnapshot,
    details: Option<(String, Vec<DeviceDetails>)>,
    trust: TrustState,
    connection_path: ConnectionPath,
    permissions: Vec<String>,
    freshness: Freshness,
    observed_at_ms: u64,
) -> Result<DashboardHost, TopologyError> {
    validate_code_input("operating_system", &snapshot.operating_system)?;
    validate_code_input("architecture", &snapshot.architecture)?;
    validate_raw_text("status", &snapshot.status)?;
    ensure_limit("devices", snapshot.devices.len())?;
    ensure_limit("capabilities", snapshot.capabilities.len())?;
    ensure_limit("permissions", permissions.len())?;
    validate_code_inputs("capability", &snapshot.capabilities)?;
    validate_code_inputs("permission", &permissions)?;
    if let Some((_, devices)) = &details {
        ensure_limit("device_details", devices.len())?;
        for device in devices {
            validate_identifier("device_details.id", &device.id)?;
            validate_display("device_details.display_name", &device.display_name)?;
            ensure_limit("device_details.capabilities", device.capabilities.len())?;
            ensure_limit("device_details.permissions", device.permissions.len())?;
            validate_code_inputs("device_capability", &device.capabilities)?;
            validate_code_inputs("device_permission", &device.permissions)?;
        }
    }
    if let Some((display_name, _)) = &details {
        validate_display("display_name", display_name)?;
    }
    let host_id = parse_host_id(&snapshot.id)?;
    let (display_name, device_details) = details
        .map(|(name, devices)| (name, index_device_details(devices)))
        .unwrap_or_else(|| (snapshot.id.clone(), HashMap::new()));
    let mut devices = snapshot
        .devices
        .into_iter()
        .map(|device| {
            let details = device_details.get(&device.id);
            project_device(&host_id, device, details, freshness.clone(), observed_at_ms)
        })
        .collect::<Result<Vec<_>, _>>()?;
    devices.sort_by(|left, right| left.id.cmp(&right.id));
    let mut capabilities = parse_codes(snapshot.capabilities, "capability")?;
    let mut permissions = parse_codes(permissions, "permission")?;
    capabilities.sort();
    capabilities.dedup();
    permissions.sort();
    permissions.dedup();
    let presence = parse_presence(&snapshot.status);
    let freshness = freshness_for_presence(presence, freshness, observed_at_ms);
    let dashboard = DashboardHost {
        id: host_id,
        display_name,
        platform: parse_code(&snapshot.operating_system, "operating_system")?,
        architecture: parse_code(&snapshot.architecture, "architecture")?,
        presence,
        freshness,
        trust,
        connection_path,
        capabilities,
        permissions,
        devices,
    };
    dashboard
        .validate()
        .map_err(|error| invalid("host", error.to_string()))?;
    Ok(dashboard)
}

fn project_device(
    host_id: &HostId,
    snapshot: DeviceSnapshot,
    details: Option<&DeviceDetails>,
    freshness: Freshness,
    observed_at_ms: u64,
) -> Result<DashboardDevice, TopologyError> {
    validate_code_input("device_platform", &snapshot.platform)?;
    validate_raw_text("device_state", &snapshot.state)?;
    let id = DeviceId::parse(snapshot.id.clone())
        .map_err(|error| invalid("device_id", error.to_string()))?;
    let (display_name, capabilities, permissions) = details.map_or_else(
        || (snapshot.id, Vec::new(), Vec::new()),
        |details| {
            (
                details.display_name.clone(),
                details.capabilities.clone(),
                details.permissions.clone(),
            )
        },
    );
    let mut capabilities = parse_codes(capabilities, "device_capability")?;
    let mut permissions = parse_codes(permissions, "device_permission")?;
    capabilities.sort();
    capabilities.dedup();
    permissions.sort();
    permissions.dedup();
    let presence = parse_presence(&snapshot.state);
    Ok(DashboardDevice {
        id,
        host_id: host_id.clone(),
        display_name,
        platform: parse_code(&snapshot.platform, "device_platform")?,
        presence,
        freshness: freshness_for_presence(presence, freshness, observed_at_ms),
        capabilities,
        permissions,
    })
}

fn index_device_details(devices: Vec<DeviceDetails>) -> HashMap<String, DeviceDetails> {
    devices
        .into_iter()
        .map(|details| (details.id.clone(), details))
        .collect()
}

fn parse_host_id(value: &str) -> Result<HostId, TopologyError> {
    HostId::parse(value.to_owned()).map_err(|error| invalid("host_id", error.to_string()))
}

fn parse_codes(values: Vec<String>, field: &'static str) -> Result<Vec<SafeCode>, TopologyError> {
    values
        .into_iter()
        .map(|value| parse_code(&value, field))
        .collect()
}

fn parse_code(value: &str, field: &'static str) -> Result<SafeCode, TopologyError> {
    let normalized = value.trim().to_ascii_lowercase().replace([' ', '/'], "_");
    SafeCode::parse(normalized).map_err(|error| invalid(field, error.to_string()))
}

fn parse_presence(value: &str) -> Presence {
    match value.trim().to_ascii_lowercase().as_str() {
        "online" | "connected" | "available" => Presence::Online,
        "busy" | "leased" => Presence::Busy,
        "connecting" => Presence::Connecting,
        "attention_required" | "attention-required" => Presence::AttentionRequired,
        "remote_access_paused" | "paused" => Presence::RemoteAccessPaused,
        _ => Presence::Offline,
    }
}

fn freshness_for_presence(
    presence: Presence,
    freshness: Freshness,
    observed_at_ms: u64,
) -> Freshness {
    if presence == Presence::Offline {
        Freshness::Stale {
            last_seen_at_ms: observed_at_ms,
        }
    } else {
        freshness
    }
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), TopologyError> {
    if value.trim().is_empty() || value.len() > MAX_ID_BYTES {
        return Err(invalid(field, value.into()));
    }
    Ok(())
}

fn validate_display(field: &'static str, value: &str) -> Result<(), TopologyError> {
    if value.trim().is_empty() || value.len() > MAX_TEXT_BYTES {
        return Err(invalid(field, value.len().to_string()));
    }
    Ok(())
}

fn validate_code_inputs(field: &'static str, values: &[String]) -> Result<(), TopologyError> {
    if let Some(value) = values.iter().find(|value| value.len() > 128) {
        return Err(invalid(field, value.len().to_string()));
    }
    Ok(())
}

fn validate_code_input(field: &'static str, value: &str) -> Result<(), TopologyError> {
    if value.len() > 128 {
        return Err(invalid(field, value.len().to_string()));
    }
    Ok(())
}

fn validate_raw_text(field: &'static str, value: &str) -> Result<(), TopologyError> {
    if value.len() > MAX_TEXT_BYTES {
        return Err(invalid(field, value.len().to_string()));
    }
    Ok(())
}

fn ensure_limit(field: &'static str, len: usize) -> Result<(), TopologyError> {
    if len > MAX_COLLECTION_ITEMS {
        return Err(error(
            TopologyErrorKind::LimitExceeded,
            field,
            len.to_string(),
        ));
    }
    Ok(())
}

fn invalid(field: &'static str, value: String) -> TopologyError {
    error(TopologyErrorKind::InvalidField, field, value)
}

fn error(kind: TopologyErrorKind, field: &'static str, value: String) -> TopologyError {
    TopologyError { kind, field, value }
}
