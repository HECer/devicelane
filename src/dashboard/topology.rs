use crate::dashboard::{
    ConnectionPath, DashboardDevice, DashboardHost, DashboardScope, DashboardSnapshot, DeviceId,
    Freshness, HostId, Presence, SafeCode, TrustState,
};
use crate::network_processes::{DeviceSnapshot, HostSnapshot};
use std::collections::{BTreeMap, HashMap};
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
pub enum LeaseState {
    Active,
    Uncertain,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TopologyError {
    field: &'static str,
    value: String,
}

impl TopologyError {
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
    leases: HashMap<String, StoredLease>,
    local_host_id: Option<HostId>,
    local_revision: Option<u64>,
    registry_revision: Option<u64>,
    registry_authenticated: bool,
    revision: u64,
}

impl TopologyProjector {
    pub fn new() -> Self {
        Self::default()
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
        )?;
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
        self.bump_revision();
        Ok(())
    }

    pub fn observe_registry(
        &mut self,
        source_revision: u64,
        observed_at_ms: u64,
        authenticated: bool,
        hosts: Vec<RegistryHost>,
    ) -> Result<(), TopologyError> {
        if self
            .registry_revision
            .is_some_and(|stored| source_revision <= stored)
        {
            return Ok(());
        }
        let mut projected = Vec::with_capacity(hosts.len());
        for host in hosts {
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
            )?;
            projected.push((host_id, dashboard));
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
        self.registry_revision = Some(source_revision);
        self.registry_authenticated = authenticated;
        self.bump_revision();
        Ok(())
    }

    pub fn mark_disconnected(&mut self, host_id: &HostId, _detected_at_ms: u64) {
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
        self.bump_revision();
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
        if lease_id.trim().is_empty() {
            return Err(invalid("lease_id", lease_id));
        }
        let owner_host_id = parse_host_id(&owner_host_id.into())?;
        let device_id = DeviceId::parse(device_id.into())
            .map_err(|error| invalid("device_id", error.to_string()))?;
        let state = if self.host_is_live(&owner_host_id) {
            LeaseState::Active
        } else {
            LeaseState::Uncertain
        };
        self.leases.insert(
            lease_id,
            StoredLease {
                owner_host_id,
                device_id,
                state,
            },
        );
        self.bump_revision();
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
        })
    }

    fn host_is_live(&self, host_id: &HostId) -> bool {
        self.hosts.get(host_id).is_some_and(|host| {
            !matches!(host.dashboard.freshness, Freshness::Stale { .. })
                && host.dashboard.presence != Presence::Offline
        })
    }

    fn host_owns_device(&self, host_id: &HostId, device_id: &DeviceId) -> bool {
        self.hosts.get(host_id).is_some_and(|host| {
            host.dashboard
                .devices
                .iter()
                .any(|device| device.id == *device_id && device.host_id == *host_id)
        })
    }

    fn bump_revision(&mut self) {
        self.revision = self.revision.saturating_add(1);
    }
}

fn project_host(
    snapshot: HostSnapshot,
    details: Option<(String, Vec<DeviceDetails>)>,
    trust: TrustState,
    connection_path: ConnectionPath,
    permissions: Vec<String>,
    freshness: Freshness,
) -> Result<DashboardHost, TopologyError> {
    let host_id = parse_host_id(&snapshot.id)?;
    let (display_name, device_details) = details
        .map(|(name, devices)| (name, index_device_details(devices)))
        .unwrap_or_else(|| (snapshot.id.clone(), HashMap::new()));
    let mut devices = snapshot
        .devices
        .into_iter()
        .map(|device| {
            let details = device_details.get(&device.id);
            project_device(&host_id, device, details, freshness.clone())
        })
        .collect::<Result<Vec<_>, _>>()?;
    devices.sort_by(|left, right| left.id.cmp(&right.id));
    let mut capabilities = parse_codes(snapshot.capabilities, "capability")?;
    let mut permissions = parse_codes(permissions, "permission")?;
    capabilities.sort();
    capabilities.dedup();
    permissions.sort();
    permissions.dedup();
    Ok(DashboardHost {
        id: host_id,
        display_name,
        platform: parse_code(&snapshot.operating_system, "operating_system")?,
        architecture: parse_code(&snapshot.architecture, "architecture")?,
        presence: parse_presence(&snapshot.status),
        freshness,
        trust,
        connection_path,
        capabilities,
        permissions,
        devices,
    })
}

fn project_device(
    host_id: &HostId,
    snapshot: DeviceSnapshot,
    details: Option<&DeviceDetails>,
    freshness: Freshness,
) -> Result<DashboardDevice, TopologyError> {
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
    Ok(DashboardDevice {
        id,
        host_id: host_id.clone(),
        display_name,
        platform: parse_code(&snapshot.platform, "device_platform")?,
        presence: parse_presence(&snapshot.state),
        freshness,
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

fn invalid(field: &'static str, value: String) -> TopologyError {
    TopologyError { field, value }
}
