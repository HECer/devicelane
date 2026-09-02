use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashSet;
use std::fmt;
use std::hash::Hash;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidationError {
    code: &'static str,
    path: String,
    index: Option<usize>,
}

impl ValidationError {
    fn at(code: &'static str, path: impl Into<String>) -> Self {
        Self {
            code,
            path: path.into(),
            index: None,
        }
    }

    fn at_index(code: &'static str, path: impl Into<String>, index: usize) -> Self {
        Self {
            code,
            path: path.into(),
            index: Some(index),
        }
    }

    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn index(&self) -> Option<usize> {
        self.index
    }

    fn prepend(mut self, prefix: impl AsRef<str>) -> Self {
        let prefix = prefix.as_ref();
        self.path = if self.path.is_empty() {
            prefix.to_owned()
        } else {
            format!("{prefix}.{}", self.path)
        };
        self
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} at {}", self.code, self.path)?;
        if let Some(index) = self.index {
            write!(formatter, "[{index}]")?;
        }
        Ok(())
    }
}

impl std::error::Error for ValidationError {}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ValidatedId(String);

impl ValidatedId {
    pub fn parse(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        if value.len() > MAX_ID_BYTES {
            return Err(ValidationError::at("id_too_long", "id"));
        }
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(ValidationError::at("empty_id", "id"));
        }
        Ok(Self(trimmed.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub const MAX_ID_BYTES: usize = 256;
pub const MAX_TEXT_BYTES: usize = 4096;
pub const MAX_COLLECTION_ITEMS: usize = 128;
pub const MAX_PAGE_ITEMS: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct SafeCode(String);

impl SafeCode {
    pub fn parse(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        if value.is_empty() {
            return Err(ValidationError::at("empty_code", "code"));
        }
        if value.len() > 128 {
            return Err(ValidationError::at("code_too_long", "code"));
        }
        if !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_.-".contains(&byte)
        }) {
            return Err(ValidationError::at("invalid_code", "code"));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for SafeCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum MessageCode {
    ActivityStarted,
    RegistryStale,
    ObserverUnavailable,
    OperationSucceeded,
    OperationFailed,
    TargetOffline,
    RegistryDisconnected,
    DaemonRestarted,
    EventResyncRequired,
    AuditUnavailable,
    ApprovalExpired,
    PolicyDenied,
    LeaseStale,
    OperationCancelled,
    AgentIncompatible,
    AccessDenied,
    TargetConfirmationRequired,
    Redacted,
}

impl MessageCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ActivityStarted => "activity_started",
            Self::RegistryStale => "registry_stale",
            Self::ObserverUnavailable => "observer_unavailable",
            Self::OperationSucceeded => "operation_succeeded",
            Self::OperationFailed => "operation_failed",
            Self::TargetOffline => "target_offline",
            Self::RegistryDisconnected => "registry_disconnected",
            Self::DaemonRestarted => "daemon_restarted",
            Self::EventResyncRequired => "event_resync_required",
            Self::AuditUnavailable => "audit_unavailable",
            Self::ApprovalExpired => "approval_expired",
            Self::PolicyDenied => "policy_denied",
            Self::LeaseStale => "lease_stale",
            Self::OperationCancelled => "operation_cancelled",
            Self::AgentIncompatible => "agent_incompatible",
            Self::AccessDenied => "access_denied",
            Self::TargetConfirmationRequired => "target_confirmation_required",
            Self::Redacted => "redacted",
        }
    }

    pub fn from_safe_str(value: &str) -> Option<Self> {
        Some(match value {
            "activity_started" => Self::ActivityStarted,
            "registry_stale" => Self::RegistryStale,
            "observer_unavailable" => Self::ObserverUnavailable,
            "operation_succeeded" => Self::OperationSucceeded,
            "operation_failed" => Self::OperationFailed,
            "target_offline" => Self::TargetOffline,
            "registry_disconnected" => Self::RegistryDisconnected,
            "daemon_restarted" => Self::DaemonRestarted,
            "event_resync_required" => Self::EventResyncRequired,
            "audit_unavailable" => Self::AuditUnavailable,
            "approval_expired" => Self::ApprovalExpired,
            "policy_denied" => Self::PolicyDenied,
            "lease_stale" => Self::LeaseStale,
            "operation_cancelled" => Self::OperationCancelled,
            "agent_incompatible" => Self::AgentIncompatible,
            "access_denied" => Self::AccessDenied,
            "target_confirmation_required" => Self::TargetConfirmationRequired,
            "redacted" => Self::Redacted,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum MessageParam {
    Local,
    Remote,
    Allowed,
    Denied,
    Unavailable,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, try_from = "DisplayMessageWire")]
pub struct DisplayMessage {
    pub code: MessageCode,
    pub params: Vec<MessageParam>,
}

impl DisplayMessage {
    pub fn new(code: MessageCode, params: Vec<MessageParam>) -> Result<Self, ValidationError> {
        let value = Self { code, params };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_len(self.params.len(), "params")
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DisplayMessageWire {
    code: MessageCode,
    params: Vec<MessageParam>,
}

impl TryFrom<DisplayMessageWire> for DisplayMessage {
    type Error = ValidationError;

    fn try_from(wire: DisplayMessageWire) -> Result<Self, Self::Error> {
        Self::new(wire.code, wire.params)
    }
}

impl Serialize for DisplayMessage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.validate().map_err(serde::ser::Error::custom)?;
        DisplayMessageWire {
            code: self.code,
            params: self.params.clone(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ValidatedId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

macro_rules! define_id {
    ($name:ident) => {
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(ValidatedId);

        impl $name {
            pub fn parse(value: impl Into<String>) -> Result<Self, ValidationError> {
                ValidatedId::parse(value).map(Self)
            }

            pub fn as_str(&self) -> &str {
                self.0.as_str()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }
    };
}

define_id!(HostId);
define_id!(DeviceId);
define_id!(ActivityId);
define_id!(PrincipalId);
define_id!(RuleId);
define_id!(OperationId);
define_id!(ApprovalId);
define_id!(SubscriberId);
define_id!(LeaseId);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum DashboardScope {
    Local,
    Mesh,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Presence {
    Offline,
    Connecting,
    Online,
    Busy,
    AttentionRequired,
    RemoteAccessPaused,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Freshness {
    Live,
    Stale { last_seen_at_ms: u64 },
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum LeaseState {
    Active,
    Uncertain,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    rename_all = "snake_case",
    deny_unknown_fields,
    try_from = "MetricValueWire"
)]
pub enum MetricValue {
    Available { value: u64 },
    Unavailable { reason: SafeCode },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ResourceClass {
    WorkspaceRead,
    WorkspaceWrite,
    ArtifactUpload,
    ArtifactDownload,
    DeviceLease,
    ApplicationInstall,
    ApplicationLaunch,
    Debugger,
    Signing,
    Microphone,
    ScreenCapture,
    NetworkEndpoint,
    DeviceLanePolicy,
    DeviceLaneService,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ActivityState {
    AwaitingApproval,
    Queued,
    Running,
    Reconnecting,
    Succeeded,
    Failed,
    Denied,
    Cancelled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PolicyEffect {
    Allow,
    Deny,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ApprovalDecision {
    AllowOnce,
    AllowAndRemember,
    DenyOnce,
    DenyAndBlock,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum TrustState {
    Local,
    Trusted,
    Untrusted,
    Revoked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ConnectionPath {
    Local,
    Direct,
    Registry,
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PolicyOrigin {
    User,
    Managed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum AuditResult {
    Attempted,
    Succeeded,
    Failed,
    Denied,
    Cancelled,
    Deleted,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, try_from = "DashboardDeviceWire")]
pub struct DashboardDevice {
    pub id: DeviceId,
    pub host_id: HostId,
    pub display_name: String,
    pub platform: SafeCode,
    pub presence: Presence,
    pub freshness: Freshness,
    pub capabilities: Vec<SafeCode>,
    pub permissions: Vec<SafeCode>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, try_from = "DashboardHostWire")]
pub struct DashboardHost {
    pub id: HostId,
    pub display_name: String,
    pub platform: SafeCode,
    pub architecture: SafeCode,
    pub presence: Presence,
    pub freshness: Freshness,
    pub trust: TrustState,
    pub connection_path: ConnectionPath,
    pub capabilities: Vec<SafeCode>,
    pub permissions: Vec<SafeCode>,
    pub devices: Vec<DashboardDevice>,
}

impl DashboardDevice {
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_text(&self.display_name, "display_name")?;
        validate_presence(self.presence, &self.freshness)?;
        validate_len(self.capabilities.len(), "capabilities")?;
        validate_len(self.permissions.len(), "permissions")
    }
}

impl DashboardHost {
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_text(&self.display_name, "display_name")?;
        validate_presence(self.presence, &self.freshness)?;
        validate_len(self.capabilities.len(), "capabilities")?;
        validate_len(self.permissions.len(), "permissions")?;
        validate_len(self.devices.len(), "devices")?;
        for (index, device) in self.devices.iter().enumerate() {
            device
                .validate()
                .map_err(|error| error.prepend(format!("devices[{index}]")))?;
            if device.host_id != self.id {
                return Err(ValidationError::at(
                    "device_host_mismatch",
                    format!("devices[{index}].host_id"),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, try_from = "MetricSnapshotWire")]
pub struct MetricSnapshot {
    pub current_memory_bytes: MetricValue,
    pub peak_memory_bytes: MetricValue,
    pub cpu_time_ms: MetricValue,
    pub process_count: MetricValue,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Authorization {
    pub effect: PolicyEffect,
    pub rule_id: Option<RuleId>,
    pub approval_id: Option<ApprovalId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, try_from = "ActivityEventWire")]
pub struct ActivityEvent {
    pub activity_id: ActivityId,
    pub sequence: u64,
    pub occurred_at_ms: u64,
    pub principal_id: PrincipalId,
    pub source_host_id: HostId,
    pub target_host_id: HostId,
    pub device_id: Option<DeviceId>,
    pub operation: OperationId,
    pub resources: Vec<ResourceClass>,
    pub authorization: Authorization,
    pub state: ActivityState,
    pub message: Option<DisplayMessage>,
    pub metrics: MetricSnapshot,
    pub started_at_ms: Option<u64>,
    pub finished_at_ms: Option<u64>,
}

impl ActivityEvent {
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_unique_resources(&self.resources)?;
        self.metrics.validate()?;
        validate_lifecycle(
            self.state,
            self.started_at_ms,
            self.finished_at_ms,
            Some(self.occurred_at_ms),
        )
    }
}

impl MetricSnapshot {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if let (MetricValue::Available { value: current }, MetricValue::Available { value: peak }) =
            (&self.current_memory_bytes, &self.peak_memory_bytes)
        {
            if peak < current {
                return Err(ValidationError::at(
                    "invalid_metric_snapshot",
                    "metrics.peak_memory_bytes",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, try_from = "ActivitySummaryWire")]
pub struct ActivitySummary {
    pub activity_id: ActivityId,
    pub principal_id: PrincipalId,
    pub source_host_id: HostId,
    pub target_host_id: HostId,
    pub device_id: Option<DeviceId>,
    pub operation: OperationId,
    pub resources: Vec<ResourceClass>,
    pub state: ActivityState,
    pub started_at_ms: Option<u64>,
    pub finished_at_ms: Option<u64>,
}

impl From<&ActivityEvent> for ActivitySummary {
    fn from(event: &ActivityEvent) -> Self {
        Self {
            activity_id: event.activity_id.clone(),
            principal_id: event.principal_id.clone(),
            source_host_id: event.source_host_id.clone(),
            target_host_id: event.target_host_id.clone(),
            device_id: event.device_id.clone(),
            operation: event.operation.clone(),
            resources: event.resources.clone(),
            state: event.state,
            started_at_ms: event.started_at_ms,
            finished_at_ms: event.finished_at_ms,
        }
    }
}

impl ActivitySummary {
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_unique_resources(&self.resources)?;
        validate_lifecycle(self.state, self.started_at_ms, self.finished_at_ms, None)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceOccupancy {
    pub activity_id: ActivityId,
    pub principal_id: PrincipalId,
    pub target_host_id: HostId,
    pub device_id: Option<DeviceId>,
    pub resource: ResourceClass,
    pub acquired_at_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DashboardLease {
    pub id: LeaseId,
    pub owner_host_id: HostId,
    pub device_id: DeviceId,
    pub state: LeaseState,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, try_from = "ApprovalRequestWire")]
pub struct ApprovalRequest {
    pub id: ApprovalId,
    pub activity_id: ActivityId,
    pub principal_id: PrincipalId,
    pub source_host_id: HostId,
    pub target_host_id: HostId,
    pub device_id: Option<DeviceId>,
    pub operation: OperationId,
    pub resources: Vec<ResourceClass>,
    pub requested_at_ms: u64,
    pub expires_at_ms: u64,
    pub risk: SafeCode,
}

impl ApprovalRequest {
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_unique_resources(&self.resources)?;
        if self.requested_at_ms >= self.expires_at_ms {
            return Err(ValidationError::at("non_monotonic_time", "expires_at_ms"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, try_from = "PolicyRuleWire")]
pub struct PolicyRule {
    pub id: RuleId,
    pub revision: u64,
    pub effect: PolicyEffect,
    pub principal_id: Option<PrincipalId>,
    pub source_host_id: Option<HostId>,
    pub target_host_id: Option<HostId>,
    pub device_id: Option<DeviceId>,
    pub operation: Option<OperationId>,
    pub resources: Vec<ResourceClass>,
    pub expires_at_ms: Option<u64>,
    pub require_user_presence: bool,
    pub user_presence: Option<bool>,
    pub physical_device: Option<bool>,
    pub match_device_exact: bool,
    pub match_resources_exact: bool,
    pub enabled: bool,
    pub origin: PolicyOrigin,
}

impl PolicyRule {
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_unique_resources(&self.resources)?;
        if self.require_user_presence && self.user_presence.is_some() {
            return Err(ValidationError::at(
                "redundant_presence_constraints",
                "user_presence",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, try_from = "AuditRecordWire")]
pub struct AuditRecord {
    pub sequence: u64,
    pub occurred_at_ms: u64,
    pub activity_id: Option<ActivityId>,
    pub principal_id: PrincipalId,
    pub source_host_id: HostId,
    pub target_host_id: HostId,
    pub device_id: Option<DeviceId>,
    pub operation: OperationId,
    pub resources: Vec<ResourceClass>,
    pub decision: PolicyEffect,
    pub result: AuditResult,
    pub redacted_message: Option<DisplayMessage>,
}

impl AuditRecord {
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_unique_resources(&self.resources)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, try_from = "DashboardWarningWire")]
pub struct DashboardWarning {
    pub code: SafeCode,
    pub message: DisplayMessage,
    pub host_id: Option<HostId>,
}

impl DashboardWarning {
    pub fn validate(&self) -> Result<(), ValidationError> {
        self.message.validate()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, try_from = "DashboardSnapshotWire")]
pub struct DashboardSnapshot {
    pub revision: u64,
    pub generated_at_ms: u64,
    pub scope: DashboardScope,
    pub hosts: Vec<DashboardHost>,
    pub activities: Vec<ActivitySummary>,
    pub leases: Vec<DashboardLease>,
    pub pending_approvals: Vec<ApprovalRequest>,
    pub warnings: Vec<DashboardWarning>,
}

impl DashboardSnapshot {
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_len(self.hosts.len(), "hosts")?;
        validate_len(self.activities.len(), "activities")?;
        validate_len(self.leases.len(), "leases")?;
        validate_len(self.pending_approvals.len(), "pending_approvals")?;
        validate_len(self.warnings.len(), "warnings")?;
        for (index, host) in self.hosts.iter().enumerate() {
            host.validate()
                .map_err(|error| error.prepend(format!("hosts[{index}]")))?;
        }
        for (index, activity) in self.activities.iter().enumerate() {
            activity
                .validate()
                .map_err(|error| error.prepend(format!("activities[{index}]")))?;
        }
        let mut lease_ids = HashSet::with_capacity(self.leases.len());
        for (index, lease) in self.leases.iter().enumerate() {
            if !lease_ids.insert(&lease.id) {
                return Err(ValidationError::at_index(
                    "duplicate_lease_id",
                    "leases",
                    index,
                ));
            }
            let owner = self
                .hosts
                .iter()
                .find(|host| host.id == lease.owner_host_id);
            if !owner.is_some_and(|host| {
                host.devices
                    .iter()
                    .any(|device| device.id == lease.device_id)
            }) {
                return Err(ValidationError::at(
                    "lease_device_mismatch",
                    format!("leases[{index}].device_id"),
                ));
            }
        }
        for (index, approval) in self.pending_approvals.iter().enumerate() {
            approval
                .validate()
                .map_err(|error| error.prepend(format!("pending_approvals[{index}]")))?;
        }
        for (index, warning) in self.warnings.iter().enumerate() {
            warning
                .validate()
                .map_err(|error| error.prepend(format!("warnings[{index}]")))?;
        }
        Ok(())
    }
}

macro_rules! validate_wire {
    ($wire:ty, $model:ty, $convert:expr) => {
        impl TryFrom<$wire> for $model {
            type Error = ValidationError;

            fn try_from(wire: $wire) -> Result<Self, Self::Error> {
                let value: Self = ($convert)(wire);
                value.validate()?;
                Ok(value)
            }
        }
    };
}

macro_rules! validated_serialize {
    ($model:ty, $wire:ty, $convert:expr) => {
        impl Serialize for $model {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                self.validate().map_err(serde::ser::Error::custom)?;
                let wire: $wire = ($convert)(self);
                wire.serialize(serializer)
            }
        }
    };
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DashboardDeviceWire {
    id: DeviceId,
    host_id: HostId,
    display_name: String,
    platform: SafeCode,
    presence: Presence,
    freshness: Freshness,
    capabilities: Vec<SafeCode>,
    permissions: Vec<SafeCode>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum MetricValueWire {
    Available { value: u64 },
    Unavailable { reason: SafeCode },
}

impl TryFrom<MetricValueWire> for MetricValue {
    type Error = ValidationError;

    fn try_from(wire: MetricValueWire) -> Result<Self, Self::Error> {
        match wire {
            MetricValueWire::Available { value } => Ok(Self::Available { value }),
            MetricValueWire::Unavailable { reason } => Ok(Self::Unavailable { reason }),
        }
    }
}

validate_wire!(
    DashboardDeviceWire,
    DashboardDevice,
    |wire: DashboardDeviceWire| DashboardDevice {
        id: wire.id,
        host_id: wire.host_id,
        display_name: wire.display_name,
        platform: wire.platform,
        presence: wire.presence,
        freshness: wire.freshness,
        capabilities: wire.capabilities,
        permissions: wire.permissions,
    }
);
validated_serialize!(
    DashboardDevice,
    DashboardDeviceWire,
    |value: &DashboardDevice| DashboardDeviceWire {
        id: value.id.clone(),
        host_id: value.host_id.clone(),
        display_name: value.display_name.clone(),
        platform: value.platform.clone(),
        presence: value.presence,
        freshness: value.freshness.clone(),
        capabilities: value.capabilities.clone(),
        permissions: value.permissions.clone(),
    }
);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DashboardHostWire {
    id: HostId,
    display_name: String,
    platform: SafeCode,
    architecture: SafeCode,
    presence: Presence,
    freshness: Freshness,
    trust: TrustState,
    connection_path: ConnectionPath,
    capabilities: Vec<SafeCode>,
    permissions: Vec<SafeCode>,
    devices: Vec<DashboardDevice>,
}

validate_wire!(
    DashboardHostWire,
    DashboardHost,
    |wire: DashboardHostWire| DashboardHost {
        id: wire.id,
        display_name: wire.display_name,
        platform: wire.platform,
        architecture: wire.architecture,
        presence: wire.presence,
        freshness: wire.freshness,
        trust: wire.trust,
        connection_path: wire.connection_path,
        capabilities: wire.capabilities,
        permissions: wire.permissions,
        devices: wire.devices,
    }
);
validated_serialize!(DashboardHost, DashboardHostWire, |value: &DashboardHost| {
    DashboardHostWire {
        id: value.id.clone(),
        display_name: value.display_name.clone(),
        platform: value.platform.clone(),
        architecture: value.architecture.clone(),
        presence: value.presence,
        freshness: value.freshness.clone(),
        trust: value.trust,
        connection_path: value.connection_path,
        capabilities: value.capabilities.clone(),
        permissions: value.permissions.clone(),
        devices: value.devices.clone(),
    }
});

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MetricSnapshotWire {
    current_memory_bytes: MetricValue,
    peak_memory_bytes: MetricValue,
    cpu_time_ms: MetricValue,
    process_count: MetricValue,
}

validate_wire!(
    MetricSnapshotWire,
    MetricSnapshot,
    |wire: MetricSnapshotWire| MetricSnapshot {
        current_memory_bytes: wire.current_memory_bytes,
        peak_memory_bytes: wire.peak_memory_bytes,
        cpu_time_ms: wire.cpu_time_ms,
        process_count: wire.process_count,
    }
);
validated_serialize!(
    MetricSnapshot,
    MetricSnapshotWire,
    |value: &MetricSnapshot| MetricSnapshotWire {
        current_memory_bytes: value.current_memory_bytes.clone(),
        peak_memory_bytes: value.peak_memory_bytes.clone(),
        cpu_time_ms: value.cpu_time_ms.clone(),
        process_count: value.process_count.clone(),
    }
);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivityEventWire {
    activity_id: ActivityId,
    sequence: u64,
    occurred_at_ms: u64,
    principal_id: PrincipalId,
    source_host_id: HostId,
    target_host_id: HostId,
    device_id: Option<DeviceId>,
    operation: OperationId,
    resources: Vec<ResourceClass>,
    authorization: Authorization,
    state: ActivityState,
    message: Option<DisplayMessage>,
    metrics: MetricSnapshot,
    started_at_ms: Option<u64>,
    finished_at_ms: Option<u64>,
}

validate_wire!(
    ActivityEventWire,
    ActivityEvent,
    |wire: ActivityEventWire| ActivityEvent {
        activity_id: wire.activity_id,
        sequence: wire.sequence,
        occurred_at_ms: wire.occurred_at_ms,
        principal_id: wire.principal_id,
        source_host_id: wire.source_host_id,
        target_host_id: wire.target_host_id,
        device_id: wire.device_id,
        operation: wire.operation,
        resources: wire.resources,
        authorization: wire.authorization,
        state: wire.state,
        message: wire.message,
        metrics: wire.metrics,
        started_at_ms: wire.started_at_ms,
        finished_at_ms: wire.finished_at_ms,
    }
);
validated_serialize!(ActivityEvent, ActivityEventWire, |value: &ActivityEvent| {
    ActivityEventWire {
        activity_id: value.activity_id.clone(),
        sequence: value.sequence,
        occurred_at_ms: value.occurred_at_ms,
        principal_id: value.principal_id.clone(),
        source_host_id: value.source_host_id.clone(),
        target_host_id: value.target_host_id.clone(),
        device_id: value.device_id.clone(),
        operation: value.operation.clone(),
        resources: value.resources.clone(),
        authorization: value.authorization.clone(),
        state: value.state,
        message: value.message.clone(),
        metrics: value.metrics.clone(),
        started_at_ms: value.started_at_ms,
        finished_at_ms: value.finished_at_ms,
    }
});

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivitySummaryWire {
    activity_id: ActivityId,
    principal_id: PrincipalId,
    source_host_id: HostId,
    target_host_id: HostId,
    device_id: Option<DeviceId>,
    operation: OperationId,
    resources: Vec<ResourceClass>,
    state: ActivityState,
    started_at_ms: Option<u64>,
    finished_at_ms: Option<u64>,
}

validate_wire!(
    ActivitySummaryWire,
    ActivitySummary,
    |wire: ActivitySummaryWire| ActivitySummary {
        activity_id: wire.activity_id,
        principal_id: wire.principal_id,
        source_host_id: wire.source_host_id,
        target_host_id: wire.target_host_id,
        device_id: wire.device_id,
        operation: wire.operation,
        resources: wire.resources,
        state: wire.state,
        started_at_ms: wire.started_at_ms,
        finished_at_ms: wire.finished_at_ms,
    }
);
validated_serialize!(
    ActivitySummary,
    ActivitySummaryWire,
    |value: &ActivitySummary| ActivitySummaryWire {
        activity_id: value.activity_id.clone(),
        principal_id: value.principal_id.clone(),
        source_host_id: value.source_host_id.clone(),
        target_host_id: value.target_host_id.clone(),
        device_id: value.device_id.clone(),
        operation: value.operation.clone(),
        resources: value.resources.clone(),
        state: value.state,
        started_at_ms: value.started_at_ms,
        finished_at_ms: value.finished_at_ms,
    }
);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalRequestWire {
    id: ApprovalId,
    activity_id: ActivityId,
    principal_id: PrincipalId,
    source_host_id: HostId,
    target_host_id: HostId,
    device_id: Option<DeviceId>,
    operation: OperationId,
    resources: Vec<ResourceClass>,
    requested_at_ms: u64,
    expires_at_ms: u64,
    risk: SafeCode,
}

validate_wire!(
    ApprovalRequestWire,
    ApprovalRequest,
    |wire: ApprovalRequestWire| ApprovalRequest {
        id: wire.id,
        activity_id: wire.activity_id,
        principal_id: wire.principal_id,
        source_host_id: wire.source_host_id,
        target_host_id: wire.target_host_id,
        device_id: wire.device_id,
        operation: wire.operation,
        resources: wire.resources,
        requested_at_ms: wire.requested_at_ms,
        expires_at_ms: wire.expires_at_ms,
        risk: wire.risk,
    }
);
validated_serialize!(
    ApprovalRequest,
    ApprovalRequestWire,
    |value: &ApprovalRequest| ApprovalRequestWire {
        id: value.id.clone(),
        activity_id: value.activity_id.clone(),
        principal_id: value.principal_id.clone(),
        source_host_id: value.source_host_id.clone(),
        target_host_id: value.target_host_id.clone(),
        device_id: value.device_id.clone(),
        operation: value.operation.clone(),
        resources: value.resources.clone(),
        requested_at_ms: value.requested_at_ms,
        expires_at_ms: value.expires_at_ms,
        risk: value.risk.clone(),
    }
);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyRuleWire {
    id: RuleId,
    revision: u64,
    effect: PolicyEffect,
    principal_id: Option<PrincipalId>,
    source_host_id: Option<HostId>,
    target_host_id: Option<HostId>,
    device_id: Option<DeviceId>,
    operation: Option<OperationId>,
    resources: Vec<ResourceClass>,
    expires_at_ms: Option<u64>,
    require_user_presence: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    user_presence: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    physical_device: Option<bool>,
    #[serde(default)]
    match_device_exact: bool,
    #[serde(default)]
    match_resources_exact: bool,
    enabled: bool,
    origin: PolicyOrigin,
}

validate_wire!(PolicyRuleWire, PolicyRule, |wire: PolicyRuleWire| {
    PolicyRule {
        id: wire.id,
        revision: wire.revision,
        effect: wire.effect,
        principal_id: wire.principal_id,
        source_host_id: wire.source_host_id,
        target_host_id: wire.target_host_id,
        device_id: wire.device_id,
        operation: wire.operation,
        resources: wire.resources,
        expires_at_ms: wire.expires_at_ms,
        require_user_presence: wire.require_user_presence,
        user_presence: wire.user_presence,
        physical_device: wire.physical_device,
        match_device_exact: wire.match_device_exact,
        match_resources_exact: wire.match_resources_exact,
        enabled: wire.enabled,
        origin: wire.origin,
    }
});
validated_serialize!(PolicyRule, PolicyRuleWire, |value: &PolicyRule| {
    PolicyRuleWire {
        id: value.id.clone(),
        revision: value.revision,
        effect: value.effect,
        principal_id: value.principal_id.clone(),
        source_host_id: value.source_host_id.clone(),
        target_host_id: value.target_host_id.clone(),
        device_id: value.device_id.clone(),
        operation: value.operation.clone(),
        resources: value.resources.clone(),
        expires_at_ms: value.expires_at_ms,
        require_user_presence: value.require_user_presence,
        user_presence: value.user_presence,
        physical_device: value.physical_device,
        match_device_exact: value.match_device_exact,
        match_resources_exact: value.match_resources_exact,
        enabled: value.enabled,
        origin: value.origin,
    }
});

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditRecordWire {
    sequence: u64,
    occurred_at_ms: u64,
    activity_id: Option<ActivityId>,
    principal_id: PrincipalId,
    source_host_id: HostId,
    target_host_id: HostId,
    device_id: Option<DeviceId>,
    operation: OperationId,
    resources: Vec<ResourceClass>,
    decision: PolicyEffect,
    result: AuditResult,
    redacted_message: Option<DisplayMessage>,
}

validate_wire!(AuditRecordWire, AuditRecord, |wire: AuditRecordWire| {
    AuditRecord {
        sequence: wire.sequence,
        occurred_at_ms: wire.occurred_at_ms,
        activity_id: wire.activity_id,
        principal_id: wire.principal_id,
        source_host_id: wire.source_host_id,
        target_host_id: wire.target_host_id,
        device_id: wire.device_id,
        operation: wire.operation,
        resources: wire.resources,
        decision: wire.decision,
        result: wire.result,
        redacted_message: wire.redacted_message,
    }
});
validated_serialize!(AuditRecord, AuditRecordWire, |value: &AuditRecord| {
    AuditRecordWire {
        sequence: value.sequence,
        occurred_at_ms: value.occurred_at_ms,
        activity_id: value.activity_id.clone(),
        principal_id: value.principal_id.clone(),
        source_host_id: value.source_host_id.clone(),
        target_host_id: value.target_host_id.clone(),
        device_id: value.device_id.clone(),
        operation: value.operation.clone(),
        resources: value.resources.clone(),
        decision: value.decision,
        result: value.result,
        redacted_message: value.redacted_message.clone(),
    }
});

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DashboardWarningWire {
    code: SafeCode,
    message: DisplayMessage,
    host_id: Option<HostId>,
}

validate_wire!(
    DashboardWarningWire,
    DashboardWarning,
    |wire: DashboardWarningWire| DashboardWarning {
        code: wire.code,
        message: wire.message,
        host_id: wire.host_id,
    }
);
validated_serialize!(
    DashboardWarning,
    DashboardWarningWire,
    |value: &DashboardWarning| DashboardWarningWire {
        code: value.code.clone(),
        message: value.message.clone(),
        host_id: value.host_id.clone(),
    }
);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DashboardSnapshotWire {
    revision: u64,
    generated_at_ms: u64,
    scope: DashboardScope,
    hosts: Vec<DashboardHost>,
    activities: Vec<ActivitySummary>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    leases: Vec<DashboardLease>,
    pending_approvals: Vec<ApprovalRequest>,
    warnings: Vec<DashboardWarning>,
}

validate_wire!(
    DashboardSnapshotWire,
    DashboardSnapshot,
    |wire: DashboardSnapshotWire| DashboardSnapshot {
        revision: wire.revision,
        generated_at_ms: wire.generated_at_ms,
        scope: wire.scope,
        hosts: wire.hosts,
        activities: wire.activities,
        leases: wire.leases,
        pending_approvals: wire.pending_approvals,
        warnings: wire.warnings,
    }
);
validated_serialize!(
    DashboardSnapshot,
    DashboardSnapshotWire,
    |value: &DashboardSnapshot| DashboardSnapshotWire {
        revision: value.revision,
        generated_at_ms: value.generated_at_ms,
        scope: value.scope,
        hosts: value.hosts.clone(),
        activities: value.activities.clone(),
        leases: value.leases.clone(),
        pending_approvals: value.pending_approvals.clone(),
        warnings: value.warnings.clone(),
    }
);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventCursor {
    pub epoch: u64,
    pub sequence: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CursorPage<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<EventCursor>,
}

impl<T> Serialize for CursorPage<T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if self.items.len() > MAX_PAGE_ITEMS {
            return Err(serde::ser::Error::custom(ValidationError::at(
                "page_too_large",
                "items",
            )));
        }
        let mut state = serializer.serialize_struct("CursorPage", 2)?;
        state.serialize_field("items", &self.items)?;
        state.serialize_field("next_cursor", &self.next_cursor)?;
        state.end()
    }
}

impl<'de, T> Deserialize<'de> for CursorPage<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire<T> {
            items: Vec<T>,
            next_cursor: Option<EventCursor>,
        }

        let wire = Wire::<T>::deserialize(deserializer)?;
        if wire.items.len() > MAX_PAGE_ITEMS {
            return Err(serde::de::Error::custom(ValidationError::at(
                "page_too_large",
                "items",
            )));
        }
        Ok(Self {
            items: wire.items,
            next_cursor: wire.next_cursor,
        })
    }
}

fn validate_unique_resources(resources: &[ResourceClass]) -> Result<(), ValidationError> {
    validate_len(resources.len(), "resources")?;
    let mut unique = HashSet::with_capacity(resources.len());
    for (index, resource) in resources.iter().enumerate() {
        if !unique.insert(*resource) {
            return Err(ValidationError::at_index(
                "duplicate_resource_class",
                "resources",
                index,
            ));
        }
    }
    Ok(())
}

fn validate_presence(presence: Presence, freshness: &Freshness) -> Result<(), ValidationError> {
    if matches!(presence, Presence::Offline) && !matches!(freshness, Freshness::Stale { .. }) {
        return Err(ValidationError::at("missing_last_seen_at", "freshness"));
    }
    Ok(())
}

fn validate_lifecycle(
    state: ActivityState,
    started_at_ms: Option<u64>,
    finished_at_ms: Option<u64>,
    occurred_at_ms: Option<u64>,
) -> Result<(), ValidationError> {
    match state {
        ActivityState::AwaitingApproval | ActivityState::Queued => {
            if started_at_ms.is_some() {
                return Err(ValidationError::at(
                    "unexpected_started_at",
                    "started_at_ms",
                ));
            }
            if finished_at_ms.is_some() {
                return Err(ValidationError::at(
                    "unexpected_finished_at",
                    "finished_at_ms",
                ));
            }
        }
        ActivityState::Running | ActivityState::Reconnecting => {
            if started_at_ms.is_none() {
                return Err(ValidationError::at("missing_started_at", "started_at_ms"));
            }
            if finished_at_ms.is_some() {
                return Err(ValidationError::at(
                    "unexpected_finished_at",
                    "finished_at_ms",
                ));
            }
        }
        ActivityState::Succeeded | ActivityState::Failed => {
            if started_at_ms.is_none() {
                return Err(ValidationError::at("missing_started_at", "started_at_ms"));
            }
            if finished_at_ms.is_none() {
                return Err(ValidationError::at("missing_finished_at", "finished_at_ms"));
            }
        }
        ActivityState::Denied | ActivityState::Cancelled => {
            if finished_at_ms.is_none() {
                return Err(ValidationError::at("missing_finished_at", "finished_at_ms"));
            }
        }
    }
    if let (Some(started), Some(occurred)) = (started_at_ms, occurred_at_ms) {
        if started > occurred {
            return Err(ValidationError::at("non_monotonic_time", "occurred_at_ms"));
        }
    }
    if let (Some(started), Some(finished)) = (started_at_ms, finished_at_ms) {
        if started > finished {
            return Err(ValidationError::at("non_monotonic_time", "finished_at_ms"));
        }
    }
    if let (Some(occurred), Some(finished)) = (occurred_at_ms, finished_at_ms) {
        if occurred > finished {
            return Err(ValidationError::at("non_monotonic_time", "finished_at_ms"));
        }
    }
    Ok(())
}

fn validate_len(length: usize, path: &'static str) -> Result<(), ValidationError> {
    if length > MAX_COLLECTION_ITEMS {
        Err(ValidationError::at("collection_too_large", path))
    } else {
        Ok(())
    }
}

fn validate_text(value: &str, path: &'static str) -> Result<(), ValidationError> {
    if value.trim().is_empty() {
        return Err(ValidationError::at("empty_text", path));
    }
    if value.len() > MAX_TEXT_BYTES {
        return Err(ValidationError::at("text_too_long", path));
    }
    Ok(())
}
