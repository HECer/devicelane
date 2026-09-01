use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashSet;
use std::fmt;
use std::hash::Hash;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidationError {
    code: &'static str,
    path: &'static str,
    index: Option<usize>,
}

impl ValidationError {
    fn at(code: &'static str, path: &'static str) -> Self {
        Self {
            code,
            path,
            index: None,
        }
    }

    fn at_index(code: &'static str, path: &'static str, index: usize) -> Self {
        Self {
            code,
            path,
            index: Some(index),
        }
    }

    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn path(&self) -> &'static str {
        self.path
    }

    pub fn index(&self) -> Option<usize> {
        self.index
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
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(ValidationError::at("empty_id", "id"));
        }
        if trimmed.len() > MAX_ID_BYTES {
            return Err(ValidationError::at("id_too_long", "id"));
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct RedactedText(String);

impl RedactedText {
    pub fn parse(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        if value.len() > MAX_TEXT_BYTES {
            return Err(ValidationError::at("text_too_long", "text"));
        }
        let normalized = value.to_ascii_lowercase();
        const FORBIDDEN: [&str; 11] = [
            "bearer ",
            "token=",
            "\"token\"",
            "private_key",
            "private key",
            "environment:",
            "environment=",
            "env=",
            "workspace_content",
            "workspace contents",
            "secret=",
        ];
        if FORBIDDEN.iter().any(|pattern| normalized.contains(pattern)) {
            return Err(ValidationError::at("sensitive_text", "text"));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for RedactedText {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    rename_all = "snake_case",
    deny_unknown_fields,
    try_from = "MetricValueWire"
)]
pub enum MetricValue {
    Available { value: u64 },
    Unavailable { reason: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
    Succeeded,
    Failed,
    Denied,
    Cancelled,
    Deleted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, try_from = "DashboardDeviceWire")]
pub struct DashboardDevice {
    pub id: DeviceId,
    pub host_id: HostId,
    pub display_name: String,
    pub platform: String,
    pub presence: Presence,
    pub freshness: Freshness,
    pub capabilities: Vec<String>,
    pub permissions: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, try_from = "DashboardHostWire")]
pub struct DashboardHost {
    pub id: HostId,
    pub display_name: String,
    pub platform: String,
    pub architecture: String,
    pub presence: Presence,
    pub freshness: Freshness,
    pub trust: TrustState,
    pub connection_path: ConnectionPath,
    pub capabilities: Vec<String>,
    pub permissions: Vec<String>,
    pub devices: Vec<DashboardDevice>,
}

impl DashboardDevice {
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_text(&self.display_name, "display_name")?;
        validate_text(&self.platform, "platform")?;
        validate_presence(self.presence, &self.freshness)?;
        validate_texts(&self.capabilities, "capabilities")?;
        validate_texts(&self.permissions, "permissions")
    }
}

impl DashboardHost {
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_text(&self.display_name, "display_name")?;
        validate_text(&self.platform, "platform")?;
        validate_text(&self.architecture, "architecture")?;
        validate_presence(self.presence, &self.freshness)?;
        validate_texts(&self.capabilities, "capabilities")?;
        validate_texts(&self.permissions, "permissions")?;
        validate_len(self.devices.len(), "devices")?;
        for (index, device) in self.devices.iter().enumerate() {
            device.validate()?;
            if device.host_id != self.id {
                return Err(ValidationError::at_index(
                    "device_host_mismatch",
                    "devices",
                    index,
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
    pub message: Option<RedactedText>,
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
        for value in [
            &self.current_memory_bytes,
            &self.peak_memory_bytes,
            &self.cpu_time_ms,
            &self.process_count,
        ] {
            if matches!(value, MetricValue::Unavailable { reason } if reason.trim().is_empty()) {
                return Err(ValidationError::at("missing_metric_reason", "metrics"));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
    pub risk: String,
}

impl ApprovalRequest {
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_unique_resources(&self.resources)?;
        validate_text(&self.risk, "risk")?;
        if self.requested_at_ms > self.expires_at_ms {
            return Err(ValidationError::at("non_monotonic_time", "expires_at_ms"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
    pub enabled: bool,
    pub origin: PolicyOrigin,
}

impl PolicyRule {
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_unique_resources(&self.resources)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
    pub redacted_message: Option<RedactedText>,
}

impl AuditRecord {
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_unique_resources(&self.resources)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, try_from = "DashboardWarningWire")]
pub struct DashboardWarning {
    pub code: String,
    pub message: RedactedText,
    pub host_id: Option<HostId>,
}

impl DashboardWarning {
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_text(&self.code, "code")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, try_from = "DashboardSnapshotWire")]
pub struct DashboardSnapshot {
    pub revision: u64,
    pub generated_at_ms: u64,
    pub scope: DashboardScope,
    pub hosts: Vec<DashboardHost>,
    pub activities: Vec<ActivitySummary>,
    pub pending_approvals: Vec<ApprovalRequest>,
    pub warnings: Vec<DashboardWarning>,
}

impl DashboardSnapshot {
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_len(self.hosts.len(), "hosts")?;
        validate_len(self.activities.len(), "activities")?;
        validate_len(self.pending_approvals.len(), "pending_approvals")?;
        validate_len(self.warnings.len(), "warnings")?;
        for host in &self.hosts {
            host.validate()?;
        }
        for activity in &self.activities {
            activity.validate()?;
        }
        for approval in &self.pending_approvals {
            approval.validate()?;
        }
        for warning in &self.warnings {
            warning.validate()?;
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DashboardDeviceWire {
    id: DeviceId,
    host_id: HostId,
    display_name: String,
    platform: String,
    presence: Presence,
    freshness: Freshness,
    capabilities: Vec<String>,
    permissions: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum MetricValueWire {
    Available { value: u64 },
    Unavailable { reason: String },
}

impl TryFrom<MetricValueWire> for MetricValue {
    type Error = ValidationError;

    fn try_from(wire: MetricValueWire) -> Result<Self, Self::Error> {
        match wire {
            MetricValueWire::Available { value } => Ok(Self::Available { value }),
            MetricValueWire::Unavailable { reason } => {
                validate_text(&reason, "reason")?;
                Ok(Self::Unavailable { reason })
            }
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DashboardHostWire {
    id: HostId,
    display_name: String,
    platform: String,
    architecture: String,
    presence: Presence,
    freshness: Freshness,
    trust: TrustState,
    connection_path: ConnectionPath,
    capabilities: Vec<String>,
    permissions: Vec<String>,
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

#[derive(Deserialize)]
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

#[derive(Deserialize)]
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
    message: Option<RedactedText>,
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

#[derive(Deserialize)]
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

#[derive(Deserialize)]
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
    risk: String,
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

#[derive(Deserialize)]
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
        enabled: wire.enabled,
        origin: wire.origin,
    }
});

#[derive(Deserialize)]
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
    redacted_message: Option<RedactedText>,
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DashboardWarningWire {
    code: String,
    message: RedactedText,
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DashboardSnapshotWire {
    revision: u64,
    generated_at_ms: u64,
    scope: DashboardScope,
    hosts: Vec<DashboardHost>,
    activities: Vec<ActivitySummary>,
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
        pending_approvals: wire.pending_approvals,
        warnings: wire.warnings,
    }
);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventCursor {
    pub epoch: u64,
    pub sequence: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CursorPage<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<EventCursor>,
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
        ActivityState::Succeeded
        | ActivityState::Failed
        | ActivityState::Denied
        | ActivityState::Cancelled => {
            if started_at_ms.is_none() {
                return Err(ValidationError::at("missing_started_at", "started_at_ms"));
            }
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

fn validate_texts(values: &[String], path: &'static str) -> Result<(), ValidationError> {
    validate_len(values.len(), path)?;
    for value in values {
        validate_text(value, path)?;
    }
    Ok(())
}
