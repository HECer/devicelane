use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashSet;
use std::fmt;
use std::hash::Hash;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidationError {
    code: &'static str,
}

impl ValidationError {
    fn new(code: &'static str) -> Self {
        Self { code }
    }

    pub fn code(&self) -> &'static str {
        self.code
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code)
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
            return Err(ValidationError::new("empty_id"));
        }
        Ok(Self(trimmed.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
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
#[serde(rename_all = "snake_case")]
pub enum DashboardScope {
    Local,
    Mesh,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Presence {
    Offline,
    Connecting,
    Online,
    Busy,
    AttentionRequired,
    RemoteAccessPaused,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Freshness {
    Live,
    Stale { last_seen_at_ms: u64 },
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricValue {
    Available { value: u64 },
    Unavailable { reason: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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
#[serde(rename_all = "snake_case")]
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

impl ActivityState {
    fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::Denied | Self::Cancelled
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyEffect {
    Allow,
    Deny,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecision {
    AllowOnce,
    AllowAndRemember,
    DenyOnce,
    DenyAndBlock,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustState {
    Local,
    Trusted,
    Untrusted,
    Revoked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionPath {
    Local,
    Direct,
    Registry,
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyOrigin {
    User,
    Managed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditResult {
    Succeeded,
    Failed,
    Denied,
    Cancelled,
    Deleted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
    pub message: Option<String>,
    pub metrics: MetricSnapshot,
    pub started_at_ms: Option<u64>,
    pub finished_at_ms: Option<u64>,
}

impl ActivityEvent {
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_unique_resources(&self.resources)?;
        self.metrics.validate()?;
        if self.state.is_terminal() && self.finished_at_ms.is_none() {
            return Err(ValidationError::new("missing_finished_at"));
        }
        if !self.state.is_terminal() && self.finished_at_ms.is_some() {
            return Err(ValidationError::new("unexpected_finished_at"));
        }
        Ok(())
    }
}

impl MetricSnapshot {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if let (MetricValue::Available { value: current }, MetricValue::Available { value: peak }) =
            (&self.current_memory_bytes, &self.peak_memory_bytes)
            && peak < current
        {
            return Err(ValidationError::new("invalid_metric_snapshot"));
        }
        for value in [
            &self.current_memory_bytes,
            &self.peak_memory_bytes,
            &self.cpu_time_ms,
            &self.process_count,
        ] {
            if matches!(value, MetricValue::Unavailable { reason } if reason.trim().is_empty()) {
                return Err(ValidationError::new("missing_metric_reason"));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
    pub redacted_message: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DashboardWarning {
    pub code: String,
    pub message: String,
    pub host_id: Option<HostId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
        for host in &self.hosts {
            validate_presence(host.presence, &host.freshness)?;
            for device in &host.devices {
                if device.host_id != host.id {
                    return Err(ValidationError::new("device_host_mismatch"));
                }
                validate_presence(device.presence, &device.freshness)?;
            }
        }
        for activity in &self.activities {
            validate_unique_resources(&activity.resources)?;
            if activity.state.is_terminal() && activity.finished_at_ms.is_none() {
                return Err(ValidationError::new("missing_finished_at"));
            }
        }
        for approval in &self.pending_approvals {
            validate_unique_resources(&approval.resources)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventCursor {
    pub epoch: u64,
    pub sequence: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CursorPage<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<EventCursor>,
}

fn validate_unique_resources(resources: &[ResourceClass]) -> Result<(), ValidationError> {
    let mut unique = HashSet::with_capacity(resources.len());
    if resources.iter().any(|resource| !unique.insert(*resource)) {
        return Err(ValidationError::new("duplicate_resource_class"));
    }
    Ok(())
}

fn validate_presence(presence: Presence, freshness: &Freshness) -> Result<(), ValidationError> {
    if matches!(presence, Presence::Offline) && !matches!(freshness, Freshness::Stale { .. }) {
        return Err(ValidationError::new("missing_last_seen_at"));
    }
    Ok(())
}
