use crate::dashboard::audit::{AuditDeletionScope, AuditExport, AuditFilter, ExportManifest};
use crate::dashboard::event_log::EventRead;
use crate::dashboard::model::{
    ActivityId, AuditRecord, CursorPage, DashboardScope, DashboardSnapshot, EventCursor, HostId,
    RuleId, SubscriberId,
};
use crate::dashboard::model::{ApprovalDecision, ApprovalRequest, PolicyRule};
use crate::dashboard::policy::{AccessRequest, PolicyEngine};
use crate::dashboard::service::{AdminMutation, DashboardService, ExistingJobs};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::fmt;
use std::io::{BufRead, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};

/// Opaque proof issued only inside the authorized local IPC dispatch path.
///
/// ```compile_fail
/// use device_development_mesh::{dashboard::HostId, local_ipc::AuthenticatedTargetSession};
/// let _ = AuthenticatedTargetSession { local_host_id: HostId::parse("spoof").unwrap() };
/// ```
pub struct AuthenticatedTargetSession {
    local_host_id: HostId,
}

impl AuthenticatedTargetSession {
    fn issue(local_host_id: HostId) -> Self {
        Self { local_host_id }
    }

    pub(crate) fn local_host_id(&self) -> &HostId {
        &self.local_host_id
    }
}

#[cfg(test)]
pub(crate) fn authenticated_target_session_for_test(
    local_host_id: HostId,
) -> AuthenticatedTargetSession {
    AuthenticatedTargetSession::issue(local_host_id)
}
#[cfg(unix)]
use std::{io, path::PathBuf};

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
compile_error!("local IPC peer credentials are supported only on Linux and macOS Unix targets");

pub const MAX_FRAME_BYTES: usize = 512 * 1024;
pub const MAX_LOCAL_WORKERS: usize = 8;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalProtocolVersion {
    pub major: u16,
    pub minor: u16,
}

impl LocalProtocolVersion {
    pub const CURRENT: Self = Self { major: 1, minor: 1 };

    pub fn is_compatible(self) -> bool {
        self.major == Self::CURRENT.major
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "request", rename_all = "snake_case", deny_unknown_fields)]
pub enum LocalRequest {
    Status {
        version: LocalProtocolVersion,
    },
    PauseRemoteAccess {
        version: LocalProtocolVersion,
    },
    ResumeRemoteAccess {
        version: LocalProtocolVersion,
    },
    SetAutostart {
        version: LocalProtocolVersion,
        enabled: bool,
    },
    Diagnostics {
        version: LocalProtocolVersion,
    },
    RequestApproval {
        version: LocalProtocolVersion,
        access: AccessRequest,
        lifetime_ms: u64,
    },
    RequestAdminMutationApproval {
        version: LocalProtocolVersion,
        mutation: AdminMutation,
        lifetime_ms: u64,
    },
    DecideApproval {
        version: LocalProtocolVersion,
        nonce: String,
        access: AccessRequest,
        decision: ApprovalDecision,
    },
    DecidePendingApproval {
        version: LocalProtocolVersion,
        approval_id: crate::dashboard::ApprovalId,
        decision: ApprovalDecision,
    },
    DashboardSnapshot {
        version: LocalProtocolVersion,
        scope: DashboardScope,
    },
    ActivityEvents {
        version: LocalProtocolVersion,
        #[serde(default = "default_dashboard_scope")]
        scope: DashboardScope,
        cursor: EventCursor,
        limit: usize,
    },
    AcknowledgeEvents {
        version: LocalProtocolVersion,
        subscriber_id: SubscriberId,
        cursor: EventCursor,
    },
    PendingApprovals {
        version: LocalProtocolVersion,
    },
    PendingApprovalForNotification {
        version: LocalProtocolVersion,
        approval_id: crate::dashboard::ApprovalId,
    },
    PolicyRules {
        version: LocalProtocolVersion,
    },
    PutPolicyRule {
        version: LocalProtocolVersion,
        rule: PolicyRule,
    },
    DeletePolicyRule {
        version: LocalProtocolVersion,
        rule_id: RuleId,
    },
    DeletePolicyRuleIfRevision {
        version: LocalProtocolVersion,
        rule_id: RuleId,
        expected_revision: u64,
    },
    AuditQuery {
        version: LocalProtocolVersion,
        filter: AuditFilter,
        cursor: Option<EventCursor>,
        limit: usize,
    },
    AuditExport {
        version: LocalProtocolVersion,
        filter: AuditFilter,
    },
    AuditExportManifest {
        version: LocalProtocolVersion,
        filter: AuditFilter,
    },
    AuditDelete {
        version: LocalProtocolVersion,
        scope: AuditDeletionScope,
        filter: AuditFilter,
    },
    CancelActivity {
        version: LocalProtocolVersion,
        activity_id: ActivityId,
    },
    PauseRemoteAccessWithJobs {
        version: LocalProtocolVersion,
        existing_jobs: ExistingJobs,
    },
}

impl LocalRequest {
    pub fn version(&self) -> LocalProtocolVersion {
        match *self {
            Self::Status { version }
            | Self::PauseRemoteAccess { version }
            | Self::ResumeRemoteAccess { version }
            | Self::SetAutostart { version, .. }
            | Self::Diagnostics { version }
            | Self::RequestApproval { version, .. }
            | Self::RequestAdminMutationApproval { version, .. }
            | Self::DecideApproval { version, .. }
            | Self::DecidePendingApproval { version, .. }
            | Self::DashboardSnapshot { version, .. }
            | Self::ActivityEvents { version, .. }
            | Self::AcknowledgeEvents { version, .. }
            | Self::PendingApprovals { version }
            | Self::PendingApprovalForNotification { version, .. }
            | Self::PolicyRules { version }
            | Self::PutPolicyRule { version, .. }
            | Self::DeletePolicyRule { version, .. }
            | Self::DeletePolicyRuleIfRevision { version, .. }
            | Self::AuditQuery { version, .. }
            | Self::AuditExport { version, .. }
            | Self::AuditExportManifest { version, .. }
            | Self::AuditDelete { version, .. }
            | Self::CancelActivity { version, .. }
            | Self::PauseRemoteAccessWithJobs { version, .. } => version,
        }
    }

    pub fn validate(&self) -> Result<(), LocalProtocolError> {
        self.version()
            .is_compatible()
            .then_some(())
            .ok_or(LocalProtocolError::IncompatibleVersion)?;
        if self.requires_dashboard() && self.version().minor < 1 {
            return Err(LocalProtocolError::FeatureUnavailable);
        }
        Ok(())
    }

    fn requires_dashboard(&self) -> bool {
        !matches!(
            self,
            Self::Status { .. }
                | Self::PauseRemoteAccess { .. }
                | Self::ResumeRemoteAccess { .. }
                | Self::SetAutostart { .. }
                | Self::Diagnostics { .. }
                | Self::RequestApproval { .. }
                | Self::DecideApproval { .. }
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "type",
    content = "payload",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum LocalResponse {
    Snapshot(DaemonSnapshot),
    Acknowledged,
    Diagnostics(Vec<DiagnosticItem>),
    ApprovalCreated {
        nonce: String,
        expires_at_ms: u64,
    },
    ApprovalDecided {
        decision: ApprovalDecision,
        created_rule: Option<PolicyRule>,
    },
    DashboardSnapshot(DashboardSnapshot),
    ActivityEvents(EventRead),
    PendingApprovals(Vec<ApprovalRequest>),
    PendingApprovalForNotification(ApprovalRequest),
    PolicyRules(Vec<PolicyRule>),
    AuditRecords(CursorPage<AuditRecord>),
    AuditExport(AuditExport),
    AuditExportManifest(ExportManifest),
    AuditDeleted {
        deleted: usize,
    },
    Cancellation {
        cancelled: bool,
    },
    RuleDeleted {
        deleted: bool,
    },
    Error {
        code: String,
        message: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonSnapshot {
    pub public_identity: String,
    pub daemon_version: String,
    pub os: String,
    pub architecture: String,
    pub role: DaemonRole,
    pub endpoint: String,
    pub connection: ConnectionState,
    pub local_protocol: LocalProtocolVersion,
    pub remote_protocol: String,
    pub warnings: Vec<String>,
    pub remote_access_paused: bool,
    pub autostart: bool,
    pub log_location: String,
    #[serde(default)]
    pub features: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DaemonRole {
    Workstation,
    Agent,
    Registry,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Degraded,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticItem {
    pub code: String,
    pub message: String,
    pub healthy: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LocalProtocolError {
    IncompatibleVersion,
    FrameTooLarge,
    InvalidFrame,
    Io,
    StatePathNotAbsolute,
    InvalidLocalEndpoint,
    Unauthorized,
    FeatureUnavailable,
    PermissionDenied,
    ApprovalExpired,
    AuditUnavailable,
    CursorAhead,
    ResyncRequired,
    LimitExceeded,
    RevisionConflict,
}

impl fmt::Display for LocalProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}",
            match self {
                Self::IncompatibleVersion => "incompatible local protocol version",
                Self::FrameTooLarge => "local IPC frame exceeds 512 KiB",
                Self::InvalidFrame => "invalid local IPC frame",
                Self::Io => "local IPC I/O failed",
                Self::StatePathNotAbsolute => "daemon state paths must be absolute",
                Self::InvalidLocalEndpoint => "invalid local IPC endpoint",
                Self::Unauthorized => "local IPC peer is not authorized",
                Self::FeatureUnavailable => "dashboard feature was not negotiated",
                Self::PermissionDenied => "dashboard permission denied",
                Self::ApprovalExpired => "dashboard approval expired",
                Self::AuditUnavailable => "dashboard audit unavailable",
                Self::CursorAhead => "dashboard cursor is ahead",
                Self::ResyncRequired => "dashboard resynchronization required",
                Self::LimitExceeded => "dashboard limit exceeded",
                Self::RevisionConflict => "dashboard revision conflict",
            }
        )
    }
}

impl std::error::Error for LocalProtocolError {}

pub fn read_frame<R: BufRead, T: DeserializeOwned>(
    reader: &mut R,
) -> Result<T, LocalProtocolError> {
    let mut frame = Vec::new();
    let mut limited = std::io::Read::take(reader, (MAX_FRAME_BYTES + 1) as u64);
    limited
        .read_until(b'\n', &mut frame)
        .map_err(|_| LocalProtocolError::Io)?;
    if frame.len() > MAX_FRAME_BYTES {
        return Err(LocalProtocolError::FrameTooLarge);
    }
    if frame.pop() != Some(b'\n') {
        return Err(LocalProtocolError::InvalidFrame);
    }
    serde_json::from_slice(&frame).map_err(|_| LocalProtocolError::InvalidFrame)
}

pub fn write_frame<W: Write, T: Serialize>(
    writer: &mut W,
    value: &T,
) -> Result<(), LocalProtocolError> {
    let mut frame = serde_json::to_vec(value).map_err(|_| LocalProtocolError::InvalidFrame)?;
    if frame.len() + 1 > MAX_FRAME_BYTES {
        return Err(LocalProtocolError::FrameTooLarge);
    }
    frame.push(b'\n');
    writer.write_all(&frame).map_err(|_| LocalProtocolError::Io)
}

pub fn send_local_request(
    endpoint: &LocalEndpoint,
    request: &LocalRequest,
) -> Result<LocalResponse, LocalProtocolError> {
    request.validate()?;
    let mut bytes = serde_json::to_vec(request).map_err(|_| LocalProtocolError::InvalidFrame)?;
    bytes.push(b'\n');
    send_raw_local_frame(endpoint, &bytes)
}

pub fn send_raw_local_frame(
    endpoint: &LocalEndpoint,
    frame: &[u8],
) -> Result<LocalResponse, LocalProtocolError> {
    let stream = connect_local(endpoint)?;
    let mut writer = stream.try_clone().map_err(|_| LocalProtocolError::Io)?;
    writer
        .write_all(frame)
        .map_err(|_| LocalProtocolError::Io)?;
    writer.flush().map_err(|_| LocalProtocolError::Io)?;
    read_frame(&mut std::io::BufReader::new(stream))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PeerCredentials {
    Unix {
        uid: u32,
        gid: u32,
        pid: Option<u32>,
    },
    Windows {
        process_id: u32,
        user_sid: String,
    },
}

pub trait Authorizer: Send + Sync {
    fn authorize(&self, peer: &PeerCredentials) -> bool;
}

enum ExpectedUser {
    Unix(u32),
    Windows(String),
}

pub struct SameUserAuthorizer(ExpectedUser);

impl SameUserAuthorizer {
    pub fn unix(uid: u32) -> Self {
        Self(ExpectedUser::Unix(uid))
    }

    pub fn windows(user_sid: impl Into<String>) -> Self {
        Self(ExpectedUser::Windows(user_sid.into()))
    }
}

impl Authorizer for SameUserAuthorizer {
    fn authorize(&self, peer: &PeerCredentials) -> bool {
        match (&self.0, peer) {
            (ExpectedUser::Unix(expected), PeerCredentials::Unix { uid, .. }) => expected == uid,
            (ExpectedUser::Windows(expected), PeerCredentials::Windows { user_sid, .. }) => {
                !expected.is_empty() && expected == user_sid
            }
            _ => false,
        }
    }
}

pub struct DaemonState {
    snapshot: DaemonSnapshot,
    diagnostics: Vec<DiagnosticItem>,
    autostart_adapter: Option<Arc<dyn AutostartAdapter>>,
    dashboard_policy: Option<DashboardPolicyRuntime>,
    dashboard: Option<DashboardService>,
}

struct DashboardPolicyRuntime {
    local_host_id: HostId,
    engine: PolicyEngine,
}

pub trait AutostartAdapter: Send + Sync {
    fn set_enabled(&self, enabled: bool) -> Result<(), LocalProtocolError>;
}

struct PlatformAutostartAdapter;

impl AutostartAdapter for PlatformAutostartAdapter {
    fn set_enabled(&self, enabled: bool) -> Result<(), LocalProtocolError> {
        set_platform_autostart(enabled)
    }
}

impl DaemonState {
    pub fn new(snapshot: DaemonSnapshot, diagnostics: Vec<DiagnosticItem>) -> Self {
        Self {
            snapshot,
            diagnostics,
            autostart_adapter: None,
            dashboard_policy: None,
            dashboard: None,
        }
    }

    pub fn new_with_platform_lifecycle(
        snapshot: DaemonSnapshot,
        diagnostics: Vec<DiagnosticItem>,
    ) -> Self {
        Self {
            snapshot,
            diagnostics,
            autostart_adapter: Some(Arc::new(PlatformAutostartAdapter)),
            dashboard_policy: None,
            dashboard: None,
        }
    }

    pub fn new_with_autostart_adapter(
        snapshot: DaemonSnapshot,
        diagnostics: Vec<DiagnosticItem>,
        autostart_adapter: Arc<dyn AutostartAdapter>,
    ) -> Self {
        Self {
            snapshot,
            diagnostics,
            autostart_adapter: Some(autostart_adapter),
            dashboard_policy: None,
            dashboard: None,
        }
    }

    pub fn snapshot(&self) -> &DaemonSnapshot {
        &self.snapshot
    }

    pub fn enable_dashboard_policy(&mut self, local_host_id: HostId, engine: PolicyEngine) {
        self.dashboard_policy = Some(DashboardPolicyRuntime {
            local_host_id,
            engine,
        });
    }

    pub fn enable_dashboard(&mut self, service: DashboardService) {
        self.dashboard = Some(service);
    }

    fn local_policy_host_id(&self) -> Option<HostId> {
        self.dashboard
            .as_ref()
            .map(|service| service.local_host_id().clone())
            .or_else(|| {
                self.dashboard_policy
                    .as_ref()
                    .map(|runtime| runtime.local_host_id.clone())
            })
    }

    pub fn handle(&mut self, request: LocalRequest) -> Result<LocalResponse, LocalProtocolError> {
        request.validate()?;
        match request {
            LocalRequest::Status { .. } => Ok(LocalResponse::Snapshot(self.snapshot.clone())),
            LocalRequest::PauseRemoteAccess { .. } => {
                self.snapshot.remote_access_paused = true;
                Ok(LocalResponse::Acknowledged)
            }
            LocalRequest::ResumeRemoteAccess { .. } => {
                if let Some(service) = self.dashboard.as_mut() {
                    let now_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_err(|_| LocalProtocolError::Io)?
                        .as_millis() as u64;
                    service.resume(now_ms).map_err(map_dashboard_error)?;
                }
                self.snapshot.remote_access_paused = false;
                Ok(LocalResponse::Acknowledged)
            }
            LocalRequest::SetAutostart { enabled, .. } => {
                if let Some(adapter) = &self.autostart_adapter {
                    adapter.set_enabled(enabled)?;
                }
                self.snapshot.autostart = enabled;
                Ok(LocalResponse::Acknowledged)
            }
            LocalRequest::Diagnostics { .. } => {
                Ok(LocalResponse::Diagnostics(self.diagnostics.clone()))
            }
            LocalRequest::RequestApproval { .. }
            | LocalRequest::DecideApproval { .. }
            | LocalRequest::DecidePendingApproval { .. }
            | LocalRequest::DashboardSnapshot { .. }
            | LocalRequest::ActivityEvents { .. }
            | LocalRequest::AcknowledgeEvents { .. }
            | LocalRequest::PendingApprovals { .. }
            | LocalRequest::PendingApprovalForNotification { .. }
            | LocalRequest::PolicyRules { .. }
            | LocalRequest::PutPolicyRule { .. }
            | LocalRequest::DeletePolicyRule { .. }
            | LocalRequest::DeletePolicyRuleIfRevision { .. }
            | LocalRequest::AuditQuery { .. }
            | LocalRequest::AuditExport { .. }
            | LocalRequest::AuditExportManifest { .. }
            | LocalRequest::AuditDelete { .. }
            | LocalRequest::CancelActivity { .. }
            | LocalRequest::PauseRemoteAccessWithJobs { .. } => {
                Err(LocalProtocolError::Unauthorized)
            }
            LocalRequest::RequestAdminMutationApproval { .. } => {
                Err(LocalProtocolError::Unauthorized)
            }
        }
    }

    fn handle_authorized(
        &mut self,
        request: LocalRequest,
        session: &AuthenticatedTargetSession,
    ) -> Result<LocalResponse, LocalProtocolError> {
        request.validate()?;
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| LocalProtocolError::Io)?
            .as_millis() as u64;
        match request {
            LocalRequest::RequestApproval {
                access,
                lifetime_ms,
                ..
            } => {
                if let Some(service) = self.dashboard.as_mut() {
                    if session.local_host_id() != service.local_host_id()
                        || access.target_host_id != *service.local_host_id()
                    {
                        return Err(LocalProtocolError::Unauthorized);
                    }
                    let (nonce, expires_at_ms) = service
                        .request_approval(access, lifetime_ms, now_ms)
                        .map_err(map_dashboard_error)?;
                    return Ok(LocalResponse::ApprovalCreated {
                        nonce,
                        expires_at_ms,
                    });
                }
                let runtime = self
                    .dashboard_policy
                    .as_mut()
                    .ok_or(LocalProtocolError::Unauthorized)?;
                if session.local_host_id() != &runtime.local_host_id
                    || access.target_host_id != runtime.local_host_id
                {
                    return Err(LocalProtocolError::Unauthorized);
                }
                let approval = runtime
                    .engine
                    .create_approval(&access, now_ms, lifetime_ms)
                    .map_err(|_| LocalProtocolError::Unauthorized)?;
                Ok(LocalResponse::ApprovalCreated {
                    nonce: approval.nonce,
                    expires_at_ms: approval.expires_at_ms,
                })
            }
            LocalRequest::RequestAdminMutationApproval {
                mutation,
                lifetime_ms,
                ..
            } => {
                let (nonce, expires_at_ms) = self
                    .dashboard
                    .as_mut()
                    .ok_or(LocalProtocolError::FeatureUnavailable)?
                    .request_admin_mutation_approval(mutation, lifetime_ms, now_ms)
                    .map_err(map_dashboard_error)?;
                Ok(LocalResponse::ApprovalCreated {
                    nonce,
                    expires_at_ms,
                })
            }
            LocalRequest::DecideApproval {
                nonce,
                access,
                decision,
                ..
            } => {
                if let Some(service) = self.dashboard.as_mut() {
                    let created_rule = service
                        .decide_approval(&nonce, session, &access, decision, now_ms)
                        .map_err(map_dashboard_error)?;
                    return Ok(LocalResponse::ApprovalDecided {
                        decision,
                        created_rule,
                    });
                }
                let runtime = self
                    .dashboard_policy
                    .as_mut()
                    .ok_or(LocalProtocolError::Unauthorized)?;
                if session.local_host_id() != &runtime.local_host_id
                    || access.target_host_id != runtime.local_host_id
                {
                    return Err(LocalProtocolError::Unauthorized);
                }
                let outcome = runtime
                    .engine
                    .decide(&nonce, session, &access, decision, now_ms)
                    .map_err(|_| LocalProtocolError::Unauthorized)?;
                Ok(LocalResponse::ApprovalDecided {
                    decision: outcome.decision,
                    created_rule: outcome.created_rule,
                })
            }
            LocalRequest::DecidePendingApproval {
                approval_id,
                decision,
                ..
            } => {
                let created_rule = self
                    .dashboard
                    .as_mut()
                    .ok_or(LocalProtocolError::FeatureUnavailable)?
                    .decide_pending_approval(&approval_id, session, decision, now_ms)
                    .map_err(map_dashboard_error)?;
                Ok(LocalResponse::ApprovalDecided {
                    decision,
                    created_rule,
                })
            }
            LocalRequest::DashboardSnapshot { scope, .. } => {
                let service = self
                    .dashboard
                    .as_ref()
                    .ok_or(LocalProtocolError::FeatureUnavailable)?;
                Ok(LocalResponse::DashboardSnapshot(
                    service.snapshot(scope, now_ms),
                ))
            }
            LocalRequest::ActivityEvents {
                scope,
                cursor,
                limit,
                ..
            } => {
                let service = self
                    .dashboard
                    .as_ref()
                    .ok_or(LocalProtocolError::FeatureUnavailable)?;
                Ok(LocalResponse::ActivityEvents(
                    service.events_in_scope(scope, cursor, limit),
                ))
            }
            LocalRequest::AcknowledgeEvents {
                subscriber_id,
                cursor,
                ..
            } => {
                self.dashboard
                    .as_ref()
                    .ok_or(LocalProtocolError::FeatureUnavailable)?
                    .acknowledge(subscriber_id, cursor, now_ms)
                    .map_err(map_dashboard_error)?;
                Ok(LocalResponse::Acknowledged)
            }
            LocalRequest::PendingApprovals { .. } => Ok(LocalResponse::PendingApprovals(
                self.dashboard
                    .as_ref()
                    .ok_or(LocalProtocolError::FeatureUnavailable)?
                    .pending_approvals(now_ms),
            )),
            LocalRequest::PendingApprovalForNotification { approval_id, .. } => {
                let approval = self
                    .dashboard
                    .as_ref()
                    .ok_or(LocalProtocolError::FeatureUnavailable)?
                    .pending_approval_for_notification(&approval_id, now_ms)
                    .map_err(map_dashboard_error)?;
                Ok(LocalResponse::PendingApprovalForNotification(approval))
            }
            LocalRequest::PolicyRules { .. } => Ok(LocalResponse::PolicyRules(
                self.dashboard
                    .as_ref()
                    .ok_or(LocalProtocolError::FeatureUnavailable)?
                    .policy_rules(),
            )),
            LocalRequest::PutPolicyRule { rule, .. } => {
                self.dashboard
                    .as_mut()
                    .ok_or(LocalProtocolError::FeatureUnavailable)?
                    .put_policy_rule(rule, now_ms)
                    .map_err(map_dashboard_error)?;
                Ok(LocalResponse::Acknowledged)
            }
            LocalRequest::DeletePolicyRule { rule_id, .. } => {
                let deleted = self
                    .dashboard
                    .as_mut()
                    .ok_or(LocalProtocolError::FeatureUnavailable)?
                    .delete_policy_rule(&rule_id, now_ms)
                    .map_err(map_dashboard_error)?;
                Ok(LocalResponse::RuleDeleted { deleted })
            }
            LocalRequest::DeletePolicyRuleIfRevision {
                rule_id,
                expected_revision,
                ..
            } => {
                let deleted = self
                    .dashboard
                    .as_mut()
                    .ok_or(LocalProtocolError::FeatureUnavailable)?
                    .delete_policy_rule_if_revision(&rule_id, expected_revision, now_ms)
                    .map_err(map_dashboard_error)?;
                Ok(LocalResponse::RuleDeleted { deleted })
            }
            LocalRequest::AuditQuery {
                filter,
                cursor,
                limit,
                ..
            } => {
                let page = self
                    .dashboard
                    .as_ref()
                    .ok_or(LocalProtocolError::FeatureUnavailable)?
                    .audit_query(filter, cursor, limit)
                    .map_err(map_dashboard_error)?;
                Ok(LocalResponse::AuditRecords(page))
            }
            LocalRequest::AuditExport { filter, .. } => {
                let export = self
                    .dashboard
                    .as_ref()
                    .ok_or(LocalProtocolError::FeatureUnavailable)?
                    .audit_export(filter, None)
                    .map_err(map_dashboard_error)?;
                Ok(LocalResponse::AuditExport(export))
            }
            LocalRequest::AuditExportManifest { filter, .. } => {
                let manifest = self
                    .dashboard
                    .as_ref()
                    .ok_or(LocalProtocolError::FeatureUnavailable)?
                    .audit_export(filter, None)
                    .map_err(map_dashboard_error)?
                    .manifest;
                Ok(LocalResponse::AuditExportManifest(manifest))
            }
            LocalRequest::AuditDelete { scope, filter, .. } => {
                let deleted = self
                    .dashboard
                    .as_mut()
                    .ok_or(LocalProtocolError::FeatureUnavailable)?
                    .delete_audit_exact(scope, filter, now_ms)
                    .map_err(map_dashboard_error)?;
                Ok(LocalResponse::AuditDeleted { deleted })
            }
            LocalRequest::CancelActivity { activity_id, .. } => {
                let cancelled = self
                    .dashboard
                    .as_mut()
                    .ok_or(LocalProtocolError::FeatureUnavailable)?
                    .cancel_activity(&activity_id, now_ms)
                    .map_err(map_dashboard_error)?;
                Ok(LocalResponse::Cancellation { cancelled })
            }
            LocalRequest::PauseRemoteAccessWithJobs { existing_jobs, .. } => {
                self.dashboard
                    .as_mut()
                    .ok_or(LocalProtocolError::FeatureUnavailable)?
                    .pause(existing_jobs, now_ms)
                    .map_err(map_dashboard_error)?;
                self.snapshot.remote_access_paused = true;
                Ok(LocalResponse::Acknowledged)
            }
            legacy => self.handle(legacy),
        }
    }
}

fn default_dashboard_scope() -> DashboardScope {
    DashboardScope::Local
}

fn map_dashboard_error(
    error: crate::dashboard::service::DashboardServiceError,
) -> LocalProtocolError {
    use crate::dashboard::service::DashboardServiceError as Error;
    match error {
        Error::PermissionDenied => LocalProtocolError::PermissionDenied,
        Error::ApprovalExpired => LocalProtocolError::ApprovalExpired,
        Error::AuditUnavailable => LocalProtocolError::AuditUnavailable,
        Error::CursorAhead => LocalProtocolError::CursorAhead,
        Error::ResyncRequired => LocalProtocolError::ResyncRequired,
        Error::LimitExceeded => LocalProtocolError::LimitExceeded,
        Error::RevisionConflict => LocalProtocolError::RevisionConflict,
        Error::InvalidRequest | Error::NotFound => LocalProtocolError::InvalidFrame,
    }
}

fn set_platform_autostart(enabled: bool) -> Result<(), LocalProtocolError> {
    #[cfg(target_os = "linux")]
    let status = std::process::Command::new("systemctl")
        .args([
            "--user",
            if enabled { "enable" } else { "disable" },
            "devicelane.service",
        ])
        .status();
    #[cfg(target_os = "macos")]
    let status = std::process::Command::new("launchctl")
        .args([
            if enabled { "enable" } else { "disable" },
            &format!("gui/{}/dev.devicelane.service", unsafe { libc::geteuid() }),
        ])
        .status();
    #[cfg(windows)]
    let status = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            if enabled {
                "$sid=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value; Enable-ScheduledTask -TaskName \"DeviceLane Service-$sid\" | Out-Null"
            } else {
                "$sid=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value; Disable-ScheduledTask -TaskName \"DeviceLane Service-$sid\" | Out-Null"
            },
        ])
        .status();
    status
        .map_err(|_| LocalProtocolError::Io)?
        .success()
        .then_some(())
        .ok_or(LocalProtocolError::Io)
}

pub fn platform_autostart_enabled() -> bool {
    #[cfg(target_os = "linux")]
    return std::process::Command::new("systemctl")
        .args(["--user", "is-enabled", "--quiet", "devicelane.service"])
        .status()
        .is_ok_and(|status| status.success());
    #[cfg(target_os = "macos")]
    return std::env::var_os("HOME").is_some_and(|home| {
        let plist = PathBuf::from(home).join("Library/LaunchAgents/dev.devicelane.service.plist");
        std::process::Command::new("launchctl")
            .args([
                "print-disabled",
                &format!("gui/{}", unsafe { libc::geteuid() }),
            ])
            .output()
            .is_ok_and(|output| {
                output.status.success() && launch_agent_autostart_enabled(&plist, &output.stdout)
            })
    });
    #[cfg(windows)]
    return std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "$sid=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value; $task=Get-ScheduledTask -TaskName \"DeviceLane Service-$sid\" -ErrorAction SilentlyContinue; if ($null -ne $task -and $task.State -ne 'Disabled') { exit 0 } else { exit 1 }",
        ])
        .status()
        .is_ok_and(|status| status.success());
}

pub fn launch_agent_autostart_enabled(plist: &Path, print_disabled_output: &[u8]) -> bool {
    plist.is_file()
        && !String::from_utf8_lossy(print_disabled_output)
            .contains("\"dev.devicelane.service\" => true")
}

pub fn validate_state_paths<'a>(
    paths: impl IntoIterator<Item = &'a Path>,
) -> Result<(), LocalProtocolError> {
    paths
        .into_iter()
        .all(Path::is_absolute)
        .then_some(())
        .ok_or(LocalProtocolError::StatePathNotAbsolute)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LocalEndpoint {
    #[cfg(windows)]
    NamedPipe(String),
    #[cfg(unix)]
    UnixSocket(PathBuf),
}

pub fn local_endpoint(
    runtime_dir: &Path,
    listen: &str,
) -> Result<LocalEndpoint, LocalProtocolError> {
    if !runtime_dir.is_absolute() {
        return Err(LocalProtocolError::StatePathNotAbsolute);
    }
    #[cfg(windows)]
    {
        let pipe = if listen.is_empty() {
            r"\\.\pipe\devicelane-service"
        } else {
            listen
        };
        if !pipe.starts_with(r"\\.\pipe\") {
            return Err(LocalProtocolError::InvalidLocalEndpoint);
        }
        Ok(LocalEndpoint::NamedPipe(pipe.to_owned()))
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if listen.contains("://") {
            return Err(LocalProtocolError::InvalidLocalEndpoint);
        }
        let original = std::fs::symlink_metadata(runtime_dir)
            .map_err(|_| LocalProtocolError::InvalidLocalEndpoint)?;
        if original.file_type().is_symlink() || !original.is_dir() {
            return Err(LocalProtocolError::InvalidLocalEndpoint);
        }
        let runtime_dir = std::fs::canonicalize(runtime_dir)
            .map_err(|_| LocalProtocolError::InvalidLocalEndpoint)?;
        let metadata = std::fs::metadata(&runtime_dir)
            .map_err(|_| LocalProtocolError::InvalidLocalEndpoint)?;
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o777 != 0o700
        {
            return Err(LocalProtocolError::Unauthorized);
        }
        let path = if listen.is_empty() {
            runtime_dir.join("devicelane.sock")
        } else {
            PathBuf::from(listen)
        };
        if !path.is_absolute() || path.parent() != Some(runtime_dir.as_path()) {
            return Err(LocalProtocolError::InvalidLocalEndpoint);
        }
        Ok(LocalEndpoint::UnixSocket(path))
    }
}

pub fn serve_local(
    endpoint: &LocalEndpoint,
    state: Arc<Mutex<DaemonState>>,
) -> Result<(), LocalProtocolError> {
    platform::serve(endpoint, state)
}

fn dispatch_connection(
    stream: PlatformStream,
    peer: PeerCredentials,
    authorizer: &dyn Authorizer,
    state: &Arc<Mutex<DaemonState>>,
) {
    let mut writer = match duplicate_stream(&stream) {
        Ok(writer) => writer,
        Err(_) => return,
    };
    let request = platform::read_request(&stream);
    let response = if !authorizer.authorize(&peer) {
        LocalResponse::Error {
            code: "unauthorized".into(),
            message: "local IPC peer is not authorized".into(),
        }
    } else {
        match request {
            Ok(request) => match state.lock() {
                Ok(mut state) => {
                    if matches!(
                        request,
                        LocalRequest::RequestApproval { .. }
                            | LocalRequest::RequestAdminMutationApproval { .. }
                            | LocalRequest::DecideApproval { .. }
                            | LocalRequest::DecidePendingApproval { .. }
                            | LocalRequest::DashboardSnapshot { .. }
                            | LocalRequest::ActivityEvents { .. }
                            | LocalRequest::AcknowledgeEvents { .. }
                            | LocalRequest::PendingApprovals { .. }
                            | LocalRequest::PendingApprovalForNotification { .. }
                            | LocalRequest::PolicyRules { .. }
                            | LocalRequest::PutPolicyRule { .. }
                            | LocalRequest::DeletePolicyRule { .. }
                            | LocalRequest::DeletePolicyRuleIfRevision { .. }
                            | LocalRequest::AuditQuery { .. }
                            | LocalRequest::AuditExport { .. }
                            | LocalRequest::AuditExportManifest { .. }
                            | LocalRequest::AuditDelete { .. }
                            | LocalRequest::CancelActivity { .. }
                            | LocalRequest::PauseRemoteAccessWithJobs { .. }
                    ) {
                        match state.local_policy_host_id() {
                            Some(local_host_id) => {
                                let session = AuthenticatedTargetSession::issue(local_host_id);
                                state
                                    .handle_authorized(request, &session)
                                    .unwrap_or_else(error_response)
                            }
                            None => error_response(LocalProtocolError::Unauthorized),
                        }
                    } else {
                        state.handle(request).unwrap_or_else(error_response)
                    }
                }
                Err(_) => LocalResponse::Error {
                    code: "internal_error".into(),
                    message: "daemon state unavailable".into(),
                },
            },
            Err(error) => error_response(error),
        }
    };
    let response = enforce_response_bound(response);
    let _ = write_frame(&mut writer, &response);
}

pub fn enforce_response_bound(response: LocalResponse) -> LocalResponse {
    match serde_json::to_vec(&response) {
        Ok(frame) if frame.len().saturating_add(1) <= MAX_FRAME_BYTES => response,
        Ok(_) => LocalResponse::Error {
            code: "limit_exceeded".into(),
            message: "local IPC response exceeds 512 KiB; request a smaller page".into(),
        },
        Err(_) => LocalResponse::Error {
            code: "invalid_request".into(),
            message: "local IPC response could not be encoded".into(),
        },
    }
}

fn error_response(error: LocalProtocolError) -> LocalResponse {
    LocalResponse::Error {
        code: match error {
            LocalProtocolError::IncompatibleVersion => "incompatible_version",
            LocalProtocolError::FrameTooLarge => "frame_too_large",
            LocalProtocolError::Unauthorized => "unauthorized",
            LocalProtocolError::FeatureUnavailable => "feature_unavailable",
            LocalProtocolError::PermissionDenied => "permission_denied",
            LocalProtocolError::ApprovalExpired => "approval_expired",
            LocalProtocolError::AuditUnavailable => "audit_unavailable",
            LocalProtocolError::CursorAhead => "cursor_ahead",
            LocalProtocolError::ResyncRequired => "resync_required",
            LocalProtocolError::LimitExceeded => "limit_exceeded",
            LocalProtocolError::RevisionConflict => "revision_conflict",
            _ => "invalid_request",
        }
        .into(),
        message: error.to_string(),
    }
}

struct WorkerGuard(Arc<std::sync::atomic::AtomicUsize>);

impl WorkerGuard {
    fn acquire(active: &Arc<std::sync::atomic::AtomicUsize>) -> Option<Self> {
        active
            .fetch_update(
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
                |count| (count < MAX_LOCAL_WORKERS).then_some(count + 1),
            )
            .ok()?;
        Some(Self(Arc::clone(active)))
    }
}

impl Drop for WorkerGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

#[cfg(unix)]
pub type PlatformStream = std::os::unix::net::UnixStream;
#[cfg(windows)]
pub type PlatformStream = std::fs::File;

pub type LocalStream = PlatformStream;

pub fn open_local_stream(endpoint: &LocalEndpoint) -> Result<LocalStream, LocalProtocolError> {
    connect_local(endpoint)
}

#[cfg(windows)]
pub fn windows_pipe_security_sddl(user_sid: &str) -> Result<String, LocalProtocolError> {
    (!user_sid.is_empty())
        .then(|| format!("D:P(A;;GA;;;SY)(A;;GA;;;{user_sid})"))
        .ok_or(LocalProtocolError::Unauthorized)
}

#[cfg(not(windows))]
pub fn windows_pipe_security_sddl(_user_sid: &str) -> Result<String, LocalProtocolError> {
    Err(LocalProtocolError::InvalidLocalEndpoint)
}

fn duplicate_stream(stream: &PlatformStream) -> std::io::Result<PlatformStream> {
    stream.try_clone()
}

fn connect_local(endpoint: &LocalEndpoint) -> Result<PlatformStream, LocalProtocolError> {
    platform::connect(endpoint)
}

#[cfg(unix)]
pub fn bind_local(endpoint: &LocalEndpoint) -> io::Result<std::os::unix::net::UnixListener> {
    let LocalEndpoint::UnixSocket(path) = endpoint;
    std::os::unix::net::UnixListener::bind(path)
}

#[cfg(unix)]
mod platform {
    use super::*;
    use std::os::fd::AsRawFd;

    pub fn connect(endpoint: &LocalEndpoint) -> Result<PlatformStream, LocalProtocolError> {
        let LocalEndpoint::UnixSocket(path) = endpoint;
        PlatformStream::connect(path).map_err(|_| LocalProtocolError::Io)
    }

    pub fn serve(
        endpoint: &LocalEndpoint,
        state: Arc<Mutex<DaemonState>>,
    ) -> Result<(), LocalProtocolError> {
        use std::os::unix::fs::{FileTypeExt, PermissionsExt};
        let LocalEndpoint::UnixSocket(path) = endpoint;
        if let Ok(metadata) = std::fs::symlink_metadata(path) {
            if !metadata.file_type().is_socket() {
                return Err(LocalProtocolError::InvalidLocalEndpoint);
            }
            match PlatformStream::connect(path) {
                Ok(_) => return Err(LocalProtocolError::InvalidLocalEndpoint),
                Err(error) if error.raw_os_error() == Some(libc::ECONNREFUSED) => {}
                Err(_) => return Err(LocalProtocolError::InvalidLocalEndpoint),
            }
            std::fs::remove_file(path).map_err(|_| LocalProtocolError::Io)?;
        }
        let listener = bind_local(endpoint).map_err(|_| LocalProtocolError::Io)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|_| LocalProtocolError::Io)?;
        let _cleanup = SocketCleanup(path.clone());
        let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        for accepted in listener.incoming() {
            let Ok(stream) = accepted else { continue };
            let Some(guard) = WorkerGuard::acquire(&active) else {
                continue;
            };
            let Ok(peer) = peer_credentials(&stream) else {
                continue;
            };
            if stream
                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .is_err()
                || stream
                    .set_write_timeout(Some(std::time::Duration::from_secs(2)))
                    .is_err()
            {
                continue;
            }
            let state = Arc::clone(&state);
            let authorizer = SameUserAuthorizer::unix(unsafe { libc::geteuid() });
            std::thread::spawn(move || {
                let _guard = guard;
                dispatch_connection(stream, peer, &authorizer, &state)
            });
        }
        Err(LocalProtocolError::Io)
    }

    struct SocketCleanup(PathBuf);
    impl Drop for SocketCleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    pub(super) fn peer_credentials(
        stream: &PlatformStream,
    ) -> Result<PeerCredentials, LocalProtocolError> {
        #[cfg(target_os = "linux")]
        unsafe {
            let mut credentials: libc::ucred = std::mem::zeroed();
            let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
            if libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut credentials as *mut libc::ucred).cast(),
                &mut length,
            ) != 0
            {
                return Err(LocalProtocolError::Unauthorized);
            }
            Ok(PeerCredentials::Unix {
                uid: credentials.uid,
                gid: credentials.gid,
                pid: u32::try_from(credentials.pid).ok(),
            })
        }
        #[cfg(target_os = "macos")]
        unsafe {
            let mut uid = 0;
            let mut gid = 0;
            if libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) != 0 {
                return Err(LocalProtocolError::Unauthorized);
            }
            Ok(PeerCredentials::Unix {
                uid,
                gid,
                pid: None,
            })
        }
    }

    pub(super) fn read_request(
        stream: &PlatformStream,
    ) -> Result<LocalRequest, LocalProtocolError> {
        let reader = stream.try_clone().map_err(|_| LocalProtocolError::Io)?;
        read_frame(&mut std::io::BufReader::new(reader))
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_PIPE_CONNECTED, GetLastError, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{
        GetTokenInformation, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_GENERIC_READ,
        FILE_GENERIC_WRITE, FILE_SHARE_NONE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
    };
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
        PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES,
        PIPE_WAIT, PeekNamedPipe, WaitNamedPipeW,
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    pub fn connect(endpoint: &LocalEndpoint) -> Result<PlatformStream, LocalProtocolError> {
        let LocalEndpoint::NamedPipe(path) = endpoint;
        let name: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
        unsafe { WaitNamedPipeW(name.as_ptr(), 100) };
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                FILE_SHARE_NONE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(LocalProtocolError::Io);
        }
        Ok(unsafe { PlatformStream::from_raw_handle(handle as _) })
    }

    pub fn serve(
        endpoint: &LocalEndpoint,
        state: Arc<Mutex<DaemonState>>,
    ) -> Result<(), LocalProtocolError> {
        let LocalEndpoint::NamedPipe(path) = endpoint;
        let expected_sid = current_user_sid()?;
        let security = PipeSecurity::new(&windows_pipe_security_sddl(&expected_sid)?)?;
        let name: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
        let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut first = true;
        loop {
            let access = PIPE_ACCESS_DUPLEX
                | if first {
                    FILE_FLAG_FIRST_PIPE_INSTANCE
                } else {
                    0
                };
            first = false;
            let handle = unsafe {
                CreateNamedPipeW(
                    name.as_ptr(),
                    access,
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                    PIPE_UNLIMITED_INSTANCES,
                    MAX_FRAME_BYTES as u32,
                    MAX_FRAME_BYTES as u32,
                    0,
                    &security.attributes,
                )
            };
            if handle == INVALID_HANDLE_VALUE {
                return Err(LocalProtocolError::Io);
            }
            let connected = unsafe { ConnectNamedPipe(handle, std::ptr::null_mut()) } != 0
                || unsafe { GetLastError() } == ERROR_PIPE_CONNECTED;
            if !connected {
                unsafe { CloseHandle(handle) };
                continue;
            }
            let stream = unsafe { PlatformStream::from_raw_handle(handle as _) };
            let Some(guard) = WorkerGuard::acquire(&active) else {
                unsafe { DisconnectNamedPipe(handle) };
                continue;
            };
            let Ok(peer) = peer_credentials(&stream) else {
                unsafe { DisconnectNamedPipe(handle) };
                continue;
            };
            let state = Arc::clone(&state);
            let expected_sid = expected_sid.clone();
            std::thread::spawn(move || {
                let _guard = guard;
                let authorizer = SameUserAuthorizer::windows(expected_sid);
                if let Ok(worker) = stream.try_clone() {
                    dispatch_connection(worker, peer, &authorizer, &state);
                }
                unsafe {
                    DisconnectNamedPipe(stream.as_raw_handle() as HANDLE);
                }
            });
        }
    }

    pub(super) fn peer_credentials(
        stream: &PlatformStream,
    ) -> Result<PeerCredentials, LocalProtocolError> {
        let handle = stream.as_raw_handle() as HANDLE;
        let mut process_id = 0;
        if unsafe { GetNamedPipeClientProcessId(handle, &mut process_id) } == 0 {
            return Err(LocalProtocolError::Unauthorized);
        }
        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
        if process.is_null() {
            return Err(LocalProtocolError::Unauthorized);
        }
        let mut token = std::ptr::null_mut();
        let opened = unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } != 0;
        unsafe { CloseHandle(process) };
        if !opened {
            return Err(LocalProtocolError::Unauthorized);
        }
        let sid = token_sid(token);
        unsafe { CloseHandle(token) };
        sid.map(|user_sid| PeerCredentials::Windows {
            process_id,
            user_sid,
        })
    }

    fn current_user_sid() -> Result<String, LocalProtocolError> {
        let mut token = std::ptr::null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(LocalProtocolError::Unauthorized);
        }
        let result = token_sid(token);
        unsafe { CloseHandle(token) };
        result
    }

    fn token_sid(token: HANDLE) -> Result<String, LocalProtocolError> {
        let mut needed = 0;
        unsafe { GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed) };
        if needed == 0 {
            return Err(LocalProtocolError::Unauthorized);
        }
        let mut buffer = vec![0_u8; needed as usize];
        if unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                needed,
                &mut needed,
            )
        } == 0
        {
            return Err(LocalProtocolError::Unauthorized);
        }
        let user = unsafe { &*(buffer.as_ptr().cast::<TOKEN_USER>()) };
        let mut text = std::ptr::null_mut();
        if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) } == 0 {
            return Err(LocalProtocolError::Unauthorized);
        }
        let mut length = 0;
        while unsafe { *text.add(length) } != 0 {
            length += 1;
        }
        let sid = String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) });
        unsafe { LocalFree(text.cast()) };
        sid.map_err(|_| LocalProtocolError::Unauthorized)
    }

    pub(super) fn read_request(
        stream: &PlatformStream,
    ) -> Result<LocalRequest, LocalProtocolError> {
        use std::io::Read;
        let started = std::time::Instant::now();
        let mut frame = Vec::new();
        let mut reader = stream.try_clone().map_err(|_| LocalProtocolError::Io)?;
        while started.elapsed() < std::time::Duration::from_secs(2) {
            let mut available = 0;
            if unsafe {
                PeekNamedPipe(
                    stream.as_raw_handle() as HANDLE,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                    &mut available,
                    std::ptr::null_mut(),
                )
            } == 0
            {
                return Err(LocalProtocolError::Io);
            }
            if available == 0 {
                std::thread::sleep(std::time::Duration::from_millis(5));
                continue;
            }
            let remaining = MAX_FRAME_BYTES + 1 - frame.len();
            let mut chunk = vec![0_u8; remaining.min(available as usize)];
            reader
                .read_exact(&mut chunk)
                .map_err(|_| LocalProtocolError::Io)?;
            frame.extend_from_slice(&chunk);
            if frame.len() > MAX_FRAME_BYTES {
                return Err(LocalProtocolError::FrameTooLarge);
            }
            if frame.last() == Some(&b'\n') {
                return serde_json::from_slice(&frame[..frame.len() - 1])
                    .map_err(|_| LocalProtocolError::InvalidFrame);
            }
        }
        Err(LocalProtocolError::Io)
    }

    struct PipeSecurity {
        descriptor: *mut core::ffi::c_void,
        attributes: SECURITY_ATTRIBUTES,
    }

    impl PipeSecurity {
        fn new(sddl: &str) -> Result<Self, LocalProtocolError> {
            let wide: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
            let mut descriptor = std::ptr::null_mut();
            if unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    wide.as_ptr(),
                    SDDL_REVISION_1,
                    &mut descriptor,
                    std::ptr::null_mut(),
                )
            } == 0
            {
                return Err(LocalProtocolError::Unauthorized);
            }
            Ok(Self {
                descriptor,
                attributes: SECURITY_ATTRIBUTES {
                    nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                    lpSecurityDescriptor: descriptor,
                    bInheritHandle: 0,
                },
            })
        }
    }

    impl Drop for PipeSecurity {
        fn drop(&mut self) {
            unsafe { LocalFree(self.descriptor) };
        }
    }
}
