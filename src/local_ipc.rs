use crate::controller_session::{MeshApprovalAssertion, verify_mesh_approval};
use crate::dashboard::audit::{AuditDeletionScope, AuditExport, AuditFilter, ExportManifest};
use crate::dashboard::event_log::EventRead;
use crate::dashboard::model::{
    ActivityEvent, ActivityId, ActivityState, AuditRecord, CursorPage, DashboardScope,
    DashboardSnapshot, DisplayMessage, EventCursor, HostId, MessageCode, MetricSnapshot,
    MetricValue, PolicyEffect, ResourceClass, RuleId, SafeCode, SubscriberId,
};
use crate::dashboard::model::{ApprovalDecision, ApprovalRequest, PolicyRule};
use crate::dashboard::policy::{AccessRequest, PolicyEngine, RemoteOperationGrant};
use crate::dashboard::service::{AdminMutation, DashboardService, ExistingJobs};
use crate::network_processes::{LeaseRequest, Request as MeshRequest, Response as MeshResponse};
use crate::remote_apple_protocol::{AppleOperation, AppleRequest, RemoteProtocolVersion};
use crate::secure_transport::SecureTransport;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::collections::HashMap;
use std::fmt;
use std::io::{BufRead, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
use std::io;

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
compile_error!("local IPC peer credentials are supported only on Linux and macOS Unix targets");

pub const MAX_FRAME_BYTES: usize = 512 * 1024;
pub const MAX_LOCAL_WORKERS: usize = 8;

#[cfg(windows)]
pub(crate) fn current_process_principal() -> Result<String, LocalProtocolError> {
    platform::current_user_sid().map(|sid| sid.to_ascii_lowercase())
}

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
    ConnectionSettings {
        version: LocalProtocolVersion,
    },
    SetConnection {
        version: LocalProtocolVersion,
        configuration: crate::connection_config::ConnectionConfig,
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
    RequestAuthenticatedApproval {
        version: LocalProtocolVersion,
        assertion: MeshApprovalAssertion,
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
    StartRemoteExecution {
        version: LocalProtocolVersion,
        activity_id: ActivityId,
        workspace_path: String,
        request_id: String,
        app_path: String,
    },
}

impl LocalRequest {
    pub fn version(&self) -> LocalProtocolVersion {
        match *self {
            Self::Status { version }
            | Self::ConnectionSettings { version }
            | Self::SetConnection { version, .. }
            | Self::PauseRemoteAccess { version }
            | Self::ResumeRemoteAccess { version }
            | Self::SetAutostart { version, .. }
            | Self::Diagnostics { version }
            | Self::RequestApproval { version, .. }
            | Self::RequestAuthenticatedApproval { version, .. }
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
            | Self::PauseRemoteAccessWithJobs { version, .. }
            | Self::StartRemoteExecution { version, .. } => version,
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
    /// Effective runtime configuration, including transient CLI overrides.
    /// Never exposes credential storage paths or private identity material.
    ConnectionSettings {
        registry_address: Option<String>,
        registry_peer_id: Option<String>,
        connection: ConnectionState,
    },
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
    ExecutionStarted {
        activity_id: ActivityId,
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
    TargetOffline,
    MeshIdentityMismatch,
    RemoteUnavailable,
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
                Self::TargetOffline => {
                    "target is offline; reconnect the paired target before requesting approval"
                }
                Self::MeshIdentityMismatch => {
                    "mesh identity does not match the signed authenticated session"
                }
                Self::RemoteUnavailable => {
                    "remote execution unavailable; verify paired registry and agent connectivity"
                }
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
    connection_storage: Option<PathBuf>,
    snapshot: DaemonSnapshot,
    diagnostics: Vec<DiagnosticItem>,
    autostart_adapter: Option<Arc<dyn AutostartAdapter>>,
    dashboard_policy: Option<DashboardPolicyRuntime>,
    dashboard: Option<DashboardService>,
    remote_execution: Option<RemoteExecutionConfig>,
    remote_execution_generation: Arc<()>,
    remote_execution_boundary: Option<Arc<dyn MeshRpcBoundary>>,
    remote_execution_timeout: Duration,
    inflight_executions: HashMap<ActivityId, Arc<AtomicBool>>,
}

#[derive(Clone, Debug)]
pub struct RemoteExecutionConfig {
    pub registry_address: String,
    pub registry_peer_id: String,
    pub identity_path: PathBuf,
    pub client_id: String,
}

struct ConnectionWriteObservation {
    before: Result<
        Option<crate::connection_config::ConnectionConfig>,
        crate::connection_config::ConnectionConfigError,
    >,
    saved: Result<(), crate::connection_config::ConnectionConfigError>,
    after: Result<
        Option<crate::connection_config::ConnectionConfig>,
        crate::connection_config::ConnectionConfigError,
    >,
}

impl ConnectionWriteObservation {
    fn callback_result(
        &self,
        target: &crate::connection_config::ConnectionConfig,
    ) -> Result<(), crate::dashboard::service::DashboardServiceError> {
        if self.saved.is_ok() && self.after.as_ref().ok().and_then(Option::as_ref) == Some(target) {
            Ok(())
        } else {
            Err(crate::dashboard::service::DashboardServiceError::ConfigurationUnavailable)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteExecutionFailure {
    OperationFailed,
    TargetOffline,
    RegistryDisconnected,
    DaemonRestarted,
    ObserverUnavailable,
    EventResyncRequired,
    AuditUnavailable,
    ApprovalExpired,
    PolicyDenied,
    StaleLease,
    Cancelled,
    AgentIncompatible,
}

impl RemoteExecutionFailure {
    fn message_code(self) -> MessageCode {
        match self {
            Self::OperationFailed => MessageCode::OperationFailed,
            Self::TargetOffline => MessageCode::TargetOffline,
            Self::RegistryDisconnected => MessageCode::RegistryDisconnected,
            Self::DaemonRestarted => MessageCode::DaemonRestarted,
            Self::ObserverUnavailable => MessageCode::ObserverUnavailable,
            Self::EventResyncRequired => MessageCode::EventResyncRequired,
            Self::AuditUnavailable => MessageCode::AuditUnavailable,
            Self::ApprovalExpired => MessageCode::ApprovalExpired,
            Self::PolicyDenied => MessageCode::PolicyDenied,
            Self::StaleLease => MessageCode::LeaseStale,
            Self::Cancelled => MessageCode::OperationCancelled,
            Self::AgentIncompatible => MessageCode::AgentIncompatible,
        }
    }
}

pub trait MeshRpcBoundary: Send + Sync {
    fn call(
        &self,
        config: &RemoteExecutionConfig,
        request: &MeshRequest,
    ) -> Result<MeshResponse, RemoteExecutionFailure>;

    fn uses_persistent_session(&self) -> bool {
        false
    }
}

pub struct PersistentMeshRpcBoundary {
    state: Mutex<PersistentMeshState>,
}

#[derive(Default)]
struct PersistentMeshState {
    transport: Option<CachedMeshTransport>,
    session: Option<CachedMeshSession>,
}

struct CachedMeshTransport {
    identity_path: PathBuf,
    client_id: String,
    transport: SecureTransport,
}

struct CachedMeshSession {
    registry_address: String,
    registry_peer_id: String,
    stream: rustls::StreamOwned<rustls::ClientConnection, TcpStream>,
}

impl Default for PersistentMeshRpcBoundary {
    fn default() -> Self {
        Self {
            state: Mutex::new(PersistentMeshState::default()),
        }
    }
}

impl PersistentMeshRpcBoundary {
    fn call_once(
        state: &mut PersistentMeshState,
        config: &RemoteExecutionConfig,
        request: &MeshRequest,
    ) -> Result<MeshResponse, LocalProtocolError> {
        let transport_matches = state.transport.as_ref().is_some_and(|cached| {
            cached.identity_path == config.identity_path && cached.client_id == config.client_id
        });
        if !transport_matches {
            state.session = None;
            state.transport = Some(CachedMeshTransport {
                identity_path: config.identity_path.clone(),
                client_id: config.client_id.clone(),
                transport: SecureTransport::load_or_create(
                    &config.identity_path,
                    &config.client_id,
                )
                .map_err(|_| LocalProtocolError::RemoteUnavailable)?,
            });
        }
        let session_matches = state.session.as_ref().is_some_and(|cached| {
            cached.registry_address == config.registry_address
                && cached.registry_peer_id == config.registry_peer_id
        });
        if !session_matches {
            let transport = &state
                .transport
                .as_ref()
                .ok_or(LocalProtocolError::RemoteUnavailable)?
                .transport;
            state.session = Some(open_mesh_session(config, transport)?);
        }
        let stream = &mut state
            .session
            .as_mut()
            .ok_or(LocalProtocolError::RemoteUnavailable)?
            .stream;
        write_frame(stream, request)?;
        stream
            .flush()
            .map_err(|_| LocalProtocolError::RemoteUnavailable)?;
        read_frame(&mut std::io::BufReader::new(stream))
    }
}

impl MeshRpcBoundary for PersistentMeshRpcBoundary {
    fn call(
        &self,
        config: &RemoteExecutionConfig,
        request: &MeshRequest,
    ) -> Result<MeshResponse, RemoteExecutionFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| RemoteExecutionFailure::RegistryDisconnected)?;
        for attempt in 0..2 {
            match Self::call_once(&mut state, config, request) {
                Ok(response) => return Ok(response),
                Err(_) if attempt == 0 => {
                    state.session = None;
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(_) => return Err(RemoteExecutionFailure::RegistryDisconnected),
            }
        }
        Err(RemoteExecutionFailure::RegistryDisconnected)
    }

    fn uses_persistent_session(&self) -> bool {
        true
    }
}

#[derive(Clone)]
struct RemoteExecutionJob {
    generation: Arc<()>,
    config: RemoteExecutionConfig,
    boundary: Arc<dyn MeshRpcBoundary>,
    timeout: Duration,
    activity: ActivityEvent,
    workspace_path: String,
    request_id: String,
    app_path: String,
    cancelled: Arc<AtomicBool>,
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
            connection_storage: None,
            snapshot,
            diagnostics,
            autostart_adapter: None,
            dashboard_policy: None,
            dashboard: None,
            remote_execution: None,
            remote_execution_generation: Arc::new(()),
            remote_execution_boundary: None,
            remote_execution_timeout: Duration::from_secs(30),
            inflight_executions: HashMap::new(),
        }
    }

    pub fn new_with_platform_lifecycle(
        snapshot: DaemonSnapshot,
        diagnostics: Vec<DiagnosticItem>,
    ) -> Self {
        Self {
            connection_storage: None,
            snapshot,
            diagnostics,
            autostart_adapter: Some(Arc::new(PlatformAutostartAdapter)),
            dashboard_policy: None,
            dashboard: None,
            remote_execution: None,
            remote_execution_generation: Arc::new(()),
            remote_execution_boundary: None,
            remote_execution_timeout: Duration::from_secs(30),
            inflight_executions: HashMap::new(),
        }
    }

    pub fn new_with_autostart_adapter(
        snapshot: DaemonSnapshot,
        diagnostics: Vec<DiagnosticItem>,
        autostart_adapter: Arc<dyn AutostartAdapter>,
    ) -> Self {
        Self {
            connection_storage: None,
            snapshot,
            diagnostics,
            autostart_adapter: Some(autostart_adapter),
            dashboard_policy: None,
            dashboard: None,
            remote_execution: None,
            remote_execution_generation: Arc::new(()),
            remote_execution_boundary: None,
            remote_execution_timeout: Duration::from_secs(30),
            inflight_executions: HashMap::new(),
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

    /// Fixed by daemon startup, never accepted from an IPC client.
    pub fn configure_connection_storage(
        &mut self,
        identity: PathBuf,
    ) -> Result<(), LocalProtocolError> {
        if !identity.is_absolute() || self.connection_storage.is_some() {
            return Err(LocalProtocolError::InvalidFrame);
        }
        self.connection_storage = Some(identity);
        Ok(())
    }

    fn set_connection(
        &mut self,
        configuration: crate::connection_config::ConnectionConfig,
        now: u64,
    ) -> Result<LocalResponse, LocalProtocolError> {
        use crate::connection_config::ConnectionConfig;
        let identity = self
            .connection_storage
            .clone()
            .ok_or(LocalProtocolError::FeatureUnavailable)?;
        let mut disk_observation = None;
        let result = self
            .dashboard
            .as_mut()
            .ok_or(LocalProtocolError::Unauthorized)?
            .apply_connection_change(
                &configuration,
                || {
                    let before = ConnectionConfig::load(&identity);
                    let saved = configuration.save(&identity);
                    let after = ConnectionConfig::load(&identity);
                    let observation = ConnectionWriteObservation {
                        before,
                        saved,
                        after,
                    };
                    let verified = observation.callback_result(&configuration);
                    disk_observation = Some(observation);
                    verified
                },
                now,
            );
        // The daemon mutex serializes writers. A failed atomic replace may have
        // committed: inspect disk, never claim a rollback that did not happen.
        if let Some(observation) = disk_observation {
            self.reconcile_connection_write(&configuration, identity, observation);
        }
        result.map_err(map_dashboard_error)?;
        Ok(LocalResponse::Acknowledged)
    }

    fn reconcile_connection_write(
        &mut self,
        target: &crate::connection_config::ConnectionConfig,
        identity: PathBuf,
        observation: ConnectionWriteObservation,
    ) {
        let target_observed =
            observation.after.as_ref().ok().and_then(Option::as_ref) == Some(target);
        if target_observed && (observation.saved.is_ok() || observation.after != observation.before)
        {
            // Independent of the final audit result: activate only the exact
            // authorized target, never a concurrently substituted configuration.
            self.enable_remote_execution(RemoteExecutionConfig {
                registry_address: target.registry_address().into(),
                registry_peer_id: target.registry_peer_id().into(),
                identity_path: identity,
                client_id: self.snapshot.public_identity.clone(),
            });
            self.snapshot
                .warnings
                .retain(|warning| warning != "connection_configuration_invalid");
            self.diagnostics
                .retain(|item| item.code != "connection_configuration_invalid");
        } else if observation.saved.is_err()
            && observation.after.is_ok()
            && observation.after == observation.before
        {
            // A pre-replacement failure must retain any transient override.
        } else {
            self.invalidate_inventory_generation();
            self.remote_execution = None;
            self.remote_execution_boundary = None;
            self.snapshot.connection = ConnectionState::Degraded;
            if !self
                .snapshot
                .warnings
                .iter()
                .any(|warning| warning == "connection_configuration_invalid")
            {
                self.snapshot
                    .warnings
                    .push("connection_configuration_invalid".into());
            }
        }
    }

    pub fn enable_remote_execution(&mut self, config: RemoteExecutionConfig) {
        self.invalidate_inventory_generation();
        self.remote_execution = Some(config);
        self.remote_execution_boundary = Some(Arc::new(PersistentMeshRpcBoundary::default()));
        self.remote_execution_timeout = Duration::from_secs(30);
    }

    pub fn enable_remote_execution_with_boundary(
        &mut self,
        config: RemoteExecutionConfig,
        boundary: Arc<dyn MeshRpcBoundary>,
        timeout: Duration,
    ) {
        self.invalidate_inventory_generation();
        self.remote_execution = Some(config);
        self.remote_execution_boundary = Some(boundary);
        self.remote_execution_timeout = timeout.max(Duration::from_millis(1));
    }

    fn invalidate_inventory_generation(&mut self) {
        // The old token remains alive in each in-flight poll: no overflow or
        // same-address ABA can make an obsolete result current again.
        self.remote_execution_generation = Arc::new(());
        if let Some(dashboard) = self.dashboard.as_mut() {
            dashboard.disconnect_inventory(now_ms());
        }
        self.snapshot.connection = ConnectionState::Connecting;
    }

    fn observe_job_controller(
        &mut self,
        generation: &Arc<()>,
        peer_id: &str,
    ) -> Result<(), RemoteExecutionFailure> {
        if !Arc::ptr_eq(generation, &self.remote_execution_generation) {
            return Ok(());
        }
        self.dashboard
            .as_mut()
            .ok_or(RemoteExecutionFailure::AuditUnavailable)?
            .observe_authenticated_controller(peer_id, now_ms())
            .map_err(map_dashboard_error)
            .map_err(map_transition_failure)?;
        self.snapshot.connection = ConnectionState::Connected;
        Ok(())
    }

    fn prepare_remote_execution(
        &mut self,
        activity_id: ActivityId,
        workspace_path: String,
        request_id: String,
        app_path: String,
        session: &AuthenticatedTargetSession,
    ) -> Result<RemoteExecutionJob, LocalProtocolError> {
        if !valid_remote_component(&workspace_path)
            || !valid_remote_component(&app_path)
            || !valid_remote_identifier(&request_id)
        {
            return Err(LocalProtocolError::InvalidFrame);
        }
        let config = self
            .remote_execution
            .clone()
            .ok_or(LocalProtocolError::FeatureUnavailable)?;
        let activity = self
            .dashboard
            .as_ref()
            .ok_or(LocalProtocolError::FeatureUnavailable)?
            .activity(&activity_id)
            .cloned()
            .ok_or(LocalProtocolError::PermissionDenied)?;
        let candidate_grant = RemoteOperationGrant::new(
            request_id.clone(),
            workspace_path.clone(),
            activity.device_id.clone(),
            AppleOperation::InstallApp {
                app_path: app_path.clone(),
            },
        )
        .map_err(|_| LocalProtocolError::PermissionDenied)?;
        if activity.state != ActivityState::Queued
            || activity.authorization.effect != PolicyEffect::Allow
            || activity.target_host_id != *session.local_host_id()
            || activity.device_id.is_none()
            || activity.operation.as_str() != "apple.install_app"
            || !activity.resources.contains(&ResourceClass::WorkspaceRead)
            || !activity.resources.contains(&ResourceClass::DeviceLease)
            || !activity
                .resources
                .contains(&ResourceClass::ApplicationInstall)
            || activity.remote_operation_sha256.as_deref()
                != Some(candidate_grant.canonical_sha256())
        {
            return Err(LocalProtocolError::PermissionDenied);
        }
        if self.inflight_executions.contains_key(&activity_id) {
            return Err(LocalProtocolError::RevisionConflict);
        }
        let cancelled = Arc::new(AtomicBool::new(false));
        self.inflight_executions
            .insert(activity_id.clone(), Arc::clone(&cancelled));
        Ok(RemoteExecutionJob {
            generation: Arc::clone(&self.remote_execution_generation),
            config,
            boundary: self
                .remote_execution_boundary
                .clone()
                .ok_or(LocalProtocolError::FeatureUnavailable)?,
            timeout: self.remote_execution_timeout,
            activity,
            workspace_path,
            request_id,
            app_path,
            cancelled,
        })
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
            LocalRequest::ConnectionSettings { .. } => Ok(LocalResponse::ConnectionSettings {
                registry_address: self
                    .remote_execution
                    .as_ref()
                    .map(|config| config.registry_address.clone()),
                registry_peer_id: self
                    .remote_execution
                    .as_ref()
                    .map(|config| config.registry_peer_id.clone()),
                connection: self.snapshot.connection,
            }),
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
            | LocalRequest::SetConnection { .. }
            | LocalRequest::RequestAuthenticatedApproval { .. }
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
            | LocalRequest::StartRemoteExecution { .. } => Err(LocalProtocolError::Unauthorized),
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
            LocalRequest::SetConnection { configuration, .. } => {
                self.set_connection(configuration, now_ms)
            }
            LocalRequest::RequestApproval {
                access,
                lifetime_ms,
                ..
            } => {
                let requires_remote_target =
                    access.resources.contains(&ResourceClass::WorkspaceRead)
                        && access.resources.contains(&ResourceClass::DeviceLease);
                let production_mesh_identity =
                    self.remote_execution.as_ref().is_some_and(|config| {
                        config.identity_path.join("certificate.der").is_file()
                            && config.identity_path.join("private-key.der").is_file()
                    });
                if requires_remote_target
                    && production_mesh_identity
                    && self
                        .dashboard
                        .as_ref()
                        .is_some_and(|service| access.source_host_id != *service.local_host_id())
                {
                    return Err(LocalProtocolError::MeshIdentityMismatch);
                }
                if requires_remote_target {
                    let online = self
                        .remote_execution
                        .as_ref()
                        .zip(self.remote_execution_boundary.as_ref())
                        .and_then(|(config, boundary)| {
                            boundary.call(config, &MeshRequest::List).ok()
                        })
                        .is_some_and(|response| {
                            response.accepted
                                && response.hosts.iter().any(|host| {
                                    host.id == access.target_host_id.as_str()
                                        && host.status == "online"
                                        && access.device_id.as_ref().is_none_or(|device_id| {
                                            host.devices.iter().any(|device| {
                                                device.id == device_id.as_str()
                                                    && device.state == "connected"
                                            })
                                        })
                                })
                        });
                    if !online {
                        self.dashboard
                            .as_mut()
                            .ok_or(LocalProtocolError::FeatureUnavailable)?
                            .record_preapproval_target_offline(&access, now_ms)
                            .map_err(map_dashboard_error)?;
                        return Err(LocalProtocolError::TargetOffline);
                    }
                }
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
            LocalRequest::RequestAuthenticatedApproval {
                assertion,
                lifetime_ms,
                ..
            } => {
                let config = self
                    .remote_execution
                    .as_ref()
                    .ok_or(LocalProtocolError::MeshIdentityMismatch)?;
                let verifier = SecureTransport::load_or_create(
                    &config.identity_path,
                    config.client_id.clone(),
                )
                .map_err(|_| LocalProtocolError::MeshIdentityMismatch)?;
                let local_host = self
                    .dashboard
                    .as_ref()
                    .ok_or(LocalProtocolError::FeatureUnavailable)?
                    .local_host_id()
                    .clone();
                let access = verify_mesh_approval(
                    &verifier,
                    &assertion,
                    &config.registry_peer_id,
                    &local_host,
                    now_ms,
                )
                .map_err(|_| LocalProtocolError::MeshIdentityMismatch)?;
                if session.local_host_id() != &local_host {
                    return Err(LocalProtocolError::MeshIdentityMismatch);
                }
                let online = self
                    .remote_execution_boundary
                    .as_ref()
                    .and_then(|boundary| boundary.call(config, &MeshRequest::List).ok())
                    .is_some_and(|response| {
                        response.accepted
                            && response.hosts.iter().any(|host| {
                                host.id == access.target_host_id.as_str()
                                    && host.status == "online"
                                    && access.device_id.as_ref().is_none_or(|device_id| {
                                        host.devices.iter().any(|device| {
                                            device.id == device_id.as_str()
                                                && device.state == "connected"
                                        })
                                    })
                            })
                    });
                if !online {
                    self.dashboard
                        .as_mut()
                        .ok_or(LocalProtocolError::FeatureUnavailable)?
                        .record_preapproval_target_offline(&access, now_ms)
                        .map_err(map_dashboard_error)?;
                    return Err(LocalProtocolError::TargetOffline);
                }
                let (nonce, expires_at_ms) = self
                    .dashboard
                    .as_mut()
                    .ok_or(LocalProtocolError::FeatureUnavailable)?
                    .request_approval(access, lifetime_ms, now_ms)
                    .map_err(map_dashboard_error)?;
                Ok(LocalResponse::ApprovalCreated {
                    nonce,
                    expires_at_ms,
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
                    .audit_export_manifest(filter, None)
                    .map_err(map_dashboard_error)?;
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
                if cancelled {
                    if let Some(token) = self.inflight_executions.get(&activity_id) {
                        token.store(true, Ordering::Release);
                    }
                }
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
            LocalRequest::StartRemoteExecution { .. } => {
                Err(LocalProtocolError::FeatureUnavailable)
            }
            legacy => self.handle(legacy),
        }
    }
}

fn valid_remote_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn valid_remote_component(value: &str) -> bool {
    let path = Path::new(value);
    !value.is_empty()
        && value.len() <= 1024
        && !path.is_absolute()
        && !value.contains(['\r', '\n', '\0'])
        && path.components().all(|component| {
            matches!(
                component,
                std::path::Component::Normal(_) | std::path::Component::CurDir
            )
        })
}

fn execution_metrics() -> MetricSnapshot {
    let unavailable = || MetricValue::Unavailable {
        reason: SafeCode::parse("observer_unavailable").expect("constant safe code"),
    };
    MetricSnapshot {
        current_memory_bytes: unavailable(),
        peak_memory_bytes: unavailable(),
        cpu_time_ms: unavailable(),
        process_count: unavailable(),
    }
}

fn execution_message(code: MessageCode) -> DisplayMessage {
    DisplayMessage::new(code, Vec::new()).expect("constant display message")
}

/// Poll using a separate transport and without holding the local IPC state lock during I/O.
/// A weak reference lets the worker exit when its daemon state is released.
pub fn start_registry_inventory_observer(state: &Arc<Mutex<DaemonState>>) {
    let state = Arc::downgrade(state);
    std::thread::spawn(move || {
        let boundary = PersistentMeshRpcBoundary::default();
        while poll_registry_inventory(&state, &boundary) {
            std::thread::sleep(Duration::from_secs(1));
        }
    });
}

fn poll_registry_inventory(
    weak: &std::sync::Weak<Mutex<DaemonState>>,
    boundary: &dyn MeshRpcBoundary,
) -> bool {
    let (config, generation) = {
        let Some(state) = weak.upgrade() else {
            return false;
        };
        let Ok(state) = state.lock() else {
            return false;
        };
        let Some(config) = state.remote_execution.clone() else {
            return true;
        };
        (config, Arc::clone(&state.remote_execution_generation))
    };
    let result = boundary.call(&config, &MeshRequest::List);
    let Some(state) = weak.upgrade() else {
        return false;
    };
    let Ok(mut state) = state.lock() else {
        return false;
    };
    if !Arc::ptr_eq(&generation, &state.remote_execution_generation) {
        return true;
    }
    let connected = if let Some(dashboard) = state.dashboard.as_mut() {
        match result {
            Ok(response) if response.accepted => dashboard
                .observe_authenticated_inventory(&config.registry_peer_id, now_ms(), response.hosts)
                .is_ok(),
            _ => false,
        }
    } else {
        false
    };
    if !connected {
        if let Some(dashboard) = state.dashboard.as_mut() {
            dashboard.disconnect_inventory(now_ms());
        }
    }
    state.snapshot.connection = if connected {
        ConnectionState::Connected
    } else {
        ConnectionState::Disconnected
    };
    true
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod inventory_generation_tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn connection_write_reconciliation_only_activates_the_approved_target() {
        use crate::connection_config::{ConnectionConfig, ConnectionConfigError};
        let target = ConnectionConfig::new("127.0.0.1:7444", "registry").unwrap();
        let foreign = ConnectionConfig::new("127.0.0.1:7445", "foreign").unwrap();
        let state = state();
        let mut daemon = state.lock().unwrap();
        daemon.enable_remote_execution(config());
        let old_generation = daemon.remote_execution_generation.clone();
        let verified = ConnectionWriteObservation {
            before: Ok(Some(target.clone())),
            saved: Ok(()),
            after: Ok(Some(target.clone())),
        };
        assert!(verified.callback_result(&target).is_ok());
        // A final audit failure does not erase verified write evidence: disk A
        // and transient runtime B must converge to the authorized A.
        daemon.reconcile_connection_write(&target, PathBuf::from("unused"), verified);
        assert_eq!(
            daemon.remote_execution.as_ref().unwrap().registry_address,
            target.registry_address()
        );
        assert!(!Arc::ptr_eq(
            &old_generation,
            &daemon.remote_execution_generation
        ));
        for after in [
            Ok(Some(foreign.clone())),
            Err(ConnectionConfigError::Unavailable),
            Ok(None),
        ] {
            let observation = ConnectionWriteObservation {
                before: Ok(Some(target.clone())),
                saved: Ok(()),
                after,
            };
            assert!(
                observation.callback_result(&target).is_err(),
                "unverified write must audit Failed"
            );
            daemon.reconcile_connection_write(&target, PathBuf::from("unused"), observation);
            assert!(
                daemon.remote_execution.is_none(),
                "foreign or unknown configuration activated"
            );
            assert_eq!(daemon.snapshot.connection, ConnectionState::Degraded);
        }
        daemon.diagnostics.push(DiagnosticItem {
            code: "connection_configuration_invalid".into(),
            message: "invalid configuration".into(),
            healthy: false,
        });
        daemon.reconcile_connection_write(
            &target,
            PathBuf::from("unused"),
            ConnectionWriteObservation {
                before: Err(ConnectionConfigError::InvalidFormat),
                saved: Ok(()),
                after: Ok(Some(target.clone())),
            },
        );
        assert!(
            !daemon
                .snapshot
                .warnings
                .iter()
                .any(|warning| warning == "connection_configuration_invalid")
        );
        assert!(
            !daemon
                .diagnostics
                .iter()
                .any(|item| item.code == "connection_configuration_invalid")
        );
    }

    #[test]
    fn connection_settings_reports_only_active_public_connection_data() {
        let state = state();
        let mut daemon = state.lock().unwrap();
        let request = || {
            serde_json::from_value::<LocalRequest>(serde_json::json!({
                "request": "connection_settings",
                "version": { "major": 1, "minor": 1 }
            }))
            .expect("connection settings must be part of the local protocol")
        };
        assert_eq!(
            serde_json::to_value(daemon.handle(request()).unwrap()).unwrap(),
            serde_json::json!({
                "type": "connection_settings",
                "payload": {
                    "registry_address": null,
                    "registry_peer_id": null,
                    "connection": "disconnected"
                }
            })
        );
        daemon.enable_remote_execution(config());
        assert_eq!(
            serde_json::to_value(daemon.handle(request()).unwrap()).unwrap(),
            serde_json::json!({
                "type": "connection_settings",
                "payload": {
                    "registry_address": "127.0.0.1:7443",
                    "registry_peer_id": "registry",
                    "connection": "connecting"
                }
            })
        );
        assert_eq!(
            daemon.handle(LocalRequest::ConnectionSettings {
                version: LocalProtocolVersion { major: 1, minor: 0 },
            }),
            Err(LocalProtocolError::FeatureUnavailable)
        );
        assert!(
            serde_json::from_value::<LocalRequest>(serde_json::json!({
                "request": "connection_settings",
                "version": { "major": 1, "minor": 1 },
                "identity_path": "not-client-controlled"
            }))
            .is_err()
        );
    }

    fn state() -> Arc<Mutex<DaemonState>> {
        Arc::new(Mutex::new(DaemonState::new(
            DaemonSnapshot {
                public_identity: "workstation".into(),
                daemon_version: "test".into(),
                os: "windows".into(),
                architecture: "x86_64".into(),
                role: DaemonRole::Workstation,
                endpoint: "test".into(),
                connection: ConnectionState::Disconnected,
                local_protocol: LocalProtocolVersion::CURRENT,
                remote_protocol: "1.0".into(),
                warnings: vec![],
                remote_access_paused: false,
                autostart: false,
                log_location: String::new(),
                features: vec![],
            },
            vec![],
        )))
    }

    fn config() -> RemoteExecutionConfig {
        RemoteExecutionConfig {
            registry_address: "127.0.0.1:7443".into(),
            registry_peer_id: "registry".into(),
            identity_path: PathBuf::from("unused"),
            client_id: "workstation".into(),
        }
    }

    struct Gate {
        entered: mpsc::Sender<()>,
        release: Mutex<mpsc::Receiver<()>>,
    }
    impl MeshRpcBoundary for Gate {
        fn call(
            &self,
            _: &RemoteExecutionConfig,
            request: &MeshRequest,
        ) -> Result<MeshResponse, RemoteExecutionFailure> {
            assert!(matches!(request, MeshRequest::List));
            self.entered.send(()).unwrap();
            self.release
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(5))
                .unwrap();
            Err(RemoteExecutionFailure::RegistryDisconnected)
        }
    }

    #[test]
    fn obsolete_job_controller_response_does_not_change_new_connection_state() {
        let state = state();
        let mut daemon = state.lock().unwrap();
        daemon.enable_remote_execution(config());
        let old_generation = Arc::clone(&daemon.remote_execution_generation);
        daemon.enable_remote_execution(config());
        daemon
            .observe_job_controller(&old_generation, "registry")
            .unwrap();
        assert_eq!(daemon.snapshot.connection, ConnectionState::Connecting);
    }

    #[test]
    fn inventory_tick_sees_late_configuration_and_discards_same_address_old_generation() {
        let state = state();
        let weak = Arc::downgrade(&state);
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let gate = Gate {
            entered: entered_tx,
            release: Mutex::new(release_rx),
        };
        // An observer started in local-only mode must remain usable after setup.
        assert!(poll_registry_inventory(&weak, &gate));
        assert!(entered_rx.try_recv().is_err());
        state.lock().unwrap().enable_remote_execution(config());
        let worker = std::thread::spawn(move || poll_registry_inventory(&weak, &gate));
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        // Even reconnecting the same address is a new generation, not equality
        // of strings. Acquiring this lock also proves no lock spans network I/O.
        state.lock().unwrap().enable_remote_execution(config());
        assert_eq!(
            state.lock().unwrap().snapshot.connection,
            ConnectionState::Connecting
        );
        release_tx.send(()).unwrap();
        assert!(worker.join().unwrap());
        assert_eq!(
            state.lock().unwrap().snapshot.connection,
            ConnectionState::Connecting
        );
    }
}

fn open_mesh_session(
    config: &RemoteExecutionConfig,
    transport: &SecureTransport,
) -> Result<CachedMeshSession, LocalProtocolError> {
    let address = config
        .registry_address
        .to_socket_addrs()
        .map_err(|_| LocalProtocolError::RemoteUnavailable)?
        .next()
        .ok_or(LocalProtocolError::RemoteUnavailable)?;
    let stream = TcpStream::connect_timeout(&address, Duration::from_millis(500))
        .map_err(|_| LocalProtocolError::RemoteUnavailable)?;
    stream
        .set_read_timeout(Some(Duration::from_millis(250)))
        .map_err(|_| LocalProtocolError::RemoteUnavailable)?;
    stream
        .set_write_timeout(Some(Duration::from_millis(250)))
        .map_err(|_| LocalProtocolError::RemoteUnavailable)?;
    let stream = transport
        .connect_tls(stream, &config.registry_peer_id)
        .map_err(|_| LocalProtocolError::RemoteUnavailable)?;
    Ok(CachedMeshSession {
        registry_address: config.registry_address.clone(),
        registry_peer_id: config.registry_peer_id.clone(),
        stream,
    })
}

fn transition_execution(
    state: &Arc<Mutex<DaemonState>>,
    activity_id: &ActivityId,
    activity_state: ActivityState,
    message: MessageCode,
) -> Result<(), LocalProtocolError> {
    let mut state = state.lock().map_err(|_| LocalProtocolError::Io)?;
    state
        .dashboard
        .as_mut()
        .ok_or(LocalProtocolError::FeatureUnavailable)?
        .transition_activity(
            activity_id,
            activity_state,
            execution_metrics(),
            Some(execution_message(message)),
            now_ms(),
        )
        .map_err(map_dashboard_error)?;
    Ok(())
}

fn map_transition_failure(error: LocalProtocolError) -> RemoteExecutionFailure {
    if error == LocalProtocolError::AuditUnavailable {
        RemoteExecutionFailure::AuditUnavailable
    } else {
        RemoteExecutionFailure::RegistryDisconnected
    }
}

fn classify_remote_rejection(value: Option<&str>) -> RemoteExecutionFailure {
    let value = value.unwrap_or_default().to_ascii_lowercase();
    if value == "artifact_publish_failed" {
        RemoteExecutionFailure::OperationFailed
    } else if value.contains("observer_unavailable") {
        RemoteExecutionFailure::ObserverUnavailable
    } else if value.contains("resync") || value.contains("overflow") {
        RemoteExecutionFailure::EventResyncRequired
    } else if value.contains("daemon_restarted") {
        RemoteExecutionFailure::DaemonRestarted
    } else if value.contains("audit_unavailable") {
        RemoteExecutionFailure::AuditUnavailable
    } else if value.contains("lease") && (value.contains("stale") || value.contains("expired")) {
        RemoteExecutionFailure::StaleLease
    } else if value.contains("version")
        || value.contains("unsupported")
        || value.contains("incompatible")
    {
        RemoteExecutionFailure::AgentIncompatible
    } else if value.contains("denied") || value.contains("policy") {
        RemoteExecutionFailure::PolicyDenied
    } else {
        RemoteExecutionFailure::RegistryDisconnected
    }
}

fn interruptible_rpc(
    job: &RemoteExecutionJob,
    request: MeshRequest,
) -> Result<MeshResponse, RemoteExecutionFailure> {
    if job.boundary.uses_persistent_session() {
        if job.cancelled.load(Ordering::Acquire) {
            return Err(RemoteExecutionFailure::Cancelled);
        }
        let result = job.boundary.call(&job.config, &request);
        if job.cancelled.load(Ordering::Acquire) {
            return Err(RemoteExecutionFailure::Cancelled);
        }
        return result;
    }
    let boundary = Arc::clone(&job.boundary);
    let config = job.config.clone();
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let _ = sender.send(boundary.call(&config, &request));
    });
    loop {
        if job.cancelled.load(Ordering::Acquire) {
            return Err(RemoteExecutionFailure::Cancelled);
        }
        match receiver.recv_timeout(Duration::from_millis(20)) {
            Ok(result) => return result,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                return Err(RemoteExecutionFailure::RegistryDisconnected);
            }
        }
    }
}

fn bounded_cleanup_rpc(job: &RemoteExecutionJob, request: MeshRequest) {
    let boundary = Arc::clone(&job.boundary);
    let config = job.config.clone();
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let _ = sender.send(boundary.call(&config, &request));
    });
    let _ = receiver.recv_timeout(Duration::from_millis(500));
}

struct RemoteCleanupGuard<'a> {
    job: &'a RemoteExecutionJob,
    lease_id: String,
    dispatched_job_id: Option<String>,
}

impl<'a> RemoteCleanupGuard<'a> {
    fn new(job: &'a RemoteExecutionJob, lease_id: String) -> Self {
        Self {
            job,
            lease_id,
            dispatched_job_id: None,
        }
    }

    fn dispatched(&mut self, job_id: &str) {
        self.dispatched_job_id = Some(job_id.to_owned());
    }

    fn completed(&mut self) {
        self.dispatched_job_id = None;
    }
}

impl Drop for RemoteCleanupGuard<'_> {
    fn drop(&mut self) {
        if let Some(job_id) = self.dispatched_job_id.take() {
            bounded_cleanup_rpc(self.job, MeshRequest::AppleCancel { job_id });
        }
        bounded_cleanup_rpc(
            self.job,
            MeshRequest::Lease {
                operation: LeaseRequest::Release {
                    lease_id: self.lease_id.clone(),
                },
            },
        );
    }
}

fn execute_remote_job(
    state: &Arc<Mutex<DaemonState>>,
    job: &RemoteExecutionJob,
) -> Result<(), RemoteExecutionFailure> {
    let device_id = job
        .activity
        .device_id
        .as_ref()
        .ok_or(RemoteExecutionFailure::PolicyDenied)?
        .as_str()
        .to_owned();
    let lease = job
        .boundary
        .call(
            &job.config,
            &MeshRequest::Lease {
                operation: LeaseRequest::Acquire {
                    device_id: device_id.clone(),
                    lifetime_ms: 30_000,
                },
            },
        )
        .map_err(|failure| {
            if failure == RemoteExecutionFailure::RegistryDisconnected {
                RemoteExecutionFailure::TargetOffline
            } else {
                failure
            }
        })?;
    let grant = lease
        .lease_grant
        .ok_or_else(|| classify_remote_rejection(lease.error.as_deref()))?;
    let mut cleanup = RemoteCleanupGuard::new(job, grant.lease_id.clone());
    if job.cancelled.load(Ordering::Acquire) {
        return Err(RemoteExecutionFailure::Cancelled);
    }
    {
        let mut daemon = state
            .lock()
            .map_err(|_| RemoteExecutionFailure::AuditUnavailable)?;
        daemon.observe_job_controller(&job.generation, &job.config.registry_peer_id)?;
    }
    let accepted = job.boundary.call(
        &job.config,
        &MeshRequest::AppleRun {
            operation: AppleRequest {
                version: RemoteProtocolVersion { major: 1, minor: 0 },
                request_id: job.request_id.clone(),
                idempotency_key: job.request_id.clone(),
                capability: "apple.simulator@1".into(),
                workspace_path: job.workspace_path.clone(),
                device_id: Some(device_id),
                lease_id: Some(grant.lease_id.clone()),
                operation: AppleOperation::InstallApp {
                    app_path: job.app_path.clone(),
                },
            },
        },
    )?;
    let job_id = if accepted.accepted {
        accepted.job_id
    } else if accepted.error.is_none() {
        return Err(RemoteExecutionFailure::AgentIncompatible);
    } else {
        return Err(classify_remote_rejection(accepted.error.as_deref()));
    }
    .ok_or(RemoteExecutionFailure::AgentIncompatible)?;
    cleanup.dispatched(&job_id);
    if job.cancelled.load(Ordering::Acquire) {
        return Err(RemoteExecutionFailure::Cancelled);
    }
    transition_execution(
        state,
        &job.activity.activity_id,
        ActivityState::Running,
        MessageCode::ActivityStarted,
    )
    .map_err(map_transition_failure)?;

    let deadline = Instant::now() + job.timeout;
    let mut after = 0;
    let mut reconnecting = false;
    let mut last_failure = RemoteExecutionFailure::RegistryDisconnected;
    loop {
        if Instant::now() >= deadline {
            return Err(last_failure);
        }
        match interruptible_rpc(
            job,
            MeshRequest::Events {
                job_id: job_id.clone(),
                after,
            },
        ) {
            Ok(response) => {
                if !response.accepted {
                    return Err(classify_remote_rejection(response.error.as_deref()));
                }
                if reconnecting {
                    transition_execution(
                        state,
                        &job.activity.activity_id,
                        ActivityState::Running,
                        MessageCode::ActivityStarted,
                    )
                    .map_err(map_transition_failure)?;
                    reconnecting = false;
                }
                after = response
                    .events
                    .iter()
                    .map(|event| event.sequence)
                    .max()
                    .unwrap_or(after)
                    .max(after);
                if let Some(terminal) = response.events.iter().rev().find(|event| {
                    matches!(event.kind.as_str(), "completed" | "rejected" | "cancelled")
                }) {
                    let (terminal_state, message) = match terminal.kind.as_str() {
                        "completed" => (ActivityState::Succeeded, MessageCode::OperationSucceeded),
                        "cancelled" => (ActivityState::Failed, MessageCode::OperationCancelled),
                        _ => (
                            ActivityState::Failed,
                            classify_remote_rejection(Some(&terminal.payload)).message_code(),
                        ),
                    };
                    transition_execution(state, &job.activity.activity_id, terminal_state, message)
                        .map_err(map_transition_failure)?;
                    cleanup.completed();
                    return Ok(());
                }
            }
            Err(RemoteExecutionFailure::Cancelled) => {
                return Err(RemoteExecutionFailure::Cancelled);
            }
            Err(failure) if !reconnecting => {
                last_failure = failure;
                transition_execution(
                    state,
                    &job.activity.activity_id,
                    ActivityState::Reconnecting,
                    MessageCode::RegistryStale,
                )
                .map_err(map_transition_failure)?;
                reconnecting = true;
            }
            Err(failure) => last_failure = failure,
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn run_remote_job(state: Arc<Mutex<DaemonState>>, job: RemoteExecutionJob) {
    let activity_id = job.activity.activity_id.clone();
    if let Err(failure) = execute_remote_job(&state, &job) {
        if failure == RemoteExecutionFailure::AuditUnavailable {
            if let Ok(mut daemon) = state.lock() {
                if let Some(dashboard) = daemon.dashboard.as_mut() {
                    let _ = dashboard.record_audit_unavailable_terminal(
                        &activity_id,
                        execution_metrics(),
                        now_ms(),
                    );
                }
            }
        }
        let current = state
            .lock()
            .ok()
            .and_then(|state| state.dashboard.as_ref()?.activity(&activity_id).cloned());
        if let Some(current) = current {
            if current.state == ActivityState::Queued {
                let _ = transition_execution(
                    &state,
                    &activity_id,
                    ActivityState::Reconnecting,
                    failure.message_code(),
                );
            }
            if !matches!(
                current.state,
                ActivityState::Succeeded
                    | ActivityState::Failed
                    | ActivityState::Denied
                    | ActivityState::Cancelled
            ) {
                let _ = transition_execution(
                    &state,
                    &activity_id,
                    ActivityState::Failed,
                    failure.message_code(),
                );
            }
        }
    }
    if let Ok(mut state) = state.lock() {
        state.inflight_executions.remove(&activity_id);
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
        Error::ConfigurationUnavailable => LocalProtocolError::Io,
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
            Ok(LocalRequest::StartRemoteExecution {
                activity_id,
                workspace_path,
                request_id,
                app_path,
                ..
            }) => match state.lock() {
                Ok(mut daemon) => match daemon.local_policy_host_id() {
                    Some(local_host_id) => {
                        let session = AuthenticatedTargetSession::issue(local_host_id);
                        match daemon.prepare_remote_execution(
                            activity_id.clone(),
                            workspace_path,
                            request_id,
                            app_path,
                            &session,
                        ) {
                            Ok(job) => {
                                drop(daemon);
                                let worker_state = Arc::clone(state);
                                std::thread::spawn(move || run_remote_job(worker_state, job));
                                LocalResponse::ExecutionStarted { activity_id }
                            }
                            Err(error) => error_response(error),
                        }
                    }
                    None => error_response(LocalProtocolError::Unauthorized),
                },
                Err(_) => LocalResponse::Error {
                    code: "internal_error".into(),
                    message: "daemon state unavailable".into(),
                },
            },
            Ok(request) => match state.lock() {
                Ok(mut state) => {
                    if matches!(
                        request,
                        LocalRequest::RequestApproval { .. }
                            | LocalRequest::SetConnection { .. }
                            | LocalRequest::RequestAuthenticatedApproval { .. }
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
                            | LocalRequest::StartRemoteExecution { .. }
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
            LocalProtocolError::TargetOffline => "target_offline",
            LocalProtocolError::MeshIdentityMismatch => "mesh_identity_mismatch",
            LocalProtocolError::RemoteUnavailable => "remote_unavailable",
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

    pub(super) fn current_user_sid() -> Result<String, LocalProtocolError> {
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
