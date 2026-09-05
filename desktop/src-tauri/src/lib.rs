use command_group::CommandGroup;
use device_development_mesh::dashboard::audit::{
    AuditDeletionScope, AuditFilter, ExportManifest, write_private_atomic,
};
use device_development_mesh::dashboard::event_log::EventRead;
use device_development_mesh::dashboard::service::AdminMutation;
use device_development_mesh::dashboard::{
    ApprovalDecision, ApprovalId, ApprovalRequest, AuditRecord, CursorPage, DashboardScope,
    DashboardSnapshot, EventCursor, PolicyRule, RuleId, SubscriberId,
};
use device_development_mesh::local_ipc::{
    ConnectionState, DaemonSnapshot, DiagnosticItem, LocalProtocolVersion, LocalRequest,
    LocalResponse, local_endpoint, send_local_request,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tauri::menu::{Menu, MenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Emitter, Manager, State, WindowEvent};
use tauri_plugin_notification::NotificationExt;
use tauri_plugin_shell::ShellExt;

mod repair_integrity {
    include!(concat!(env!("OUT_DIR"), "/repair_integrity.rs"));
}

pub trait DaemonTransport: Send + Sync + 'static {
    fn send(&self, request: LocalRequest) -> Result<LocalResponse, String>;
}

pub struct LocalDaemonTransport;

impl DaemonTransport for LocalDaemonTransport {
    fn send(&self, request: LocalRequest) -> Result<LocalResponse, String> {
        let endpoint = local_endpoint(&runtime_dir(), "").map_err(|error| error.to_string())?;
        send_local_request(&endpoint, &request).map_err(|error| error.to_string())
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct DiagnosticsResult {
    pub path: String,
    pub items: Vec<DiagnosticItem>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ConnectionSettings {
    pub registry_address: Option<String>,
    pub registry_peer_id: Option<String>,
    pub connection: ConnectionState,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum AuditSaveResult {
    Saved {
        file_name: String,
        manifest: ExportManifest,
    },
    Cancelled,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireEventCursor {
    pub epoch: String,
    pub sequence: String,
}

impl TryFrom<WireEventCursor> for EventCursor {
    type Error = String;

    fn try_from(value: WireEventCursor) -> Result<Self, Self::Error> {
        let parse = |name: &str, raw: String| {
            if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(format!("{name} must be an unsigned decimal string"));
            }
            raw.parse::<u64>()
                .map_err(|_| format!("{name} exceeds u64"))
        };
        Ok(Self {
            epoch: parse("cursor.epoch", value.epoch)?,
            sequence: parse("cursor.sequence", value.sequence)?,
        })
    }
}

fn parse_u64_decimal(name: &str, raw: String) -> Result<u64, String> {
    if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!("{name} must be an unsigned decimal string"));
    }
    raw.parse::<u64>()
        .map_err(|_| format!("{name} exceeds u64"))
}

#[derive(Clone, Debug)]
pub struct JavaScriptWire<T>(pub T);

fn stringify_unsigned_numbers(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Array(values) => values.iter_mut().for_each(stringify_unsigned_numbers),
        serde_json::Value::Object(values) => {
            values.values_mut().for_each(stringify_unsigned_numbers)
        }
        serde_json::Value::Number(number) if number.is_u64() => {
            *value = serde_json::Value::String(number.to_string());
        }
        _ => {}
    }
}

impl<T: Serialize> Serialize for JavaScriptWire<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut value = serde_json::to_value(&self.0).map_err(serde::ser::Error::custom)?;
        stringify_unsigned_numbers(&mut value);
        value.serialize(serializer)
    }
}

pub struct DesktopBridge<T> {
    transport: T,
}

impl<T: DaemonTransport> DesktopBridge<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    pub fn status(&self) -> Result<DaemonSnapshot, String> {
        match self.transport.send(LocalRequest::Status {
            version: LocalProtocolVersion::CURRENT,
        })? {
            LocalResponse::Snapshot(snapshot) => Ok(snapshot),
            response => Err(unexpected_response(response)),
        }
    }

    pub fn connection_settings(&self) -> Result<ConnectionSettings, String> {
        match self.transport.send(LocalRequest::ConnectionSettings {
            version: LocalProtocolVersion::CURRENT,
        })? {
            LocalResponse::ConnectionSettings {
                registry_address,
                registry_peer_id,
                connection,
            } => Ok(ConnectionSettings {
                registry_address,
                registry_peer_id,
                connection,
            }),
            response => Err(unexpected_response(response)),
        }
    }

    pub fn pause(&self) -> Result<(), String> {
        self.acknowledge(LocalRequest::PauseRemoteAccess {
            version: LocalProtocolVersion::CURRENT,
        })
    }

    pub fn resume(&self) -> Result<(), String> {
        self.acknowledge(LocalRequest::ResumeRemoteAccess {
            version: LocalProtocolVersion::CURRENT,
        })
    }

    pub fn set_autostart(&self, enabled: bool) -> Result<(), String> {
        self.acknowledge(LocalRequest::SetAutostart {
            version: LocalProtocolVersion::CURRENT,
            enabled,
        })
    }

    pub fn diagnostics(&self) -> Result<DiagnosticsResult, String> {
        match self.transport.send(LocalRequest::Diagnostics {
            version: LocalProtocolVersion::CURRENT,
        })? {
            LocalResponse::Diagnostics(items) => Ok(DiagnosticsResult {
                path: diagnostics_dir().display().to_string(),
                items,
            }),
            response => Err(unexpected_response(response)),
        }
    }

    pub fn dashboard_snapshot(&self, scope: DashboardScope) -> Result<DashboardSnapshot, String> {
        match self.transport.send(LocalRequest::DashboardSnapshot {
            version: LocalProtocolVersion::CURRENT,
            scope,
        })? {
            LocalResponse::DashboardSnapshot(snapshot) => Ok(snapshot),
            response => Err(unexpected_response(response)),
        }
    }

    pub fn activity_events(
        &self,
        scope: DashboardScope,
        cursor: EventCursor,
        limit: usize,
    ) -> Result<EventRead, String> {
        match self.transport.send(LocalRequest::ActivityEvents {
            version: LocalProtocolVersion::CURRENT,
            scope,
            cursor,
            limit,
        })? {
            LocalResponse::ActivityEvents(events) => Ok(events),
            response => Err(unexpected_response(response)),
        }
    }

    pub fn start_remote_execution(
        &self,
        activity_id: &str,
        workspace_path: &str,
        request_id: &str,
        app_path: &str,
    ) -> Result<device_development_mesh::dashboard::ActivityId, String> {
        let activity_id = device_development_mesh::dashboard::ActivityId::parse(activity_id)
            .map_err(|error| format!("invalid activity_id: {error}"))?;
        match self.transport.send(LocalRequest::StartRemoteExecution {
            version: LocalProtocolVersion::CURRENT,
            activity_id,
            workspace_path: workspace_path.to_owned(),
            request_id: request_id.to_owned(),
            app_path: app_path.to_owned(),
        })? {
            LocalResponse::ExecutionStarted { activity_id } => Ok(activity_id),
            response => Err(unexpected_response(response)),
        }
    }

    pub fn acknowledge_events(
        &self,
        subscriber_id: &str,
        cursor: EventCursor,
    ) -> Result<(), String> {
        let subscriber_id = SubscriberId::parse(subscriber_id)
            .map_err(|error| format!("invalid subscriber_id: {error}"))?;
        self.acknowledge(LocalRequest::AcknowledgeEvents {
            version: LocalProtocolVersion::CURRENT,
            subscriber_id,
            cursor,
        })
    }

    pub fn pending_approvals(&self) -> Result<Vec<ApprovalRequest>, String> {
        match self.transport.send(LocalRequest::PendingApprovals {
            version: LocalProtocolVersion::CURRENT,
        })? {
            LocalResponse::PendingApprovals(approvals) => Ok(approvals),
            response => Err(unexpected_response(response)),
        }
    }

    pub fn with_pending_approval_for_notification<F>(
        &self,
        approval_id: &str,
        notify: F,
    ) -> Result<(), String>
    where
        F: FnOnce(ApprovalRequest) -> Result<(), String>,
    {
        let approval_id = ApprovalId::parse(approval_id)
            .map_err(|error| format!("invalid approval_id: {error}"))?;
        let approval = match self
            .transport
            .send(LocalRequest::PendingApprovalForNotification {
                version: LocalProtocolVersion::CURRENT,
                approval_id,
            })? {
            LocalResponse::PendingApprovalForNotification(approval) => approval,
            response => return Err(unexpected_response(response)),
        };
        notify(approval)
    }

    pub fn decide_pending_approval(
        &self,
        approval_id: &str,
        decision: ApprovalDecision,
    ) -> Result<Option<PolicyRule>, String> {
        let approval_id = ApprovalId::parse(approval_id)
            .map_err(|error| format!("invalid approval_id: {error}"))?;
        match self.transport.send(LocalRequest::DecidePendingApproval {
            version: LocalProtocolVersion::CURRENT,
            approval_id,
            decision,
        })? {
            LocalResponse::ApprovalDecided { created_rule, .. } => Ok(created_rule),
            response => Err(unexpected_response(response)),
        }
    }

    pub fn policy_rules(&self) -> Result<Vec<PolicyRule>, String> {
        match self.transport.send(LocalRequest::PolicyRules {
            version: LocalProtocolVersion::CURRENT,
        })? {
            LocalResponse::PolicyRules(rules) => Ok(rules),
            response => Err(unexpected_response(response)),
        }
    }

    pub fn put_policy_rule(&self, rule: PolicyRule) -> Result<(), String> {
        self.acknowledge(LocalRequest::PutPolicyRule {
            version: LocalProtocolVersion::CURRENT,
            rule,
        })
    }

    pub fn request_admin_mutation_approval(&self, mutation: AdminMutation) -> Result<(), String> {
        match self
            .transport
            .send(LocalRequest::RequestAdminMutationApproval {
                version: LocalProtocolVersion::CURRENT,
                mutation,
                lifetime_ms: 5 * 60 * 1_000,
            })? {
            LocalResponse::ApprovalCreated { .. } => Ok(()),
            response => Err(unexpected_response(response)),
        }
    }

    pub fn delete_policy_rule(
        &self,
        rule_id: &str,
        expected_revision: u64,
    ) -> Result<bool, String> {
        let rule_id =
            RuleId::parse(rule_id).map_err(|error| format!("invalid rule_id: {error}"))?;
        match self
            .transport
            .send(LocalRequest::DeletePolicyRuleIfRevision {
                version: LocalProtocolVersion::CURRENT,
                rule_id,
                expected_revision,
            })? {
            LocalResponse::RuleDeleted { deleted } => Ok(deleted),
            response => Err(unexpected_response(response)),
        }
    }

    pub fn audit_query(
        &self,
        filter: AuditFilter,
        cursor: Option<EventCursor>,
        limit: usize,
    ) -> Result<CursorPage<AuditRecord>, String> {
        match self.transport.send(LocalRequest::AuditQuery {
            version: LocalProtocolVersion::CURRENT,
            filter,
            cursor,
            limit,
        })? {
            LocalResponse::AuditRecords(page) => Ok(page),
            response => Err(unexpected_response(response)),
        }
    }

    fn audit_export_manifest(&self, filter: AuditFilter) -> Result<ExportManifest, String> {
        match self.transport.send(LocalRequest::AuditExportManifest {
            version: LocalProtocolVersion::CURRENT,
            filter,
        })? {
            LocalResponse::AuditExportManifest(manifest) => Ok(manifest),
            response => Err(unexpected_response(response)),
        }
    }

    pub fn save_audit_export_to_path(
        &self,
        filter: AuditFilter,
        path: &Path,
    ) -> Result<AuditSaveResult, String> {
        let manifest = self.audit_export_manifest(filter.clone())?;
        let mut cursor = None;
        let mut records = Vec::with_capacity(manifest.record_count);
        loop {
            let page = self.audit_query(filter.clone(), cursor, 32)?;
            if page.items.is_empty() {
                break;
            }
            cursor = page.next_cursor;
            records.extend(page.items);
            if records.len() > manifest.record_count {
                return Err("audit export changed while saving".into());
            }
        }
        let records_json = serde_json::to_vec(&records).map_err(|error| error.to_string())?;
        if records.len() != manifest.record_count
            || format!("{:x}", Sha256::digest(&records_json)) != manifest.records_sha256
        {
            return Err("audit export changed while saving".into());
        }
        let document = serde_json::to_vec_pretty(
            &serde_json::json!({ "records": records, "manifest": manifest }),
        )
        .map_err(|error| error.to_string())?;
        write_private_atomic(path, &document).map_err(|error| error.to_string())?;
        Ok(AuditSaveResult::Saved {
            file_name: path
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("audit-export.json")
                .to_owned(),
            manifest,
        })
    }

    pub fn save_audit_export_with_picker<F>(
        &self,
        filter: AuditFilter,
        picker: F,
    ) -> Result<AuditSaveResult, String>
    where
        F: FnOnce() -> Option<PathBuf>,
    {
        match picker() {
            Some(path) => self.save_audit_export_to_path(filter, &path),
            None => Ok(AuditSaveResult::Cancelled),
        }
    }

    pub fn delete_audit(
        &self,
        scope: AuditDeletionScope,
        filter: AuditFilter,
    ) -> Result<usize, String> {
        match self.transport.send(LocalRequest::AuditDelete {
            version: LocalProtocolVersion::CURRENT,
            scope,
            filter,
        })? {
            LocalResponse::AuditDeleted { deleted } => Ok(deleted),
            response => Err(unexpected_response(response)),
        }
    }

    fn acknowledge(&self, request: LocalRequest) -> Result<(), String> {
        match self.transport.send(request)? {
            LocalResponse::Acknowledged => Ok(()),
            response => Err(unexpected_response(response)),
        }
    }
}

pub fn run_smoke_probe_with_transport<T: DaemonTransport>(transport: T) -> Result<String, String> {
    serde_json::to_string(&DesktopBridge::new(transport).status()?)
        .map_err(|error| error.to_string())
}

pub fn run_smoke_probe() -> Result<String, String> {
    run_smoke_probe_with_transport(LocalDaemonTransport)
}

fn unexpected_response(response: LocalResponse) -> String {
    match response {
        LocalResponse::Error { code, message } => format!("daemon error ({code}): {message}"),
        _ => "unexpected response from DeviceLane service".into(),
    }
}

fn user_home() -> PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
}

fn runtime_dir() -> PathBuf {
    if let Some(smoke_runtime) = std::env::var_os("DEVICELANE_RUNTIME_DIR") {
        return PathBuf::from(smoke_runtime);
    }
    #[cfg(target_os = "macos")]
    return user_home().join("Library/Application Support/DeviceLane/state/runtime");
    #[cfg(target_os = "linux")]
    return std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| user_home().join(".local/state/devicelane/runtime"))
        .join("devicelane");
    #[cfg(windows)]
    return std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| user_home().join("AppData/Local"))
        .join("DeviceLane/service/runtime");
}

fn log_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    return user_home().join("Library/Logs/DeviceLane");
    #[cfg(target_os = "linux")]
    return user_home().join(".local/state/devicelane/logs");
    #[cfg(windows)]
    return std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| user_home().join("AppData/Local"))
        .join("DeviceLane/service/logs");
}

fn diagnostics_dir() -> PathBuf {
    log_dir().join("diagnostics")
}

type AppBridge = DesktopBridge<LocalDaemonTransport>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepairSpec {
    pub program: PathBuf,
    pub arguments: Vec<OsString>,
    pub service_binary: PathBuf,
}

pub trait RepairProcess {
    fn execute(&self, spec: &RepairSpec) -> Result<(), String>;
}

struct CommandRepairProcess;

const REPAIR_TIMEOUT: Duration = Duration::from_secs(120);
const REPAIR_OUTPUT_LIMIT: usize = 64 * 1024;

fn drain_bounded(mut reader: impl Read, limit: usize) -> Result<(Vec<u8>, bool), String> {
    let mut kept = Vec::with_capacity(limit.min(8192));
    let mut buffer = [0_u8; 8192];
    let mut truncated = false;
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|error| error.to_string())?;
        if count == 0 {
            break;
        }
        let available = limit.saturating_sub(kept.len());
        kept.extend_from_slice(&buffer[..count.min(available)]);
        truncated |= count > available;
    }
    Ok((kept, truncated))
}

fn format_output(bytes: &[u8], truncated: bool) -> String {
    let mut text = String::from_utf8_lossy(bytes).trim().to_owned();
    if truncated {
        text.push_str(" [output truncated]");
    }
    text
}

impl RepairProcess for CommandRepairProcess {
    fn execute(&self, spec: &RepairSpec) -> Result<(), String> {
        execute_repair_process(spec, REPAIR_TIMEOUT, REPAIR_OUTPUT_LIMIT)
    }
}

pub fn execute_repair_process(
    spec: &RepairSpec,
    timeout: Duration,
    output_limit: usize,
) -> Result<(), String> {
    let mut child = Command::new(&spec.program)
        .args(&spec.arguments)
        .env("DEVICELANE_SERVICE_BINARY", &spec.service_binary)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .group_spawn()
        .map_err(|error| format!("DeviceLane repair could not start: {error}"))?;
    let stdout = child
        .inner()
        .stdout
        .take()
        .ok_or("repair stdout pipe unavailable")?;
    let stderr = child
        .inner()
        .stderr
        .take()
        .ok_or("repair stderr pipe unavailable")?;
    let stdout_reader = thread::spawn(move || drain_bounded(stdout, output_limit));
    let stderr_reader = thread::spawn(move || drain_bounded(stderr, output_limit));
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
            break status;
        }
        if started.elapsed() >= timeout {
            child
                .kill()
                .map_err(|error| format!("repair timeout; process tree kill failed: {error}"))?;
            child
                .wait()
                .map_err(|error| format!("repair timeout; child reap failed: {error}"))?;
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err(format!(
                "DeviceLane repair timed out after {} seconds",
                timeout.as_secs_f64()
            ));
        }
        thread::sleep(Duration::from_millis(20));
    };
    let (_, _) = stdout_reader
        .join()
        .map_err(|_| "repair stdout reader panicked")??;
    let (stderr, truncated) = stderr_reader
        .join()
        .map_err(|_| "repair stderr reader panicked")??;
    if status.success() {
        Ok(())
    } else {
        let detail = format_output(&stderr, truncated);
        Err(if detail.is_empty() {
            format!("DeviceLane repair exited with {status}")
        } else {
            format!("DeviceLane repair failed: {detail}")
        })
    }
}

pub fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file = File::open(path).map_err(|error| format!("asset cannot be opened: {error}"))?;
    let mut digest = Sha256::new();
    std::io::copy(&mut file, &mut digest)
        .map_err(|error| format!("asset cannot be hashed: {error}"))?;
    Ok(format!("{:x}", digest.finalize()))
}

pub fn validate_bundle_asset(
    root: &Path,
    asset: &Path,
    expected_sha256: &str,
) -> Result<PathBuf, String> {
    let relative = asset
        .strip_prefix(root)
        .map_err(|_| "asset is outside the trusted bundle root")?
        .to_owned();
    let root = root
        .canonicalize()
        .map_err(|error| format!("bundle root unavailable: {error}"))?;
    let asset = root.join(&relative);
    let mut component = root.clone();
    for part in relative.components() {
        component.push(part);
        let metadata = std::fs::symlink_metadata(&component)
            .map_err(|error| format!("bundle asset unavailable: {error}"))?;
        if metadata.file_type().is_symlink() {
            return Err("bundle asset contains a symbolic link".into());
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err("bundle asset contains a reparse point".into());
            }
        }
    }
    if !asset.is_file() {
        return Err("bundle asset is not a regular file".into());
    }
    if sha256_file(&asset)? != expected_sha256 {
        return Err("bundle asset integrity check failed".into());
    }
    Ok(asset)
}

pub fn repair_spec(
    platform: &str,
    resource_dir: &Path,
    service_binary: &Path,
) -> Result<RepairSpec, String> {
    let (program, script, mode, prefix): (PathBuf, &str, &str, Vec<OsString>) = match platform {
        "windows" => (
            PathBuf::from(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
            "setup-windows.ps1",
            "--service-repair",
            [
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
            ]
            .into_iter()
            .map(OsString::from)
            .collect(),
        ),
        "macos" => (
            PathBuf::from("/bin/sh"),
            "setup-mac.sh",
            "--repair",
            Vec::new(),
        ),
        "linux" => (
            PathBuf::from("/bin/sh"),
            "setup-linux.sh",
            "--repair",
            Vec::new(),
        ),
        _ => return Err(format!("unsupported repair platform: {platform}")),
    };
    let script = resource_dir.join("scripts").join(script);
    let mut arguments = prefix;
    arguments.push(script.into_os_string());
    arguments.push(mode.into());
    Ok(RepairSpec {
        program,
        arguments,
        service_binary: service_binary.to_owned(),
    })
}

fn run_repair(platform: &str, resource_dir: &Path, service_binary: &Path) -> Result<(), String> {
    let trusted_root = resource_dir
        .canonicalize()
        .map_err(|error| format!("DeviceLane resource directory is unavailable: {error}"))?;
    let spec = repair_spec(platform, &trusted_root, service_binary)?;
    let script_index = spec.arguments.len().saturating_sub(2);
    let script = PathBuf::from(&spec.arguments[script_index]);
    let script_hash = match platform {
        "windows" => repair_integrity::WINDOWS_SCRIPT_SHA256,
        "macos" => repair_integrity::MACOS_SCRIPT_SHA256,
        "linux" => repair_integrity::LINUX_SCRIPT_SHA256,
        _ => "",
    };
    if script_hash.is_empty() || repair_integrity::SIDECAR_SHA256.is_empty() {
        return Err("DeviceLane bundle integrity manifest is incomplete".into());
    }
    let trusted_script = validate_bundle_asset(&trusted_root, &script, script_hash)?;
    let service_root = service_binary
        .parent()
        .ok_or("Bundled DeviceLane service has no parent directory")?;
    let trusted_service = validate_bundle_asset(
        service_root,
        service_binary,
        repair_integrity::SIDECAR_SHA256,
    )?;
    let mut arguments = spec.arguments;
    arguments[script_index] = trusted_script.into_os_string();
    let trusted_spec = RepairSpec {
        arguments,
        service_binary: trusted_service,
        ..spec
    };
    CommandRepairProcess.execute(&trusted_spec)
}

async fn locate_service_sidecar(app: &AppHandle) -> Result<PathBuf, String> {
    let output = app
        .shell()
        .sidecar("devicelane-service")
        .map_err(|error| format!("DeviceLane sidecar cannot be resolved: {error}"))?
        .arg("--print-executable-path")
        .output()
        .await
        .map_err(|error| format!("DeviceLane sidecar cannot be queried: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "DeviceLane sidecar path query failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let path = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
    path.is_absolute()
        .then_some(path)
        .ok_or_else(|| "DeviceLane sidecar returned a non-absolute path".into())
}

fn notify_error(app: &AppHandle, error: &str) {
    let _ = app
        .notification()
        .builder()
        .title("DeviceLane")
        .body(error)
        .show();
}

fn report<T>(app: &AppHandle, result: Result<T, String>) -> Result<T, String> {
    if let Err(error) = &result {
        notify_error(app, error);
    }
    result
}

#[tauri::command]
fn daemon_status(app: AppHandle, bridge: State<'_, AppBridge>) -> Result<DaemonSnapshot, String> {
    report(&app, bridge.status())
}

#[tauri::command]
fn connection_settings(
    app: AppHandle,
    bridge: State<'_, AppBridge>,
) -> Result<ConnectionSettings, String> {
    report(&app, bridge.connection_settings())
}

#[tauri::command]
fn pause_remote_access(app: AppHandle, bridge: State<'_, AppBridge>) -> Result<(), String> {
    report(&app, bridge.pause())
}

#[tauri::command]
fn resume_remote_access(app: AppHandle, bridge: State<'_, AppBridge>) -> Result<(), String> {
    report(&app, bridge.resume())
}

#[tauri::command]
fn set_autostart(
    app: AppHandle,
    bridge: State<'_, AppBridge>,
    enabled: bool,
) -> Result<(), String> {
    report(&app, bridge.set_autostart(enabled))
}

#[tauri::command]
fn create_diagnostics(
    app: AppHandle,
    bridge: State<'_, AppBridge>,
) -> Result<DiagnosticsResult, String> {
    report(&app, bridge.diagnostics())
}

#[tauri::command]
fn dashboard_snapshot(
    app: AppHandle,
    bridge: State<'_, AppBridge>,
    scope: DashboardScope,
) -> Result<JavaScriptWire<DashboardSnapshot>, String> {
    report(&app, bridge.dashboard_snapshot(scope).map(JavaScriptWire))
}

#[tauri::command]
fn activity_events(
    app: AppHandle,
    bridge: State<'_, AppBridge>,
    scope: DashboardScope,
    cursor: WireEventCursor,
    limit: usize,
) -> Result<JavaScriptWire<EventRead>, String> {
    let result = EventCursor::try_from(cursor)
        .and_then(|cursor| bridge.activity_events(scope, cursor, limit));
    report(&app, result.map(JavaScriptWire))
}

#[tauri::command]
fn start_remote_execution(
    app: AppHandle,
    bridge: State<'_, AppBridge>,
    activity_id: String,
    workspace_path: String,
    request_id: String,
    app_path: String,
) -> Result<String, String> {
    report(
        &app,
        bridge
            .start_remote_execution(&activity_id, &workspace_path, &request_id, &app_path)
            .map(|activity_id| activity_id.to_string()),
    )
}

#[tauri::command]
fn acknowledge_events(
    app: AppHandle,
    bridge: State<'_, AppBridge>,
    subscriber_id: String,
    cursor: WireEventCursor,
) -> Result<(), String> {
    let result = EventCursor::try_from(cursor)
        .and_then(|cursor| bridge.acknowledge_events(&subscriber_id, cursor));
    report(&app, result)
}

#[tauri::command]
fn pending_approvals(
    app: AppHandle,
    bridge: State<'_, AppBridge>,
) -> Result<JavaScriptWire<Vec<ApprovalRequest>>, String> {
    report(&app, bridge.pending_approvals().map(JavaScriptWire))
}

#[tauri::command]
fn decide_approval(
    app: AppHandle,
    bridge: State<'_, AppBridge>,
    approval_id: String,
    decision: ApprovalDecision,
) -> Result<(), String> {
    report(
        &app,
        bridge
            .decide_pending_approval(&approval_id, decision)
            .map(|_| ()),
    )
}

#[tauri::command]
fn policy_rules(
    app: AppHandle,
    bridge: State<'_, AppBridge>,
) -> Result<JavaScriptWire<Vec<PolicyRule>>, String> {
    report(&app, bridge.policy_rules().map(JavaScriptWire))
}

#[tauri::command]
fn put_policy_rule(
    app: AppHandle,
    bridge: State<'_, AppBridge>,
    rule: PolicyRule,
) -> Result<(), String> {
    report(&app, bridge.put_policy_rule(rule))
}

#[tauri::command]
fn request_admin_policy_put(
    app: AppHandle,
    bridge: State<'_, AppBridge>,
    rule: PolicyRule,
    expected_revision: String,
) -> Result<(), String> {
    let result = parse_u64_decimal("expected_revision", expected_revision).and_then(|revision| {
        bridge.request_admin_mutation_approval(AdminMutation::PolicyPut {
            rule,
            expected_revision: revision,
        })
    });
    report(&app, result)
}

#[tauri::command]
fn request_admin_policy_delete(
    app: AppHandle,
    bridge: State<'_, AppBridge>,
    rule_id: String,
    expected_revision: String,
) -> Result<(), String> {
    let result = RuleId::parse(rule_id)
        .map_err(|error| format!("invalid rule_id: {error}"))
        .and_then(|rule_id| {
            parse_u64_decimal("expected_revision", expected_revision).and_then(|revision| {
                bridge.request_admin_mutation_approval(AdminMutation::PolicyDelete {
                    rule_id,
                    expected_revision: revision,
                })
            })
        });
    report(&app, result)
}

#[tauri::command]
fn request_admin_audit_delete(
    app: AppHandle,
    bridge: State<'_, AppBridge>,
    scope: AuditDeletionScope,
    filter: AuditFilter,
) -> Result<(), String> {
    report(
        &app,
        bridge.request_admin_mutation_approval(AdminMutation::AuditDelete { scope, filter }),
    )
}

#[tauri::command]
fn delete_policy_rule(
    app: AppHandle,
    bridge: State<'_, AppBridge>,
    rule_id: String,
    expected_revision: String,
) -> Result<(), String> {
    let result = parse_u64_decimal("expected_revision", expected_revision)
        .and_then(|revision| bridge.delete_policy_rule(&rule_id, revision).map(|_| ()));
    report(&app, result)
}

#[tauri::command]
fn audit_query(
    app: AppHandle,
    bridge: State<'_, AppBridge>,
    filter: AuditFilter,
    cursor: Option<WireEventCursor>,
    limit: usize,
) -> Result<JavaScriptWire<CursorPage<AuditRecord>>, String> {
    let cursor = cursor.map(EventCursor::try_from).transpose();
    report(
        &app,
        cursor
            .and_then(|cursor| bridge.audit_query(filter, cursor, limit))
            .map(JavaScriptWire),
    )
}

#[tauri::command]
fn save_audit_export(
    app: AppHandle,
    bridge: State<'_, AppBridge>,
    filter: AuditFilter,
) -> Result<JavaScriptWire<AuditSaveResult>, String> {
    report(
        &app,
        bridge
            .save_audit_export_with_picker(filter, || {
                rfd::FileDialog::new()
                    .set_file_name("devicelane-audit.json")
                    .add_filter("JSON", &["json"])
                    .save_file()
            })
            .map(JavaScriptWire),
    )
}

#[tauri::command]
fn delete_audit(
    app: AppHandle,
    bridge: State<'_, AppBridge>,
    scope: AuditDeletionScope,
    filter: AuditFilter,
) -> Result<(), String> {
    report(&app, bridge.delete_audit(scope, filter).map(|_| ()))
}

#[tauri::command]
fn notify_pending_approval(
    app: AppHandle,
    bridge: State<'_, AppBridge>,
    approval_id: String,
) -> Result<(), String> {
    let app_for_notification = app.clone();
    let result = bridge.with_pending_approval_for_notification(&approval_id, move |approval| {
        let approval_id = approval.id.as_str().to_owned();
        let mut notification = notify_rust::Notification::new();
        notification
            .summary("DeviceLane Freigabe")
            .body(&format!(
                "{} möchte {} verwenden. Freigabe {}",
                approval.principal_id.as_str(),
                approval.operation.as_str(),
                approval_id
            ))
            .action("open_approval", "In DeviceLane öffnen");
        #[cfg(windows)]
        notification.app_id(&app_for_notification.config().identifier);
        let handle = notification.show().map_err(|error| error.to_string())?;
        let app_for_action = app_for_notification.clone();
        thread::spawn(move || {
            handle.wait_for_action(|action| {
                if action == "__closed" {
                    return;
                }
                show_main_window(&app_for_action);
                let _ = app_for_action.emit("open-approval", approval_id);
            });
        });
        Ok(())
    });
    report(&app, result)
}

#[tauri::command]
async fn repair_daemon(app: AppHandle) -> Result<(), String> {
    let service_binary = locate_service_sidecar(&app).await;
    let prepared = app
        .path()
        .resource_dir()
        .map_err(|error| format!("DeviceLane resources cannot be resolved: {error}"))
        .and_then(|resources| service_binary.map(|service| (resources, service)));
    let result = match prepared {
        Ok((resources, service)) => tauri::async_runtime::spawn_blocking(move || {
            run_repair(std::env::consts::OS, &resources, &service)
        })
        .await
        .map_err(|error| format!("DeviceLane repair worker failed: {error}"))
        .and_then(|value| value),
        Err(error) => Err(error),
    };
    report(&app, result)
}

fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.set_focus();
    }
}

pub fn run() {
    let bridge = DesktopBridge::new(LocalDaemonTransport);
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _, _| {
            show_main_window(app)
        }))
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_shell::init())
        .manage(bridge)
        .setup(|app| {
            let show = MenuItem::with_id(app, "show", "DeviceLane anzeigen", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Beenden", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show, &quit])?;
            TrayIconBuilder::new()
                .icon(
                    app.default_window_icon()
                        .cloned()
                        .ok_or("DeviceLane tray icon is missing")?,
                )
                .menu(&menu)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => show_main_window(app),
                    "quit" => app.exit(0),
                    _ => {}
                })
                .build(app)?;
            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .invoke_handler(tauri::generate_handler![
            daemon_status,
            connection_settings,
            pause_remote_access,
            resume_remote_access,
            set_autostart,
            create_diagnostics,
            dashboard_snapshot,
            activity_events,
            start_remote_execution,
            acknowledge_events,
            pending_approvals,
            decide_approval,
            policy_rules,
            put_policy_rule,
            request_admin_policy_put,
            request_admin_policy_delete,
            request_admin_audit_delete,
            delete_policy_rule,
            audit_query,
            save_audit_export,
            delete_audit,
            notify_pending_approval,
            repair_daemon
        ])
        .run(tauri::generate_context!())
        .expect("DeviceLane desktop runtime failed");
}
