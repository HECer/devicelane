use super::{
    ActivityId, AuditRecord, AuditResult, CursorPage, DeviceId, DisplayMessage, EventCursor,
    HostId, MessageCode, OperationId, PolicyEffect, PrincipalId, ResourceClass,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const DAY_MS: u64 = 86_400_000;
const MAX_SEGMENT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PAGE_RECORDS: usize = 256;
const MAX_PAGE_BYTES: usize = 1024 * 1024;
const HASH_BYTES: usize = 32;

#[derive(Debug)]
pub enum AuditError {
    Io(io::Error),
    Serialization(serde_json::Error),
    InvalidRetention,
    InvalidSequence,
    LimitExceeded,
    CursorAhead,
    CommittedCorruption,
    AuditUnavailable,
    Signing,
}

impl std::fmt::Display for AuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Io(_) => "audit_io_error",
            Self::Serialization(_) => "audit_serialization_error",
            Self::InvalidRetention => "invalid_retention",
            Self::InvalidSequence => "invalid_sequence",
            Self::LimitExceeded => "limit_exceeded",
            Self::CursorAhead => "cursor_ahead",
            Self::CommittedCorruption => "committed_corruption",
            Self::AuditUnavailable => "audit_unavailable",
            Self::Signing => "signing_failed",
        })
    }
}

impl std::error::Error for AuditError {}
impl From<io::Error> for AuditError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<serde_json::Error> for AuditError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serialization(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetentionPolicy(u16);
impl RetentionPolicy {
    pub fn new(days: u16) -> Result<Self, AuditError> {
        (1..=365)
            .contains(&days)
            .then_some(Self(days))
            .ok_or(AuditError::InvalidRetention)
    }
    pub fn days(self) -> u16 {
        self.0
    }
}
impl Default for RetentionPolicy {
    fn default() -> Self {
        Self(30)
    }
}

#[derive(Clone, Debug, Default)]
pub struct Redactor {
    literals: Vec<String>,
}
impl Redactor {
    pub fn new<I, S>(literals: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            literals: literals
                .into_iter()
                .map(Into::into)
                .filter(|v| !v.is_empty())
                .collect(),
        }
    }

    pub fn redact(&self, raw: RawAuditRecord) -> AuditRecord {
        let contains_sensitive = raw
            .message
            .as_deref()
            .is_some_and(|message| self.contains_sensitive(message));
        // Sensitive-bearing fields are deliberately consumed and never serialized.
        drop((
            raw.arguments,
            raw.environment,
            raw.stdout,
            raw.stderr,
            raw.workspace_path,
            raw.artifact_metadata,
        ));
        AuditRecord {
            sequence: raw.sequence,
            occurred_at_ms: raw.occurred_at_ms,
            activity_id: raw.activity_id.map(|value| {
                if self.contains_sensitive(value.as_str()) {
                    ActivityId::parse("redacted").expect("constant id")
                } else {
                    value
                }
            }),
            principal_id: if self.contains_sensitive(raw.principal_id.as_str()) {
                PrincipalId::parse("redacted").expect("constant id")
            } else {
                raw.principal_id
            },
            source_host_id: if self.contains_sensitive(raw.source_host_id.as_str()) {
                HostId::parse("redacted").expect("constant id")
            } else {
                raw.source_host_id
            },
            target_host_id: if self.contains_sensitive(raw.target_host_id.as_str()) {
                HostId::parse("redacted").expect("constant id")
            } else {
                raw.target_host_id
            },
            device_id: raw.device_id.map(|value| {
                if self.contains_sensitive(value.as_str()) {
                    DeviceId::parse("redacted").expect("constant id")
                } else {
                    value
                }
            }),
            operation: if self.contains_sensitive(raw.operation.as_str()) {
                OperationId::parse("redacted").expect("constant id")
            } else {
                raw.operation
            },
            resources: raw.resources,
            decision: raw.decision,
            result: raw.result,
            redacted_message: raw.message.map(|_| {
                DisplayMessage::new(
                    if contains_sensitive {
                        MessageCode::Redacted
                    } else {
                        MessageCode::OperationSucceeded
                    },
                    Vec::new(),
                )
                .expect("empty structured message is valid")
            }),
        }
    }

    fn contains_sensitive(&self, value: &str) -> bool {
        let lower = value.to_ascii_lowercase();
        lower.contains("bearer")
            || lower.contains("authorization")
            || lower.contains("token")
            || lower.contains("secret")
            || lower.contains("private-key")
            || self.literals.iter().any(|literal| value.contains(literal))
    }
}

#[derive(Clone, Debug)]
pub struct RawAuditRecord {
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
    pub message: Option<String>,
    pub arguments: Vec<String>,
    pub environment: Vec<(String, String)>,
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    pub workspace_path: Option<String>,
    pub artifact_metadata: Vec<(String, String)>,
}

#[derive(Clone, Debug, Default)]
pub struct AuditFilter {
    pub from_ms: Option<u64>,
    pub through_ms: Option<u64>,
    pub principal_id: Option<PrincipalId>,
    pub source_host_id: Option<HostId>,
    pub target_host_id: Option<HostId>,
    pub device_id: Option<DeviceId>,
    pub operation: Option<OperationId>,
    pub resource: Option<ResourceClass>,
    pub decision: Option<PolicyEffect>,
    pub result: Option<AuditResult>,
}

impl AuditFilter {
    fn matches(&self, value: &AuditRecord) -> bool {
        self.from_ms.is_none_or(|v| value.occurred_at_ms >= v)
            && self.through_ms.is_none_or(|v| value.occurred_at_ms <= v)
            && self
                .principal_id
                .as_ref()
                .is_none_or(|v| &value.principal_id == v)
            && self
                .source_host_id
                .as_ref()
                .is_none_or(|v| &value.source_host_id == v)
            && self
                .target_host_id
                .as_ref()
                .is_none_or(|v| &value.target_host_id == v)
            && self
                .device_id
                .as_ref()
                .is_none_or(|v| value.device_id.as_ref() == Some(v))
            && self
                .operation
                .as_ref()
                .is_none_or(|v| &value.operation == v)
            && self.resource.is_none_or(|v| value.resources.contains(&v))
            && self.decision.is_none_or(|v| value.decision == v)
            && self.result.is_none_or(|v| value.result == v)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "signature_status")]
pub enum ExportSignature {
    Signed {
        key_id: String,
        signature_hex: String,
    },
    Unavailable,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExportManifest {
    pub format_version: u16,
    pub record_count: usize,
    pub records_sha256: String,
    pub signature: ExportSignature,
}
#[derive(Clone, Debug, Serialize)]
pub struct AuditExport {
    pub records: Vec<AuditRecord>,
    pub records_json: Vec<u8>,
    pub manifest: ExportManifest,
}

pub trait AuditSigner: Send + Sync {
    fn key_id(&self) -> &str;
    fn sign(&self, bytes: &[u8]) -> Result<Vec<u8>, AuditError>;
}

#[derive(Serialize, Deserialize)]
struct Index {
    version: u16,
    current: u64,
}

pub struct AuditStore {
    root: PathBuf,
    retention: RetentionPolicy,
    redactor: Redactor,
    current: u64,
    current_day: Option<u64>,
    records: Vec<AuditRecord>,
    recovered: bool,
    available: bool,
    max_segment_bytes: u64,
}

impl AuditStore {
    pub fn open(
        root: impl AsRef<Path>,
        retention: RetentionPolicy,
        redactor: Redactor,
    ) -> Result<Self, AuditError> {
        Self::open_with_segment_limit(root, retention, redactor, MAX_SEGMENT_BYTES)
    }

    pub fn open_with_segment_limit(
        root: impl AsRef<Path>,
        retention: RetentionPolicy,
        redactor: Redactor,
        max_segment_bytes: u64,
    ) -> Result<Self, AuditError> {
        if max_segment_bytes == 0 || max_segment_bytes > MAX_SEGMENT_BYTES {
            return Err(AuditError::LimitExceeded);
        }
        let root = root.as_ref().to_owned();
        create_private_dir(&root)?;
        let current = read_index(&root)?.unwrap_or(1);
        let mut records = Vec::new();
        let mut recovered = false;
        for path in segment_paths(&root)? {
            recovered |= read_segment(&path, &mut records)?;
        }
        let current_day = records.last().map(|record| record.occurred_at_ms / DAY_MS);
        let mut store = Self {
            root,
            retention,
            redactor,
            current,
            current_day,
            records,
            recovered,
            available: true,
            max_segment_bytes,
        };
        if !store.segment_path(current).exists() {
            store.create_segment(current)?;
        }
        store.write_index()?;
        if recovered {
            let sequence = store
                .records
                .iter()
                .map(|record| record.sequence)
                .max()
                .unwrap_or(0)
                + 1;
            store.append(RawAuditRecord {
                sequence,
                occurred_at_ms: store
                    .records
                    .last()
                    .map_or(0, |record| record.occurred_at_ms),
                activity_id: None,
                principal_id: PrincipalId::parse("local-system").map_err(validation_error)?,
                source_host_id: HostId::parse("local-host").map_err(validation_error)?,
                target_host_id: HostId::parse("local-host").map_err(validation_error)?,
                device_id: None,
                operation: OperationId::parse("audit-tail-recovery").map_err(validation_error)?,
                resources: Vec::new(),
                decision: PolicyEffect::Allow,
                result: AuditResult::Failed,
                message: Some("incomplete audit tail recovered".to_owned()),
                arguments: Vec::new(),
                environment: Vec::new(),
                stdout: None,
                stderr: None,
                workspace_path: None,
                artifact_metadata: Vec::new(),
            })?;
        }
        Ok(store)
    }

    pub fn append(&mut self, raw: RawAuditRecord) -> Result<(), AuditError> {
        if !self.available {
            return Err(AuditError::AuditUnavailable);
        }
        if self
            .records
            .last()
            .is_some_and(|record| raw.sequence <= record.sequence)
        {
            return Err(AuditError::InvalidSequence);
        }
        if let Err(error) = self.append_inner(raw) {
            self.available = false;
            return Err(error);
        }
        Ok(())
    }

    fn append_inner(&mut self, raw: RawAuditRecord) -> Result<(), AuditError> {
        let record = self.redactor.redact(raw);
        let payload = serde_json::to_vec(&record)?;
        let frame_len = 4 + payload.len() as u64 + HASH_BYTES as u64;
        let day = record.occurred_at_ms / DAY_MS;
        let segment_len = fs::metadata(self.segment_path(self.current))?.len();
        if segment_len + frame_len > self.max_segment_bytes
            || self.current_day.is_some_and(|old| old != day)
        {
            self.rotate()?;
        }
        append_frame(&self.segment_path(self.current), &payload)?;
        self.current_day = Some(day);
        self.records.push(record);
        self.write_index()?;
        Ok(())
    }

    pub fn query(
        &self,
        filter: AuditFilter,
        cursor: Option<EventCursor>,
        limit: usize,
    ) -> Result<CursorPage<AuditRecord>, AuditError> {
        if !self.available {
            return Err(AuditError::AuditUnavailable);
        }
        if limit == 0 || limit > MAX_PAGE_RECORDS {
            return Err(AuditError::LimitExceeded);
        }
        let after = cursor.map_or(0, |value| value.sequence);
        if after > self.records.last().map_or(0, |value| value.sequence) {
            return Err(AuditError::CursorAhead);
        }
        let mut items = Vec::new();
        for record in self
            .records
            .iter()
            .filter(|record| record.sequence > after && filter.matches(record))
        {
            let mut candidate = items.clone();
            candidate.push(record.clone());
            if serde_json::to_vec(&candidate)?.len() > MAX_PAGE_BYTES {
                break;
            }
            items.push(record.clone());
            if items.len() == limit {
                break;
            }
        }
        let next_cursor = items.last().map(|record| EventCursor {
            epoch: 1,
            sequence: record.sequence,
        });
        Ok(CursorPage { items, next_cursor })
    }

    pub fn enforce_retention(&mut self, now_ms: u64) -> Result<(), AuditError> {
        let cutoff = now_ms.saturating_sub(u64::from(self.retention.days()) * DAY_MS);
        let expired: Vec<_> = self
            .records
            .iter()
            .filter(|record| record.occurred_at_ms < cutoff)
            .cloned()
            .collect();
        if expired.is_empty() {
            return Ok(());
        }
        self.rotate()?;
        let max_sequence = self
            .records
            .iter()
            .map(|record| record.sequence)
            .max()
            .unwrap_or(0);
        let first = &expired[0];
        self.append(RawAuditRecord {
            sequence: max_sequence + 1,
            occurred_at_ms: now_ms,
            activity_id: None,
            principal_id: first.principal_id.clone(),
            source_host_id: first.source_host_id.clone(),
            target_host_id: first.target_host_id.clone(),
            device_id: None,
            operation: OperationId::parse("retention-delete").map_err(|_| {
                AuditError::Serialization(serde_json::Error::io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid operation",
                )))
            })?,
            resources: Vec::new(),
            decision: PolicyEffect::Allow,
            result: AuditResult::Deleted,
            message: Some("retention deletion".to_owned()),
            arguments: Vec::new(),
            environment: Vec::new(),
            stdout: None,
            stderr: None,
            workspace_path: None,
            artifact_metadata: Vec::new(),
        })?;
        // The tombstone is durable before old segment removal. Only wholly expired day segments are deleted.
        let expired_days: std::collections::BTreeSet<_> = expired
            .iter()
            .map(|record| record.occurred_at_ms / DAY_MS)
            .collect();
        for path in segment_paths(&self.root)? {
            if path != self.segment_path(self.current) {
                let mut values = Vec::new();
                read_segment(&path, &mut values)?;
                if !values.is_empty()
                    && values
                        .iter()
                        .all(|record| expired_days.contains(&(record.occurred_at_ms / DAY_MS)))
                {
                    fs::remove_file(path)?;
                }
            }
        }
        self.records.retain(|record| {
            record.occurred_at_ms >= cutoff || record.result == AuditResult::Deleted
        });
        sync_directory(&self.root)?;
        self.write_index()?;
        Ok(())
    }

    pub fn export(
        &self,
        filter: AuditFilter,
        signer: Option<&dyn AuditSigner>,
    ) -> Result<AuditExport, AuditError> {
        let records: Vec<_> = self
            .records
            .iter()
            .filter(|record| filter.matches(record))
            .cloned()
            .collect();
        let records_json = serde_json::to_vec(&records)?;
        let digest = Sha256::digest(&records_json);
        let records_sha256 = hex(&digest);
        let signature = match signer {
            Some(signer) => ExportSignature::Signed {
                key_id: signer.key_id().to_owned(),
                signature_hex: hex(&signer.sign(&records_json)?),
            },
            None => ExportSignature::Unavailable,
        };
        Ok(AuditExport {
            manifest: ExportManifest {
                format_version: 1,
                record_count: records.len(),
                records_sha256,
                signature,
            },
            records,
            records_json,
        })
    }

    pub fn current_segment_path(&self) -> PathBuf {
        self.segment_path(self.current)
    }
    pub fn recovery_performed(&self) -> bool {
        self.recovered
    }
    pub fn is_available(&self) -> bool {
        self.available
    }
    fn segment_path(&self, number: u64) -> PathBuf {
        self.root.join(format!("segment-{number:020}.audit"))
    }
    fn create_segment(&self, number: u64) -> Result<(), AuditError> {
        create_private_file(&self.segment_path(number)).map(|_| ())
    }
    fn rotate(&mut self) -> Result<(), AuditError> {
        let next = self.current + 1;
        self.create_segment(next)?;
        sync_directory(&self.root)?;
        self.current = next;
        self.current_day = None;
        self.write_index()
    }
    fn write_index(&self) -> Result<(), AuditError> {
        let tmp = self.root.join("index.tmp");
        if tmp.exists() {
            fs::remove_file(&tmp)?;
        }
        let mut file = create_private_file(&tmp)?;
        file.write_all(&serde_json::to_vec(&Index {
            version: 1,
            current: self.current,
        })?)?;
        file.sync_all()?;
        drop(file);
        fs::rename(tmp, self.root.join("index.json"))?;
        sync_directory(&self.root)
    }
}

pub struct AuditGuard {
    store: Arc<Mutex<AuditStore>>,
}
impl AuditGuard {
    pub fn new(store: Arc<Mutex<AuditStore>>) -> Self {
        Self { store }
    }
    pub fn may_start_remote_mutation(&self) -> Result<(), AuditError> {
        self.store
            .lock()
            .map_err(|_| AuditError::AuditUnavailable)?
            .is_available()
            .then_some(())
            .ok_or(AuditError::AuditUnavailable)
    }
}

fn append_frame(path: &Path, payload: &[u8]) -> Result<(), AuditError> {
    let mut file = OpenOptions::new().append(true).open(path)?;
    file.write_all(&(payload.len() as u32).to_be_bytes())?;
    file.write_all(payload)?;
    file.write_all(&Sha256::digest(payload))?;
    file.sync_all()?;
    Ok(())
}

fn read_segment(path: &Path, records: &mut Vec<AuditRecord>) -> Result<bool, AuditError> {
    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    loop {
        let start = file.stream_position()?;
        let mut length = [0_u8; 4];
        match file.read_exact(&mut length) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                let recovered = fs::metadata(path)?.len() != start;
                file.set_len(start)?;
                if recovered {
                    file.sync_all()?;
                }
                return Ok(recovered);
            }
            Err(error) => return Err(error.into()),
        }
        let length = u32::from_be_bytes(length) as usize;
        if length > MAX_PAGE_BYTES {
            return Err(AuditError::CommittedCorruption);
        }
        let mut payload = vec![0; length];
        let mut expected = [0; HASH_BYTES];
        if file.read_exact(&mut payload).is_err() || file.read_exact(&mut expected).is_err() {
            file.set_len(start)?;
            file.sync_all()?;
            return Ok(true);
        }
        if Sha256::digest(&payload).as_slice() != expected {
            return Err(AuditError::CommittedCorruption);
        }
        records
            .push(serde_json::from_slice(&payload).map_err(|_| AuditError::CommittedCorruption)?);
    }
}

fn segment_paths(root: &Path) -> Result<Vec<PathBuf>, AuditError> {
    let mut paths = fs::read_dir(root)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|v| v.to_str())
                .is_some_and(|v| v.starts_with("segment-") && v.ends_with(".audit"))
        })
        .collect::<Vec<_>>();
    paths.sort();
    Ok(paths)
}

fn read_index(root: &Path) -> Result<Option<u64>, AuditError> {
    let path = root.join("index.json");
    if !path.exists() {
        return Ok(None);
    }
    let index: Index =
        serde_json::from_slice(&fs::read(path)?).map_err(|_| AuditError::CommittedCorruption)?;
    if index.version != 1 || index.current == 0 {
        return Err(AuditError::CommittedCorruption);
    }
    Ok(Some(index.current))
}

#[cfg(not(windows))]
fn create_private_dir(path: &Path) -> Result<(), AuditError> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}
#[cfg(windows)]
fn create_private_dir(path: &Path) -> Result<(), AuditError> {
    windows_private::create_dir(path)
}

#[cfg(not(windows))]
fn create_private_file(path: &Path) -> Result<File, AuditError> {
    let file = OpenOptions::new().write(true).create_new(true).open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}
#[cfg(windows)]
fn create_private_file(path: &Path) -> Result<File, AuditError> {
    windows_private::create_file(path)
}

#[cfg(windows)]
mod windows_private {
    use super::*;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_ALREADY_EXISTS, GetLastError, INVALID_HANDLE_VALUE, LocalFree,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{
        GetTokenInformation, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CREATE_NEW, CreateDirectoryW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_WRITE,
        FILE_SHARE_NONE,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    pub fn create_dir(path: &Path) -> Result<(), AuditError> {
        if path.exists() {
            return Ok(());
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let security = Security::current_user()?;
        let wide = wide(path);
        if unsafe { CreateDirectoryW(wide.as_ptr(), &security.attributes) } == 0 {
            let code = unsafe { GetLastError() };
            if code != ERROR_ALREADY_EXISTS {
                return Err(io::Error::from_raw_os_error(code as i32).into());
            }
        }
        Ok(())
    }

    pub fn create_file(path: &Path) -> Result<File, AuditError> {
        let security = Security::current_user()?;
        let wide = wide(path);
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_GENERIC_WRITE,
                FILE_SHARE_NONE,
                &security.attributes,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error().into());
        }
        Ok(unsafe { File::from_raw_handle(handle as _) })
    }

    struct Security {
        descriptor: *mut core::ffi::c_void,
        attributes: SECURITY_ATTRIBUTES,
    }
    impl Security {
        fn current_user() -> Result<Self, AuditError> {
            let sid = current_sid()?;
            let sddl = format!("D:P(A;;FA;;;{sid})(A;;FA;;;SY)");
            let text: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
            let mut descriptor = std::ptr::null_mut();
            if unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    text.as_ptr(),
                    SDDL_REVISION_1,
                    &mut descriptor,
                    std::ptr::null_mut(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error().into());
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
    impl Drop for Security {
        fn drop(&mut self) {
            unsafe { LocalFree(self.descriptor) };
        }
    }

    fn current_sid() -> Result<String, AuditError> {
        let mut token = std::ptr::null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error().into());
        }
        let result = token_sid(token);
        unsafe { CloseHandle(token) };
        result
    }
    fn token_sid(token: *mut core::ffi::c_void) -> Result<String, AuditError> {
        let mut needed = 0;
        unsafe { GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed) };
        if needed == 0 {
            return Err(io::Error::last_os_error().into());
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
            return Err(io::Error::last_os_error().into());
        }
        let user = unsafe { &*(buffer.as_ptr().cast::<TOKEN_USER>()) };
        let mut text = std::ptr::null_mut();
        if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) } == 0 {
            return Err(io::Error::last_os_error().into());
        }
        let mut length = 0;
        while unsafe { *text.add(length) } != 0 {
            length += 1;
        }
        let value = String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) })
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error));
        unsafe { LocalFree(text.cast()) };
        value.map_err(Into::into)
    }
    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str().encode_wide().chain(Some(0)).collect()
    }
}
fn sync_directory(path: &Path) -> Result<(), AuditError> {
    #[cfg(unix)]
    {
        File::open(path)?.sync_all()?;
    }
    #[cfg(windows)]
    {
        let _ = path;
    }
    Ok(())
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn validation_error(error: super::ValidationError) -> AuditError {
    AuditError::Io(io::Error::new(io::ErrorKind::InvalidData, error))
}
