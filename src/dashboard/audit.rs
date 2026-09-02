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
const MAX_EXPORT_RECORDS: usize = 256;
const MAX_EXPORT_BYTES: usize = 8 * 1024 * 1024;
const HASH_BYTES: usize = 32;

#[derive(Debug)]
pub enum AuditError {
    Io(io::Error),
    Serialization(serde_json::Error),
    InvalidRetention,
    InvalidSequence,
    InvalidRecord,
    FrameTooLarge,
    InsecureStorage,
    InjectedCrash,
    StoreLocked,
    NonMonotonicSequence,
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
            Self::InvalidRecord => "invalid_record",
            Self::FrameTooLarge => "frame_too_large",
            Self::InsecureStorage => "insecure_storage",
            Self::InjectedCrash => "injected_crash",
            Self::StoreLocked => "store_locked",
            Self::NonMonotonicSequence => "non_monotonic_sequence",
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

#[derive(Serialize)]
struct ExportSigningEnvelope<'a> {
    domain: &'static str,
    format_version: u16,
    record_count: usize,
    records_sha256: &'a str,
    key_id: &'a str,
}

pub fn canonical_export_signing_envelope(manifest: &ExportManifest) -> Result<Vec<u8>, AuditError> {
    let key_id = match &manifest.signature {
        ExportSignature::Signed { key_id, .. } => key_id.as_str(),
        ExportSignature::Unavailable => "unavailable",
    };
    signing_envelope(
        manifest.format_version,
        manifest.record_count,
        &manifest.records_sha256,
        key_id,
    )
}

fn signing_envelope(
    format_version: u16,
    record_count: usize,
    records_sha256: &str,
    key_id: &str,
) -> Result<Vec<u8>, AuditError> {
    Ok(serde_json::to_vec(&ExportSigningEnvelope {
        domain: "devicelane.audit-export.v1",
        format_version,
        record_count,
        records_sha256,
        key_id,
    })?)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeletedSegmentSummary {
    pub id: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RetentionTombstoneSummary {
    pub deleted_record_count: usize,
    pub first_occurred_at_ms: u64,
    pub last_occurred_at_ms: u64,
    pub segments: Vec<DeletedSegmentSummary>,
    #[serde(default)]
    pub replacement_segments: Vec<DeletedSegmentSummary>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetentionFault {
    None,
    BeforeIndexSwap,
    AfterIndexSwap,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum StoredEntry {
    Record(AuditRecord),
    RetentionTombstone {
        retention_tombstone: RetentionTombstoneSummary,
    },
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
    #[serde(default)]
    active_segments: Vec<u64>,
}

pub struct AuditStore {
    root: PathBuf,
    retention: RetentionPolicy,
    redactor: Redactor,
    current: u64,
    current_day: Option<u64>,
    records: Vec<AuditRecord>,
    tombstones: Vec<RetentionTombstoneSummary>,
    recovered: bool,
    available: bool,
    max_segment_bytes: u64,
    active_segments: Vec<u64>,
    _lock: File,
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
        validate_private_dir(&root)?;
        let store_lock = acquire_store_lock(&root.join("store.lock"))?;
        let index = read_index(&root)?;
        let current = index.as_ref().map_or(1, |index| index.current);
        let discovered = segment_paths(&root)?;
        for path in &discovered {
            validate_private_file(path)?;
        }
        let active_segments = index
            .as_ref()
            .filter(|index| !index.active_segments.is_empty())
            .map(|index| index.active_segments.clone())
            .unwrap_or_else(|| {
                discovered
                    .iter()
                    .filter_map(|path| segment_number(path))
                    .collect()
            });
        let mut records = Vec::new();
        let mut tombstones = Vec::new();
        let mut recovered = false;
        for number in &active_segments {
            let path = root.join(format!("segment-{number:020}.audit"));
            if !path.exists() {
                return Err(AuditError::CommittedCorruption);
            }
            let is_current = path == root.join(format!("segment-{current:020}.audit"));
            recovered |= read_segment(&path, &mut records, &mut tombstones, is_current)?;
        }
        if records
            .windows(2)
            .any(|pair| pair[0].sequence >= pair[1].sequence)
        {
            return Err(AuditError::NonMonotonicSequence);
        }
        for path in &discovered {
            if segment_number(path).is_some_and(|number| !active_segments.contains(&number)) {
                fs::remove_file(path)?;
            }
        }
        sync_directory(&root)?;
        let current_day = records.last().map(|record| record.occurred_at_ms / DAY_MS);
        let mut store = Self {
            root,
            retention,
            redactor,
            current,
            current_day,
            records,
            tombstones,
            recovered,
            available: true,
            max_segment_bytes,
            active_segments,
            _lock: store_lock,
        };
        if !store.segment_path(current).exists() {
            store.create_segment(current)?;
            store.active_segments.push(current);
        }
        validate_private_file(&store.segment_path(current))?;
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
        let record = self.redactor.redact(raw);
        if record.validate().is_err() {
            return Err(AuditError::InvalidRecord);
        }
        let payload = serde_json::to_vec(&StoredEntry::Record(record.clone()))
            .map_err(|_| AuditError::InvalidRecord)?;
        let frame_len = frame_len(&payload)?;
        if frame_len > self.max_segment_bytes || frame_len > MAX_SEGMENT_BYTES {
            return Err(AuditError::FrameTooLarge);
        }
        if let Err(error) = self.append_inner(record, payload, frame_len) {
            self.available = false;
            return Err(error);
        }
        Ok(())
    }

    fn append_inner(
        &mut self,
        record: AuditRecord,
        payload: Vec<u8>,
        frame_len: u64,
    ) -> Result<(), AuditError> {
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
        let mut encoded_items_bytes = 0_usize;
        for record in self
            .records
            .iter()
            .filter(|record| record.sequence > after && filter.matches(record))
        {
            let item_bytes = serde_json::to_vec(record)?.len();
            let candidate_items_bytes =
                encoded_items_bytes.saturating_add(item_bytes + usize::from(!items.is_empty()));
            let candidate_cursor = EventCursor {
                epoch: 1,
                sequence: record.sequence,
            };
            if cursor_page_encoded_len(candidate_items_bytes, &candidate_cursor)? > MAX_PAGE_BYTES {
                break;
            }
            items.push(record.clone());
            encoded_items_bytes = candidate_items_bytes;
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
        let result = self.compact_retention(now_ms, RetentionFault::None);
        if result.is_err() {
            self.available = false;
        }
        result
    }

    pub fn enforce_retention_with_fault(
        &mut self,
        now_ms: u64,
        fault: RetentionFault,
    ) -> Result<(), AuditError> {
        self.compact_retention(now_ms, fault)
    }

    fn compact_retention(&mut self, now_ms: u64, fault: RetentionFault) -> Result<(), AuditError> {
        let cutoff = now_ms.saturating_sub(u64::from(self.retention.days()) * DAY_MS);
        if !self
            .records
            .iter()
            .any(|record| record.occurred_at_ms < cutoff)
        {
            return Ok(());
        }

        // Seal even an idle current segment so every candidate is immutable during compaction.
        self.rotate()?;
        let sealed_current = self.current;
        let candidates = self
            .active_segments
            .iter()
            .copied()
            .filter(|number| *number != sealed_current)
            .collect::<Vec<_>>();
        let mut next_number = segment_paths(&self.root)?
            .iter()
            .filter_map(|path| segment_number(path))
            .max()
            .unwrap_or(0)
            + 1;
        let mut new_active = Vec::new();
        let mut replaced_originals = Vec::new();
        let mut replacements = Vec::new();
        let mut deleted_records = Vec::new();

        for number in candidates {
            let path = self.segment_path(number);
            let mut records = Vec::new();
            let mut tombstones = Vec::new();
            read_segment(&path, &mut records, &mut tombstones, false)?;
            if !records.iter().any(|record| record.occurred_at_ms < cutoff) {
                new_active.push(number);
                continue;
            }
            replaced_originals.push(DeletedSegmentSummary {
                id: segment_id(number),
                sha256: hex(&Sha256::digest(fs::read(&path)?)),
            });
            deleted_records.extend(
                records
                    .iter()
                    .filter(|record| record.occurred_at_ms < cutoff)
                    .cloned(),
            );
            let retained = records
                .into_iter()
                .filter(|record| record.occurred_at_ms >= cutoff)
                .map(StoredEntry::Record)
                .chain(tombstones.into_iter().map(|retention_tombstone| {
                    StoredEntry::RetentionTombstone {
                        retention_tombstone,
                    }
                }))
                .collect::<Vec<_>>();
            if !retained.is_empty() {
                let replacement_path = self.segment_path(next_number);
                self.create_segment(next_number)?;
                for entry in &retained {
                    let payload = serde_json::to_vec(entry)?;
                    if frame_len(&payload)? > self.max_segment_bytes {
                        return Err(AuditError::FrameTooLarge);
                    }
                    append_frame(&replacement_path, &payload)?;
                }
                replacements.push(DeletedSegmentSummary {
                    id: segment_id(next_number),
                    sha256: hex(&Sha256::digest(fs::read(&replacement_path)?)),
                });
                new_active.push(next_number);
                next_number += 1;
            }
        }

        let summary = RetentionTombstoneSummary {
            deleted_record_count: deleted_records.len(),
            first_occurred_at_ms: deleted_records
                .iter()
                .map(|record| record.occurred_at_ms)
                .min()
                .unwrap_or(0),
            last_occurred_at_ms: deleted_records
                .iter()
                .map(|record| record.occurred_at_ms)
                .max()
                .unwrap_or(0),
            segments: replaced_originals.clone(),
            replacement_segments: replacements,
        };
        let payload = serde_json::to_vec(&StoredEntry::RetentionTombstone {
            retention_tombstone: summary.clone(),
        })?;
        let length = frame_len(&payload)?;
        if length > self.max_segment_bytes || length > MAX_SEGMENT_BYTES {
            return Err(AuditError::FrameTooLarge);
        }
        let tombstone_segment = next_number;
        self.create_segment(tombstone_segment)?;
        append_frame(&self.segment_path(tombstone_segment), &payload)?;
        self.tombstones.push(summary);
        // Prove the durable tombstone can be read strictly before deleting referenced segments.
        let mut verified_records = Vec::new();
        let mut verified_tombstones = Vec::new();
        read_segment(
            &self.segment_path(tombstone_segment),
            &mut verified_records,
            &mut verified_tombstones,
            false,
        )?;
        if verified_tombstones.last() != self.tombstones.last() {
            return Err(AuditError::CommittedCorruption);
        }
        sync_directory(&self.root)?;
        if fault == RetentionFault::BeforeIndexSwap {
            return Err(AuditError::InjectedCrash);
        }
        new_active.push(tombstone_segment);
        new_active.push(sealed_current);
        self.active_segments = new_active;
        self.current = sealed_current;
        self.current_day = None;
        self.write_index()?;
        if fault == RetentionFault::AfterIndexSwap {
            return Err(AuditError::InjectedCrash);
        }
        for original in replaced_originals {
            let number =
                segment_number_from_id(&original.id).ok_or(AuditError::CommittedCorruption)?;
            fs::remove_file(self.segment_path(number))?;
        }
        sync_directory(&self.root)?;
        self.records.clear();
        self.tombstones.clear();
        for number in &self.active_segments {
            let path = self.segment_path(*number);
            read_segment(&path, &mut self.records, &mut self.tombstones, false)?;
        }
        Ok(())
    }

    pub fn export(
        &self,
        filter: AuditFilter,
        signer: Option<&dyn AuditSigner>,
    ) -> Result<AuditExport, AuditError> {
        let mut records = Vec::new();
        let mut encoded_bytes = 2_usize;
        for record in self.records.iter().filter(|record| filter.matches(record)) {
            if records.len() == MAX_EXPORT_RECORDS {
                return Err(AuditError::LimitExceeded);
            }
            let item_bytes = serde_json::to_vec(record)?.len();
            encoded_bytes =
                encoded_bytes.saturating_add(item_bytes + usize::from(!records.is_empty()));
            if encoded_bytes > MAX_EXPORT_BYTES {
                return Err(AuditError::LimitExceeded);
            }
            records.push(record.clone());
        }
        let records_json = serde_json::to_vec(&records)?;
        let digest = Sha256::digest(&records_json);
        let records_sha256 = hex(&digest);
        let signature = match signer {
            Some(signer) => {
                let key_id = signer.key_id().to_owned();
                let envelope = signing_envelope(1, records.len(), &records_sha256, &key_id)?;
                ExportSignature::Signed {
                    key_id,
                    signature_hex: hex(&signer.sign(&envelope)?),
                }
            }
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
    pub fn retention_tombstones(&self) -> &[RetentionTombstoneSummary] {
        &self.tombstones
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
        self.active_segments.push(next);
        self.write_index()
    }
    fn write_index(&self) -> Result<(), AuditError> {
        let tmp = self.root.join("index.tmp");
        if tmp.exists() {
            fs::remove_file(&tmp)?;
        }
        let mut file = create_private_file(&tmp)?;
        file.write_all(&serde_json::to_vec(&Index {
            version: 2,
            current: self.current,
            active_segments: self.active_segments.clone(),
        })?)?;
        file.sync_all()?;
        drop(file);
        atomic_replace(&tmp, &self.root.join("index.json"), &self.root)
    }
}

fn cursor_page_encoded_len(items_bytes: usize, cursor: &EventCursor) -> Result<usize, AuditError> {
    Ok(b"{\"items\":[".len()
        + items_bytes
        + b"],\"next_cursor\":".len()
        + serde_json::to_vec(cursor)?.len()
        + 1)
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

fn frame_len(payload: &[u8]) -> Result<u64, AuditError> {
    let payload_len = u32::try_from(payload.len()).map_err(|_| AuditError::FrameTooLarge)?;
    Ok(u64::from(payload_len) + 4 + HASH_BYTES as u64)
}

fn read_segment(
    path: &Path,
    records: &mut Vec<AuditRecord>,
    tombstones: &mut Vec<RetentionTombstoneSummary>,
    allow_tail_recovery: bool,
) -> Result<bool, AuditError> {
    let mut options = OpenOptions::new();
    options.read(true).write(allow_tail_recovery);
    let mut file = options.open(path)?;
    loop {
        let start = file.stream_position()?;
        let mut length = [0_u8; 4];
        match file.read_exact(&mut length) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                let recovered = fs::metadata(path)?.len() != start;
                if recovered && !allow_tail_recovery {
                    return Err(AuditError::CommittedCorruption);
                }
                if recovered {
                    file.set_len(start)?;
                    file.sync_all()?;
                }
                return Ok(recovered);
            }
            Err(error) => return Err(error.into()),
        }
        let length = u32::from_be_bytes(length) as usize;
        let remaining = fs::metadata(path)?.len().saturating_sub(start + 4);
        let required = length as u64 + HASH_BYTES as u64;
        if remaining < required {
            if !allow_tail_recovery {
                return Err(AuditError::CommittedCorruption);
            }
            file.set_len(start)?;
            file.sync_all()?;
            return Ok(true);
        }
        if required + 4 > MAX_SEGMENT_BYTES {
            return Err(AuditError::CommittedCorruption);
        }
        let mut payload = vec![0; length];
        let mut expected = [0; HASH_BYTES];
        if file.read_exact(&mut payload).is_err() || file.read_exact(&mut expected).is_err() {
            if !allow_tail_recovery {
                return Err(AuditError::CommittedCorruption);
            }
            file.set_len(start)?;
            file.sync_all()?;
            return Ok(true);
        }
        if Sha256::digest(&payload).as_slice() != expected {
            return Err(AuditError::CommittedCorruption);
        }
        match serde_json::from_slice(&payload).map_err(|_| AuditError::CommittedCorruption)? {
            StoredEntry::Record(record) => records.push(record),
            StoredEntry::RetentionTombstone {
                retention_tombstone,
            } => tombstones.push(retention_tombstone),
        }
    }
}

fn segment_paths(root: &Path) -> Result<Vec<PathBuf>, AuditError> {
    let mut paths = Vec::new();
    for entry in fs::read_dir(root)? {
        let path = entry?.path();
        if path
            .file_name()
            .and_then(|v| v.to_str())
            .is_some_and(|v| v.starts_with("segment-") && v.ends_with(".audit"))
        {
            paths.push(path);
        }
    }
    paths.sort();
    Ok(paths)
}

fn read_index(root: &Path) -> Result<Option<Index>, AuditError> {
    let path = root.join("index.json");
    if !path.exists() {
        return Ok(None);
    }
    validate_private_file(&path)?;
    let index: Index =
        serde_json::from_slice(&fs::read(path)?).map_err(|_| AuditError::CommittedCorruption)?;
    if !(1..=2).contains(&index.version)
        || index.current == 0
        || (!index.active_segments.is_empty() && !index.active_segments.contains(&index.current))
    {
        return Err(AuditError::CommittedCorruption);
    }
    Ok(Some(index))
}

fn segment_id(number: u64) -> String {
    format!("segment-{number:020}.audit")
}

fn segment_number(path: &Path) -> Option<u64> {
    segment_number_from_id(path.file_name()?.to_str()?)
}

fn segment_number_from_id(id: &str) -> Option<u64> {
    id.strip_prefix("segment-")?
        .strip_suffix(".audit")?
        .parse()
        .ok()
}

#[cfg(not(windows))]
fn create_private_dir(path: &Path) -> Result<(), AuditError> {
    if fs::symlink_metadata(path).is_err() {
        fs::create_dir_all(path)?;
    }
    validate_private_dir(path)
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

#[cfg(unix)]
fn acquire_store_lock(path: &Path) -> Result<File, AuditError> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    if fs::symlink_metadata(path).is_ok() {
        validate_private_file(path)?;
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    validate_private_file(path)?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(AuditError::StoreLocked);
    }
    Ok(file)
}

#[cfg(windows)]
fn acquire_store_lock(path: &Path) -> Result<File, AuditError> {
    windows_private::lock(path)
}

#[cfg(unix)]
fn validate_private_dir(path: &Path) -> Result<(), AuditError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let metadata = fs::symlink_metadata(path).map_err(|_| AuditError::InsecureStorage)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
    {
        return Err(AuditError::InsecureStorage);
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(unix)]
fn validate_private_file(path: &Path) -> Result<(), AuditError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let metadata = fs::symlink_metadata(path).map_err(|_| AuditError::InsecureStorage)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(AuditError::InsecureStorage);
    }
    Ok(())
}

#[cfg(windows)]
fn validate_private_dir(path: &Path) -> Result<(), AuditError> {
    windows_private::validate(path, true)
}

#[cfg(windows)]
fn validate_private_file(path: &Path) -> Result<(), AuditError> {
    windows_private::validate(path, false)
}

#[cfg(windows)]
mod windows_private {
    use super::*;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_ALREADY_EXISTS, ERROR_SHARING_VIOLATION, GetLastError,
        INVALID_HANDLE_VALUE, LocalFree,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        GetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT, SetNamedSecurityInfoW,
    };
    use windows_sys::Win32::Security::{
        ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, GetTokenInformation,
        OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
        PSID, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CREATE_NEW, CreateDirectoryW, CreateFileW, FILE_ATTRIBUTE_NORMAL,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_DELETE, FILE_SHARE_NONE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, FlushFileBuffers, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
        MoveFileExW, OPEN_ALWAYS, OPEN_EXISTING,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    pub fn create_dir(path: &Path) -> Result<(), AuditError> {
        if path.exists() {
            return tighten_existing_dir(path);
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

    pub fn validate(path: &Path, directory: bool) -> Result<(), AuditError> {
        use std::os::windows::fs::MetadataExt;
        let metadata = fs::symlink_metadata(path).map_err(|_| AuditError::InsecureStorage)?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || if directory {
                !metadata.is_dir()
            } else {
                !metadata.is_file()
            }
            || !super::super::managed_policy::windows_acl_is_restrictive(
                path,
                &std::collections::HashSet::new(),
            )
        {
            return Err(AuditError::InsecureStorage);
        }
        Ok(())
    }

    fn tighten_existing_dir(path: &Path) -> Result<(), AuditError> {
        use std::os::windows::fs::MetadataExt;
        let metadata = fs::symlink_metadata(path).map_err(|_| AuditError::InsecureStorage)?;
        if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(AuditError::InsecureStorage);
        }
        if !owner_is_current(path)? {
            return Err(AuditError::InsecureStorage);
        }
        let security = Security::current_user()?;
        let mut present = 0;
        let mut defaulted = 0;
        let mut dacl: *mut ACL = std::ptr::null_mut();
        if unsafe {
            GetSecurityDescriptorDacl(security.descriptor, &mut present, &mut dacl, &mut defaulted)
        } == 0
            || present == 0
            || dacl.is_null()
        {
            return Err(AuditError::InsecureStorage);
        }
        let mut wide = wide(path);
        let status = unsafe {
            SetNamedSecurityInfoW(
                wide.as_mut_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                dacl,
                std::ptr::null_mut(),
            )
        };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32).into());
        }
        validate(path, true)
    }

    fn owner_is_current(path: &Path) -> Result<bool, AuditError> {
        let mut wide = wide(path);
        let mut owner: PSID = std::ptr::null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let status = unsafe {
            GetNamedSecurityInfoW(
                wide.as_mut_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut descriptor,
            )
        };
        if status != 0 || owner.is_null() || descriptor.is_null() {
            return Err(AuditError::InsecureStorage);
        }
        let owner_sid = sid_text(owner);
        unsafe { LocalFree(descriptor.cast()) };
        Ok(owner_sid.is_some_and(|owner| {
            current_sid().is_ok_and(|current| owner.eq_ignore_ascii_case(&current))
        }))
    }

    fn sid_text(sid: PSID) -> Option<String> {
        let mut text = std::ptr::null_mut();
        if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 || text.is_null() {
            return None;
        }
        let mut length = 0;
        while unsafe { *text.add(length) } != 0 {
            length += 1;
        }
        let value = String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) }).ok();
        unsafe { LocalFree(text.cast()) };
        value
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
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error().into());
        }
        Ok(unsafe { File::from_raw_handle(handle as _) })
    }

    pub fn lock(path: &Path) -> Result<File, AuditError> {
        if path.exists() {
            validate(path, false)?;
        }
        let security = Security::current_user()?;
        let wide_path = wide(path);
        let handle = unsafe {
            CreateFileW(
                wide_path.as_ptr(),
                FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                FILE_SHARE_NONE,
                &security.attributes,
                OPEN_ALWAYS,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return if unsafe { GetLastError() } == ERROR_SHARING_VIOLATION {
                Err(AuditError::StoreLocked)
            } else {
                Err(io::Error::last_os_error().into())
            };
        }
        let file = unsafe { File::from_raw_handle(handle as _) };
        Ok(file)
    }

    pub fn sync_dir(path: &Path) -> Result<(), AuditError> {
        let path = wide(path);
        let handle = unsafe {
            CreateFileW(
                path.as_ptr(),
                FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error().into());
        }
        let flushed = unsafe { FlushFileBuffers(handle) };
        unsafe { CloseHandle(handle) };
        if flushed == 0 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(())
    }

    pub fn atomic_replace(source: &Path, destination: &Path) -> Result<(), AuditError> {
        let source = wide(source);
        let destination = wide(destination);
        if unsafe {
            MoveFileExW(
                source.as_ptr(),
                destination.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            return Err(io::Error::last_os_error().into());
        }
        Ok(())
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
        windows_private::sync_dir(path)?;
    }
    Ok(())
}

#[cfg(not(windows))]
fn atomic_replace(source: &Path, destination: &Path, root: &Path) -> Result<(), AuditError> {
    fs::rename(source, destination)?;
    sync_directory(root)
}

#[cfg(windows)]
fn atomic_replace(source: &Path, destination: &Path, root: &Path) -> Result<(), AuditError> {
    windows_private::atomic_replace(source, destination)?;
    sync_directory(root)
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn validation_error(error: super::ValidationError) -> AuditError {
    AuditError::Io(io::Error::new(io::ErrorKind::InvalidData, error))
}
