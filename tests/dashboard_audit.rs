use device_development_mesh::dashboard::audit::{
    AuditError, AuditFilter, AuditGuard, AuditSigner, AuditStore, ExportSignature, RawAuditRecord,
    Redactor, RetentionFault, RetentionPolicy,
};
use device_development_mesh::dashboard::{
    ActivityId, AuditResult, HostId, OperationId, PolicyEffect, PrincipalId, ResourceClass,
};
use sha2::{Digest, Sha256};
use std::fs;
use std::sync::Arc;
use tempfile::TempDir;

fn raw(sequence: u64, occurred_at_ms: u64, message: &str) -> RawAuditRecord {
    RawAuditRecord {
        sequence,
        occurred_at_ms,
        activity_id: Some(ActivityId::parse(format!("activity-{sequence}")).unwrap()),
        principal_id: PrincipalId::parse("principal-1").unwrap(),
        source_host_id: HostId::parse("windows-1").unwrap(),
        target_host_id: HostId::parse("mac-1").unwrap(),
        device_id: None,
        operation: OperationId::parse("xcode-build").unwrap(),
        resources: vec![ResourceClass::WorkspaceRead],
        decision: PolicyEffect::Allow,
        result: AuditResult::Succeeded,
        message: Some(message.to_owned()),
        arguments: vec!["--password=hunter2".to_owned()],
        environment: vec![("API_TOKEN".to_owned(), "env-secret".to_owned())],
        stdout: Some("stdout-private".to_owned()),
        stderr: Some("stderr-private".to_owned()),
        workspace_path: Some("/Users/alice/SecretProject".to_owned()),
        artifact_metadata: vec![(
            "authorization".to_owned(),
            "Bearer artifact-secret".to_owned(),
        )],
    }
}

fn open(temp: &TempDir) -> AuditStore {
    AuditStore::open(
        temp.path(),
        RetentionPolicy::new(30).unwrap(),
        Redactor::new(["configured-secret"]),
    )
    .unwrap()
}

#[test]
fn redacts_before_any_bytes_reach_disk() {
    let temp = TempDir::new().unwrap();
    let mut store = open(&temp);
    let mut sensitive = raw(
        1,
        10,
        "Authorization: Bearer token-secret configured-secret private-key",
    );
    sensitive.principal_id = PrincipalId::parse("configured-secret").unwrap();
    sensitive.operation = OperationId::parse("token-secret").unwrap();
    store.append(sensitive).unwrap();
    drop(store);

    let forbidden = [
        "token-secret",
        "configured-secret",
        "private-key",
        "hunter2",
        "env-secret",
        "stdout-private",
        "stderr-private",
        "SecretProject",
        "artifact-secret",
    ];
    for entry in fs::read_dir(temp.path()).unwrap() {
        let path = entry.unwrap().path();
        if path.is_file() {
            let bytes = fs::read(path).unwrap();
            for value in forbidden {
                assert!(
                    !bytes
                        .windows(value.len())
                        .any(|window| window == value.as_bytes())
                );
            }
        }
    }
}

#[test]
fn retention_is_bounded_and_uses_an_inclusive_utc_cutoff() {
    assert_eq!(RetentionPolicy::default().days(), 30);
    assert!(RetentionPolicy::new(0).is_err());
    assert!(RetentionPolicy::new(366).is_err());
    let temp = TempDir::new().unwrap();
    let mut store = open(&temp);
    let day = 86_400_000;
    store.append(raw(1, 100 * day, "old")).unwrap();
    store.append(raw(2, 101 * day, "boundary")).unwrap();
    store.append(raw(3, 131 * day, "current")).unwrap();
    store.enforce_retention(131 * day).unwrap();
    let page = store.query(AuditFilter::default(), None, 256).unwrap();
    assert_eq!(
        page.items
            .iter()
            .take(2)
            .map(|item| item.sequence)
            .collect::<Vec<_>>(),
        vec![2, 3]
    );
    assert_eq!(store.retention_tombstones().len(), 1);
}

#[test]
fn query_limits_filters_and_cursor_are_stable() {
    let temp = TempDir::new().unwrap();
    let mut store = open(&temp);
    for sequence in 1..=300 {
        store.append(raw(sequence, sequence, "ok")).unwrap();
    }
    assert!(matches!(
        store.query(AuditFilter::default(), None, 257),
        Err(AuditError::LimitExceeded)
    ));
    let first = store.query(AuditFilter::default(), None, 200).unwrap();
    assert!(serde_json::to_vec(&first).unwrap().len() <= 1024 * 1024);
    let second = store
        .query(AuditFilter::default(), first.next_cursor, 200)
        .unwrap();
    assert_eq!(first.items.len(), 200);
    assert_eq!(second.items.first().unwrap().sequence, 201);
    let filtered = store
        .query(
            AuditFilter {
                source_host_id: Some(HostId::parse("windows-1").unwrap()),
                result: Some(AuditResult::Succeeded),
                ..Default::default()
            },
            None,
            10,
        )
        .unwrap();
    assert_eq!(filtered.items.len(), 10);

    let exact = store
        .query(
            AuditFilter {
                from_ms: Some(42),
                through_ms: Some(42),
                principal_id: Some(PrincipalId::parse("principal-1").unwrap()),
                source_host_id: Some(HostId::parse("windows-1").unwrap()),
                target_host_id: Some(HostId::parse("mac-1").unwrap()),
                device_id: None,
                operation: Some(OperationId::parse("xcode-build").unwrap()),
                resource: Some(ResourceClass::WorkspaceRead),
                decision: Some(PolicyEffect::Allow),
                result: Some(AuditResult::Succeeded),
            },
            None,
            10,
        )
        .unwrap();
    assert_eq!(
        exact
            .items
            .iter()
            .map(|item| item.sequence)
            .collect::<Vec<_>>(),
        vec![42]
    );
}

#[test]
fn sequence_must_increase_so_cursors_cannot_skip_records() {
    let temp = TempDir::new().unwrap();
    let mut store = open(&temp);
    store.append(raw(2, 1, "ok")).unwrap();
    assert!(matches!(
        store.append(raw(2, 2, "duplicate")),
        Err(AuditError::InvalidSequence)
    ));
    assert!(matches!(
        store.append(raw(1, 3, "older")),
        Err(AuditError::InvalidSequence)
    ));
}

#[test]
fn rotates_before_the_configured_cap_and_never_allows_over_64_mib() {
    let temp = TempDir::new().unwrap();
    assert!(matches!(
        AuditStore::open_with_segment_limit(
            temp.path(),
            RetentionPolicy::default(),
            Redactor::default(),
            64 * 1024 * 1024 + 1,
        ),
        Err(AuditError::LimitExceeded)
    ));
    let mut store = AuditStore::open_with_segment_limit(
        temp.path(),
        RetentionPolicy::default(),
        Redactor::default(),
        1024,
    )
    .unwrap();
    for sequence in 1..=20 {
        store.append(raw(sequence, 1, "ok")).unwrap();
    }
    drop(store);
    let segments = fs::read_dir(temp.path())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().ends_with(".audit"))
        .collect::<Vec<_>>();
    assert!(segments.len() > 1);
    assert!(
        segments
            .iter()
            .all(|entry| entry.metadata().unwrap().len() <= 1024)
    );
}

#[test]
fn only_an_incomplete_tail_is_recovered_and_committed_corruption_fails_closed() {
    let temp = TempDir::new().unwrap();
    let mut store = open(&temp);
    store.append(raw(1, 1, "ok")).unwrap();
    let segment = store.current_segment_path().to_owned();
    drop(store);
    use std::io::Write;
    let mut file = fs::OpenOptions::new().append(true).open(&segment).unwrap();
    file.write_all(&[0, 0, 0, 20, b'{']).unwrap();
    drop(file);
    let recovered = open(&temp);
    assert!(recovered.recovery_performed());
    drop(recovered);

    let mut bytes = fs::read(&segment).unwrap();
    let payload_byte = 4;
    bytes[payload_byte] ^= 1;
    fs::write(&segment, bytes).unwrap();
    assert!(matches!(
        AuditStore::open(temp.path(), RetentionPolicy::default(), Redactor::default()),
        Err(AuditError::CommittedCorruption)
    ));
}

#[test]
fn storage_failure_blocks_remote_mutations() {
    let temp = TempDir::new().unwrap();
    let mut audit = open(&temp);
    fs::remove_file(audit.current_segment_path()).unwrap();
    assert!(matches!(
        audit.append(raw(1, 1, "ok")),
        Err(AuditError::Io(_))
    ));
    let store = Arc::new(std::sync::Mutex::new(audit));
    let guard = AuditGuard::new(Arc::clone(&store));
    assert!(matches!(
        guard.may_start_remote_mutation(),
        Err(AuditError::AuditUnavailable)
    ));
}

struct TestSigner;
impl AuditSigner for TestSigner {
    fn key_id(&self) -> &str {
        "identity-1"
    }
    fn sign(&self, bytes: &[u8]) -> Result<Vec<u8>, AuditError> {
        Ok(Sha256::digest(bytes).to_vec())
    }
}

#[test]
fn export_is_canonical_hashed_and_has_explicit_signature_status() {
    let temp = TempDir::new().unwrap();
    let mut store = open(&temp);
    store.append(raw(1, 1, "ok")).unwrap();
    let signed = store
        .export(AuditFilter::default(), Some(&TestSigner))
        .unwrap();
    assert!(
        matches!(signed.manifest.signature, ExportSignature::Signed { ref key_id, .. } if key_id == "identity-1")
    );
    assert_eq!(signed.manifest.records_sha256.len(), 64);
    assert_eq!(
        signed.records_json,
        serde_json::to_vec(&signed.records).unwrap()
    );
    let unsigned = store.export(AuditFilter::default(), None).unwrap();
    assert_eq!(unsigned.manifest.signature, ExportSignature::Unavailable);
}

#[test]
fn midday_retention_compacts_mixed_segments_at_the_exact_cutoff_and_reopens() {
    let temp = TempDir::new().unwrap();
    let day = 86_400_000;
    let mut store = AuditStore::open(
        temp.path(),
        RetentionPolicy::new(1).unwrap(),
        Redactor::default(),
    )
    .unwrap();
    store.append(raw(1, day / 4, "expired-in-mixed")).unwrap();
    store.append(raw(2, day / 2, "exact-cutoff")).unwrap();
    store.append(raw(3, day + day / 2, "current")).unwrap();
    store.enforce_retention(day + day / 2).unwrap();
    let summary = store.retention_tombstones().last().unwrap();
    assert_eq!(summary.deleted_record_count, 1);
    assert_eq!(
        (summary.first_occurred_at_ms, summary.last_occurred_at_ms),
        (day / 4, day / 4)
    );
    assert_eq!(summary.segments.len(), 1);
    assert_eq!(summary.replacement_segments.len(), 1);
    assert_eq!(summary.segments[0].sha256.len(), 64);
    assert_eq!(summary.replacement_segments[0].sha256.len(), 64);
    assert_eq!(
        store
            .query(AuditFilter::default(), None, 20)
            .unwrap()
            .items
            .iter()
            .filter(|record| record.result != AuditResult::Deleted)
            .map(|record| record.sequence)
            .collect::<Vec<_>>(),
        vec![2, 3]
    );
    drop(store);
    let reopened = open(&temp);
    assert_eq!(
        reopened
            .query(AuditFilter::default(), None, 20)
            .unwrap()
            .items
            .iter()
            .filter(|record| record.result != AuditResult::Deleted)
            .map(|record| record.sequence)
            .collect::<Vec<_>>(),
        vec![2, 3]
    );
}

#[test]
fn idle_current_only_segment_is_sealed_and_compacted() {
    let temp = TempDir::new().unwrap();
    let day = 86_400_000;
    let mut store = AuditStore::open(
        temp.path(),
        RetentionPolicy::new(1).unwrap(),
        Redactor::default(),
    )
    .unwrap();
    store.append(raw(1, day / 4, "expired-current")).unwrap();
    store.append(raw(2, day / 2, "boundary-current")).unwrap();
    store.enforce_retention(day + day / 2).unwrap();
    assert_eq!(
        store
            .query(AuditFilter::default(), None, 20)
            .unwrap()
            .items
            .iter()
            .map(|record| record.sequence)
            .collect::<Vec<_>>(),
        vec![2]
    );
    drop(store);
    let reopened = AuditStore::open(
        temp.path(),
        RetentionPolicy::new(1).unwrap(),
        Redactor::default(),
    )
    .unwrap();
    assert_eq!(
        reopened
            .query(AuditFilter::default(), None, 20)
            .unwrap()
            .items
            .iter()
            .map(|record| record.sequence)
            .collect::<Vec<_>>(),
        vec![2]
    );
}

#[test]
fn compaction_crash_recovery_chooses_only_the_indexed_generation() {
    let day = 86_400_000;
    for (fault, expected) in [
        (RetentionFault::BeforeIndexSwap, vec![1, 2]),
        (RetentionFault::AfterIndexSwap, vec![2]),
    ] {
        let temp = TempDir::new().unwrap();
        let mut store = AuditStore::open(
            temp.path(),
            RetentionPolicy::new(1).unwrap(),
            Redactor::default(),
        )
        .unwrap();
        store.append(raw(1, day / 4, "expired")).unwrap();
        store.append(raw(2, day / 2, "boundary")).unwrap();
        assert!(matches!(
            store.enforce_retention_with_fault(day + day / 2, fault),
            Err(AuditError::InjectedCrash)
        ));
        drop(store);
        let reopened = AuditStore::open(
            temp.path(),
            RetentionPolicy::new(1).unwrap(),
            Redactor::default(),
        )
        .unwrap();
        assert_eq!(
            reopened
                .query(AuditFilter::default(), None, 20)
                .unwrap()
                .items
                .iter()
                .map(|record| record.sequence)
                .collect::<Vec<_>>(),
            expected
        );
    }
}

#[test]
fn an_incomplete_tail_in_a_rotated_segment_is_committed_corruption() {
    let temp = TempDir::new().unwrap();
    let mut store = open(&temp);
    store.append(raw(1, 1, "first-day")).unwrap();
    store.append(raw(2, 86_400_001, "second-day")).unwrap();
    drop(store);
    let mut segments = fs::read_dir(temp.path())
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|value| value == "audit"))
        .collect::<Vec<_>>();
    segments.sort();
    use std::io::Write;
    fs::OpenOptions::new()
        .append(true)
        .open(&segments[0])
        .unwrap()
        .write_all(&[0, 0, 0, 20, b'{'])
        .unwrap();
    assert!(matches!(
        AuditStore::open(temp.path(), RetentionPolicy::default(), Redactor::default()),
        Err(AuditError::CommittedCorruption)
    ));
}

#[test]
fn oversized_typed_records_fail_before_rotation_or_any_write() {
    let temp = TempDir::new().unwrap();
    let mut store = AuditStore::open_with_segment_limit(
        temp.path(),
        RetentionPolicy::default(),
        Redactor::default(),
        300,
    )
    .unwrap();
    let before = fs::metadata(store.current_segment_path()).unwrap().len();
    assert!(matches!(
        store.append(raw(1, 1, "ok")),
        Err(AuditError::FrameTooLarge)
    ));
    assert_eq!(
        fs::metadata(store.current_segment_path()).unwrap().len(),
        before
    );
    assert_eq!(
        fs::read_dir(temp.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".audit"))
            .count(),
        1
    );

    let temp = TempDir::new().unwrap();
    let mut store = open(&temp);
    let mut oversized = raw(1, 1, "ok");
    oversized.resources = vec![ResourceClass::WorkspaceRead; 257];
    assert!(matches!(
        store.append(oversized),
        Err(AuditError::InvalidRecord)
    ));
    assert_eq!(fs::metadata(store.current_segment_path()).unwrap().len(), 0);
}

#[test]
fn retention_tombstone_names_exact_deleted_segments_and_survives_reopen() {
    let temp = TempDir::new().unwrap();
    let day = 86_400_000;
    let mut store = AuditStore::open(
        temp.path(),
        RetentionPolicy::new(1).unwrap(),
        Redactor::default(),
    )
    .unwrap();
    store.append(raw(1, 1, "old")).unwrap();
    store.append(raw(2, 2 * day, "new")).unwrap();
    store.enforce_retention(2 * day).unwrap();
    let summary = store.retention_tombstones().last().unwrap();
    assert_eq!(summary.deleted_record_count, 1);
    assert_eq!(
        (summary.first_occurred_at_ms, summary.last_occurred_at_ms),
        (1, 1)
    );
    assert_eq!(summary.segments.len(), 1);
    assert_eq!(summary.segments[0].sha256.len(), 64);
    assert!(summary.segments[0].id.starts_with("segment-"));
    assert!(summary.replacement_segments.is_empty());
    drop(store);
    let reopened = open(&temp);
    assert_eq!(reopened.retention_tombstones().len(), 1);
    assert_eq!(reopened.retention_tombstones()[0].deleted_record_count, 1);
    assert!(
        !reopened
            .query(AuditFilter::default(), None, 20)
            .unwrap()
            .items
            .iter()
            .any(|record| record.sequence == 1)
    );
}

#[cfg(unix)]
#[test]
fn existing_unix_storage_is_non_link_owned_and_restrictive() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let outer = TempDir::new().unwrap();
    let root = outer.path().join("audit");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
    let store = AuditStore::open(&root, RetentionPolicy::default(), Redactor::default()).unwrap();
    assert_eq!(
        fs::metadata(&root).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let segment = store.current_segment_path();
    drop(store);
    fs::set_permissions(&segment, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        AuditStore::open(&root, RetentionPolicy::default(), Redactor::default()),
        Err(AuditError::InsecureStorage)
    ));

    fs::set_permissions(&segment, fs::Permissions::from_mode(0o600)).unwrap();
    let index = root.join("index.json");
    let target = outer.path().join("foreign-index");
    fs::write(&target, b"{}").unwrap();
    fs::remove_file(&index).unwrap();
    symlink(&target, &index).unwrap();
    assert!(matches!(
        AuditStore::open(&root, RetentionPolicy::default(), Redactor::default()),
        Err(AuditError::InsecureStorage)
    ));

    let linked = outer.path().join("linked");
    symlink(&root, &linked).unwrap();
    assert!(matches!(
        AuditStore::open(&linked, RetentionPolicy::default(), Redactor::default()),
        Err(AuditError::InsecureStorage)
    ));
}

#[cfg(windows)]
#[test]
fn existing_windows_storage_rejects_a_native_foreign_writer_acl() {
    let temp = TempDir::new().unwrap();
    let store = open(&temp);
    let segment = store.current_segment_path();
    drop(store);
    let status = std::process::Command::new("icacls")
        .arg(&segment)
        .args(["/grant", "*S-1-1-0:(F)"])
        .status()
        .unwrap();
    assert!(status.success());
    assert!(matches!(
        AuditStore::open(temp.path(), RetentionPolicy::default(), Redactor::default()),
        Err(AuditError::InsecureStorage)
    ));
}
