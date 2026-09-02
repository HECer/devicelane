use device_development_mesh::dashboard::audit::{
    AuditError, AuditFilter, AuditGuard, AuditSigner, AuditStore, ExportSignature, RawAuditRecord,
    Redactor, RetentionPolicy,
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
    assert!(
        page.items
            .iter()
            .any(|item| item.result == AuditResult::Deleted)
    );
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
