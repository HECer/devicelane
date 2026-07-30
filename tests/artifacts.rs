use device_development_mesh::artifacts::{ArtifactError, ArtifactMetadata, ArtifactStore};
use sha2::{Digest, Sha256};
use std::env;
use std::fs;

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn store(name: &str) -> ArtifactStore {
    let root = env::temp_dir().join(format!("mesh-artifacts-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    ArtifactStore::new(root).unwrap()
}

fn metadata(contents: &[u8], expires_at: u64) -> ArtifactMetadata {
    ArtifactMetadata {
        sha256: hash(contents),
        size: contents.len() as u64,
        mime_type: "application/octet-stream".into(),
        job_id: "job-1".into(),
        expires_at,
    }
}

#[test]
fn registers_metadata_and_resumes_only_missing_chunks_idempotently() {
    let mut store = store("resume");
    let chunks = [b"first".as_slice(), b"second".as_slice()];
    let contents = chunks.concat();
    let artifact = store
        .register(
            "session-1",
            metadata(&contents, 200),
            chunks.iter().map(|chunk| hash(chunk)).collect(),
            100,
        )
        .unwrap();

    assert_eq!(artifact.metadata().sha256, hash(&contents));
    assert_eq!(artifact.metadata().size, contents.len() as u64);
    assert_eq!(artifact.metadata().mime_type, "application/octet-stream");
    assert_eq!(artifact.metadata().job_id, "job-1");
    assert_eq!(artifact.metadata().expires_at, 200);
    store
        .write_chunk("session-1", &artifact.id(), 0, chunks[0], 100)
        .unwrap();
    store
        .write_chunk("session-1", &artifact.id(), 0, chunks[0], 100)
        .unwrap();
    assert_eq!(
        store
            .missing_chunks("session-1", &artifact.id(), 100)
            .unwrap(),
        vec![1]
    );
}

#[test]
fn invalid_or_changed_chunk_prevents_publication() {
    let mut store = store("invalid");
    let contents = b"good";
    let artifact = store
        .register(
            "session-1",
            metadata(contents, 200),
            vec![hash(contents)],
            100,
        )
        .unwrap();

    assert_eq!(
        store.write_chunk("session-1", &artifact.id(), 0, b"bad", 100),
        Err(ArtifactError::ChunkHashMismatch)
    );
    assert_eq!(
        store.read("session-1", &artifact.id(), 100),
        Err(ArtifactError::NotPublished)
    );
    store
        .write_chunk("session-1", &artifact.id(), 0, contents, 100)
        .unwrap();
    assert_eq!(
        store.write_chunk("session-1", &artifact.id(), 0, b"changed", 100),
        Err(ArtifactError::ChunkConflict)
    );
    assert_eq!(
        store.read("session-1", &artifact.id(), 100).unwrap(),
        contents
    );
}

#[test]
fn failed_aggregate_validation_keeps_the_final_chunk_missing() {
    let mut store = store("aggregate");
    let contents = b"good";
    let mut invalid = metadata(contents, 200);
    invalid.size += 1;
    let artifact = store
        .register("session-1", invalid, vec![hash(contents)], 100)
        .unwrap();

    assert_eq!(
        store.write_chunk("session-1", &artifact.id(), 0, contents, 100),
        Err(ArtifactError::ChunkHashMismatch)
    );
    assert_eq!(
        store
            .missing_chunks("session-1", &artifact.id(), 100)
            .unwrap(),
        vec![0]
    );
    assert_eq!(
        store.read("session-1", &artifact.id(), 100),
        Err(ArtifactError::NotPublished)
    );
}

#[test]
fn existing_content_addressed_artifact_is_published_for_another_session() {
    let mut store = store("duplicate");
    let contents = b"shared";
    for session in ["session-1", "session-2"] {
        let artifact = store
            .register(session, metadata(contents, 200), vec![hash(contents)], 100)
            .unwrap();
        store
            .write_chunk(session, &artifact.id(), 0, contents, 100)
            .unwrap();
        assert_eq!(store.read(session, &artifact.id(), 100).unwrap(), contents);
    }
}

#[test]
fn rejects_path_traversal_expiry_and_wrong_session() {
    let mut store = store("access");
    let contents = b"safe";
    assert_eq!(
        store.register(
            "../escape",
            metadata(contents, 200),
            vec![hash(contents)],
            100
        ),
        Err(ArtifactError::PathTraversal)
    );
    let artifact = store
        .register(
            "session-1",
            metadata(contents, 110),
            vec![hash(contents)],
            100,
        )
        .unwrap();
    assert_eq!(
        store.missing_chunks("session-2", &artifact.id(), 100),
        Err(ArtifactError::SessionDenied)
    );
    assert_eq!(
        store.write_chunk("session-1", &artifact.id(), 0, contents, 111),
        Err(ArtifactError::Expired)
    );
}
