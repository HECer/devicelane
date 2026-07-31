use device_development_mesh::{
    network_processes::{ArtifactChunk, NetworkArtifactMetadata, Request, Response},
    remote_apple_protocol::{AppleOperation, AppleRequest, RemoteProtocolVersion},
    secure_transport::SecureTransport,
};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::Duration,
};
use tempfile::TempDir;

const CHUNK: usize = 4;

#[test]
fn transfers_apple_artifacts_in_bounded_resumable_chunks_over_mtls() {
    let fixture_root = Path::new("tests/fixtures/network-artifacts");
    for name in [
        "Test.app",
        "Test.dSYM",
        "Test.xcresult",
        "screenshot.png",
        "device.log",
        "session.trace",
    ] {
        transfer_fixture(fixture_root.join(name));
    }
}

#[test]
fn rejects_tampering_unknown_artifacts_invalid_offsets_and_non_participants() {
    let setup = Setup::new();
    let contents = b"abcdefgh";
    let metadata = setup.register("trace", contents);

    let tampered = setup.rpc(
        &setup.agent,
        Request::ArtifactWrite {
            artifact_id: metadata.id.clone(),
            offset: 0,
            total_size: contents.len() as u64,
            sha256: hash(contents),
            chunk_sha256: hash(b"different"),
            bytes: b"abcd".to_vec(),
        },
    );
    assert_eq!(tampered.error.as_deref(), Some("chunk_hash_mismatch"));

    let invalid_offset = setup.rpc(
        &setup.agent,
        Request::ArtifactWrite {
            artifact_id: metadata.id.clone(),
            offset: 1,
            total_size: contents.len() as u64,
            sha256: hash(contents),
            chunk_sha256: hash(b"abcd"),
            bytes: b"abcd".to_vec(),
        },
    );
    assert_eq!(invalid_offset.error.as_deref(), Some("invalid_offset"));

    let unknown = setup.rpc(
        &setup.cli,
        Request::ArtifactRead {
            artifact_id: "missing".into(),
            offset: 0,
            length: CHUNK as u64,
            total_size: contents.len() as u64,
            sha256: hash(contents),
        },
    );
    assert_eq!(unknown.error.as_deref(), Some("unknown_artifact"));

    let denied = setup.rpc(
        &setup.outsider,
        Request::ArtifactRead {
            artifact_id: metadata.id.clone(),
            offset: 0,
            length: CHUNK as u64,
            total_size: contents.len() as u64,
            sha256: hash(contents),
        },
    );
    assert_eq!(denied.error.as_deref(), Some("artifact_access_denied"));
    assert!(denied.artifact_chunk.is_none());

    setup.rpc(
        &setup.outsider,
        Request::Heartbeat {
            host: device_development_mesh::network_processes::HostSnapshot {
                id: "mac-1".into(),
                operating_system: "macos".into(),
                architecture: "arm64".into(),
                status: "online".into(),
                capabilities: vec!["apple.build@1".into()],
                devices: vec![],
            },
        },
    );
    let hijacked = setup.rpc(
        &setup.outsider,
        Request::ArtifactRegister {
            job_id: setup.job_id.clone(),
            name: "hijacked.trace".into(),
            media_type: "application/octet-stream".into(),
            total_size: 4,
            sha256: hash(b"data"),
        },
    );
    assert_eq!(hijacked.error.as_deref(), Some("artifact_access_denied"));

    let oversized = setup.rpc(
        &setup.agent,
        Request::ArtifactWrite {
            artifact_id: metadata.id.clone(),
            offset: 0,
            total_size: contents.len() as u64,
            sha256: hash(contents),
            chunk_sha256: hash(&vec![0; 65 * 1024]),
            bytes: vec![0; 65 * 1024],
        },
    );
    assert_eq!(oversized.error.as_deref(), Some("invalid_chunk_length"));

    let mismatch = setup.rpc(
        &setup.agent,
        Request::ArtifactWrite {
            artifact_id: metadata.id.clone(),
            offset: 0,
            total_size: contents.len() as u64 + 1,
            sha256: hash(contents),
            chunk_sha256: hash(b"abcd"),
            bytes: b"abcd".to_vec(),
        },
    );
    assert_eq!(
        mismatch.error.as_deref(),
        Some("artifact_metadata_mismatch")
    );

    setup.write(&metadata, 0, b"abcd");
    setup.write(&metadata, 4, b"efgh");
    for request in [
        Request::ArtifactWrite {
            artifact_id: metadata.id.clone(),
            offset: 4,
            total_size: contents.len() as u64,
            sha256: hash(b"wrong"),
            chunk_sha256: hash(b"efgh"),
            bytes: b"efgh".to_vec(),
        },
        Request::ArtifactRead {
            artifact_id: metadata.id.clone(),
            offset: 4,
            length: CHUNK as u64,
            total_size: contents.len() as u64,
            sha256: hash(b"wrong"),
        },
        Request::ArtifactRead {
            artifact_id: metadata.id.clone(),
            offset: 4,
            length: 65 * 1024,
            total_size: contents.len() as u64,
            sha256: hash(contents),
        },
    ] {
        let response = setup.rpc(&setup.cli, request);
        assert!(
            matches!(
                response.error.as_deref(),
                Some("artifact_metadata_mismatch" | "invalid_offset")
            ),
            "{:?}",
            response.error
        );
    }
}

#[test]
fn aggregate_hash_failure_does_not_confirm_or_publish_the_final_chunk() {
    let setup = Setup::new();
    let contents = b"abcdefgh";
    let metadata = setup.register_with_hash("bad.trace", contents, &hash(b"abcdxxxx"));
    assert_eq!(setup.write(&metadata, 0, b"abcd").confirmed_offset, Some(4));
    let failed = setup.write(&metadata, 4, b"efgh");
    assert_eq!(failed.error.as_deref(), Some("artifact_hash_mismatch"));
    assert!(failed.confirmed_offset.is_none());
    let retry = setup.write(&metadata, 4, b"efgh");
    assert_eq!(retry.error.as_deref(), Some("artifact_hash_mismatch"));
    assert!(retry.confirmed_offset.is_none());
}

fn transfer_fixture(path: impl AsRef<Path>) {
    let setup = Setup::new();
    let contents = fs::read(path.as_ref()).unwrap();
    let metadata = setup.register(
        path.as_ref().file_name().unwrap().to_str().unwrap(),
        &contents,
    );

    let first = &contents[..contents.len().min(CHUNK)];
    let response = setup.write(&metadata, 0, first);
    assert_eq!(response.confirmed_offset, Some(first.len() as u64));

    let resumed = setup.write(&metadata, first.len() as u64, &contents[first.len()..]);
    assert_eq!(resumed.confirmed_offset, Some(contents.len() as u64));

    let duplicate = setup.write(&metadata, 0, first);
    assert_eq!(duplicate.confirmed_offset, Some(contents.len() as u64));

    let mut downloaded = Vec::new();
    while downloaded.len() < contents.len() {
        let response = setup.rpc(
            &setup.cli,
            Request::ArtifactRead {
                artifact_id: metadata.id.clone(),
                offset: downloaded.len() as u64,
                length: CHUNK as u64,
                total_size: contents.len() as u64,
                sha256: hash(&contents),
            },
        );
        let ArtifactChunk { offset, bytes, .. } = response.artifact_chunk.unwrap();
        assert_eq!(offset, downloaded.len() as u64);
        assert!(bytes.len() <= CHUNK);
        downloaded.extend(bytes);
    }
    assert_eq!(downloaded, contents);
    assert_eq!(hash(&downloaded), metadata.sha256);
}

struct Setup {
    _root: TempDir,
    _registry: ChildGuard,
    address: String,
    agent: SecureTransport,
    cli: SecureTransport,
    outsider: SecureTransport,
    job_id: String,
}

impl Setup {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let registry_path = root.path().join("registry");
        let agent_path = root.path().join("agent");
        let cli_path = root.path().join("cli");
        let outsider_path = root.path().join("outsider");
        pair(&registry_path, "registry", &agent_path, "agent");
        pair(&registry_path, "registry", &cli_path, "cli");
        pair(&registry_path, "registry", &outsider_path, "outsider");
        let address = free_address();
        let registry = ChildGuard(
            Command::new(env!("CARGO_BIN_EXE_mesh-registry"))
                .args([
                    "--listen",
                    &address,
                    "--identity",
                    registry_path.to_str().unwrap(),
                    "--offline-after-ms",
                    "10000",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
        );
        let agent = SecureTransport::load_or_create(agent_path, "agent").unwrap();
        let cli = SecureTransport::load_or_create(cli_path, "cli").unwrap();
        let outsider = SecureTransport::load_or_create(outsider_path, "outsider").unwrap();
        let setup = Self {
            _root: root,
            _registry: registry,
            address,
            agent,
            cli,
            outsider,
            job_id: String::new(),
        };
        setup.rpc(
            &setup.agent,
            Request::Heartbeat {
                host: device_development_mesh::network_processes::HostSnapshot {
                    id: "mac-1".into(),
                    operating_system: "macos".into(),
                    architecture: "arm64".into(),
                    status: "online".into(),
                    capabilities: vec!["apple.build@1".into()],
                    devices: vec![],
                },
            },
        );
        let accepted = setup.rpc(
            &setup.cli,
            Request::AppleRun {
                operation: AppleRequest {
                    version: RemoteProtocolVersion { major: 1, minor: 0 },
                    request_id: "request-32".into(),
                    idempotency_key: "idempotency-32".into(),
                    capability: "apple.build@1".into(),
                    workspace_path: "workspace".into(),
                    device_id: None,
                    lease_id: None,
                    operation: AppleOperation::BuildApp {
                        container: "MeshApp.xcodeproj".into(),
                        scheme: "MeshApp".into(),
                        destination: "platform=iOS Simulator,id=sim-1".into(),
                    },
                },
            },
        );
        Self {
            job_id: accepted.job_id.unwrap(),
            ..setup
        }
    }

    fn register(&self, name: &str, contents: &[u8]) -> NetworkArtifactMetadata {
        self.register_with_hash(name, contents, &hash(contents))
    }

    fn register_with_hash(
        &self,
        name: &str,
        contents: &[u8],
        sha256: &str,
    ) -> NetworkArtifactMetadata {
        self.rpc(
            &self.agent,
            Request::ArtifactRegister {
                job_id: self.job_id.clone(),
                name: name.into(),
                media_type: "application/octet-stream".into(),
                total_size: contents.len() as u64,
                sha256: sha256.into(),
            },
        )
        .artifact_metadata
        .unwrap()
    }

    fn write(&self, metadata: &NetworkArtifactMetadata, offset: u64, bytes: &[u8]) -> Response {
        self.rpc(
            &self.agent,
            Request::ArtifactWrite {
                artifact_id: metadata.id.clone(),
                offset,
                total_size: metadata.total_size,
                sha256: metadata.sha256.clone(),
                chunk_sha256: hash(bytes),
                bytes: bytes.to_vec(),
            },
        )
    }

    fn rpc(&self, identity: &SecureTransport, request: Request) -> Response {
        let stream = connect(&self.address);
        let mut stream = identity.connect_tls(stream, "registry").unwrap();
        serde_json::to_writer(&mut stream, &request).unwrap();
        stream.write_all(b"\n").unwrap();
        let mut line = String::new();
        BufReader::new(stream).read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap()
    }
}

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn pair(left_path: &Path, left_id: &str, right_path: &Path, right_id: &str) {
    let mut left = SecureTransport::load_or_create(left_path, left_id).unwrap();
    let mut right = SecureTransport::load_or_create(right_path, right_id).unwrap();
    let code = left.issue_pairing_code(Duration::from_secs(10));
    left.accept_pairing(&code, right.certificate_der(), Duration::ZERO)
        .unwrap();
    right.trust(left_id, left.certificate_der()).unwrap();
}

fn free_address() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().to_string()
}

fn connect(address: &str) -> TcpStream {
    for _ in 0..100 {
        if let Ok(stream) = TcpStream::connect(address) {
            return stream;
        }
        thread::sleep(Duration::from_millis(10));
    }
    TcpStream::connect(address).unwrap()
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
