use device_development_mesh::connection_config::{ConnectionConfig, ConnectionConfigError};

fn document(address: &str, peer: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "version": 1, "registry_address": address, "registry_peer_id": peer
    }))
    .unwrap()
}

#[test]
fn absent_configuration_is_local_only() {
    let root = tempfile::tempdir().unwrap();
    assert_eq!(ConnectionConfig::load(root.path()).unwrap(), None);
    assert_eq!(
        ConnectionConfig::load(&root.path().join("missing")).unwrap(),
        None
    );
}

#[test]
fn loads_public_connection_without_changing_identity_or_trust() {
    let root = tempfile::tempdir().unwrap();
    let bytes = document("macbook.local:7443", "paired-registry");
    std::fs::write(root.path().join("connection.json"), &bytes).unwrap();
    let config = ConnectionConfig::load(root.path()).unwrap().unwrap();
    assert_eq!(config.registry_address(), "macbook.local:7443");
    assert_eq!(config.registry_peer_id(), "paired-registry");
    assert_eq!(
        std::fs::read(root.path().join("connection.json")).unwrap(),
        bytes
    );
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 1);
}

#[test]
fn saves_and_replaces_only_the_public_connection_file() {
    let root = tempfile::tempdir().unwrap();
    let identity = root.path().join("identity");
    let transport = device_development_mesh::secure_transport::SecureTransport::load_or_create(
        &identity,
        "workstation",
    )
    .unwrap();
    let certificate = transport.certificate_der().to_vec();
    fn collect_files(root: &std::path::Path, files: &mut Vec<(std::path::PathBuf, Vec<u8>)>) {
        for entry in std::fs::read_dir(root).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if entry.file_type().unwrap().is_dir() {
                collect_files(&path, files);
            } else {
                files.push((path.clone(), std::fs::read(path).unwrap()));
            }
        }
    }
    let mut identity_files = Vec::new();
    collect_files(&identity, &mut identity_files);
    let first = ConnectionConfig::new("127.0.0.1:7443", "registry").unwrap();
    first.save(&identity).unwrap();
    assert_eq!(ConnectionConfig::load(&identity).unwrap(), Some(first));
    let second = ConnectionConfig::new("macbook.local:7443", "another-registry").unwrap();
    second.save(&identity).unwrap();
    assert_eq!(ConnectionConfig::load(&identity).unwrap(), Some(second));
    let reopened = device_development_mesh::secure_transport::SecureTransport::load_or_create(
        &identity,
        "workstation",
    )
    .unwrap();
    assert_eq!(reopened.certificate_der(), certificate);
    for (path, bytes) in identity_files {
        assert!(
            std::fs::read(path).unwrap() == bytes,
            "identity material changed"
        );
    }
}

#[test]
fn failed_staging_preserves_previous_connection() {
    let root = tempfile::tempdir().unwrap();
    let identity = root.path().join("identity");
    device_development_mesh::secure_transport::SecureTransport::load_or_create(
        &identity,
        "workstation",
    )
    .unwrap();
    let first = ConnectionConfig::new("127.0.0.1:7443", "registry").unwrap();
    first.save(&identity).unwrap();
    let before = std::fs::read(identity.join("connection.json")).unwrap();
    let staging = identity.join(format!(
        ".connection.json.devicelane-{}.tmp",
        std::process::id()
    ));
    std::fs::create_dir(&staging).unwrap();
    let second = ConnectionConfig::new("macbook.local:7443", "another-registry").unwrap();
    assert!(second.save(&identity).is_err());
    assert_eq!(
        std::fs::read(identity.join("connection.json")).unwrap(),
        before
    );
    assert!(staging.is_dir());
}

#[test]
fn save_refuses_non_regular_destination_without_deleting_it() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("connection.json")).unwrap();
    let config = ConnectionConfig::new("127.0.0.1:7443", "registry").unwrap();
    assert_eq!(
        config.save(root.path()),
        Err(ConnectionConfigError::InvalidFile)
    );
    assert!(root.path().join("connection.json").is_dir());
    assert_eq!(
        config.save(std::path::Path::new("relative")),
        Err(ConnectionConfigError::InvalidFile)
    );
}

#[test]
fn rejects_unknown_fields_versions_and_oversized_input() {
    let root = tempfile::tempdir().unwrap();
    for bytes in [
        br#"{"version":2,"registry_address":"127.0.0.1:7443","registry_peer_id":"registry"}"#.to_vec(),
        br#"{"version":1,"registry_address":"127.0.0.1:7443","registry_peer_id":"registry","identity_path":"elsewhere"}"#.to_vec(),
        vec![b' '; 4097],
        b"not json".to_vec(),
    ] {
        std::fs::write(root.path().join("connection.json"), bytes).unwrap();
        assert!(ConnectionConfig::load(root.path()).is_err());
    }
}

#[test]
fn validates_endpoints_without_dns_or_network_io() {
    for address in ["127.0.0.1:7443", "[::1]:7443", "macbook.local:7443"] {
        assert!(ConnectionConfig::new(address, "registry").is_ok());
    }
    for address in [
        "",
        "https://mac:7443",
        "mac:0",
        "mac:65536",
        "mac:7443/path",
        "mac:7443\n",
        "user@mac:7443",
        "-mac:7443",
        "::1:7443",
        "999.1.1.1:7443",
    ] {
        assert_eq!(
            ConnectionConfig::new(address, "registry"),
            Err(ConnectionConfigError::InvalidEndpoint),
            "{address:?}"
        );
    }
    for peer in [
        "",
        "registry\n",
        "registry/other",
        "registry with spaces",
        "registry:other",
        ".",
        "-registry",
        "registry-",
    ] {
        assert_eq!(
            ConnectionConfig::new("127.0.0.1:7443", peer),
            Err(ConnectionConfigError::InvalidPeer)
        );
    }
}

#[test]
fn rejects_non_regular_file_and_relative_identity() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("connection.json")).unwrap();
    assert!(ConnectionConfig::load(root.path()).is_err());
    assert_eq!(
        ConnectionConfig::load(std::path::Path::new("relative")),
        Err(ConnectionConfigError::InvalidFile)
    );
}

#[test]
fn bounds_configuration_fields_and_rejects_duplicate_keys() {
    assert!(ConnectionConfig::new(&format!("{}:7443", "a".repeat(300)), "registry").is_err());
    assert!(ConnectionConfig::new("127.0.0.1:7443", &"r".repeat(129)).is_err());
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("connection.json"), br#"{"version":1,"version":1,"registry_address":"127.0.0.1:7443","registry_peer_id":"registry"}"#).unwrap();
    assert!(ConnectionConfig::load(root.path()).is_err());
}

#[test]
fn ipc_deserialization_uses_the_same_configuration_validation() {
    let config = ConnectionConfig::new("macbook.local:7443", "registry").unwrap();
    let encoded = serde_json::to_vec(&config).unwrap();
    assert_eq!(
        serde_json::from_slice::<ConnectionConfig>(&encoded).unwrap(),
        config
    );
    for bytes in [
        document("127.0.0.1:7443", "registry:other"),
        document("mac:0", "registry"),
        br#"{"version":2,"registry_address":"127.0.0.1:7443","registry_peer_id":"registry"}"#.to_vec(),
        br#"{"version":1,"registry_address":"127.0.0.1:7443","registry_peer_id":"registry","command":"whoami"}"#.to_vec(),
    ] {
        assert!(serde_json::from_slice::<ConnectionConfig>(&bytes).is_err());
    }
}

#[test]
fn invalid_saved_settings_keep_local_diagnostics_available_without_overwriting_file() {
    use device_development_mesh::local_ipc::{
        ConnectionState, LocalProtocolVersion, LocalRequest, LocalResponse, local_endpoint,
        send_local_request,
    };
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};
    struct Service(Child);
    impl Drop for Service {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let root = tempfile::tempdir().unwrap();
    let identity = root.path().join("identity");
    let runtime = root.path().join("runtime");
    let logs = root.path().join("logs");
    for path in [&identity, &runtime, &logs] {
        std::fs::create_dir(path).unwrap();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let bytes = b"malformed settings: do-not-echo-this";
    let path = identity.join("connection.json");
    std::fs::write(&path, bytes).unwrap();
    #[cfg(windows)]
    let listen = format!(r"\\.\pipe\devicelane-invalid-config-{}", std::process::id());
    #[cfg(unix)]
    let listen = runtime
        .canonicalize()
        .unwrap()
        .join("config.sock")
        .display()
        .to_string();
    let endpoint = local_endpoint(&runtime, &listen).unwrap();
    let _service = Service(
        Command::new(env!("CARGO_BIN_EXE_devicelane-service"))
            .args([
                "--identity",
                identity.to_str().unwrap(),
                "--runtime-dir",
                runtime.to_str().unwrap(),
                "--role",
                "workstation",
                "--listen",
                &listen,
                "--log-dir",
                logs.to_str().unwrap(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    let snapshot = loop {
        if let Ok(LocalResponse::Snapshot(snapshot)) = send_local_request(
            &endpoint,
            &LocalRequest::Status {
                version: LocalProtocolVersion::CURRENT,
            },
        ) {
            break snapshot;
        }
        assert!(
            Instant::now() < deadline,
            "invalid configuration made local service unreachable"
        );
        std::thread::sleep(Duration::from_millis(25));
    };
    assert_eq!(snapshot.connection, ConnectionState::Disconnected);
    assert_eq!(snapshot.warnings, vec!["connection_configuration_invalid"]);
    let response = send_local_request(
        &endpoint,
        &LocalRequest::Diagnostics {
            version: LocalProtocolVersion::CURRENT,
        },
    )
    .unwrap();
    assert!(
        !serde_json::to_string(&response)
            .unwrap()
            .contains("do-not-echo-this")
    );
    let LocalResponse::Diagnostics(items) = response else {
        panic!("missing diagnostics")
    };
    assert!(
        items
            .iter()
            .any(|item| item.code == "connection_configuration_invalid" && !item.healthy)
    );
    assert_eq!(std::fs::read(path).unwrap(), bytes);
}

#[cfg(unix)]
#[test]
fn refuses_linked_or_group_writable_configuration() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let root = tempfile::tempdir().unwrap();
    let external = root.path().join("external.json");
    std::fs::write(&external, document("127.0.0.1:7443", "registry")).unwrap();
    let identity = root.path().join("identity");
    std::fs::create_dir(&identity).unwrap();
    symlink(&external, identity.join("connection.json")).unwrap();
    assert!(ConnectionConfig::load(&identity).is_err());
    std::fs::remove_file(identity.join("connection.json")).unwrap();
    std::fs::copy(external, identity.join("connection.json")).unwrap();
    std::fs::set_permissions(
        identity.join("connection.json"),
        std::fs::Permissions::from_mode(0o666),
    )
    .unwrap();
    assert!(ConnectionConfig::load(&identity).is_err());
}
