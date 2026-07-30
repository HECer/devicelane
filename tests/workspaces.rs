use device_development_mesh::workspace::{ManifestEntry, WorkspaceError, WorkspaceManager};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_root(name: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("mesh-{name}-{unique}"))
}

#[test]
fn manifest_upload_returns_identical_sha256_hashes() {
    let root = temp_root("manifest");
    let mut manager = WorkspaceManager::new(&root).unwrap();
    manager
        .acquire_write_lease("agent-1", "session-1", "client-1")
        .unwrap();
    let contents = b"fn main() {}".to_vec();
    let expected = format!("{:x}", Sha256::digest(&contents));

    let manifest = manager
        .upload_manifest(
            "agent-1",
            "session-1",
            "client-1",
            vec![ManifestEntry::new("src/main.rs", contents)],
        )
        .unwrap();

    assert_eq!(manifest.entries()[0].path(), "src/main.rs");
    assert_eq!(manifest.entries()[0].sha256(), expected);
    assert_eq!(
        fs::read(root.join("agent-1/session-1/src/main.rs")).unwrap(),
        b"fn main() {}"
    );
    drop(manager);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn absolute_and_parent_paths_are_rejected() {
    let root = temp_root("paths");
    let mut manager = WorkspaceManager::new(&root).unwrap();
    manager
        .acquire_write_lease("agent", "session", "client")
        .unwrap();

    for path in [PathBuf::from("../escape"), root.join("absolute")] {
        assert_eq!(
            manager.upload_manifest(
                "agent",
                "session",
                "client",
                vec![ManifestEntry::new(path, b"blocked".to_vec())],
            ),
            Err(WorkspaceError::PathEscape)
        );
    }
    drop(manager);
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn symlink_escape_is_rejected() {
    use std::os::unix::fs::symlink;

    let root = temp_root("symlink");
    let outside = temp_root("outside");
    fs::create_dir_all(&outside).unwrap();
    let mut manager = WorkspaceManager::new(&root).unwrap();
    manager
        .acquire_write_lease("agent", "session", "client")
        .unwrap();
    symlink(&outside, root.join("agent/session/link")).unwrap();

    assert_eq!(
        manager.upload_manifest(
            "agent",
            "session",
            "client",
            vec![ManifestEntry::new("link/escape", b"blocked".to_vec())],
        ),
        Err(WorkspaceError::PathEscape)
    );
    drop(manager);
    fs::remove_dir_all(root).unwrap();
    fs::remove_dir_all(outside).unwrap();
}

#[cfg(unix)]
#[test]
fn destination_symlink_escape_is_rejected() {
    use std::os::unix::fs::symlink;

    let root = temp_root("file-symlink");
    let outside = temp_root("outside-file");
    fs::write(&outside, b"original").unwrap();
    let mut manager = WorkspaceManager::new(&root).unwrap();
    manager
        .acquire_write_lease("agent", "session", "client")
        .unwrap();
    symlink(&outside, root.join("agent/session/escape")).unwrap();

    assert_eq!(
        manager.upload_manifest(
            "agent",
            "session",
            "client",
            vec![ManifestEntry::new("escape", b"blocked".to_vec())],
        ),
        Err(WorkspaceError::PathEscape)
    );
    assert_eq!(fs::read(&outside).unwrap(), b"original");
    drop(manager);
    fs::remove_dir_all(root).unwrap();
    fs::remove_file(outside).unwrap();
}

#[cfg(windows)]
#[test]
fn junction_escape_is_rejected() {
    use std::process::Command;

    let root = temp_root("junction");
    let outside = temp_root("outside");
    fs::create_dir_all(&outside).unwrap();
    let mut manager = WorkspaceManager::new(&root).unwrap();
    manager
        .acquire_write_lease("agent", "session", "client")
        .unwrap();
    let link = root.join("agent/session/link");
    let link_arg = link
        .to_string_lossy()
        .trim_start_matches(r"\\?\")
        .replace('/', "\\");
    let outside_arg = outside
        .to_string_lossy()
        .trim_start_matches(r"\\?\")
        .replace('/', "\\");
    let command = format!(
        "New-Item -ItemType Junction -Path '{link_arg}' -Target '{outside_arg}' | Out-Null"
    );
    assert!(
        Command::new("powershell")
            .args(["-NoProfile", "-Command", &command])
            .status()
            .unwrap()
            .success()
    );

    assert_eq!(
        manager.upload_manifest(
            "agent",
            "session",
            "client",
            vec![ManifestEntry::new("link/escape", b"blocked".to_vec())],
        ),
        Err(WorkspaceError::PathEscape)
    );
    drop(manager);
    fs::remove_dir(&link).unwrap();
    fs::remove_dir_all(root).unwrap();
    fs::remove_dir_all(outside).unwrap();
}

#[test]
fn second_write_client_gets_a_clear_conflict() {
    let root = temp_root("lease");
    let mut manager = WorkspaceManager::new(&root).unwrap();
    manager
        .acquire_write_lease("agent", "session", "client-1")
        .unwrap();

    assert_eq!(
        manager.acquire_write_lease("agent", "session", "client-2"),
        Err(WorkspaceError::WriteLeaseConflict)
    );
    drop(manager);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn second_manager_gets_the_same_write_conflict() {
    let root = temp_root("shared-lease");
    let mut first = WorkspaceManager::new(&root).unwrap();
    let mut second = WorkspaceManager::new(&root).unwrap();
    first
        .acquire_write_lease("agent", "session", "client-1")
        .unwrap();

    assert_eq!(
        second.acquire_write_lease("agent", "session", "client-2"),
        Err(WorkspaceError::WriteLeaseConflict)
    );
    drop(first);
    drop(second);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn internal_lease_namespace_cannot_be_an_agent_workspace() {
    let root = temp_root("reserved-agent");
    let mut manager = WorkspaceManager::new(&root).unwrap();

    assert_eq!(
        manager.acquire_write_lease(".LeAsEs", "agent", "client"),
        Err(WorkspaceError::PathEscape)
    );
    drop(manager);
    fs::remove_dir_all(root).unwrap();
}
