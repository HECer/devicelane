//! Read-only state-directory validation and private preparation.
//!
//! Validates directory authority before state is created. This boundary excludes
//! replacement by other untrusted OS accounts; it does not isolate the same user
//! or an administrator, nor validate the contents of individual store files.

use std::io;
use std::path::{Path, PathBuf};

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

pub fn validate_state_directory(path: &Path) -> io::Result<PathBuf> {
    walk(path, WalkMode::Validate)
}

/// Check preparation eligibility without creating directories or changing permissions.
pub fn validate_private_state_directory(path: &Path) -> io::Result<PathBuf> {
    walk(path, WalkMode::ValidatePrivate)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum WalkMode {
    Validate,
    ValidatePrivate,
    Prepare,
}

impl WalkMode {
    fn prepares(self) -> bool {
        self == Self::Prepare
    }

    fn requires_private(self) -> bool {
        self != Self::Validate
    }
}

fn absolute_state_path(path: &Path, captured_cwd: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_owned()
    } else {
        captured_cwd.join(path)
    }
}

pub fn prepare_private_state_directory(path: &Path) -> io::Result<PathBuf> {
    walk(path, WalkMode::Prepare)
}

fn walk(path: &Path, mode: WalkMode) -> io::Result<PathBuf> {
    let captured_cwd = std::env::current_dir()?;
    let absolute = absolute_state_path(path, &captured_cwd);
    if !absolute.is_absolute()
        || absolute
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(insecure());
    }
    #[cfg(windows)]
    {
        windows::walk(&absolute, mode)
    }
    #[cfg(unix)]
    {
        unix::walk(&absolute, mode)
    }
}

fn insecure() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "state_path_insecure")
}

fn audit_error(error: crate::dashboard::audit::AuditError) -> io::Error {
    match error {
        crate::dashboard::audit::AuditError::Io(error) => error,
        _ => insecure(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owned_root(root: &Path) -> PathBuf {
        let directory = root.join("owned");
        crate::dashboard::audit::create_private_dir(&directory).unwrap();
        directory
    }

    #[test]
    fn private_eligibility_rejects_filesystem_root_without_preparation() {
        let root = tempfile::tempdir().unwrap();
        let absolute = root.path().canonicalize().unwrap();
        let filesystem_root = absolute.ancestors().last().unwrap();
        assert_eq!(
            validate_state_directory(filesystem_root).unwrap(),
            filesystem_root
        );
        let error = validate_private_state_directory(filesystem_root).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(error.to_string(), "state_path_insecure");
    }

    #[test]
    fn private_eligibility_preserves_existing_root_and_missing_suffix() {
        let root = tempfile::tempdir().unwrap();
        let directory = owned_root(root.path());
        let sentinel = directory.join("sentinel");
        std::fs::write(&sentinel, b"unchanged preflight").unwrap();
        assert_eq!(
            validate_private_state_directory(&directory).unwrap(),
            directory
        );
        let requested = directory.join("missing").join("identity");
        assert_eq!(
            validate_private_state_directory(&requested).unwrap(),
            requested
        );
        assert!(!directory.join("missing").exists());
        assert_eq!(std::fs::read(sentinel).unwrap(), b"unchanged preflight");
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 1);
    }

    #[test]
    fn read_only_existing_directory_preserves_sentinel() {
        let root = tempfile::tempdir().unwrap();
        let directory = owned_root(root.path());
        std::fs::write(directory.join("sentinel"), b"existing data").unwrap();
        let resolved = validate_state_directory(&directory).unwrap();
        assert_eq!(resolved, directory);
        assert_eq!(
            std::fs::read(resolved.join("sentinel")).unwrap(),
            b"existing data"
        );
    }

    #[test]
    fn read_only_missing_suffix_does_not_create_directories() {
        let root = tempfile::tempdir().unwrap();
        let directory = owned_root(root.path());
        let requested = directory.join("missing").join("identity");
        assert_eq!(validate_state_directory(&requested).unwrap(), requested);
        assert!(!directory.join("missing").exists());
    }

    #[test]
    fn preparation_creates_each_missing_private_directory() {
        let root = tempfile::tempdir().unwrap();
        let directory = owned_root(root.path());
        let requested = directory.join("missing").join("identity");
        let resolved = prepare_private_state_directory(&requested).unwrap();
        assert_eq!(resolved, requested);
        for path in [directory.join("missing"), requested] {
            assert!(
                path.is_dir(),
                "private preparation did not create {}",
                path.display()
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::{MetadataExt, PermissionsExt};
                let metadata = std::fs::metadata(path).unwrap();
                assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
                assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
            }
            #[cfg(windows)]
            assert!(
                crate::dashboard::managed_policy::windows_acl_is_restrictive(
                    &path,
                    &Default::default()
                )
            );
        }
    }

    #[test]
    fn parent_components_are_rejected_without_normalizing_them_away() {
        let root = tempfile::tempdir().unwrap();
        let directory = owned_root(root.path());
        let requested = directory.join("missing").join("..").join("identity");
        assert!(validate_state_directory(&requested).is_err());
        assert!(prepare_private_state_directory(&requested).is_err());
        assert!(!directory.join("missing").exists());
        assert!(!directory.join("identity").exists());
    }

    #[test]
    fn ordinary_current_directory_component_keeps_the_selected_directory() {
        let root = tempfile::tempdir().unwrap();
        let directory = owned_root(root.path());
        assert_eq!(
            validate_state_directory(&directory.join(".")).unwrap(),
            directory
        );
    }

    #[test]
    fn user_created_system_alias_imitation_is_rejected() {
        let root = tempfile::tempdir().unwrap();
        let directory = owned_root(root.path());
        let target = directory.join("target");
        crate::dashboard::audit::create_private_dir(&target).unwrap();
        std::fs::write(target.join("sentinel"), b"untouched target").unwrap();
        let alias = directory.join("tmp");
        directory_symlink(&target, &alias);
        assert!(
            std::fs::symlink_metadata(&alias)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        let requested = alias.join("missing").join("identity");
        assert!(
            validate_state_directory(&requested).is_err(),
            "user-owned alias was treated as a system alias"
        );
        assert!(prepare_private_state_directory(&requested).is_err());
        assert!(!target.join("missing").exists());
        assert_eq!(
            std::fs::read(target.join("sentinel")).unwrap(),
            b"untouched target"
        );
    }

    #[test]
    fn preparation_revalidates_a_missing_component_replaced_by_file() {
        let root = tempfile::tempdir().unwrap();
        let directory = owned_root(root.path());
        let component = directory.join("missing");
        let requested = component.join("identity");
        validate_state_directory(&requested).unwrap();
        std::fs::write(&component, b"competing owned file").unwrap();
        assert!(prepare_private_state_directory(&requested).is_err());
        assert_eq!(std::fs::read(component).unwrap(), b"competing owned file");
    }

    #[test]
    fn preparation_revalidates_a_missing_component_replaced_by_link() {
        let root = tempfile::tempdir().unwrap();
        let directory = owned_root(root.path());
        let component = directory.join("missing");
        let requested = component.join("identity");
        validate_state_directory(&requested).unwrap();
        let target = directory.join("target");
        crate::dashboard::audit::create_private_dir(&target).unwrap();
        directory_symlink(&target, &component);
        assert!(prepare_private_state_directory(&requested).is_err());
        assert!(!target.join("identity").exists());
        assert!(
            std::fs::symlink_metadata(component)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn relative_state_path_is_resolved_against_captured_working_directory() {
        let root = tempfile::tempdir().unwrap();
        let captured_cwd = owned_root(root.path());
        let expected = captured_cwd.join("state-path-relative-fixture");
        assert_eq!(
            absolute_state_path(Path::new("state-path-relative-fixture"), &captured_cwd),
            expected
        );
        assert!(!expected.exists());
    }

    #[cfg(unix)]
    #[test]
    fn real_system_tmp_alias_resolves_to_its_physical_directory() {
        let requested = Path::new("/tmp");
        let resolved = validate_state_directory(requested).unwrap();
        // macOS normally aliases /tmp into /private; Linux commonly has a real
        // directory. Canonicalization here is an independent expected test value.
        assert_eq!(resolved, std::fs::canonicalize(requested).unwrap());
    }

    fn directory_symlink(target: &Path, link: &Path) {
        #[cfg(windows)]
        std::os::windows::fs::symlink_dir(target, link)
            .expect("fixture requires actual Windows directory symlink permission");
        #[cfg(unix)]
        std::os::unix::fs::symlink(target, link)
            .expect("fixture requires an actual directory symlink");
    }
}
