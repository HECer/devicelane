use super::{WalkMode, audit_error, insecure};
use std::collections::HashSet;
use std::ffi::CString;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

#[derive(Default)]
struct Redirects {
    count: usize,
    seen: HashSet<(u64, u64)>,
}

pub(super) fn walk(path: &Path, mode: WalkMode) -> io::Result<PathBuf> {
    walk_resolved(path, mode, &mut Redirects::default())
}

fn walk_resolved(path: &Path, mode: WalkMode, redirects: &mut Redirects) -> io::Result<PathBuf> {
    let parts: Vec<_> = path
        .components()
        .filter_map(|part| match part {
            Component::Normal(name) => Some(name.to_owned()),
            _ => None,
        })
        .collect();
    // Check the entire suffix before inspecting or creating any component,
    // including when this traversal follows a validated system alias target.
    if parts.iter().any(|part| part.as_bytes().contains(&0)) {
        return Err(insecure());
    }
    let mut resolved = PathBuf::from("/");
    let root = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")?;
    let mut handles = vec![root];
    let mut user_area = false;
    for (index, part) in parts.iter().enumerate() {
        let parent = handles.last().unwrap();
        let parent_metadata = parent.metadata()?;
        validate_parent(&parent_metadata)?;
        user_area |= parent_metadata.mode() & 0o022 != 0
            || (parent_metadata.uid() == unsafe { libc::geteuid() } && parent_metadata.uid() != 0);
        let candidate = resolved.join(part);
        let metadata = match fs::symlink_metadata(&candidate) {
            Ok(metadata) => Some(metadata),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        if let Some(metadata) = &metadata {
            if metadata.file_type().is_symlink() {
                if user_area
                    || parent_metadata.uid() != 0
                    || parent_metadata.mode() & 0o022 != 0
                    || metadata.uid() != 0
                    || redirects.count >= 16
                    || !redirects.seen.insert((metadata.dev(), metadata.ino()))
                {
                    return Err(insecure());
                }
                redirects.count += 1;
                let target = fs::read_link(&candidate)?;
                let mut destination = normalize_system_target(&resolved, &target)?;
                for remaining in &parts[index + 1..] {
                    destination.push(remaining);
                }
                return walk_resolved(&destination, mode, redirects);
            }
            validate_node(metadata)?;
        } else if !mode.prepares() {
            // The complete component grammar was checked before reaching here.
            // No nonexistent suffix is canonicalized or created by validation.
            for remaining in &parts[index..] {
                resolved.push(remaining);
            }
            return Ok(resolved);
        } else {
            match crate::dashboard::audit::create_private_dir_exclusive(&candidate)
                .map_err(audit_error)
            {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    let raced = fs::symlink_metadata(&candidate)?;
                    validate_node(&raced)?;
                    // A collision must already be private and current-user owned.
                    // It never enters the final-directory tightening exception.
                    if raced.uid() != unsafe { libc::geteuid() } || raced.mode() & 0o077 != 0 {
                        return Err(insecure());
                    }
                }
                Err(error) => return Err(error),
            }
        }
        let name = CString::new(part.as_bytes()).map_err(|_| insecure())?;
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(insecure());
        }
        let opened = unsafe { File::from_raw_fd(fd) };
        validate_node(&opened.metadata()?)?;
        resolved = candidate;
        handles.push(opened);
    }
    if mode.requires_private() {
        let final_directory = handles.last().unwrap();
        let metadata = final_directory.metadata()?;
        if parts.is_empty()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & libc::S_ISVTX != 0
        {
            return Err(insecure());
        }
        if mode.prepares() {
            final_directory.set_permissions(fs::Permissions::from_mode(0o700))?;
        }
    }
    Ok(resolved)
}

fn validate_node(metadata: &Metadata) -> io::Result<()> {
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || (metadata.uid() != 0 && metadata.uid() != unsafe { libc::geteuid() })
    {
        Err(insecure())
    } else {
        Ok(())
    }
}

fn validate_parent(metadata: &Metadata) -> io::Result<()> {
    validate_node(metadata)?;
    if metadata.mode() & 0o022 != 0
        && !(metadata.uid() == 0 && metadata.mode() & libc::S_ISVTX != 0)
    {
        Err(insecure())
    } else {
        Ok(())
    }
}

fn normalize_system_target(parent: &Path, target: &Path) -> io::Result<PathBuf> {
    let joined = if target.is_absolute() {
        target.to_owned()
    } else {
        parent.join(target)
    };
    let mut resolved = PathBuf::from("/");
    for component in joined.components() {
        match component {
            Component::Normal(name) => resolved.push(name),
            // A lexical pop could skip an unexamined symlink and change the
            // target's actual traversal semantics. Standard system aliases do
            // not need parent components; reject such targets in this boundary.
            Component::ParentDir => return Err(insecure()),
            Component::RootDir | Component::CurDir => {}
            _ => return Err(insecure()),
        }
    }
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_paths::{
        prepare_private_state_directory, validate_private_state_directory, validate_state_directory,
    };

    fn fixture_tree(root: &Path) -> std::collections::BTreeMap<PathBuf, (u32, Option<Vec<u8>>)> {
        fn visit(
            root: &Path,
            directory: &Path,
            tree: &mut std::collections::BTreeMap<PathBuf, (u32, Option<Vec<u8>>)>,
        ) {
            for entry in fs::read_dir(directory).unwrap() {
                let path = entry.unwrap().path();
                let metadata = fs::symlink_metadata(&path).unwrap();
                assert!(
                    !metadata.file_type().is_symlink(),
                    "unexpected fixture link"
                );
                let bytes = if metadata.is_dir() {
                    None
                } else {
                    Some(fs::read(&path).unwrap())
                };
                tree.insert(
                    path.strip_prefix(root).unwrap().to_owned(),
                    (metadata.mode(), bytes),
                );
                if metadata.is_dir() {
                    visit(root, &path, tree);
                }
            }
        }
        let mut tree = std::collections::BTreeMap::new();
        visit(root, root, &mut tree);
        tree
    }

    #[test]
    fn unix_nul_component_is_rejected_by_all_apis_before_missing_creation() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("sentinel"), b"unchanged NUL preflight").unwrap();
        let requested = root
            .path()
            .join("missing")
            .join(std::ffi::OsStr::from_bytes(b"name\0"))
            .join("identity");
        let before = fixture_tree(root.path());
        // Capture every result and side effect before asserting: baseline validation
        // accepts the suffix and preparation creates `missing` before rejecting NUL.
        let validated = validate_state_directory(&requested);
        let eligible = validate_private_state_directory(&requested);
        let prepared = prepare_private_state_directory(&requested);
        let after = fixture_tree(root.path());
        assert!(
            validated.is_err() && eligible.is_err() && prepared.is_err(),
            "NUL preflight: validate={validated:?}, eligible={eligible:?}, prepare={prepared:?}, tree_changed={}",
            before != after
        );
        assert_eq!(after, before, "NUL rejection mutated the owned fixture");
        assert!(!root.path().join("missing").exists());
    }

    #[test]
    fn unix_root_owned_sticky_tmp_allows_a_private_owned_child() {
        // Inspect the system parent, but create and mutate only our private child.
        let tmp = fs::canonicalize("/tmp").unwrap();
        let parent = fs::metadata(&tmp).unwrap();
        assert_eq!(parent.uid(), 0, "fixture requires root-owned /tmp");
        assert_ne!(
            parent.mode() & libc::S_ISVTX,
            0,
            "fixture requires sticky /tmp"
        );
        assert_ne!(parent.mode() & 0o022, 0, "fixture requires writable /tmp");
        let root = tempfile::tempdir_in(&tmp).unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let metadata = fs::metadata(root.path()).unwrap();
        assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
        assert_eq!(metadata.mode() & 0o077, 0);
        fs::write(root.path().join("sentinel"), b"sticky child").unwrap();
        let before = fixture_tree(root.path());
        assert_eq!(validate_state_directory(root.path()).unwrap(), root.path());
        assert_eq!(
            validate_private_state_directory(root.path()).unwrap(),
            root.path()
        );
        assert_eq!(
            prepare_private_state_directory(root.path()).unwrap(),
            root.path()
        );
        assert_eq!(fixture_tree(root.path()), before);
    }

    #[test]
    fn unix_writable_intermediate_parent_is_rejected_without_repair() {
        let root = tempfile::tempdir().unwrap();
        let parent = root.path().join("writable");
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o777)).unwrap();
        fs::write(parent.join("sentinel"), b"writable parent").unwrap();
        let before = fixture_tree(root.path());
        let requested = parent.join("missing").join("identity");
        let validated = validate_state_directory(&requested);
        let eligible = validate_private_state_directory(&requested);
        let prepared = prepare_private_state_directory(&requested);
        let after = fixture_tree(root.path());
        assert!(validated.is_err() && eligible.is_err() && prepared.is_err());
        assert_eq!(after, before);
        assert!(!parent.join("missing").exists());
    }

    #[test]
    fn system_alias_target_cannot_cancel_an_unexamined_component() {
        assert!(normalize_system_target(Path::new("/"), Path::new("unexamined/../other")).is_err());
        assert_eq!(
            normalize_system_target(Path::new("/"), Path::new("private/tmp")).unwrap(),
            Path::new("/private/tmp")
        );
    }
}
