use super::*;

#[test]
fn native_authority_parent_add_child_only_preserves_existing_child() {
    assert_native_edge(EdgeSide::Parent, 0x2 | 0x4, true);
}

#[test]
fn native_final_write_authority_is_rejected_without_repair() {
    for (name, mask) in [
        ("add-file", 0x2),
        ("add-subdirectory", 0x4),
        ("write-attributes", 0x100),
        ("write-extended-attributes", 0x10),
        ("delete-child", 0x40),
        ("delete", 0x10000),
        ("write-dac", 0x40000),
        ("write-owner", 0x80000),
        ("generic-write", 0x40000000),
        ("generic-all", 0x10000000),
    ] {
        let root = tempfile::tempdir().unwrap();
        let final_directory = root.path().join("owned-final");
        crate::dashboard::audit::create_private_dir_exclusive(&final_directory).unwrap();
        std::fs::write(
            final_directory.join("sentinel"),
            b"final directory sentinel",
        )
        .unwrap();
        set_fixture_extra_rights(&final_directory, mask);
        let before = security_snapshot(&final_directory);
        let validated = crate::state_paths::validate_state_directory(&final_directory);
        let prepared = crate::state_paths::prepare_private_state_directory(&final_directory);
        let after = security_snapshot(&final_directory);
        assert!(
            validated.is_err(),
            "read-only validation accepted final {name} authority; preparation_succeeded={}, security_changed={}",
            prepared.is_ok(),
            before != after
        );
        assert!(
            prepared.is_err(),
            "preparation accepted final {name} authority"
        );
        assert_eq!(
            after, before,
            "preparation repaired final {name} authority instead of rejecting"
        );
        assert_eq!(
            std::fs::read(final_directory.join("sentinel")).unwrap(),
            b"final directory sentinel"
        );
        let entries: Vec<_> = std::fs::read_dir(&final_directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(entries, [std::ffi::OsString::from("sentinel")]);
    }
}

#[test]
fn native_authority_parent_delete_child_is_rejected_without_writes() {
    assert_native_edge(EdgeSide::Parent, 0x40, false);
}

#[test]
fn native_authority_child_delete_is_rejected_without_writes() {
    assert_native_edge(EdgeSide::Child, 0x10000, false);
}

#[test]
fn native_authority_child_write_dac_is_rejected_without_writes() {
    assert_native_edge(EdgeSide::Child, 0x40000, false);
}

#[test]
fn native_authority_child_write_owner_is_rejected_without_writes() {
    assert_native_edge(EdgeSide::Child, 0x80000, false);
}

fn assert_native_edge(side: EdgeSide, rights: u32, accepted: bool) {
    let root = tempfile::tempdir().unwrap();
    let owned = root.path().join("owned");
    let parent = owned.join("parent");
    let child = parent.join("child");
    for path in [&owned, &parent, &child] {
        crate::dashboard::audit::create_private_dir_exclusive(path).unwrap();
    }
    std::fs::write(parent.join("sentinel"), b"parent sentinel").unwrap();
    std::fs::write(child.join("sentinel"), b"child sentinel").unwrap();
    set_fixture_extra_rights(
        match side {
            EdgeSide::Parent => &parent,
            EdgeSide::Child | EdgeSide::Final => &child,
        },
        rights,
    );
    let parent_security = security_snapshot(&parent);
    let child_security = security_snapshot(&child);
    let requested = child.join("missing").join("identity");
    let validated = crate::state_paths::validate_state_directory(&requested);
    if accepted {
        assert_eq!(
            validated.unwrap(),
            requested,
            "add-sibling rights must not imply child replacement"
        );
    } else {
        assert!(
            validated.is_err(),
            "native descriptor granted untrusted replacement authority"
        );
        assert!(crate::state_paths::prepare_private_state_directory(&requested).is_err());
    }
    assert!(!child.join("missing").exists());
    assert_eq!(
        security_snapshot(&parent),
        parent_security,
        "walker changed parent security"
    );
    assert_eq!(
        security_snapshot(&child),
        child_security,
        "walker changed child security"
    );
    assert_eq!(
        std::fs::read(parent.join("sentinel")).unwrap(),
        b"parent sentinel"
    );
    assert_eq!(
        std::fs::read(child.join("sentinel")).unwrap(),
        b"child sentinel"
    );
}

#[derive(Clone, Copy)]
enum Winner {
    File,
    Link,
    InsecureDirectory,
    PrivateDirectory,
}

#[test]
fn native_creation_collision_file_is_rejected_without_mutation() {
    assert_collision(Winner::File);
}

#[test]
fn native_creation_collision_link_is_rejected_without_mutation() {
    assert_collision(Winner::Link);
}

#[test]
fn native_creation_collision_insecure_directory_is_rejected_without_tightening() {
    assert_collision(Winner::InsecureDirectory);
}

#[test]
fn native_creation_collision_private_directory_is_revalidated_and_accepted() {
    assert_collision(Winner::PrivateDirectory);
}

fn assert_collision(kind: Winner) {
    let root = tempfile::tempdir().unwrap();
    let owned = root.path().join("owned");
    let target = owned.join("target");
    crate::dashboard::audit::create_private_dir_exclusive(&owned).unwrap();
    crate::dashboard::audit::create_private_dir_exclusive(&target).unwrap();
    std::fs::write(target.join("sentinel"), b"target sentinel").unwrap();
    let winner = owned.join("winner");
    let requested = winner.join("identity");
    let owner_security = security_snapshot(&owned);
    let mut injected = false;
    let mut winner_security = None;
    let mut winner_link = None;
    let result = walk_with_creator(&requested, WalkMode::Prepare, &mut |candidate| {
        if injected {
            return crate::dashboard::audit::create_private_dir_exclusive(candidate)
                .map_err(audit_error);
        }
        assert_eq!(candidate, winner);
        assert!(
            !candidate.exists(),
            "creation seam did not follow an observed missing child"
        );
        injected = true;
        match kind {
            Winner::File => std::fs::write(candidate, b"winning file bytes").unwrap(),
            Winner::Link => {
                std::os::windows::fs::symlink_dir(&target, candidate)
                    .expect("fixture requires actual Windows directory symlink permission");
                winner_link = Some(std::fs::read_link(candidate).unwrap());
            }
            Winner::InsecureDirectory | Winner::PrivateDirectory => {
                // Exclusive creation never repairs an existing winner. Only our
                // newly created fixture directory receives the deliberate bad ACL.
                crate::dashboard::audit::create_private_dir_exclusive(candidate).unwrap();
                std::fs::write(candidate.join("sentinel"), b"winning directory bytes").unwrap();
                if matches!(kind, Winner::InsecureDirectory) {
                    set_fixture_extra_rights(candidate, 0x40000);
                }
                winner_security = Some(security_snapshot(candidate));
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "fixture creation collision",
        ))
    });
    assert!(
        injected,
        "test never reached the real missing-child creation branch"
    );
    match kind {
        Winner::PrivateDirectory => {
            assert_eq!(result.unwrap(), requested);
            assert!(requested.is_dir());
        }
        _ => {
            assert!(result.is_err(), "invalid collision winner was accepted");
            assert!(
                !requested.exists(),
                "invalid collision created a descendant"
            );
        }
    }
    match kind {
        Winner::File => assert_eq!(std::fs::read(&winner).unwrap(), b"winning file bytes"),
        Winner::Link => {
            assert!(
                std::fs::symlink_metadata(&winner)
                    .unwrap()
                    .file_type()
                    .is_symlink()
            );
            assert_eq!(std::fs::read_link(&winner).unwrap(), winner_link.unwrap());
        }
        _ => {
            assert_eq!(
                security_snapshot(&winner),
                winner_security.unwrap(),
                "walker tightened collision winner"
            );
            assert_eq!(
                std::fs::read(winner.join("sentinel")).unwrap(),
                b"winning directory bytes"
            );
        }
    }
    assert_eq!(security_snapshot(&owned), owner_security);
    assert_eq!(
        std::fs::read(target.join("sentinel")).unwrap(),
        b"target sentinel"
    );
    assert!(!target.join("identity").exists());
}

#[test]
fn native_creation_propagates_other_errors_without_creating_or_tightening() {
    let root = tempfile::tempdir().unwrap();
    let owned = root.path().join("owned");
    crate::dashboard::audit::create_private_dir_exclusive(&owned).unwrap();
    std::fs::write(owned.join("sentinel"), b"unchanged creation fixture").unwrap();
    let before = security_snapshot(&owned);
    let missing = owned.join("missing");
    let mut entered = false;
    let error = walk_with_creator(
        &missing.join("identity"),
        WalkMode::Prepare,
        &mut |candidate| {
            assert_eq!(candidate, missing);
            entered = true;
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "fixture create denied",
            ))
        },
    )
    .unwrap_err();
    assert!(entered);
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(error.to_string(), "fixture create denied");
    assert!(!missing.exists());
    assert_eq!(security_snapshot(&owned), before);
    assert_eq!(
        std::fs::read(owned.join("sentinel")).unwrap(),
        b"unchanged creation fixture"
    );
}

fn set_fixture_extra_rights(path: &Path, mask: u32) {
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        SetNamedSecurityInfoW,
    };
    use windows_sys::Win32::Security::{
        GetSecurityDescriptorDacl, PROTECTED_DACL_SECURITY_INFORMATION,
    };
    let current = current_user_sid().unwrap();
    let sddl = format!("D:P(A;;FA;;;{current})(A;;FA;;;SY)(A;;{mask:#x};;;WD)");
    let text: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
    let mut descriptor = std::ptr::null_mut();
    assert_ne!(
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        },
        0
    );
    let _descriptor = Descriptor(descriptor);
    let mut present = 0;
    let mut defaulted = 0;
    let mut dacl = std::ptr::null_mut();
    assert_ne!(
        unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) },
        0
    );
    assert_ne!(present, 0);
    assert!(!dacl.is_null());
    let mut name: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    assert_eq!(
        unsafe {
            SetNamedSecurityInfoW(
                name.as_mut_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                dacl,
                std::ptr::null_mut(),
            )
        },
        0
    );
}

fn security_snapshot(path: &Path) -> String {
    use windows_sys::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, SDDL_REVISION_1,
    };
    let directory = open_directory(path, &current_user_sid().unwrap()).unwrap();
    let mut descriptor = std::ptr::null_mut();
    assert_eq!(
        unsafe {
            GetSecurityInfo(
                directory._file.as_raw_handle().cast(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut descriptor,
            )
        },
        0
    );
    let _descriptor = Descriptor(descriptor);
    let mut text = std::ptr::null_mut();
    assert_ne!(
        unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor,
                SDDL_REVISION_1,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut text,
                std::ptr::null_mut(),
            )
        },
        0
    );
    let _text = Descriptor(text.cast());
    let mut length = 0;
    while unsafe { *text.add(length) } != 0 {
        length += 1;
    }
    String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) }).unwrap()
}

#[test]
fn windows_component_grammar_rejects_normalized_names_before_missing_suffix_creation() {
    let root = tempfile::tempdir().unwrap();
    let owned = root.path().join("owned");
    crate::dashboard::audit::create_private_dir(&owned).unwrap();
    std::fs::write(owned.join("sentinel"), b"untouched grammar fixture").unwrap();
    // Canonicalize only this existing owned fixture to construct independent
    // normal and verbatim spellings; never canonicalize a requested test suffix.
    let verbatim = owned.canonicalize().unwrap();
    let normal = PathBuf::from(verbatim.to_str().unwrap().strip_prefix(r"\\?\").unwrap());
    for base in [&normal, &verbatim] {
        for name in [
            ".. ",
            "child.",
            "child ",
            "name:stream",
            "control\u{1}",
            "nul\0",
            "CON",
            "con.txt",
            "PRN",
            "AUX",
            "NUL",
            "COM1",
            "LPT9",
            "lpt1.log",
            "COM¹",
            "COM².txt",
            "COM³",
            "LPT¹",
            "lpt².log",
            "LPT³",
            "less<than",
            "greater>than",
            "double\"quote",
            "pipe|name",
            "question?mark",
            "star*name",
        ] {
            let requested = base.join("missing").join(name).join("escape");
            assert!(
                crate::state_paths::validate_state_directory(&requested).is_err(),
                "read-only validation accepted Win32-normalized/device suffix {name:?} in {}",
                base.display()
            );
            assert!(
                crate::state_paths::prepare_private_state_directory(&requested).is_err(),
                "preparation accepted Win32-normalized/device suffix {name:?}"
            );
            assert!(
                !owned.join("missing").exists(),
                "preparation created ancestors before rejecting suffix {name:?}"
            );
            assert_eq!(
                std::fs::read(owned.join("sentinel")).unwrap(),
                b"untouched grammar fixture"
            );
        }
    }
}

#[test]
fn windows_component_grammar_accepts_unicode_and_dotfile_names() {
    let root = tempfile::tempdir().unwrap();
    let owned = root.path().join("owned");
    crate::dashboard::audit::create_private_dir(&owned).unwrap();
    let requested = owned
        .join("Überblick 日本語")
        .join(".config")
        .join("identity");
    assert_eq!(
        crate::state_paths::validate_state_directory(&requested).unwrap(),
        requested
    );
    assert!(!owned.join("Überblick 日本語").exists());
    assert_eq!(
        crate::state_paths::prepare_private_state_directory(&requested).unwrap(),
        requested
    );
    assert!(requested.is_dir());
}

#[test]
fn windows_component_grammar_rejects_embedded_verbatim_slash_before_creation() {
    let root = tempfile::tempdir().unwrap();
    let owned = root.path().join("owned");
    crate::dashboard::audit::create_private_dir(&owned).unwrap();
    let verbatim = owned.canonicalize().unwrap();
    let mut requested = verbatim.as_os_str().to_os_string();
    requested.push(r"\missing\child/other\identity");
    let requested = PathBuf::from(requested);
    assert!(
        requested
            .components()
            .any(|component| matches!(component, Component::Normal(name) if name == "child/other")),
        "fixture must retain slash inside a verbatim normal component"
    );
    assert!(
        crate::state_paths::validate_state_directory(&requested).is_err(),
        "verbatim embedded slash was accepted by read-only validation"
    );
    assert!(crate::state_paths::prepare_private_state_directory(&requested).is_err());
    assert!(!owned.join("missing").exists());

    let normal = PathBuf::from(verbatim.to_str().unwrap().strip_prefix(r"\\?\").unwrap());
    let normal_requested = normal.join("missing").join("child/other").join("identity");
    assert!(
        crate::state_paths::validate_state_directory(&normal_requested).is_ok(),
        "ordinary slash separators should remain supported"
    );
    assert!(!owned.join("missing").exists());
}

#[test]
fn parent_replacement_rights_are_distinct_from_adding_siblings() {
    assert!(edge_ace_is_safe(EdgeSide::Parent, 0, 0, 0x2 | 0x4, false));
    for mask in [0x40, 0x40000, 0x80000, 0x10000000] {
        assert!(
            !edge_ace_is_safe(EdgeSide::Parent, 0, 0, mask, false),
            "accepted untrusted parent replacement right {mask:#x}"
        );
    }
}

#[test]
fn child_delete_or_security_rewrite_is_rejected_independently_of_parent() {
    for mask in [0x10000, 0x40000, 0x80000, 0x10000000] {
        assert!(
            !edge_ace_is_safe(EdgeSide::Child, 0, 0, mask, false),
            "accepted untrusted child replacement right {mask:#x}"
        );
    }
}

#[test]
fn inherit_only_aces_do_not_authorize_replacement_of_current_object() {
    assert!(edge_ace_is_safe(
        EdgeSide::Parent,
        0,
        0x8,
        0x10000000,
        false
    ));
    assert!(edge_ace_is_safe(EdgeSide::Child, 0, 0x8, 0x10000000, false));
}

#[test]
fn unfamiliar_dangerous_allow_ace_fails_closed() {
    assert!(!edge_ace_is_safe(EdgeSide::Parent, 5, 0, 0x40000, false));
    assert!(!edge_ace_is_safe(EdgeSide::Child, 9, 0, 0x10000, false));
}

#[test]
fn system_owned_directory_with_current_user_control_remains_trusted() {
    let current_user = "S-1-5-21-1-2-3-1001";
    assert!(owner_is_trusted("S-1-5-18", current_user));
    assert!(owner_is_trusted(current_user, current_user));
    assert!(owner_is_trusted("S-1-5-32-544", current_user));
    assert!(!owner_is_trusted("S-1-5-21-9-9-9-1002", current_user));
    assert!(edge_ace_is_safe(EdgeSide::Parent, 0, 0, 0x10000000, true));
    assert!(edge_ace_is_safe(EdgeSide::Child, 0, 0, 0x10000000, true));
}
