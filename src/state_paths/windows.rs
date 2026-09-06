use super::{WalkMode, audit_error, insecure};
use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::MetadataExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Component, Path, PathBuf, Prefix};
use windows_sys::Win32::Foundation::{GetLastError, INVALID_HANDLE_VALUE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, GetSecurityInfo, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    ACL, ACL_SIZE_INFORMATION, AclSizeInformation, DACL_SECURITY_INFORMATION, GetAce,
    GetAclInformation, GetTokenInformation, IsValidSid, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE,
    OPEN_EXISTING, READ_CONTROL,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

const TRUSTED_INSTALLER: &str = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

#[derive(Clone, Copy)]
enum EdgeSide {
    Parent,
    Child,
    Final,
}

struct Directory {
    // No share-delete: retain each verified ancestor while opening/creating its
    // child, including during final private-directory preparation.
    _file: File,
    owner: String,
    parent_safe: bool,
    child_safe: bool,
    final_safe: bool,
}

pub(super) fn walk(path: &Path, mode: WalkMode) -> io::Result<PathBuf> {
    walk_with_creator(path, mode, &mut |candidate| {
        crate::dashboard::audit::create_private_dir_exclusive(candidate).map_err(audit_error)
    })
}

fn walk_with_creator(
    path: &Path,
    mode: WalkMode,
    creator: &mut impl FnMut(&Path) -> io::Result<()>,
) -> io::Result<PathBuf> {
    let mut components = path.components();
    let Some(Component::Prefix(prefix)) = components.next() else {
        return Err(insecure());
    };
    if !matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
        || components.next() != Some(Component::RootDir)
    {
        return Err(insecure());
    }
    let mut resolved = PathBuf::from(prefix.as_os_str());
    resolved.push(std::path::MAIN_SEPARATOR.to_string());
    let mut names = Vec::new();
    for component in components {
        match component {
            Component::Normal(name) => {
                if !valid_component(name) {
                    return Err(insecure());
                }
                names.push(name.to_owned());
            }
            Component::CurDir => {}
            _ => return Err(insecure()),
        }
    }
    let current_user = current_user_sid()?;
    let root = open_directory(&resolved, &current_user)?;
    // The volume root is the OS anchor, not an ordinary replaceable child.
    let mut directories = vec![root];
    for (index, name) in names.iter().enumerate() {
        if !directories.last().unwrap().parent_safe {
            return Err(insecure());
        }
        let candidate = resolved.join(name);
        let directory = match open_directory(&candidate, &current_user) {
            Ok(directory) => directory,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if !mode.prepares() {
                    for remaining in &names[index..] {
                        resolved.push(remaining);
                    }
                    return Ok(resolved);
                }
                let collision = match creator(&candidate) {
                    Ok(()) => false,
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => true,
                    Err(error) => return Err(error),
                };
                let directory = open_directory(&candidate, &current_user)?;
                if collision {
                    // Never repair a racing object. Validate both edge authority
                    // and existing private security from the exact opened file.
                    if !directory.owner.eq_ignore_ascii_case(&current_user)
                        || !crate::dashboard::managed_policy::windows_file_acl_is_restrictive(
                            &directory._file,
                            &Default::default(),
                        )
                    {
                        return Err(insecure());
                    }
                }
                directory
            }
            Err(error) => return Err(error),
        };
        if !directory.child_safe {
            return Err(insecure());
        }
        directories.push(directory);
        resolved = candidate;
    }
    if !names.is_empty() && !directories.last().unwrap().final_safe {
        return Err(insecure());
    }
    if mode.requires_private()
        && (names.is_empty()
            || !directories
                .last()
                .unwrap()
                .owner
                .eq_ignore_ascii_case(&current_user))
    {
        return Err(insecure());
    }
    if mode.prepares() {
        // All checked ancestors and the final directory remain pinned against
        // replacement. Tightening applies only to this selected current-user root.
        crate::dashboard::audit::create_private_dir(&resolved).map_err(audit_error)?;
        let file = &directories.last().unwrap()._file;
        let inspected = inspect_directory(file.try_clone()?, &current_user)?;
        if !inspected.final_safe
            || !crate::dashboard::managed_policy::windows_file_acl_is_restrictive(
                file,
                &Default::default(),
            )
        {
            return Err(insecure());
        }
    }
    Ok(resolved)
}

fn valid_component(name: &std::ffi::OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    if name.is_empty()
        || name.ends_with(['.', ' '])
        || name.chars().any(|value| {
            value <= '\u{1f}'
                || matches!(value, '<' | '>' | ':' | '"' | '|' | '?' | '*' | '/' | '\\')
        })
    {
        return false;
    }
    // Device names remain reserved with extensions and in verbatim paths for
    // this boundary. Superscript digits are Win32 device-name aliases as well.
    let basename = name
        .split('.')
        .next()
        .unwrap_or("")
        .trim_end_matches(' ')
        .to_ascii_uppercase();
    if matches!(basename.as_str(), "CON" | "PRN" | "AUX" | "NUL") {
        return false;
    }
    for prefix in ["COM", "LPT"] {
        if let Some(number) = basename.strip_prefix(prefix)
            && matches!(
                number,
                "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        {
            return false;
        }
    }
    true
}

fn open_directory(path: &Path, current_user: &str) -> io::Result<Directory> {
    let name: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            FILE_READ_ATTRIBUTES | READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        let error = unsafe { GetLastError() };
        return Err(io::Error::from_raw_os_error(error as i32));
    }
    let file = unsafe { File::from_raw_handle(handle.cast()) };
    inspect_directory(file, current_user)
}

fn inspect_directory(file: File, current_user: &str) -> io::Result<Directory> {
    let metadata = file.metadata()?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(insecure());
    }
    let mut owner: PSID = std::ptr::null_mut();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle().cast(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    let _descriptor = Descriptor(descriptor);
    if status != 0 || owner.is_null() || descriptor.is_null() {
        return Err(insecure());
    }
    let owner = sid_string(owner).ok_or_else(insecure)?;
    if !owner_is_trusted(&owner, current_user) {
        return Err(insecure());
    }
    let parent_safe = acl_is_safe(dacl, current_user, EdgeSide::Parent);
    let child_safe = acl_is_safe(dacl, current_user, EdgeSide::Child);
    let final_safe = acl_is_safe(dacl, current_user, EdgeSide::Final);
    Ok(Directory {
        _file: file,
        owner,
        parent_safe,
        child_safe,
        final_safe,
    })
}

fn acl_is_safe(dacl: *mut ACL, current_user: &str, side: EdgeSide) -> bool {
    if dacl.is_null() {
        return false;
    }
    let mut info: ACL_SIZE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe {
        GetAclInformation(
            dacl,
            (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
    {
        return false;
    }
    let start = dacl as usize;
    let Some(end) = start.checked_add(info.AclBytesInUse as usize) else {
        return false;
    };
    for index in 0..info.AceCount {
        let mut raw = std::ptr::null_mut();
        if unsafe { GetAce(dacl, index, &mut raw) } == 0 || raw.is_null() {
            return false;
        }
        let address = raw as usize;
        if address < start || address.checked_add(4).is_none_or(|value| value > end) {
            return false;
        }
        let bytes = raw.cast::<u8>();
        let kind = unsafe { *bytes };
        let flags = unsafe { *bytes.add(1) };
        let size = unsafe { std::ptr::read_unaligned(bytes.add(2).cast::<u16>()) } as usize;
        if size < 4 || address.checked_add(size).is_none_or(|value| value > end) {
            return false;
        }
        if flags & 0x8 != 0 {
            continue;
        } // INHERIT_ONLY does not affect this object.
        // Denial/audit/label ACEs do not grant replacement authority. Unknown
        // kinds are inspected conservatively rather than assumed to be denials.
        if matches!(
            kind,
            1 | 2 | 3 | 6 | 7 | 8 | 10 | 12 | 13 | 14 | 15 | 16 | 17 | 18 | 19
        ) {
            continue;
        }
        if size < 8 {
            return false;
        }
        let mask = unsafe { std::ptr::read_unaligned(bytes.add(4).cast::<u32>()) };
        if !dangerous_rights(side, mask) {
            continue;
        }
        if kind != 0 || size < 16 {
            return false;
        }
        let sid = unsafe { bytes.add(8) };
        let subauthorities = unsafe { *sid.add(1) } as usize;
        if subauthorities > 15 || 8 + subauthorities * 4 > size - 8 {
            return false;
        }
        let trusted =
            sid_string(sid.cast()).is_some_and(|value| owner_is_trusted(&value, current_user));
        if !edge_ace_is_safe(side, kind, flags, mask, trusted) {
            return false;
        }
    }
    true
}

fn dangerous_rights(side: EdgeSide, mask: u32) -> bool {
    let replacement = match side {
        EdgeSide::Parent => 0x40,
        EdgeSide::Child => 0x10000,
        EdgeSide::Final => 0x2 | 0x4 | 0x10 | 0x100 | 0x40 | 0x10000 | 0x40000000,
    };
    mask & (replacement | 0x40000 | 0x80000 | 0x10000000) != 0
}

fn edge_ace_is_safe(
    side: EdgeSide,
    kind: u8,
    flags: u8,
    mask: u32,
    principal_trusted: bool,
) -> bool {
    if flags & 0x8 != 0 || !dangerous_rights(side, mask) {
        return true;
    }
    kind == 0 && principal_trusted
}

fn owner_is_trusted(owner: &str, current_user: &str) -> bool {
    [current_user, "S-1-5-18", "S-1-5-32-544", TRUSTED_INSTALLER]
        .iter()
        .any(|trusted| owner.eq_ignore_ascii_case(trusted))
}

fn sid_string(sid: PSID) -> Option<String> {
    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        return None;
    }
    let mut text = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 || text.is_null() {
        return None;
    }
    let _text = Descriptor(text.cast());
    let mut length = 0;
    while unsafe { *text.add(length) } != 0 {
        length += 1;
    }
    String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) }).ok()
}

fn current_user_sid() -> io::Result<String> {
    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = unsafe { OwnedHandle::from_raw_handle(token.cast()) };
    let mut required = 0;
    unsafe {
        GetTokenInformation(
            token.as_raw_handle().cast(),
            TokenUser,
            std::ptr::null_mut(),
            0,
            &mut required,
        )
    };
    if required == 0 {
        return Err(insecure());
    }
    let mut buffer = vec![0usize; (required as usize).div_ceil(std::mem::size_of::<usize>())];
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle().cast(),
            TokenUser,
            buffer.as_mut_ptr().cast(),
            required,
            &mut required,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    sid_string(user.User.Sid).ok_or_else(insecure)
}

struct Descriptor(PSECURITY_DESCRIPTOR);
impl Drop for Descriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

#[cfg(test)]
mod tests;
