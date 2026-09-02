use super::model::{PolicyOrigin, PolicyRule};
use crate::secure_transport::SecureTransport;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ManagedPolicyLoadError {
    InsecureOwnerOrPermissions,
    InvalidBundle,
    InvalidSignature,
    NonManagedRule,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedPolicyFile {
    pub signer_id: String,
    pub rules: Vec<PolicyRule>,
    pub signature: Vec<u8>,
}

pub struct VerifiedManagedPolicyBundle {
    rules: Vec<PolicyRule>,
}

impl VerifiedManagedPolicyBundle {
    pub(crate) fn into_rules(self) -> Vec<PolicyRule> {
        self.rules
    }
}

pub struct ManagedPolicyStore;

impl ManagedPolicyStore {
    pub fn load(
        path: &Path,
        identity: &SecureTransport,
    ) -> Result<VerifiedManagedPolicyBundle, ManagedPolicyLoadError> {
        ensure_restrictive_file(path)?;
        let bytes = fs::read(path).map_err(|_| ManagedPolicyLoadError::InvalidBundle)?;
        let bundle: ManagedPolicyFile =
            serde_json::from_slice(&bytes).map_err(|_| ManagedPolicyLoadError::InvalidBundle)?;
        if bundle
            .rules
            .iter()
            .any(|rule| rule.origin != PolicyOrigin::Managed)
        {
            return Err(ManagedPolicyLoadError::NonManagedRule);
        }
        let digest = canonical_rules_digest(&bundle.rules)?;
        identity
            .verify_peer_signature(&bundle.signer_id, &digest, &bundle.signature)
            .map_err(|_| ManagedPolicyLoadError::InvalidSignature)?;
        Ok(VerifiedManagedPolicyBundle {
            rules: bundle.rules,
        })
    }
}

pub fn canonical_rules_digest(rules: &[PolicyRule]) -> Result<[u8; 32], ManagedPolicyLoadError> {
    let mut canonical = rules.to_vec();
    canonical.sort_by(|left, right| left.id.cmp(&right.id));
    for rule in &mut canonical {
        rule.resources.sort_unstable();
        rule.resources.dedup();
    }
    let bytes =
        serde_json::to_vec(&canonical).map_err(|_| ManagedPolicyLoadError::InvalidBundle)?;
    Ok(Sha256::digest(bytes).into())
}

#[cfg(unix)]
fn ensure_restrictive_file(path: &Path) -> Result<(), ManagedPolicyLoadError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| ManagedPolicyLoadError::InsecureOwnerOrPermissions)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(ManagedPolicyLoadError::InsecureOwnerOrPermissions);
    }
    Ok(())
}

#[cfg(windows)]
fn ensure_restrictive_file(path: &Path) -> Result<(), ManagedPolicyLoadError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| ManagedPolicyLoadError::InsecureOwnerOrPermissions)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ManagedPolicyLoadError::InsecureOwnerOrPermissions);
    }
    if windows_owner_sid(path).as_deref() != current_windows_sid().as_deref() {
        return Err(ManagedPolicyLoadError::InsecureOwnerOrPermissions);
    }
    let output = std::process::Command::new("icacls")
        .arg(path)
        .output()
        .map_err(|_| ManagedPolicyLoadError::InsecureOwnerOrPermissions)?;
    if !output.status.success() {
        return Err(ManagedPolicyLoadError::InsecureOwnerOrPermissions);
    }
    let acl = String::from_utf8_lossy(&output.stdout).to_ascii_lowercase();
    if acl.contains("everyone:") || acl.contains("authenticated users:") || acl.contains("users:") {
        return Err(ManagedPolicyLoadError::InsecureOwnerOrPermissions);
    }
    Ok(())
}

#[cfg(windows)]
fn current_windows_sid() -> Option<String> {
    let output = std::process::Command::new("whoami")
        .args(["/user", "/fo", "csv", "/nh"])
        .output()
        .ok()?;
    let line = String::from_utf8_lossy(&output.stdout);
    line.split(',')
        .nth(1)
        .map(|value| value.trim().trim_matches('"').to_ascii_lowercase())
}

#[cfg(windows)]
fn windows_owner_sid(path: &Path) -> Option<String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID};
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut owner: PSID = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let status = unsafe {
        GetNamedSecurityInfoW(
            wide.as_mut_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 || owner.is_null() || descriptor.is_null() {
        return None;
    }
    let mut text = std::ptr::null_mut();
    let converted = unsafe { ConvertSidToStringSidW(owner, &mut text) };
    let result = if converted == 0 || text.is_null() {
        None
    } else {
        let mut length = 0;
        while unsafe { *text.add(length) } != 0 {
            length += 1;
        }
        Some(
            String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, length) })
                .to_ascii_lowercase(),
        )
    };
    if !text.is_null() {
        unsafe { LocalFree(text as _) };
    }
    unsafe { LocalFree(descriptor as _) };
    result
}
