use super::model::{PolicyOrigin, PolicyRule};
use crate::secure_transport::SecureTransport;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ManagedPolicyLoadError {
    InsecureOwnerOrPermissions,
    InvalidBundle,
    InvalidSignature,
    NonManagedRule,
    SignerNotAuthorized,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyAdminTrustEntry {
    pub signer_id: String,
    pub certificate_der: Vec<u8>,
    pub role: String,
    #[serde(default)]
    pub revoked: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyAdminTrustFile {
    pub signers: Vec<PolicyAdminTrustEntry>,
}

pub struct PolicyAdminTrustStore {
    signers: HashMap<String, Vec<u8>>,
    allowed_windows_admin_sids: HashSet<String>,
}

impl PolicyAdminTrustStore {
    pub fn load(
        path: &Path,
        allowed_windows_admin_sids: impl IntoIterator<Item = String>,
    ) -> Result<Self, ManagedPolicyLoadError> {
        let allowed_windows_admin_sids: HashSet<_> = allowed_windows_admin_sids
            .into_iter()
            .map(|sid| sid.to_ascii_lowercase())
            .collect();
        ensure_restrictive_file(path, &allowed_windows_admin_sids)?;
        let file: PolicyAdminTrustFile = serde_json::from_slice(
            &fs::read(path).map_err(|_| ManagedPolicyLoadError::InvalidBundle)?,
        )
        .map_err(|_| ManagedPolicyLoadError::InvalidBundle)?;
        let mut signers = HashMap::new();
        for entry in file.signers {
            if entry.role != "policy_signer" || entry.revoked || entry.signer_id.is_empty() {
                continue;
            }
            if signers
                .insert(entry.signer_id, entry.certificate_der)
                .is_some()
            {
                return Err(ManagedPolicyLoadError::InvalidBundle);
            }
        }
        Ok(Self {
            signers,
            allowed_windows_admin_sids,
        })
    }
}

pub struct ManagedPolicyStore;

impl ManagedPolicyStore {
    pub fn load(
        path: &Path,
        admin_trust: &PolicyAdminTrustStore,
    ) -> Result<VerifiedManagedPolicyBundle, ManagedPolicyLoadError> {
        ensure_restrictive_file(path, &admin_trust.allowed_windows_admin_sids)?;
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
        let certificate = admin_trust
            .signers
            .get(&bundle.signer_id)
            .ok_or(ManagedPolicyLoadError::SignerNotAuthorized)?;
        SecureTransport::verify_certificate_signature(
            &bundle.signer_id,
            certificate,
            &digest,
            &bundle.signature,
        )
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
fn ensure_restrictive_file(
    path: &Path,
    _allowed_admin_sids: &HashSet<String>,
) -> Result<(), ManagedPolicyLoadError> {
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
fn ensure_restrictive_file(
    path: &Path,
    allowed_admin_sids: &HashSet<String>,
) -> Result<(), ManagedPolicyLoadError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| ManagedPolicyLoadError::InsecureOwnerOrPermissions)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ManagedPolicyLoadError::InsecureOwnerOrPermissions);
    }
    if !windows_acl_is_restrictive(path, allowed_admin_sids) {
        return Err(ManagedPolicyLoadError::InsecureOwnerOrPermissions);
    }
    Ok(())
}

#[cfg(windows)]
fn windows_acl_is_restrictive(path: &Path, configured: &HashSet<String>) -> bool {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
        DACL_SECURITY_INFORMATION, GetAce, GetAclInformation, OWNER_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, PSID,
    };
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut owner: PSID = std::ptr::null_mut();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let status = unsafe {
        GetNamedSecurityInfoW(
            wide.as_mut_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            (&mut dacl as *mut *mut ACL).cast(),
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 || owner.is_null() || descriptor.is_null() {
        return false;
    }
    let mut text = std::ptr::null_mut();
    let converted = unsafe { ConvertSidToStringSidW(owner, &mut text) };
    let owner_sid = if converted == 0 || text.is_null() {
        String::new()
    } else {
        let mut length = 0;
        while unsafe { *text.add(length) } != 0 {
            length += 1;
        }
        String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, length) })
            .to_ascii_lowercase()
    };
    if !text.is_null() {
        unsafe { LocalFree(text as _) };
    }
    let mut allowed = configured.clone();
    allowed.insert(owner_sid);
    allowed.insert("s-1-5-18".into());
    let dangerous = 0x4000_0000_u32
        | 0x1000_0000
        | 0x0001_0000
        | 0x0004_0000
        | 0x0008_0000
        | 0x0000_0002
        | 0x0000_0004
        | 0x0000_0100;
    let mut info: ACL_SIZE_INFORMATION = unsafe { std::mem::zeroed() };
    let info_ok = !dacl.is_null()
        && unsafe {
            GetAclInformation(
                dacl,
                &mut info as *mut _ as _,
                std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
        } != 0;
    let mut safe = info_ok;
    for index in 0..info.AceCount {
        let mut raw = std::ptr::null_mut();
        if unsafe { GetAce(dacl, index, &mut raw) } == 0 {
            safe = false;
            break;
        }
        let ace = unsafe { &*(raw as *const ACCESS_ALLOWED_ACE) };
        if ace.Header.AceType == 0 && ace.Mask & dangerous != 0 {
            let sid = (&ace.SidStart as *const u32).cast_mut().cast();
            if let Some(sid) = sid_string(sid) {
                if !acl_writer_allowed(&sid, &allowed) {
                    safe = false;
                    break;
                }
            } else {
                safe = false;
                break;
            }
        }
    }
    unsafe { LocalFree(descriptor as _) };
    safe
}

#[cfg(windows)]
fn acl_writer_allowed(sid: &str, allowed: &HashSet<String>) -> bool {
    allowed.contains(&sid.to_ascii_lowercase())
}

#[cfg(windows)]
fn sid_string(sid: windows_sys::Win32::Security::PSID) -> Option<String> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    let mut text = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 || text.is_null() {
        return None;
    }
    let mut length = 0;
    while unsafe { *text.add(length) } != 0 {
        length += 1;
    }
    let value = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, length) })
        .to_ascii_lowercase();
    unsafe { LocalFree(text as _) };
    Some(value)
}

#[cfg(all(test, windows))]
mod windows_acl_tests {
    use super::acl_writer_allowed;
    use std::collections::HashSet;

    #[test]
    fn dangerous_well_known_and_foreign_writers_are_never_implicit_admins() {
        let allowed = HashSet::from([
            "s-1-5-21-1-2-3-1001".to_owned(),
            "s-1-5-18".to_owned(),
            "s-1-5-32-544".to_owned(),
        ]);
        assert!(acl_writer_allowed("S-1-5-21-1-2-3-1001", &allowed));
        assert!(acl_writer_allowed("S-1-5-18", &allowed));
        assert!(acl_writer_allowed("S-1-5-32-544", &allowed));
        for sid in ["S-1-1-0", "S-1-5-11", "S-1-5-32-545", "S-1-5-21-9-9-9-2001"] {
            assert!(!acl_writer_allowed(sid, &allowed));
        }
    }
}
