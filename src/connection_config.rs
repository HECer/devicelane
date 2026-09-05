use serde::{Deserialize, Serialize};
use std::fs::{self, Metadata, OpenOptions};
use std::io::{ErrorKind, Read};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;

const MAX_BYTES: u64 = 4096;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ConnectionConfig {
    version: u16,
    registry_address: String,
    registry_peer_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireConfig {
    version: u16,
    registry_address: String,
    registry_peer_id: String,
}

impl<'de> Deserialize<'de> for ConnectionConfig {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = WireConfig::deserialize(deserializer)?;
        if wire.version != 1 {
            return Err(serde::de::Error::custom("unsupported connection version"));
        }
        Self::new(&wire.registry_address, &wire.registry_peer_id)
            .map_err(|_| serde::de::Error::custom("invalid connection settings"))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionConfigError {
    InvalidFile,
    Unavailable,
    TooLarge,
    InvalidFormat,
    UnsupportedVersion,
    InvalidEndpoint,
    InvalidPeer,
}

impl ConnectionConfig {
    pub fn new(address: &str, peer: &str) -> Result<Self, ConnectionConfigError> {
        if !valid_endpoint(address) {
            return Err(ConnectionConfigError::InvalidEndpoint);
        }
        if peer.len() > 128 || crate::secure_transport::peer_server_name(peer).is_err() {
            return Err(ConnectionConfigError::InvalidPeer);
        }
        Ok(Self {
            version: 1,
            registry_address: address.into(),
            registry_peer_id: peer.into(),
        })
    }

    pub fn registry_address(&self) -> &str {
        &self.registry_address
    }
    pub fn registry_peer_id(&self) -> &str {
        &self.registry_peer_id
    }

    /// Writes public settings without changing identity or trust. The caller must
    /// authorize/audit the mutation and serialize writers for this identity.
    /// On an error after replacement, reload before deciding the effective state.
    pub fn save(&self, identity: &Path) -> Result<(), ConnectionConfigError> {
        if !identity.is_absolute() {
            return Err(ConnectionConfigError::InvalidFile);
        }
        if matches!(fs::symlink_metadata(identity), Err(error) if error.kind() == ErrorKind::NotFound)
        {
            crate::dashboard::audit::create_private_dir(identity)
                .map_err(|_| ConnectionConfigError::Unavailable)?;
        }
        let directory =
            fs::symlink_metadata(identity).map_err(|_| ConnectionConfigError::Unavailable)?;
        if !directory.is_dir() || !safe_metadata(&directory) {
            return Err(ConnectionConfigError::InvalidFile);
        }
        let path = identity.join("connection.json");
        match fs::symlink_metadata(&path) {
            Ok(metadata) if !metadata.is_file() || !safe_metadata(&metadata) => {
                return Err(ConnectionConfigError::InvalidFile);
            }
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(_) => return Err(ConnectionConfigError::Unavailable),
        }
        let bytes = serde_json::to_vec(self).map_err(|_| ConnectionConfigError::InvalidFormat)?;
        crate::dashboard::audit::write_private_atomic(&path, &bytes)
            .map_err(|_| ConnectionConfigError::Unavailable)
    }

    /// Reads public settings only; never creates an identity or changes peer trust.
    pub fn load(identity: &Path) -> Result<Option<Self>, ConnectionConfigError> {
        if !identity.is_absolute() {
            return Err(ConnectionConfigError::InvalidFile);
        }
        let directory = match fs::symlink_metadata(identity) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(ConnectionConfigError::Unavailable),
        };
        if !directory.is_dir() || !safe_metadata(&directory) {
            return Err(ConnectionConfigError::InvalidFile);
        }
        let path = identity.join("connection.json");
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(ConnectionConfigError::Unavailable),
        };
        if !metadata.is_file() || !safe_metadata(&metadata) {
            return Err(ConnectionConfigError::InvalidFile);
        }
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
            options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        }
        let file = options
            .open(&path)
            .map_err(|_| ConnectionConfigError::Unavailable)?;
        let metadata = file
            .metadata()
            .map_err(|_| ConnectionConfigError::Unavailable)?;
        if !metadata.is_file() || !safe_metadata(&metadata) {
            return Err(ConnectionConfigError::InvalidFile);
        }
        let mut bytes = Vec::new();
        file.take(MAX_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| ConnectionConfigError::Unavailable)?;
        if bytes.len() as u64 > MAX_BYTES {
            return Err(ConnectionConfigError::TooLarge);
        }
        let wire: WireConfig =
            serde_json::from_slice(&bytes).map_err(|_| ConnectionConfigError::InvalidFormat)?;
        if wire.version != 1 {
            return Err(ConnectionConfigError::UnsupportedVersion);
        }
        Self::new(&wire.registry_address, &wire.registry_peer_id).map(Some)
    }
}

fn safe_metadata(metadata: &Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        metadata.uid() == unsafe { libc::geteuid() } && metadata.mode() & 0o022 == 0
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 == 0
    }
}

fn valid_endpoint(address: &str) -> bool {
    if address.len() > 260
        || !address.is_ascii()
        || address.bytes().any(|b| b.is_ascii_whitespace())
    {
        return false;
    }
    if let Ok(socket) = address.parse::<SocketAddr>() {
        return socket.port() != 0 && !socket.ip().is_unspecified() && !socket.ip().is_multicast();
    }
    let Some((host, port)) = address.rsplit_once(':') else {
        return false;
    };
    if port.is_empty()
        || !port.bytes().all(|b| b.is_ascii_digit())
        || port.parse::<u16>().ok().is_none_or(|p| p == 0)
    {
        return false;
    }
    if host.is_empty()
        || host.len() > 253
        || host.parse::<IpAddr>().is_ok()
        || host.bytes().all(|b| b.is_ascii_digit() || b == b'.')
    {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.as_bytes()[0].is_ascii_alphanumeric()
            && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}
