use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::fmt;
use std::io::{BufRead, Write};
use std::path::Path;
#[cfg(unix)]
use std::{io, path::PathBuf};

pub const MAX_FRAME_BYTES: usize = 512 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalProtocolVersion {
    pub major: u16,
    pub minor: u16,
}

impl LocalProtocolVersion {
    pub const CURRENT: Self = Self { major: 1, minor: 0 };

    pub fn is_compatible(self) -> bool {
        self.major == Self::CURRENT.major
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "request", rename_all = "snake_case", deny_unknown_fields)]
pub enum LocalRequest {
    Status {
        version: LocalProtocolVersion,
    },
    PauseRemoteAccess {
        version: LocalProtocolVersion,
    },
    ResumeRemoteAccess {
        version: LocalProtocolVersion,
    },
    SetAutostart {
        version: LocalProtocolVersion,
        enabled: bool,
    },
    Diagnostics {
        version: LocalProtocolVersion,
    },
}

impl LocalRequest {
    pub fn version(&self) -> LocalProtocolVersion {
        match *self {
            Self::Status { version }
            | Self::PauseRemoteAccess { version }
            | Self::ResumeRemoteAccess { version }
            | Self::SetAutostart { version, .. }
            | Self::Diagnostics { version } => version,
        }
    }

    pub fn validate(&self) -> Result<(), LocalProtocolError> {
        self.version()
            .is_compatible()
            .then_some(())
            .ok_or(LocalProtocolError::IncompatibleVersion)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "type",
    content = "payload",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum LocalResponse {
    Snapshot(DaemonSnapshot),
    Acknowledged,
    Diagnostics(Vec<DiagnosticItem>),
    Error { code: String, message: String },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonSnapshot {
    pub public_identity: String,
    pub role: DaemonRole,
    pub endpoint: String,
    pub connection: ConnectionState,
    pub local_protocol: LocalProtocolVersion,
    pub remote_protocol: String,
    pub warnings: Vec<String>,
    pub remote_access_paused: bool,
    pub autostart: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DaemonRole {
    Workstation,
    Agent,
    Registry,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Degraded,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticItem {
    pub code: String,
    pub message: String,
    pub healthy: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LocalProtocolError {
    IncompatibleVersion,
    FrameTooLarge,
    InvalidFrame,
    Io,
    StatePathNotAbsolute,
    InvalidLocalEndpoint,
    Unauthorized,
}

impl fmt::Display for LocalProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}",
            match self {
                Self::IncompatibleVersion => "incompatible local protocol version",
                Self::FrameTooLarge => "local IPC frame exceeds 512 KiB",
                Self::InvalidFrame => "invalid local IPC frame",
                Self::Io => "local IPC I/O failed",
                Self::StatePathNotAbsolute => "daemon state paths must be absolute",
                Self::InvalidLocalEndpoint => "invalid local IPC endpoint",
                Self::Unauthorized => "local IPC peer is not authorized",
            }
        )
    }
}

impl std::error::Error for LocalProtocolError {}

pub fn read_frame<R: BufRead, T: DeserializeOwned>(
    reader: &mut R,
) -> Result<T, LocalProtocolError> {
    let mut frame = Vec::new();
    let mut limited = std::io::Read::take(reader, (MAX_FRAME_BYTES + 1) as u64);
    limited
        .read_until(b'\n', &mut frame)
        .map_err(|_| LocalProtocolError::Io)?;
    if frame.len() > MAX_FRAME_BYTES {
        return Err(LocalProtocolError::FrameTooLarge);
    }
    if frame.pop() != Some(b'\n') {
        return Err(LocalProtocolError::InvalidFrame);
    }
    serde_json::from_slice(&frame).map_err(|_| LocalProtocolError::InvalidFrame)
}

pub fn write_frame<W: Write, T: Serialize>(
    writer: &mut W,
    value: &T,
) -> Result<(), LocalProtocolError> {
    let mut frame = serde_json::to_vec(value).map_err(|_| LocalProtocolError::InvalidFrame)?;
    if frame.len() + 1 > MAX_FRAME_BYTES {
        return Err(LocalProtocolError::FrameTooLarge);
    }
    frame.push(b'\n');
    writer.write_all(&frame).map_err(|_| LocalProtocolError::Io)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PeerCredentials {
    Unix {
        uid: u32,
        gid: u32,
        pid: Option<u32>,
    },
    Windows {
        process_id: u32,
        user_sid: String,
    },
}

pub trait Authorizer: Send + Sync {
    fn authorize(&self, peer: &PeerCredentials) -> bool;
}

enum ExpectedUser {
    Unix(u32),
    Windows(String),
}

pub struct SameUserAuthorizer(ExpectedUser);

impl SameUserAuthorizer {
    pub fn unix(uid: u32) -> Self {
        Self(ExpectedUser::Unix(uid))
    }

    pub fn windows(user_sid: impl Into<String>) -> Self {
        Self(ExpectedUser::Windows(user_sid.into()))
    }
}

impl Authorizer for SameUserAuthorizer {
    fn authorize(&self, peer: &PeerCredentials) -> bool {
        match (&self.0, peer) {
            (ExpectedUser::Unix(expected), PeerCredentials::Unix { uid, .. }) => expected == uid,
            (ExpectedUser::Windows(expected), PeerCredentials::Windows { user_sid, .. }) => {
                !expected.is_empty() && expected == user_sid
            }
            _ => false,
        }
    }
}

pub struct DaemonState {
    snapshot: DaemonSnapshot,
    diagnostics: Vec<DiagnosticItem>,
}

impl DaemonState {
    pub fn new(snapshot: DaemonSnapshot, diagnostics: Vec<DiagnosticItem>) -> Self {
        Self {
            snapshot,
            diagnostics,
        }
    }

    pub fn snapshot(&self) -> &DaemonSnapshot {
        &self.snapshot
    }

    pub fn handle(&mut self, request: LocalRequest) -> Result<LocalResponse, LocalProtocolError> {
        request.validate()?;
        match request {
            LocalRequest::Status { .. } => Ok(LocalResponse::Snapshot(self.snapshot.clone())),
            LocalRequest::PauseRemoteAccess { .. } => {
                self.snapshot.remote_access_paused = true;
                Ok(LocalResponse::Acknowledged)
            }
            LocalRequest::ResumeRemoteAccess { .. } => {
                self.snapshot.remote_access_paused = false;
                Ok(LocalResponse::Acknowledged)
            }
            LocalRequest::SetAutostart { enabled, .. } => {
                self.snapshot.autostart = enabled;
                Ok(LocalResponse::Acknowledged)
            }
            LocalRequest::Diagnostics { .. } => {
                Ok(LocalResponse::Diagnostics(self.diagnostics.clone()))
            }
        }
    }
}

pub fn validate_state_paths<'a>(
    paths: impl IntoIterator<Item = &'a Path>,
) -> Result<(), LocalProtocolError> {
    paths
        .into_iter()
        .all(Path::is_absolute)
        .then_some(())
        .ok_or(LocalProtocolError::StatePathNotAbsolute)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LocalEndpoint {
    #[cfg(windows)]
    NamedPipe(String),
    #[cfg(unix)]
    UnixSocket(PathBuf),
}

pub fn local_endpoint(
    runtime_dir: &Path,
    listen: &str,
) -> Result<LocalEndpoint, LocalProtocolError> {
    if !runtime_dir.is_absolute() {
        return Err(LocalProtocolError::StatePathNotAbsolute);
    }
    #[cfg(windows)]
    {
        let pipe = if listen.is_empty() {
            r"\\.\pipe\devicelane-service"
        } else {
            listen
        };
        if !pipe.starts_with(r"\\.\pipe\") {
            return Err(LocalProtocolError::InvalidLocalEndpoint);
        }
        Ok(LocalEndpoint::NamedPipe(pipe.to_owned()))
    }
    #[cfg(unix)]
    {
        if listen.contains("://") {
            return Err(LocalProtocolError::InvalidLocalEndpoint);
        }
        let path = if listen.is_empty() {
            runtime_dir.join("devicelane.sock")
        } else {
            PathBuf::from(listen)
        };
        if !path.is_absolute() {
            return Err(LocalProtocolError::InvalidLocalEndpoint);
        }
        Ok(LocalEndpoint::UnixSocket(path))
    }
}

#[cfg(unix)]
pub fn bind_local(endpoint: &LocalEndpoint) -> io::Result<std::os::unix::net::UnixListener> {
    let LocalEndpoint::UnixSocket(path) = endpoint;
    std::os::unix::net::UnixListener::bind(path)
}
