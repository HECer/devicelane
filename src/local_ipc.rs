use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::fmt;
use std::io::{BufRead, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
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

pub fn send_local_request(
    endpoint: &LocalEndpoint,
    request: &LocalRequest,
) -> Result<LocalResponse, LocalProtocolError> {
    request.validate()?;
    let mut bytes = serde_json::to_vec(request).map_err(|_| LocalProtocolError::InvalidFrame)?;
    bytes.push(b'\n');
    send_raw_local_frame(endpoint, &bytes)
}

pub fn send_raw_local_frame(
    endpoint: &LocalEndpoint,
    frame: &[u8],
) -> Result<LocalResponse, LocalProtocolError> {
    let stream = connect_local(endpoint)?;
    let mut writer = stream.try_clone().map_err(|_| LocalProtocolError::Io)?;
    writer
        .write_all(frame)
        .map_err(|_| LocalProtocolError::Io)?;
    writer.flush().map_err(|_| LocalProtocolError::Io)?;
    read_frame(&mut std::io::BufReader::new(stream))
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

pub fn serve_local(
    endpoint: &LocalEndpoint,
    state: Arc<Mutex<DaemonState>>,
) -> Result<(), LocalProtocolError> {
    platform::serve(endpoint, state)
}

fn dispatch_connection(
    stream: PlatformStream,
    authorizer: &dyn Authorizer,
    state: &Arc<Mutex<DaemonState>>,
) {
    let mut writer = match duplicate_stream(&stream) {
        Ok(writer) => writer,
        Err(_) => return,
    };
    let request =
        read_frame::<_, LocalRequest>(&mut std::io::BufReader::new(match stream.try_clone() {
            Ok(reader) => reader,
            Err(_) => return,
        }));
    let peer = platform::peer_credentials(&stream);
    let response = if !peer.as_ref().is_ok_and(|peer| authorizer.authorize(peer)) {
        LocalResponse::Error {
            code: "unauthorized".into(),
            message: "local IPC peer is not authorized".into(),
        }
    } else {
        match request {
            Ok(request) => match state.lock() {
                Ok(mut state) => state.handle(request).unwrap_or_else(error_response),
                Err(_) => LocalResponse::Error {
                    code: "internal_error".into(),
                    message: "daemon state unavailable".into(),
                },
            },
            Err(error) => error_response(error),
        }
    };
    let _ = write_frame(&mut writer, &response);
}

fn error_response(error: LocalProtocolError) -> LocalResponse {
    LocalResponse::Error {
        code: match error {
            LocalProtocolError::IncompatibleVersion => "incompatible_version",
            LocalProtocolError::FrameTooLarge => "frame_too_large",
            LocalProtocolError::Unauthorized => "unauthorized",
            _ => "invalid_request",
        }
        .into(),
        message: error.to_string(),
    }
}

#[cfg(unix)]
type PlatformStream = std::os::unix::net::UnixStream;
#[cfg(windows)]
type PlatformStream = std::fs::File;

fn duplicate_stream(stream: &PlatformStream) -> std::io::Result<PlatformStream> {
    stream.try_clone()
}

fn connect_local(endpoint: &LocalEndpoint) -> Result<PlatformStream, LocalProtocolError> {
    platform::connect(endpoint)
}

#[cfg(unix)]
pub fn bind_local(endpoint: &LocalEndpoint) -> io::Result<std::os::unix::net::UnixListener> {
    let LocalEndpoint::UnixSocket(path) = endpoint;
    std::os::unix::net::UnixListener::bind(path)
}

#[cfg(unix)]
mod platform {
    use super::*;
    use std::os::fd::AsRawFd;

    pub fn connect(endpoint: &LocalEndpoint) -> Result<PlatformStream, LocalProtocolError> {
        let LocalEndpoint::UnixSocket(path) = endpoint;
        PlatformStream::connect(path).map_err(|_| LocalProtocolError::Io)
    }

    pub fn serve(
        endpoint: &LocalEndpoint,
        state: Arc<Mutex<DaemonState>>,
    ) -> Result<(), LocalProtocolError> {
        let listener = bind_local(endpoint).map_err(|_| LocalProtocolError::Io)?;
        let authorizer = SameUserAuthorizer::unix(unsafe { libc::geteuid() });
        for accepted in listener.incoming() {
            let Ok(stream) = accepted else { continue };
            dispatch_connection(stream, &authorizer, &state);
        }
        Err(LocalProtocolError::Io)
    }

    pub(super) fn peer_credentials(
        stream: &PlatformStream,
    ) -> Result<PeerCredentials, LocalProtocolError> {
        #[cfg(target_os = "linux")]
        unsafe {
            let mut credentials: libc::ucred = std::mem::zeroed();
            let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
            if libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut credentials as *mut libc::ucred).cast(),
                &mut length,
            ) != 0
            {
                return Err(LocalProtocolError::Unauthorized);
            }
            Ok(PeerCredentials::Unix {
                uid: credentials.uid,
                gid: credentials.gid,
                pid: u32::try_from(credentials.pid).ok(),
            })
        }
        #[cfg(target_os = "macos")]
        unsafe {
            let mut uid = 0;
            let mut gid = 0;
            if libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) != 0 {
                return Err(LocalProtocolError::Unauthorized);
            }
            Ok(PeerCredentials::Unix {
                uid,
                gid,
                pid: None,
            })
        }
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_PIPE_CONNECTED, GetLastError, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
    };
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::RevertToSelf;
    use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_GENERIC_READ,
        FILE_GENERIC_WRITE, FILE_SHARE_NONE, FlushFileBuffers, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
    };
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
        ImpersonateNamedPipeClient, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES,
        PIPE_WAIT, WaitNamedPipeW,
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
    };

    pub fn connect(endpoint: &LocalEndpoint) -> Result<PlatformStream, LocalProtocolError> {
        let LocalEndpoint::NamedPipe(path) = endpoint;
        let name: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
        unsafe { WaitNamedPipeW(name.as_ptr(), 100) };
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                FILE_SHARE_NONE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(LocalProtocolError::Io);
        }
        Ok(unsafe { PlatformStream::from_raw_handle(handle as _) })
    }

    pub fn serve(
        endpoint: &LocalEndpoint,
        state: Arc<Mutex<DaemonState>>,
    ) -> Result<(), LocalProtocolError> {
        let LocalEndpoint::NamedPipe(path) = endpoint;
        let expected_sid = current_user_sid()?;
        let authorizer = SameUserAuthorizer::windows(expected_sid);
        let name: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
        let mut first = true;
        loop {
            let access = PIPE_ACCESS_DUPLEX
                | if first {
                    FILE_FLAG_FIRST_PIPE_INSTANCE
                } else {
                    0
                };
            first = false;
            let handle = unsafe {
                CreateNamedPipeW(
                    name.as_ptr(),
                    access,
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                    PIPE_UNLIMITED_INSTANCES,
                    MAX_FRAME_BYTES as u32,
                    MAX_FRAME_BYTES as u32,
                    0,
                    std::ptr::null(),
                )
            };
            if handle == INVALID_HANDLE_VALUE {
                return Err(LocalProtocolError::Io);
            }
            let connected = unsafe { ConnectNamedPipe(handle, std::ptr::null_mut()) } != 0
                || unsafe { GetLastError() } == ERROR_PIPE_CONNECTED;
            if !connected {
                unsafe { CloseHandle(handle) };
                continue;
            }
            let stream = unsafe { PlatformStream::from_raw_handle(handle as _) };
            dispatch_connection(
                stream.try_clone().map_err(|_| LocalProtocolError::Io)?,
                &authorizer,
                &state,
            );
            unsafe {
                FlushFileBuffers(stream.as_raw_handle() as HANDLE);
                DisconnectNamedPipe(stream.as_raw_handle() as HANDLE);
            }
        }
    }

    pub(super) fn peer_credentials(
        stream: &PlatformStream,
    ) -> Result<PeerCredentials, LocalProtocolError> {
        let handle = stream.as_raw_handle() as HANDLE;
        let mut process_id = 0;
        if unsafe { GetNamedPipeClientProcessId(handle, &mut process_id) } == 0 {
            return Err(LocalProtocolError::Unauthorized);
        }
        if unsafe { ImpersonateNamedPipeClient(handle) } == 0 {
            return Err(LocalProtocolError::Unauthorized);
        }
        let mut token = std::ptr::null_mut();
        let opened =
            unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) } != 0;
        let sid = if opened {
            token_sid(token)
        } else {
            Err(LocalProtocolError::Unauthorized)
        };
        if !token.is_null() {
            unsafe { CloseHandle(token) };
        }
        unsafe { RevertToSelf() };
        sid.map(|user_sid| PeerCredentials::Windows {
            process_id,
            user_sid,
        })
    }

    fn current_user_sid() -> Result<String, LocalProtocolError> {
        let mut token = std::ptr::null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(LocalProtocolError::Unauthorized);
        }
        let result = token_sid(token);
        unsafe { CloseHandle(token) };
        result
    }

    fn token_sid(token: HANDLE) -> Result<String, LocalProtocolError> {
        let mut needed = 0;
        unsafe { GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed) };
        if needed == 0 {
            return Err(LocalProtocolError::Unauthorized);
        }
        let mut buffer = vec![0_u8; needed as usize];
        if unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                needed,
                &mut needed,
            )
        } == 0
        {
            return Err(LocalProtocolError::Unauthorized);
        }
        let user = unsafe { &*(buffer.as_ptr().cast::<TOKEN_USER>()) };
        let mut text = std::ptr::null_mut();
        if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) } == 0 {
            return Err(LocalProtocolError::Unauthorized);
        }
        let mut length = 0;
        while unsafe { *text.add(length) } != 0 {
            length += 1;
        }
        let sid = String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) })
            .map_err(|_| LocalProtocolError::Unauthorized)?;
        unsafe { LocalFree(text.cast()) };
        Ok(sid)
    }
}
