pub mod protocol {
    use prost::{Enumeration, Message};

    #[derive(Clone, Copy, PartialEq, Eq, Message)]
    pub struct ProtocolVersion {
        #[prost(uint32, tag = "1")]
        pub major: u32,
        #[prost(uint32, tag = "2")]
        pub minor: u32,
    }

    #[derive(Clone, PartialEq, Message)]
    pub struct Host {
        #[prost(message, optional, tag = "1")]
        pub version: Option<ProtocolVersion>,
        #[prost(string, tag = "2")]
        pub id: String,
        #[prost(string, tag = "3")]
        pub operating_system: String,
        #[prost(string, tag = "4")]
        pub architecture: String,
    }

    #[derive(Clone, PartialEq, Message)]
    pub struct Device {
        #[prost(message, optional, tag = "1")]
        pub version: Option<ProtocolVersion>,
        #[prost(string, tag = "2")]
        pub id: String,
        #[prost(string, tag = "3")]
        pub host_id: String,
        #[prost(string, tag = "4")]
        pub platform: String,
        #[prost(string, tag = "5")]
        pub state: String,
    }

    #[derive(Clone, PartialEq, Message)]
    pub struct Capability {
        #[prost(message, optional, tag = "1")]
        pub version: Option<ProtocolVersion>,
        #[prost(string, tag = "2")]
        pub name: String,
        #[prost(uint32, tag = "3")]
        pub revision: u32,
    }

    #[derive(Clone, PartialEq, Message)]
    pub struct Job {
        #[prost(message, optional, tag = "1")]
        pub version: Option<ProtocolVersion>,
        #[prost(string, tag = "2")]
        pub id: String,
        #[prost(string, tag = "3")]
        pub capability: String,
        #[prost(string, tag = "4")]
        pub state: String,
    }

    #[derive(Clone, PartialEq, Message)]
    pub struct Event {
        #[prost(message, optional, tag = "1")]
        pub version: Option<ProtocolVersion>,
        #[prost(string, tag = "2")]
        pub job_id: String,
        #[prost(uint64, tag = "3")]
        pub sequence: u64,
        #[prost(string, tag = "4")]
        pub kind: String,
        #[prost(bytes = "vec", tag = "5")]
        pub payload: Vec<u8>,
    }

    #[derive(Clone, PartialEq, Message)]
    pub struct Artifact {
        #[prost(message, optional, tag = "1")]
        pub version: Option<ProtocolVersion>,
        #[prost(string, tag = "2")]
        pub id: String,
        #[prost(string, tag = "3")]
        pub job_id: String,
        #[prost(string, tag = "4")]
        pub sha256: String,
        #[prost(uint64, tag = "5")]
        pub size_bytes: u64,
        #[prost(string, tag = "6")]
        pub media_type: String,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Enumeration)]
    pub enum RetryClass {
        Never = 0,
        Immediate = 1,
        Backoff = 2,
        AfterRepair = 3,
    }

    #[derive(Clone, PartialEq, Message)]
    pub struct RepairAction {
        #[prost(string, tag = "1")]
        pub description: String,
        #[prost(string, optional, tag = "2")]
        pub command: Option<String>,
    }

    #[derive(Clone, PartialEq, Message)]
    struct WireError {
        #[prost(string, tag = "1")]
        code: String,
        #[prost(string, tag = "2")]
        message: String,
        #[prost(enumeration = "RetryClass", tag = "3")]
        retry_class: i32,
        #[prost(message, optional, tag = "4")]
        repair_action: Option<RepairAction>,
    }

    #[derive(Clone, Debug, PartialEq)]
    pub struct Error {
        code: String,
        message: String,
        retry_class: RetryClass,
        repair_action: Option<RepairAction>,
    }

    impl Error {
        pub fn new(
            code: impl Into<String>,
            message: impl Into<String>,
            retry_class: RetryClass,
            repair_action: Option<RepairAction>,
        ) -> Result<Self, &'static str> {
            let code = code.into();
            let message = message.into();
            if code.is_empty() {
                return Err("error code must not be empty");
            }
            if message.is_empty() {
                return Err("error message must not be empty");
            }
            Ok(Self {
                code,
                message,
                retry_class,
                repair_action,
            })
        }

        pub fn encode_to_vec(&self) -> Vec<u8> {
            WireError {
                code: self.code.clone(),
                message: self.message.clone(),
                retry_class: self.retry_class.into(),
                repair_action: self.repair_action.clone(),
            }
            .encode_to_vec()
        }

        pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
            let wire = WireError::decode(bytes).map_err(|_| "invalid error encoding")?;
            let retry_class =
                RetryClass::try_from(wire.retry_class).map_err(|_| "unknown retry class")?;
            Self::new(wire.code, wire.message, retry_class, wire.repair_action)
        }

        pub fn code(&self) -> &str {
            &self.code
        }

        pub fn message(&self) -> &str {
            &self.message
        }

        pub fn retry_class(&self) -> RetryClass {
            self.retry_class
        }

        pub fn repair_action(&self) -> Option<&RepairAction> {
            self.repair_action.as_ref()
        }
    }
}

pub mod process_execution {
    use command_group::CommandGroup;
    use std::collections::{HashMap, HashSet};
    use std::fs;
    use std::io::Read;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, mpsc};
    use std::thread;
    use std::time::{Duration, Instant};

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum TerminalStatus {
        Exited(i32),
        TimedOut,
        Cancelled,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum EventKind {
        Started,
        Stdout,
        Stderr,
        Terminal(TerminalStatus),
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct ProcessEvent {
        pub sequence: u64,
        pub kind: EventKind,
        pub payload: Vec<u8>,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum ProcessError {
        ProgramDenied,
        WorkspaceEscape,
        EnvironmentDenied,
        Io,
    }

    #[derive(Clone, Default)]
    pub struct CancellationToken(Arc<AtomicBool>);

    impl CancellationToken {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn cancel(&self) {
            self.0.store(true, Ordering::Release);
        }

        pub fn is_cancelled(&self) -> bool {
            self.0.load(Ordering::Acquire)
        }
    }

    pub struct ProcessRequest {
        pub program: PathBuf,
        pub args: Vec<String>,
        pub working_directory: PathBuf,
        pub environment: HashMap<String, String>,
    }

    pub struct ProcessExecutor {
        workspace: PathBuf,
        programs: HashSet<PathBuf>,
        environment: HashSet<String>,
    }

    pub struct ProcessStream {
        receiver: mpsc::Receiver<ProcessEvent>,
    }

    impl ProcessStream {
        pub fn next_timeout(&mut self, timeout: Duration) -> Option<ProcessEvent> {
            self.receiver.recv_timeout(timeout).ok()
        }
    }

    impl Iterator for ProcessStream {
        type Item = ProcessEvent;

        fn next(&mut self) -> Option<Self::Item> {
            self.receiver.recv().ok()
        }
    }

    impl ProcessExecutor {
        pub fn new(
            workspace: impl AsRef<Path>,
            programs: impl IntoIterator<Item = PathBuf>,
            environment: impl IntoIterator<Item = &'static str>,
        ) -> Result<Self, ProcessError> {
            let workspace = fs::canonicalize(workspace).map_err(|_| ProcessError::Io)?;
            let programs = programs
                .into_iter()
                .map(|program| fs::canonicalize(program).map_err(|_| ProcessError::ProgramDenied))
                .collect::<Result<_, _>>()?;
            Ok(Self {
                workspace,
                programs,
                environment: environment.into_iter().map(str::to_owned).collect(),
            })
        }

        pub fn execute(
            &self,
            request: ProcessRequest,
            timeout: Duration,
            cancellation: CancellationToken,
        ) -> Result<Vec<ProcessEvent>, ProcessError> {
            Ok(self.start(request, timeout, cancellation)?.collect())
        }

        pub(crate) fn workspace(&self) -> &Path {
            &self.workspace
        }

        pub fn start(
            &self,
            request: ProcessRequest,
            timeout: Duration,
            cancellation: CancellationToken,
        ) -> Result<ProcessStream, ProcessError> {
            let program =
                fs::canonicalize(&request.program).map_err(|_| ProcessError::ProgramDenied)?;
            if !self.programs.contains(&program) {
                return Err(ProcessError::ProgramDenied);
            }
            if request
                .environment
                .keys()
                .any(|name| !self.environment.contains(name))
            {
                return Err(ProcessError::EnvironmentDenied);
            }
            let working_directory =
                fs::canonicalize(self.workspace.join(request.working_directory))
                    .map_err(|_| ProcessError::WorkspaceEscape)?;
            if !working_directory.starts_with(&self.workspace) {
                return Err(ProcessError::WorkspaceEscape);
            }

            #[cfg(windows)]
            let mut command = if matches!(
                program.extension().and_then(|extension| extension.to_str()),
                Some("cmd" | "bat")
            ) {
                let mut command = Command::new("cmd.exe");
                let script = program.to_string_lossy();
                command
                    .args(["/D", "/C"])
                    .arg(script.strip_prefix(r"\\?\").unwrap_or(&script));
                command
            } else {
                Command::new(&program)
            };
            #[cfg(not(windows))]
            let mut command = Command::new(program);
            command
                .args(request.args)
                .current_dir(working_directory)
                .env_clear()
                .envs(request.environment)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let mut child = command.group_spawn().map_err(|_| ProcessError::Io)?;
            let stdout = child.inner().stdout.take().ok_or(ProcessError::Io)?;
            let stderr = child.inner().stderr.take().ok_or(ProcessError::Io)?;
            let (stream_sender, stream_receiver) = mpsc::channel();
            thread::spawn(move || {
                run_process(child, stdout, stderr, timeout, cancellation, stream_sender);
            });
            Ok(ProcessStream {
                receiver: stream_receiver,
            })
        }
    }

    fn run_process(
        mut child: command_group::GroupChild,
        stdout: impl Read + Send + 'static,
        stderr: impl Read + Send + 'static,
        timeout: Duration,
        cancellation: CancellationToken,
        sender: mpsc::Sender<ProcessEvent>,
    ) {
        let (output_sender, output_receiver) = mpsc::channel();
        let stdout_reader = read_stream(stdout, EventKind::Stdout, output_sender.clone());
        let stderr_reader = read_stream(stderr, EventKind::Stderr, output_sender);
        let mut sequence = 1;
        let _ = sender.send(ProcessEvent {
            sequence,
            kind: EventKind::Started,
            payload: Vec::new(),
        });
        let started = Instant::now();
        let mut closed_streams = 0;
        let mut exit_code = None;
        let terminal = loop {
            while let Ok(message) = output_receiver.try_recv() {
                match message {
                    Some((kind, payload)) => {
                        sequence += 1;
                        let _ = sender.send(ProcessEvent {
                            sequence,
                            kind,
                            payload,
                        });
                    }
                    None => closed_streams += 1,
                }
            }
            if cancellation.is_cancelled() {
                let _ = kill_running_group(&mut child);
                let _ = child.wait();
                break TerminalStatus::Cancelled;
            }
            if started.elapsed() >= timeout {
                let _ = kill_running_group(&mut child);
                let _ = child.wait();
                break TerminalStatus::TimedOut;
            }
            if exit_code.is_none() {
                exit_code = child
                    .try_wait()
                    .ok()
                    .flatten()
                    .map(|status| status.code().unwrap_or(-1));
            }
            if let Some(code) = exit_code.filter(|_| closed_streams == 2) {
                break TerminalStatus::Exited(code);
            }
            thread::sleep(Duration::from_millis(5));
        };
        let _ = stdout_reader.join();
        let _ = stderr_reader.join();
        for (kind, payload) in output_receiver.into_iter().flatten() {
            sequence += 1;
            let _ = sender.send(ProcessEvent {
                sequence,
                kind,
                payload,
            });
        }
        sequence += 1;
        let _ = sender.send(ProcessEvent {
            sequence,
            kind: EventKind::Terminal(terminal),
            payload: Vec::new(),
        });
    }

    fn read_stream(
        mut stream: impl Read + Send + 'static,
        kind: EventKind,
        sender: mpsc::Sender<Option<(EventKind, Vec<u8>)>>,
    ) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let mut buffer = [0; 4096];
            loop {
                match stream.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(length) => {
                        let _ = sender.send(Some((kind.clone(), buffer[..length].to_vec())));
                    }
                    Err(_) => break,
                }
            }
            let _ = sender.send(None);
        })
    }

    fn kill_running_group(child: &mut command_group::GroupChild) -> Result<(), ProcessError> {
        match child.kill() {
            Ok(()) => Ok(()),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::InvalidInput | std::io::ErrorKind::NotFound
                ) =>
            {
                Ok(())
            }
            Err(_) => Err(ProcessError::Io),
        }
    }
}

pub mod identity {
    use rand::{RngCore, rngs::OsRng};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    static NEXT_ID: AtomicU64 = AtomicU64::new(1);

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Certificate {
        machine_id: String,
        fingerprint: String,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum AuditEvent {
        PairingSucceeded { peer_id: String },
        PairingRejected { reason: &'static str },
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum PairingError {
        InvalidCode,
        CodeExpired,
        CodeReused,
        TlsRequired,
        UntrustedPeer,
        InvalidCertificate,
    }

    struct PairingCode {
        value: String,
        lifetime: Duration,
        consumed: bool,
    }

    pub struct MachineIdentity {
        id: String,
        certificate: Certificate,
        pairing_code: Option<PairingCode>,
        trusted: HashMap<String, Certificate>,
        audit: Vec<AuditEvent>,
    }

    impl MachineIdentity {
        pub fn new(id: impl Into<String>) -> Result<Self, PairingError> {
            let id = id.into();
            if id.is_empty() {
                return Err(PairingError::InvalidCertificate);
            }
            let nonce = NEXT_ID.fetch_add(1, Ordering::Relaxed);
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            Ok(Self {
                certificate: Certificate {
                    machine_id: id.clone(),
                    fingerprint: format!("{now:032x}{nonce:016x}"),
                },
                id,
                pairing_code: None,
                trusted: HashMap::new(),
                audit: Vec::new(),
            })
        }

        pub fn certificate(&self) -> &Certificate {
            &self.certificate
        }

        pub fn issue_pairing_code(&mut self, lifetime: Duration) -> String {
            let mut random = [0_u8; 4];
            OsRng.fill_bytes(&mut random);
            let value = format!("{:06}", u32::from_le_bytes(random) % 1_000_000);
            self.pairing_code = Some(PairingCode {
                value: value.clone(),
                lifetime,
                consumed: false,
            });
            value
        }

        pub fn accept_pairing(
            &mut self,
            code: &str,
            peer: &Certificate,
            elapsed: Duration,
        ) -> Result<Certificate, PairingError> {
            let result: Result<(), (PairingError, &'static str)> = match self.pairing_code.as_mut()
            {
                Some(pairing) if pairing.value != code => {
                    Err((PairingError::InvalidCode, "invalid_code"))
                }
                Some(pairing) if pairing.consumed => Err((PairingError::CodeReused, "code_reused")),
                Some(pairing) if elapsed > pairing.lifetime => {
                    Err((PairingError::CodeExpired, "code_expired"))
                }
                Some(pairing) => {
                    pairing.consumed = true;
                    self.trusted.insert(peer.machine_id.clone(), peer.clone());
                    self.audit.push(AuditEvent::PairingSucceeded {
                        peer_id: peer.machine_id.clone(),
                    });
                    return Ok(self.certificate.clone());
                }
                None => Err((PairingError::InvalidCode, "invalid_code")),
            };
            let (error, reason) = result.unwrap_err();
            self.audit.push(AuditEvent::PairingRejected { reason });
            Err(error)
        }

        pub fn trust(
            &mut self,
            peer_id: &str,
            certificate: &Certificate,
        ) -> Result<(), PairingError> {
            if peer_id != certificate.machine_id || certificate.fingerprint.is_empty() {
                return Err(PairingError::InvalidCertificate);
            }
            self.trusted.insert(peer_id.to_owned(), certificate.clone());
            Ok(())
        }

        pub fn mutual_tls_with(&self, peer: &MachineIdentity) -> Result<(), PairingError> {
            match self.trusted.get(&peer.id) {
                Some(certificate) if certificate == peer.certificate() => Ok(()),
                _ => Err(PairingError::UntrustedPeer),
            }
        }

        pub fn accept_unencrypted(&self, _peer_id: &str) -> Result<(), PairingError> {
            Err(PairingError::TlsRequired)
        }

        pub fn audit_log(&self) -> &[AuditEvent] {
            &self.audit
        }
    }
}

pub mod secure_transport {
    use rand::{RngCore, rngs::OsRng};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use rustls::{
        ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
    };
    use std::collections::{HashMap, HashSet};
    use std::fmt;
    use std::fs;
    use std::io;
    use std::net::TcpStream;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum AuditEvent {
        Paired(String),
        Rejected(&'static str),
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum TransportError {
        InvalidCode,
        CodeExpired,
        CodeReused,
        TlsRequired,
        UntrustedPeer,
        RevokedPeer,
        InvalidCertificate,
        Io,
        Tls,
    }

    struct PairingCode {
        value: String,
        lifetime: Duration,
        issued_at: Instant,
        consumed: bool,
    }

    pub struct SecureTransport {
        root: PathBuf,
        id: String,
        certificate: Vec<u8>,
        private_key: Vec<u8>,
        trusted: HashMap<String, Vec<u8>>,
        revoked: HashSet<String>,
        pairing_code: Option<PairingCode>,
        audit: Mutex<Vec<AuditEvent>>,
        rpc_count: usize,
    }

    impl fmt::Debug for SecureTransport {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("SecureTransport")
                .field("id", &self.id)
                .field("trusted_peers", &self.trusted.keys().collect::<Vec<_>>())
                .finish()
        }
    }

    impl SecureTransport {
        pub fn load_or_create(
            root: impl AsRef<Path>,
            id: impl Into<String>,
        ) -> Result<Self, TransportError> {
            let root = root.as_ref().to_owned();
            let id = id.into();
            if !valid_machine_id(&id) {
                return Err(TransportError::InvalidCertificate);
            }
            fs::create_dir_all(root.join("trust")).map_err(|_| TransportError::Io)?;
            secure_directory(&root)?;
            secure_directory(&root.join("trust"))?;
            let certificate_path = root.join("certificate.der");
            let key_path = root.join("private-key.der");
            let (certificate, private_key) = if certificate_path.exists() && key_path.exists() {
                (
                    fs::read(&certificate_path).map_err(|_| TransportError::Io)?,
                    fs::read(&key_path).map_err(|_| TransportError::Io)?,
                )
            } else {
                let generated = rcgen::generate_simple_self_signed(vec![id.clone()])
                    .map_err(|_| TransportError::InvalidCertificate)?;
                let certificate = generated.cert.der().to_vec();
                let private_key = generated.key_pair.serialize_der();
                write_secret(&certificate_path, &certificate)?;
                write_secret(&key_path, &private_key)?;
                (certificate, private_key)
            };
            let mut trusted = HashMap::new();
            for entry in fs::read_dir(root.join("trust")).map_err(|_| TransportError::Io)? {
                let entry = entry.map_err(|_| TransportError::Io)?;
                if entry.path().extension().and_then(|value| value.to_str()) == Some("der") {
                    let peer_id = entry
                        .path()
                        .file_stem()
                        .unwrap()
                        .to_string_lossy()
                        .into_owned();
                    trusted.insert(
                        peer_id,
                        fs::read(entry.path()).map_err(|_| TransportError::Io)?,
                    );
                }
            }
            let revoked = fs::read_to_string(root.join("revoked"))
                .unwrap_or_default()
                .lines()
                .map(str::to_owned)
                .collect();
            Ok(Self {
                root,
                id,
                certificate,
                private_key,
                trusted,
                revoked,
                pairing_code: None,
                audit: Mutex::new(Vec::new()),
                rpc_count: 0,
            })
        }

        pub fn certificate_der(&self) -> &[u8] {
            &self.certificate
        }

        pub fn machine_id(&self) -> &str {
            &self.id
        }

        pub fn issue_pairing_code(&mut self, lifetime: Duration) -> String {
            let mut random = [0_u8; 16];
            OsRng.fill_bytes(&mut random);
            let value: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
            self.pairing_code = Some(PairingCode {
                value: value.clone(),
                lifetime,
                issued_at: Instant::now(),
                consumed: false,
            });
            value
        }

        pub fn accept_pairing(
            &mut self,
            code: &str,
            certificate: &[u8],
            elapsed: Duration,
        ) -> Result<(), TransportError> {
            let Some(pairing) = self.pairing_code.as_ref() else {
                self.reject("invalid_code");
                return Err(TransportError::InvalidCode);
            };
            if pairing.value != code {
                self.reject("invalid_code");
                return Err(TransportError::InvalidCode);
            }
            if pairing.consumed {
                self.reject("code_reused");
                return Err(TransportError::CodeReused);
            }
            if pairing.issued_at.elapsed().saturating_add(elapsed) > pairing.lifetime {
                self.reject("code_expired");
                return Err(TransportError::CodeExpired);
            }
            self.pairing_code.as_mut().unwrap().consumed = true;
            let peer_id = certificate_dns_name(certificate)?;
            self.trust(&peer_id, certificate)?;
            self.audit
                .get_mut()
                .unwrap()
                .push(AuditEvent::Paired(peer_id));
            Ok(())
        }

        pub fn trust(&mut self, peer_id: &str, certificate: &[u8]) -> Result<(), TransportError> {
            if !valid_machine_id(peer_id) || certificate_dns_name(certificate)? != peer_id {
                return Err(TransportError::InvalidCertificate);
            }
            write_secret(
                &self.root.join("trust").join(format!("{peer_id}.der")),
                certificate,
            )?;
            self.trusted
                .insert(peer_id.to_owned(), certificate.to_vec());
            Ok(())
        }

        pub fn revoke(&mut self, peer_id: &str) -> Result<(), TransportError> {
            self.revoked.insert(peer_id.to_owned());
            let contents = self.revoked.iter().cloned().collect::<Vec<_>>().join("\n");
            write_secret(&self.root.join("revoked"), contents.as_bytes())
        }

        pub fn reject_cleartext(&self) -> Result<(), TransportError> {
            self.reject("tls_required");
            Err(TransportError::TlsRequired)
        }

        pub fn process_cleartext_rpc(&mut self) -> Result<(), TransportError> {
            self.reject_cleartext()
        }

        pub fn process_rpc(&mut self, certificate: &[u8]) -> Result<(), TransportError> {
            self.authorize_peer(certificate)?;
            self.rpc_count += 1;
            Ok(())
        }

        pub fn authorize_peer(&self, certificate: &[u8]) -> Result<(), TransportError> {
            let peer_id = self
                .trusted
                .iter()
                .find_map(|(id, trusted)| (trusted.as_slice() == certificate).then_some(id));
            let Some(peer_id) = peer_id else {
                self.reject("untrusted_peer");
                return Err(TransportError::UntrustedPeer);
            };
            if self.revoked.contains(peer_id) {
                self.reject("revoked_peer");
                return Err(TransportError::RevokedPeer);
            }
            Ok(())
        }

        pub fn peer_id(&self, certificate: &[u8]) -> Result<String, TransportError> {
            self.authorize_peer(certificate)?;
            certificate_dns_name(certificate)
        }

        pub fn connect_tls(
            &self,
            mut stream: TcpStream,
            server_name: &str,
        ) -> Result<StreamOwned<ClientConnection, TcpStream>, TransportError> {
            let config = ClientConfig::builder()
                .with_root_certificates(self.roots()?)
                .with_client_auth_cert(self.cert_chain(), self.key()?)
                .map_err(|_| TransportError::InvalidCertificate)?;
            let name = ServerName::try_from(server_name.to_owned())
                .map_err(|_| TransportError::InvalidCertificate)?;
            let mut connection =
                ClientConnection::new(Arc::new(config), name).map_err(|_| TransportError::Tls)?;
            connection.complete_io(&mut stream).map_err(|_| {
                self.reject("tls_handshake_failed");
                TransportError::Tls
            })?;
            let peer = connection
                .peer_certificates()
                .and_then(|certificates| certificates.first())
                .ok_or(TransportError::UntrustedPeer)?;
            self.authorize_peer(peer.as_ref())?;
            Ok(StreamOwned::new(connection, stream))
        }

        pub fn accept_tls(
            &self,
            mut stream: TcpStream,
        ) -> Result<StreamOwned<ServerConnection, TcpStream>, TransportError> {
            let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(self.roots()?))
                .build()
                .map_err(|_| TransportError::InvalidCertificate)?;
            let config = ServerConfig::builder()
                .with_client_cert_verifier(verifier)
                .with_single_cert(self.cert_chain(), self.key()?)
                .map_err(|_| TransportError::InvalidCertificate)?;
            let mut connection =
                ServerConnection::new(Arc::new(config)).map_err(|_| TransportError::Tls)?;
            connection.complete_io(&mut stream).map_err(|_| {
                self.reject("tls_handshake_failed");
                TransportError::Tls
            })?;
            let peer = connection
                .peer_certificates()
                .and_then(|certificates| certificates.first())
                .ok_or(TransportError::UntrustedPeer)?;
            self.authorize_peer(peer.as_ref())?;
            Ok(StreamOwned::new(connection, stream))
        }

        pub fn audit_log(&self) -> Vec<AuditEvent> {
            self.audit.lock().unwrap().clone()
        }

        pub fn rpc_count(&self) -> usize {
            self.rpc_count
        }

        fn roots(&self) -> Result<RootCertStore, TransportError> {
            let mut roots = RootCertStore::empty();
            for certificate in self.trusted.values() {
                roots
                    .add(CertificateDer::from(certificate.clone()))
                    .map_err(|_| TransportError::InvalidCertificate)?;
            }
            Ok(roots)
        }

        fn cert_chain(&self) -> Vec<CertificateDer<'static>> {
            vec![CertificateDer::from(self.certificate.clone())]
        }

        fn key(&self) -> Result<PrivateKeyDer<'static>, TransportError> {
            Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                self.private_key.clone(),
            )))
        }

        fn reject(&self, reason: &'static str) {
            self.audit
                .lock()
                .unwrap()
                .push(AuditEvent::Rejected(reason));
        }
    }

    fn certificate_dns_name(certificate: &[u8]) -> Result<String, TransportError> {
        use x509_parser::extensions::GeneralName;
        use x509_parser::prelude::FromDer;
        let (_, parsed) = x509_parser::certificate::X509Certificate::from_der(certificate)
            .map_err(|_| TransportError::InvalidCertificate)?;
        parsed
            .subject_alternative_name()
            .map_err(|_| TransportError::InvalidCertificate)?
            .and_then(|extension| {
                extension
                    .value
                    .general_names
                    .iter()
                    .find_map(|name| match name {
                        GeneralName::DNSName(name) => Some((*name).to_owned()),
                        _ => None,
                    })
            })
            .ok_or(TransportError::InvalidCertificate)
    }

    fn write_secret(path: &Path, contents: &[u8]) -> Result<(), TransportError> {
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            use std::os::unix::fs::PermissionsExt;
            if path.exists() {
                fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                    .map_err(|_| TransportError::Io)?;
            }
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(path)
                .map_err(|_| TransportError::Io)?;
            file.write_all(contents).map_err(|_| TransportError::Io)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .map_err(|_| TransportError::Io)?;
        }
        #[cfg(windows)]
        {
            if path.exists() {
                restrict_windows_path(path)?;
            }
            fs::write(path, contents).map_err(|_| TransportError::Io)?;
            restrict_windows_path(path)?;
        }
        Ok(())
    }

    fn secure_directory(path: &Path) -> Result<(), TransportError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .map_err(|_| TransportError::Io)?;
        }
        #[cfg(windows)]
        restrict_windows_path(path)?;
        Ok(())
    }

    #[cfg(windows)]
    fn restrict_windows_path(path: &Path) -> Result<(), TransportError> {
        use std::process::Command;
        let account = Command::new("whoami")
            .output()
            .map_err(|_| TransportError::Io)?;
        let account = String::from_utf8(account.stdout).map_err(|_| TransportError::Io)?;
        let status = Command::new("icacls")
            .arg(path)
            .args([
                "/inheritance:r",
                "/grant:r",
                &format!("{}:F", account.trim()),
            ])
            .output()
            .map_err(|_| TransportError::Io)?;
        if status.status.success() {
            Ok(())
        } else {
            Err(TransportError::Io)
        }
    }

    fn valid_machine_id(id: &str) -> bool {
        !id.is_empty()
            && id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    }

    impl From<io::Error> for TransportError {
        fn from(_: io::Error) -> Self {
            Self::Io
        }
    }
}

pub mod discovery {
    use std::collections::HashMap;
    use std::time::Duration;

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct CapabilitySnapshot {
        pub capabilities: Vec<String>,
        pub toolchains: Vec<String>,
    }

    pub struct AgentHeartbeat {
        pub agent_id: String,
        pub operating_system: String,
        pub architecture: String,
        pub snapshot: CapabilitySnapshot,
    }

    pub struct Agent {
        heartbeat: AgentHeartbeat,
    }

    impl Agent {
        pub fn new(heartbeat: AgentHeartbeat) -> Self {
            Self { heartbeat }
        }

        pub fn start(self, registry: &mut Registry, now: Duration) {
            registry.record_heartbeat(self.heartbeat, now);
        }
    }

    struct AgentRecord {
        heartbeat: AgentHeartbeat,
        last_seen: Duration,
        snapshot_revision: u64,
    }

    pub struct Registry {
        heartbeat_window: Duration,
        agents: HashMap<String, AgentRecord>,
    }

    impl Registry {
        pub fn new(heartbeat_window: Duration) -> Self {
            Self {
                heartbeat_window,
                agents: HashMap::new(),
            }
        }

        pub fn record_heartbeat(&mut self, heartbeat: AgentHeartbeat, now: Duration) {
            let revision = self
                .agents
                .get(&heartbeat.agent_id)
                .map(|record| {
                    record.snapshot_revision
                        + u64::from(record.heartbeat.snapshot != heartbeat.snapshot)
                })
                .unwrap_or(1);
            self.agents.insert(
                heartbeat.agent_id.clone(),
                AgentRecord {
                    heartbeat,
                    last_seen: now,
                    snapshot_revision: revision,
                },
            );
        }

        pub fn snapshot_revision(&self, agent_id: &str) -> Option<u64> {
            self.agents
                .get(agent_id)
                .map(|record| record.snapshot_revision)
        }

        pub fn cli_agents(&self, now: Duration) -> String {
            self.agents
                .values()
                .map(|record| {
                    let agent = &record.heartbeat;
                    let status = if now.saturating_sub(record.last_seen) >= self.heartbeat_window {
                        "offline"
                    } else {
                        "online"
                    };
                    format!(
                        "{} {} {} {} {} revision={} {status}",
                        agent.agent_id,
                        agent.operating_system,
                        agent.architecture,
                        agent.snapshot.capabilities.join(","),
                        agent.snapshot.toolchains.join(","),
                        record.snapshot_revision
                    )
                })
                .collect::<Vec<_>>()
                .join("\n")
        }
    }
}

pub mod authorization {
    use std::collections::{HashMap, HashSet};
    use std::time::{Duration, Instant};

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub enum Role {
        Operator,
        Observer,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Operation<'a> {
        DiscoverDevices,
        LeaseDevice,
        ReadLogs,
        StartProcess { device_id: &'a str },
        StopProcess { device_id: &'a str },
        InstallDevice { device_id: &'a str },
        ReadDeviceLogs { device_id: &'a str },
        ReadArtifact { device_id: &'a str },
        AttachDebugger { device_id: &'a str },
        SimulatorLifecycle { device_id: &'a str },
        SimulatorScreenshot { device_id: &'a str },
        SimulatorLocation { device_id: &'a str },
        SimulatorPrivacy { device_id: &'a str },
        SimulatorMedia { device_id: &'a str },
        AppleInstall { device_id: &'a str },
        AppleLaunch { device_id: &'a str },
        AppleTerminate { device_id: &'a str },
        AppleUninstall { device_id: &'a str },
        AppleLogStream { device_id: &'a str },
        AppleDeviceInfo,
        AppleReadReleasedLogs,
        AppleDebug { device_id: &'a str },
    }

    impl Operation<'_> {
        fn capability(&self) -> &str {
            match self {
                Self::DiscoverDevices => "device.discover",
                Self::LeaseDevice => "device.lease",
                Self::ReadLogs => "logs.read",
                Self::StartProcess { .. } => "process.start",
                Self::StopProcess { .. } => "process.stop",
                Self::InstallDevice { .. } => "device.install",
                Self::ReadDeviceLogs { .. } => "logs.read",
                Self::ReadArtifact { .. } => "artifact.read",
                Self::AttachDebugger { .. } => "debug.attach",
                Self::SimulatorLifecycle { .. } => "simulator.lifecycle",
                Self::SimulatorScreenshot { .. } => "simulator.screenshot",
                Self::SimulatorLocation { .. } => "simulator.location",
                Self::SimulatorPrivacy { .. } => "simulator.privacy",
                Self::SimulatorMedia { .. } => "simulator.media",
                Self::AppleInstall { .. } => "apple.app.install@1",
                Self::AppleLaunch { .. } => "apple.app.launch@1",
                Self::AppleTerminate { .. } => "apple.app.terminate@1",
                Self::AppleUninstall { .. } => "apple.app.uninstall@1",
                Self::AppleLogStream { .. } => "apple.app.logs@1",
                Self::AppleDeviceInfo => "apple.device.info@1",
                Self::AppleReadReleasedLogs => "apple.app.logs.read@1",
                Self::AppleDebug { .. } => "apple.debug@1",
            }
        }

        fn device_id(&self) -> Option<&str> {
            match self {
                Self::DiscoverDevices
                | Self::LeaseDevice
                | Self::ReadLogs
                | Self::AppleDeviceInfo
                | Self::AppleReadReleasedLogs => None,
                Self::StartProcess { device_id }
                | Self::StopProcess { device_id }
                | Self::InstallDevice { device_id }
                | Self::ReadDeviceLogs { device_id }
                | Self::ReadArtifact { device_id }
                | Self::AttachDebugger { device_id } => Some(device_id),
                Self::SimulatorLifecycle { device_id }
                | Self::SimulatorScreenshot { device_id }
                | Self::SimulatorLocation { device_id }
                | Self::SimulatorPrivacy { device_id }
                | Self::SimulatorMedia { device_id } => Some(device_id),
                Self::AppleInstall { device_id }
                | Self::AppleLaunch { device_id }
                | Self::AppleTerminate { device_id }
                | Self::AppleUninstall { device_id }
                | Self::AppleLogStream { device_id } => Some(device_id),
                Self::AppleDebug { device_id } => Some(device_id),
            }
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum AuthorizationError {
        CapabilityDenied,
        DeviceAlreadyLeased,
        LeaseInactive,
        ObserverReadOnly,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct LeaseId(u64);

    struct Lease {
        device_id: String,
        holder: String,
        expires_at: Instant,
        revoked: bool,
    }

    struct Principal {
        role: Role,
        capabilities: HashSet<String>,
    }

    pub struct PolicyEngine {
        principals: HashMap<String, Principal>,
        leases: HashMap<LeaseId, Lease>,
        next_lease_id: u64,
    }

    impl PolicyEngine {
        pub fn new() -> Self {
            Self {
                principals: HashMap::new(),
                leases: HashMap::new(),
                next_lease_id: 1,
            }
        }

        pub fn grant(
            &mut self,
            actor: impl Into<String>,
            role: Role,
            capability: impl Into<String>,
        ) {
            let principal = self.principals.entry(actor.into()).or_insert(Principal {
                role,
                capabilities: HashSet::new(),
            });
            principal.role = role;
            principal.capabilities.insert(capability.into());
        }

        pub fn acquire_lease(
            &mut self,
            device_id: &str,
            holder: &str,
            lifetime: Duration,
        ) -> Result<LeaseId, AuthorizationError> {
            if self.principals.get(holder).map(|principal| principal.role) != Some(Role::Operator) {
                return Err(AuthorizationError::ObserverReadOnly);
            }
            let now = Instant::now();
            if self.leases.values().any(|lease| {
                lease.device_id == device_id && !lease.revoked && now < lease.expires_at
            }) {
                return Err(AuthorizationError::DeviceAlreadyLeased);
            }
            let id = LeaseId(self.next_lease_id);
            self.next_lease_id += 1;
            self.leases.insert(
                id,
                Lease {
                    device_id: device_id.to_owned(),
                    holder: holder.to_owned(),
                    expires_at: now + lifetime,
                    revoked: false,
                },
            );
            Ok(id)
        }

        pub fn revoke_lease(&mut self, lease_id: LeaseId) {
            if let Some(lease) = self.leases.get_mut(&lease_id) {
                lease.revoked = true;
            }
        }

        pub fn lease_is_active(&self, lease_id: LeaseId) -> bool {
            let now = Instant::now();
            self.leases
                .get(&lease_id)
                .is_some_and(|lease| !lease.revoked && now < lease.expires_at)
        }

        pub fn execute<T>(
            &mut self,
            actor: &str,
            operation: Operation<'_>,
            lease_id: Option<LeaseId>,
            adapter: impl FnOnce() -> T,
        ) -> Result<T, AuthorizationError> {
            let Some(principal) = self.principals.get(actor) else {
                return Err(AuthorizationError::CapabilityDenied);
            };
            if !principal.capabilities.contains(operation.capability()) {
                return Err(AuthorizationError::CapabilityDenied);
            }
            let device_id = operation.device_id();
            if principal.role == Role::Observer
                && !matches!(
                    operation,
                    Operation::ReadLogs | Operation::AppleReadReleasedLogs
                )
            {
                return Err(AuthorizationError::ObserverReadOnly);
            }
            if let Some(device_id) = device_id {
                let Some(lease_id) = lease_id else {
                    return Err(AuthorizationError::LeaseInactive);
                };
                let now = Instant::now();
                let active_for_device = self.leases.get(&lease_id).is_some_and(|lease| {
                    lease.device_id == device_id
                        && lease.holder == actor
                        && !lease.revoked
                        && now < lease.expires_at
                });
                if !active_for_device {
                    return Err(AuthorizationError::LeaseInactive);
                }
            }
            Ok(adapter())
        }
    }

    impl Default for PolicyEngine {
        fn default() -> Self {
            Self::new()
        }
    }
}

pub mod device_adapter {
    use crate::authorization::{AuthorizationError, LeaseId, Operation, PolicyEngine};
    use std::time::Duration;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum AdapterError {
        CapabilityDenied,
        LeaseInactive,
        UnsupportedCapability,
        WaitingForDevice,
    }

    impl AdapterError {
        pub fn code(self) -> &'static str {
            match self {
                Self::CapabilityDenied => "capability_denied",
                Self::LeaseInactive => "lease_inactive",
                Self::UnsupportedCapability => "unsupported_capability",
                Self::WaitingForDevice => "waiting_for_device",
            }
        }
    }

    impl From<AuthorizationError> for AdapterError {
        fn from(error: AuthorizationError) -> Self {
            match error {
                AuthorizationError::LeaseInactive => Self::LeaseInactive,
                _ => Self::CapabilityDenied,
            }
        }
    }

    pub struct AdapterContext<'a> {
        policy: &'a mut PolicyEngine,
        actor: &'a str,
        lease: Option<LeaseId>,
    }

    impl<'a> AdapterContext<'a> {
        pub fn new(policy: &'a mut PolicyEngine, actor: &'a str) -> Self {
            Self {
                policy,
                actor,
                lease: None,
            }
        }

        fn authorize<T>(
            &mut self,
            operation: Operation<'_>,
            action: impl FnOnce() -> T,
        ) -> Result<T, AdapterError> {
            self.policy
                .execute(self.actor, operation, self.lease, action)
                .map_err(Into::into)
        }

        pub(crate) fn authorize_simulator<T>(
            &mut self,
            operation: Operation<'_>,
            action: impl FnOnce() -> T,
        ) -> Result<T, AdapterError> {
            self.authorize(operation, action)
        }

        pub(crate) fn authorize_adapter<T>(
            &mut self,
            operation: Operation<'_>,
            action: impl FnOnce() -> T,
        ) -> Result<T, AdapterError> {
            self.authorize(operation, action)
        }

        pub(crate) fn authorize_apple<T>(
            &mut self,
            operation: Operation<'_>,
            action: impl FnOnce() -> T,
        ) -> Result<T, AuthorizationError> {
            self.policy
                .execute(self.actor, operation, self.lease, action)
        }

        pub(crate) fn acquire_lease(
            &mut self,
            device_id: &str,
            lifetime: Duration,
        ) -> Result<(), AdapterError> {
            self.authorize(Operation::LeaseDevice, || ())?;
            self.lease = Some(self.policy.acquire_lease(device_id, self.actor, lifetime)?);
            Ok(())
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct AdapterDevice {
        pub id: String,
        pub state: DeviceState,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum DeviceState {
        Attached,
        Detached,
    }

    pub(crate) mod sealed {
        pub trait Sealed {}
    }

    pub trait DeviceAdapter: sealed::Sealed {
        fn discover(
            &mut self,
            context: &mut AdapterContext<'_>,
        ) -> Result<Vec<AdapterDevice>, AdapterError>;
        fn lease(
            &mut self,
            context: &mut AdapterContext<'_>,
            device_id: &str,
            lifetime: Duration,
        ) -> Result<(), AdapterError>;
        fn install(
            &mut self,
            context: &mut AdapterContext<'_>,
            device_id: &str,
            artifact: &[u8],
        ) -> Result<(), AdapterError>;
        fn launch(
            &mut self,
            context: &mut AdapterContext<'_>,
            device_id: &str,
            application: &str,
        ) -> Result<(), AdapterError>;
        fn stop(
            &mut self,
            context: &mut AdapterContext<'_>,
            device_id: &str,
        ) -> Result<(), AdapterError>;
        fn logs(
            &mut self,
            context: &mut AdapterContext<'_>,
            device_id: &str,
        ) -> Result<Vec<u8>, AdapterError>;
        fn artifact(
            &mut self,
            context: &mut AdapterContext<'_>,
            device_id: &str,
        ) -> Result<Vec<u8>, AdapterError>;
        fn attach_debugger(
            &mut self,
            context: &mut AdapterContext<'_>,
            device_id: &str,
        ) -> Result<(), AdapterError>;
    }

    pub trait DeviceAdapterBackend {
        fn discover(&mut self) -> Vec<AdapterDevice>;
        fn install(&mut self, device_id: &str, artifact: &[u8]);
        fn launch(&mut self, device_id: &str, application: &str) -> Result<(), AdapterError>;
        fn stop(&mut self, device_id: &str);
        fn logs(&mut self, device_id: &str) -> Vec<u8>;
        fn artifact(&mut self, device_id: &str) -> Vec<u8>;
        fn attach_debugger(&mut self, device_id: &str) -> Result<(), AdapterError>;
    }

    pub struct AuthorizedAdapter<B> {
        backend: B,
    }

    impl<B> AuthorizedAdapter<B> {
        pub fn from_backend(backend: B) -> Self {
            Self { backend }
        }
    }

    pub struct FakeBackend {
        state: DeviceState,
        installed: Vec<u8>,
        logs: Vec<u8>,
        running: bool,
    }

    pub type FakeDeviceAdapter = AuthorizedAdapter<FakeBackend>;

    impl<B> sealed::Sealed for AuthorizedAdapter<B> {}

    impl AuthorizedAdapter<FakeBackend> {
        pub fn new() -> Self {
            Self {
                backend: FakeBackend {
                    state: DeviceState::Attached,
                    installed: Vec::new(),
                    logs: Vec::new(),
                    running: false,
                },
            }
        }

        pub fn set_state(&mut self, state: DeviceState) {
            self.backend.state = state;
        }
    }

    impl Default for AuthorizedAdapter<FakeBackend> {
        fn default() -> Self {
            Self::new()
        }
    }

    impl<B: DeviceAdapterBackend> DeviceAdapter for AuthorizedAdapter<B> {
        fn discover(
            &mut self,
            context: &mut AdapterContext<'_>,
        ) -> Result<Vec<AdapterDevice>, AdapterError> {
            context.authorize(Operation::DiscoverDevices, || self.backend.discover())
        }

        fn lease(
            &mut self,
            context: &mut AdapterContext<'_>,
            device_id: &str,
            lifetime: Duration,
        ) -> Result<(), AdapterError> {
            context.authorize(Operation::LeaseDevice, || ())?;
            context.lease = Some(context.policy.acquire_lease(
                device_id,
                context.actor,
                lifetime,
            )?);
            Ok(())
        }

        fn install(
            &mut self,
            context: &mut AdapterContext<'_>,
            device_id: &str,
            artifact: &[u8],
        ) -> Result<(), AdapterError> {
            context.authorize(Operation::InstallDevice { device_id }, || ())?;
            self.backend.install(device_id, artifact);
            Ok(())
        }

        fn launch(
            &mut self,
            context: &mut AdapterContext<'_>,
            device_id: &str,
            application: &str,
        ) -> Result<(), AdapterError> {
            context.authorize(Operation::StartProcess { device_id }, || ())?;
            self.backend.launch(device_id, application)
        }

        fn stop(
            &mut self,
            context: &mut AdapterContext<'_>,
            device_id: &str,
        ) -> Result<(), AdapterError> {
            context.authorize(Operation::StopProcess { device_id }, || ())?;
            self.backend.stop(device_id);
            Ok(())
        }

        fn logs(
            &mut self,
            context: &mut AdapterContext<'_>,
            device_id: &str,
        ) -> Result<Vec<u8>, AdapterError> {
            context.authorize(Operation::ReadDeviceLogs { device_id }, || {
                self.backend.logs(device_id)
            })
        }

        fn artifact(
            &mut self,
            context: &mut AdapterContext<'_>,
            device_id: &str,
        ) -> Result<Vec<u8>, AdapterError> {
            context.authorize(Operation::ReadArtifact { device_id }, || {
                self.backend.artifact(device_id)
            })
        }

        fn attach_debugger(
            &mut self,
            context: &mut AdapterContext<'_>,
            device_id: &str,
        ) -> Result<(), AdapterError> {
            context.authorize(Operation::AttachDebugger { device_id }, || ())?;
            self.backend.attach_debugger(device_id)
        }
    }

    impl DeviceAdapterBackend for FakeBackend {
        fn discover(&mut self) -> Vec<AdapterDevice> {
            vec![AdapterDevice {
                id: "fake-1".to_owned(),
                state: self.state,
            }]
        }

        fn install(&mut self, _device_id: &str, artifact: &[u8]) {
            self.installed = artifact.to_vec();
        }

        fn launch(&mut self, _device_id: &str, application: &str) -> Result<(), AdapterError> {
            if self.state == DeviceState::Detached {
                return Err(AdapterError::WaitingForDevice);
            }
            self.running = true;
            self.logs = format!("{application} launched").into_bytes();
            Ok(())
        }

        fn stop(&mut self, _device_id: &str) {
            self.running = false;
        }

        fn logs(&mut self, _device_id: &str) -> Vec<u8> {
            self.logs.clone()
        }

        fn artifact(&mut self, _device_id: &str) -> Vec<u8> {
            self.installed.clone()
        }

        fn attach_debugger(&mut self, _device_id: &str) -> Result<(), AdapterError> {
            Err(AdapterError::UnsupportedCapability)
        }
    }
}

pub mod apple_physical_device {
    use crate::authorization::{AuthorizationError, Operation};
    use crate::device_adapter::AdapterContext;
    use crate::preflight::{AppleTool, AppleToolRunner};
    use crate::process_execution::{CancellationToken, EventKind, TerminalStatus};
    use std::collections::HashMap;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum PhysicalDeviceError {
        CapabilityDenied,
        LeaseInactive,
        ObserverReadOnly,
        InvalidDeviceId,
        InvalidBundleId,
        InvalidAppPath,
        Locked,
        Untrusted,
        DeveloperModeDisabled,
        SigningFailed,
        DeviceBusy,
        Detached,
    }

    impl PhysicalDeviceError {
        pub fn repair(self) -> &'static str {
            match self {
                Self::Locked => "Unlock the iPhone and keep it connected to this Mac.",
                Self::Untrusted => "Unlock the iPhone, trust this Mac, and pair it again.",
                Self::DeveloperModeDisabled => {
                    "Enable Developer Mode in Settings > Privacy & Security, then restart the iPhone."
                }
                Self::SigningFailed => {
                    "Select a valid development team and provisioning profile, then rebuild the app."
                }
                Self::DeviceBusy => "Wait for the current device operation to finish, then retry.",
                Self::Detached => {
                    "Reconnect the iPhone by USB or restore its paired network connection."
                }
                Self::CapabilityDenied => "Grant the required versioned Apple capability.",
                Self::LeaseInactive => "Acquire a valid exclusive lease for this device.",
                Self::ObserverReadOnly => "Use an operator identity for device operations.",
                Self::InvalidDeviceId => "Use the exact device identifier reported by discovery.",
                Self::InvalidBundleId => "Use a valid reverse-DNS bundle identifier.",
                Self::InvalidAppPath => "Use an existing .app directory inside the workspace.",
            }
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum PhysicalDeviceOperation {
        Install { app_path: PathBuf },
        Launch { bundle_id: String },
        Terminate { bundle_id: String },
        Uninstall { bundle_id: String },
        DeviceInfo,
        LogStream { bundle_id: String },
    }

    impl PhysicalDeviceOperation {
        pub fn arguments(&self, device_id: &str) -> Result<Vec<String>, PhysicalDeviceError> {
            validate_device_id(device_id)?;
            Ok(match self {
                Self::Install { app_path } => vec![
                    "device".into(),
                    "install".into(),
                    "app".into(),
                    "--device".into(),
                    device_id.into(),
                    app_path.to_string_lossy().into_owned(),
                ],
                Self::Launch { bundle_id } => {
                    validate_bundle_id(bundle_id)?;
                    vec![
                        "device".into(),
                        "process".into(),
                        "launch".into(),
                        "--device".into(),
                        device_id.into(),
                        bundle_id.clone(),
                    ]
                }
                Self::Terminate { bundle_id } => {
                    validate_bundle_id(bundle_id)?;
                    vec![
                        "device".into(),
                        "process".into(),
                        "terminate".into(),
                        "--device".into(),
                        device_id.into(),
                        bundle_id.clone(),
                    ]
                }
                Self::Uninstall { bundle_id } => {
                    validate_bundle_id(bundle_id)?;
                    vec![
                        "device".into(),
                        "uninstall".into(),
                        "app".into(),
                        "--device".into(),
                        device_id.into(),
                        bundle_id.clone(),
                    ]
                }
                Self::DeviceInfo => vec![
                    "device".into(),
                    "info".into(),
                    "details".into(),
                    "--device".into(),
                    device_id.into(),
                ],
                Self::LogStream { bundle_id } => {
                    validate_bundle_id(bundle_id)?;
                    vec![
                        "device".into(),
                        "process".into(),
                        "launch".into(),
                        "--device".into(),
                        device_id.into(),
                        "--console".into(),
                        bundle_id.clone(),
                    ]
                }
            })
        }
    }

    pub struct ApplePhysicalDevice {
        runner: AppleToolRunner,
        timeout: Duration,
        workspace: PathBuf,
        leases: HashMap<String, Instant>,
        released_logs: HashMap<String, Vec<u8>>,
    }

    impl ApplePhysicalDevice {
        pub fn new(runner: AppleToolRunner, timeout: Duration) -> Self {
            Self {
                workspace: runner.workspace().to_owned(),
                runner,
                timeout,
                leases: HashMap::new(),
                released_logs: HashMap::new(),
            }
        }

        pub fn lease(
            &mut self,
            context: &mut AdapterContext<'_>,
            device_id: &str,
            lifetime: Duration,
        ) -> Result<(), PhysicalDeviceError> {
            validate_device_id(device_id)?;
            if self
                .leases
                .get(device_id)
                .is_some_and(|expires| Instant::now() < *expires)
            {
                return Err(PhysicalDeviceError::DeviceBusy);
            }
            context
                .acquire_lease(device_id, lifetime)
                .map_err(map_adapter_error)?;
            self.leases
                .insert(device_id.into(), Instant::now() + lifetime);
            Ok(())
        }

        pub fn execute(
            &mut self,
            context: &mut AdapterContext<'_>,
            device_id: &str,
            operation: PhysicalDeviceOperation,
        ) -> Result<Vec<u8>, PhysicalDeviceError> {
            let mut args = operation.arguments(device_id)?;
            if let PhysicalDeviceOperation::Install { app_path } = &operation {
                let app_path = validate_app_path(&self.workspace, app_path)?;
                *args.last_mut().expect("install always has an app path") =
                    app_path.to_string_lossy().into_owned();
            }
            let authorization = match operation {
                PhysicalDeviceOperation::Install { .. } => Operation::AppleInstall { device_id },
                PhysicalDeviceOperation::Launch { .. } => Operation::AppleLaunch { device_id },
                PhysicalDeviceOperation::Terminate { .. } => {
                    Operation::AppleTerminate { device_id }
                }
                PhysicalDeviceOperation::Uninstall { .. } => {
                    Operation::AppleUninstall { device_id }
                }
                PhysicalDeviceOperation::LogStream { .. } => {
                    Operation::AppleLogStream { device_id }
                }
                PhysicalDeviceOperation::DeviceInfo => Operation::AppleDeviceInfo,
            };
            context
                .authorize_apple(authorization, || ())
                .map_err(PhysicalDeviceError::from)?;
            let events = self
                .runner
                .execute(
                    AppleTool::Devicectl,
                    args,
                    ".",
                    HashMap::new(),
                    self.timeout,
                    CancellationToken::new(),
                )
                .map_err(|_| PhysicalDeviceError::DeviceBusy)?;
            let output = events
                .iter()
                .filter(|event| matches!(event.kind, EventKind::Stdout))
                .flat_map(|event| event.payload.iter().copied())
                .collect::<Vec<_>>();
            if !matches!(
                events.last().map(|event| &event.kind),
                Some(EventKind::Terminal(TerminalStatus::Exited(0)))
            ) {
                let error = events
                    .iter()
                    .filter(|event| matches!(event.kind, EventKind::Stderr))
                    .flat_map(|event| event.payload.iter().copied())
                    .collect::<Vec<_>>();
                return Err(Self::normalize_failure(&String::from_utf8_lossy(&error)));
            }
            if matches!(operation, PhysicalDeviceOperation::LogStream { .. }) {
                self.release_logs(device_id, output.clone());
            }
            Ok(output)
        }

        pub fn release_logs(&mut self, device_id: &str, logs: Vec<u8>) {
            self.released_logs.insert(device_id.into(), logs);
        }

        pub fn read_released_logs(
            &self,
            context: &mut AdapterContext<'_>,
            device_id: &str,
        ) -> Result<Vec<u8>, PhysicalDeviceError> {
            validate_device_id(device_id)?;
            context
                .authorize_apple(Operation::AppleReadReleasedLogs, || ())
                .map_err(PhysicalDeviceError::from)?;
            Ok(self
                .released_logs
                .get(device_id)
                .cloned()
                .unwrap_or_default())
        }

        pub fn normalize_failure(stderr: &str) -> PhysicalDeviceError {
            let stderr = stderr.to_ascii_lowercase();
            if stderr.contains("locked") {
                Self::locked()
            } else if stderr.contains("not trusted") || stderr.contains("trust this host") {
                PhysicalDeviceError::Untrusted
            } else if stderr.contains("developer mode") && stderr.contains("disabled") {
                PhysicalDeviceError::DeveloperModeDisabled
            } else if stderr.contains("signing") || stderr.contains("applicationverificationfailed")
            {
                PhysicalDeviceError::SigningFailed
            } else if stderr.contains("disconnect") || stderr.contains("detached") {
                PhysicalDeviceError::Detached
            } else {
                PhysicalDeviceError::DeviceBusy
            }
        }

        fn locked() -> PhysicalDeviceError {
            PhysicalDeviceError::Locked
        }
    }

    fn map_adapter_error(error: crate::device_adapter::AdapterError) -> PhysicalDeviceError {
        match error {
            crate::device_adapter::AdapterError::LeaseInactive => {
                PhysicalDeviceError::LeaseInactive
            }
            _ => PhysicalDeviceError::CapabilityDenied,
        }
    }

    fn validate_device_id(value: &str) -> Result<(), PhysicalDeviceError> {
        (!value.is_empty()
            && value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')))
        .then_some(())
        .ok_or(PhysicalDeviceError::InvalidDeviceId)
    }

    fn validate_bundle_id(value: &str) -> Result<(), PhysicalDeviceError> {
        let valid = value.len() <= 255
            && value.split('.').count() >= 2
            && value.split('.').all(|part| {
                !part.is_empty() && part.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            });
        valid
            .then_some(())
            .ok_or(PhysicalDeviceError::InvalidBundleId)
    }

    fn validate_app_path(workspace: &Path, path: &Path) -> Result<PathBuf, PhysicalDeviceError> {
        if path.extension().and_then(|value| value.to_str()) != Some("app") {
            return Err(PhysicalDeviceError::InvalidAppPath);
        }
        fs::canonicalize(workspace.join(path))
            .ok()
            .filter(|resolved| resolved.starts_with(workspace) && resolved.is_dir())
            .ok_or(PhysicalDeviceError::InvalidAppPath)
    }

    impl From<AuthorizationError> for PhysicalDeviceError {
        fn from(error: AuthorizationError) -> Self {
            match error {
                AuthorizationError::LeaseInactive => Self::LeaseInactive,
                AuthorizationError::ObserverReadOnly => Self::ObserverReadOnly,
                _ => Self::CapabilityDenied,
            }
        }
    }
}

pub mod apple_simulator {
    use crate::authorization::Operation;
    use crate::device_adapter::{
        self, AdapterContext, AdapterDevice, AdapterError, DeviceAdapter, DeviceState,
    };
    use crate::preflight::AppleTool;
    use crate::preflight::AppleToolRunner;
    use crate::process_execution::{CancellationToken, EventKind, TerminalStatus};
    use std::collections::HashMap;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SimulatorState {
        Shutdown,
        Booted,
        Deleted,
        Unchanged,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SimulatorError {
        CapabilityDenied,
        LeaseInactive,
        WorkspaceEscape,
        Busy,
        BootFailed,
        RuntimeMissing,
        Detached,
    }

    impl SimulatorError {
        pub fn code(self) -> &'static str {
            match self {
                Self::CapabilityDenied => "capability_denied",
                Self::LeaseInactive => "lease_inactive",
                Self::WorkspaceEscape => "workspace_escape",
                Self::Busy => "busy",
                Self::BootFailed => "boot_failed",
                Self::RuntimeMissing => "runtime_missing",
                Self::Detached => "detach",
            }
        }
    }

    impl From<AdapterError> for SimulatorError {
        fn from(error: AdapterError) -> Self {
            match error {
                AdapterError::LeaseInactive => Self::LeaseInactive,
                _ => Self::CapabilityDenied,
            }
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum SimulatorOperation {
        Create {
            name: String,
            device_type: String,
            runtime: String,
        },
        Boot,
        BootStatus,
        Shutdown,
        Delete,
        Install {
            path: PathBuf,
        },
        Uninstall {
            bundle_id: String,
        },
        Launch {
            bundle_id: String,
        },
        Terminate {
            bundle_id: String,
        },
        Screenshot {
            path: PathBuf,
        },
        LogStream,
        Location {
            latitude: String,
            longitude: String,
        },
        Privacy {
            service: String,
            bundle_id: String,
            grant: bool,
        },
        AddMedia {
            paths: Vec<PathBuf>,
        },
    }

    impl SimulatorOperation {
        pub fn arguments(&self) -> Vec<String> {
            self.arguments_for("sim-1")
        }

        fn arguments_for(&self, device_id: &str) -> Vec<String> {
            match self {
                Self::Create {
                    name,
                    device_type,
                    runtime,
                } => vec![
                    "create".into(),
                    name.clone(),
                    device_type.clone(),
                    runtime.clone(),
                ],
                Self::Boot => vec!["boot".into(), device_id.into()],
                Self::BootStatus => vec!["bootstatus".into(), device_id.into(), "-b".into()],
                Self::Shutdown => vec!["shutdown".into(), device_id.into()],
                Self::Delete => vec!["delete".into(), device_id.into()],
                Self::Install { path } => vec![
                    "install".into(),
                    device_id.into(),
                    path.to_string_lossy().into_owned(),
                ],
                Self::Uninstall { bundle_id } => {
                    vec!["uninstall".into(), device_id.into(), bundle_id.clone()]
                }
                Self::Launch { bundle_id } => {
                    vec!["launch".into(), device_id.into(), bundle_id.clone()]
                }
                Self::Terminate { bundle_id } => {
                    vec!["terminate".into(), device_id.into(), bundle_id.clone()]
                }
                Self::Screenshot { path } => vec![
                    "io".into(),
                    device_id.into(),
                    "screenshot".into(),
                    path.to_string_lossy().into_owned(),
                ],
                Self::LogStream => vec![
                    "spawn".into(),
                    device_id.into(),
                    "log".into(),
                    "stream".into(),
                ],
                Self::Location {
                    latitude,
                    longitude,
                } => vec![
                    "location".into(),
                    device_id.into(),
                    "set".into(),
                    format!("{latitude},{longitude}"),
                ],
                Self::Privacy {
                    service,
                    bundle_id,
                    grant,
                } => vec![
                    "privacy".into(),
                    device_id.into(),
                    if *grant { "grant" } else { "revoke" }.into(),
                    service.clone(),
                    bundle_id.clone(),
                ],
                Self::AddMedia { paths } => std::iter::once("addmedia".into())
                    .chain(std::iter::once(device_id.into()))
                    .chain(paths.iter().map(|p| p.to_string_lossy().into_owned()))
                    .collect(),
            }
        }
    }

    pub struct AppleSimulator {
        runner: AppleToolRunner,
        timeout: Duration,
        workspace: PathBuf,
        states: HashMap<String, SimulatorState>,
        installed: Vec<u8>,
        application: Option<String>,
    }

    impl AppleSimulator {
        pub fn new(runner: AppleToolRunner, timeout: Duration) -> Self {
            let workspace = runner.workspace().to_owned();
            Self {
                runner,
                timeout,
                workspace,
                states: HashMap::new(),
                installed: Vec::new(),
                application: None,
            }
        }

        pub fn lease(
            &mut self,
            context: &mut AdapterContext<'_>,
            device_id: &str,
            lifetime: Duration,
        ) -> Result<(), SimulatorError> {
            context
                .acquire_lease(device_id, lifetime)
                .map_err(Into::into)
        }

        pub fn execute(
            &mut self,
            context: &mut AdapterContext<'_>,
            device_id: &str,
            operation: SimulatorOperation,
        ) -> Result<SimulatorState, SimulatorError> {
            self.validate_paths(&operation)?;
            let authorization = match operation {
                SimulatorOperation::Install { .. } => Operation::InstallDevice { device_id },
                SimulatorOperation::Launch { .. } => Operation::StartProcess { device_id },
                SimulatorOperation::Terminate { .. } => Operation::StopProcess { device_id },
                SimulatorOperation::LogStream => Operation::ReadDeviceLogs { device_id },
                SimulatorOperation::Screenshot { .. } => {
                    Operation::SimulatorScreenshot { device_id }
                }
                SimulatorOperation::Location { .. } => Operation::SimulatorLocation { device_id },
                SimulatorOperation::Privacy { .. } => Operation::SimulatorPrivacy { device_id },
                SimulatorOperation::AddMedia { .. } => Operation::SimulatorMedia { device_id },
                _ => Operation::SimulatorLifecycle { device_id },
            };
            context.authorize_simulator(authorization, || ())?;
            if matches!(operation, SimulatorOperation::Boot)
                && self.states.get(device_id) == Some(&SimulatorState::Booted)
            {
                return Ok(SimulatorState::Booted);
            }
            if matches!(operation, SimulatorOperation::Shutdown)
                && self.states.get(device_id) == Some(&SimulatorState::Shutdown)
            {
                return Ok(SimulatorState::Shutdown);
            }
            if matches!(operation, SimulatorOperation::Delete)
                && self.states.get(device_id) == Some(&SimulatorState::Deleted)
            {
                return Ok(SimulatorState::Deleted);
            }
            let events = self
                .runner
                .execute(
                    AppleTool::Simctl,
                    operation.arguments_for(device_id),
                    ".",
                    HashMap::new(),
                    self.timeout,
                    CancellationToken::new(),
                )
                .map_err(|_| SimulatorError::Busy)?;
            if !events
                .iter()
                .any(|event| matches!(event.kind, EventKind::Terminal(TerminalStatus::Exited(0))))
            {
                let stderr = events
                    .iter()
                    .filter(|event| matches!(event.kind, EventKind::Stderr))
                    .flat_map(|event| event.payload.iter().copied())
                    .collect::<Vec<_>>();
                let stderr = String::from_utf8_lossy(&stderr);
                return Err(if stderr.contains("runtime_missing") {
                    SimulatorError::RuntimeMissing
                } else if stderr.contains("boot_failed") {
                    SimulatorError::BootFailed
                } else if stderr.contains("detach") {
                    SimulatorError::Detached
                } else {
                    SimulatorError::Busy
                });
            }
            let state = match operation {
                SimulatorOperation::Boot | SimulatorOperation::BootStatus => SimulatorState::Booted,
                SimulatorOperation::Shutdown => SimulatorState::Shutdown,
                SimulatorOperation::Delete => SimulatorState::Deleted,
                _ => SimulatorState::Unchanged,
            };
            self.states.insert(device_id.to_owned(), state);
            Ok(state)
        }

        fn validate_paths(&self, operation: &SimulatorOperation) -> Result<(), SimulatorError> {
            match operation {
                SimulatorOperation::Install { path } => self.input_path(path),
                SimulatorOperation::AddMedia { paths } => {
                    paths.iter().try_for_each(|path| self.input_path(path))
                }
                SimulatorOperation::Screenshot { path } => self.output_path(path),
                _ => Ok(()),
            }
        }

        fn input_path(&self, path: &Path) -> Result<(), SimulatorError> {
            fs::canonicalize(self.workspace.join(path))
                .ok()
                .filter(|path| path.starts_with(&self.workspace))
                .map(|_| ())
                .ok_or(SimulatorError::WorkspaceEscape)
        }

        fn output_path(&self, path: &Path) -> Result<(), SimulatorError> {
            let destination = self.workspace.join(path);
            if fs::symlink_metadata(&destination)
                .ok()
                .is_some_and(|metadata| {
                    metadata.file_type().is_symlink()
                        || !fs::canonicalize(&destination)
                            .ok()
                            .is_some_and(|path| path.starts_with(&self.workspace))
                })
            {
                return Err(SimulatorError::WorkspaceEscape);
            }
            let parent = path.parent().unwrap_or(Path::new("."));
            fs::canonicalize(self.workspace.join(parent))
                .ok()
                .filter(|path| path.starts_with(&self.workspace))
                .map(|_| ())
                .ok_or(SimulatorError::WorkspaceEscape)
        }
    }

    impl device_adapter::sealed::Sealed for AppleSimulator {}

    impl DeviceAdapter for AppleSimulator {
        fn discover(
            &mut self,
            context: &mut AdapterContext<'_>,
        ) -> Result<Vec<AdapterDevice>, AdapterError> {
            context.authorize_adapter(Operation::DiscoverDevices, || {
                vec![AdapterDevice {
                    id: "sim-1".into(),
                    state: DeviceState::Attached,
                }]
            })
        }

        fn lease(
            &mut self,
            context: &mut AdapterContext<'_>,
            device_id: &str,
            lifetime: Duration,
        ) -> Result<(), AdapterError> {
            AppleSimulator::lease(self, context, device_id, lifetime)
                .map_err(simulator_adapter_error)
        }

        fn install(
            &mut self,
            context: &mut AdapterContext<'_>,
            device_id: &str,
            artifact: &[u8],
        ) -> Result<(), AdapterError> {
            context.authorize_adapter(Operation::InstallDevice { device_id }, || ())?;
            let path = self.workspace.join(".mesh-simulator-install.app");
            fs::write(&path, artifact).map_err(|_| AdapterError::UnsupportedCapability)?;
            self.execute(
                context,
                device_id,
                SimulatorOperation::Install {
                    path: path.strip_prefix(&self.workspace).unwrap().into(),
                },
            )
            .map_err(simulator_adapter_error)?;
            self.installed = artifact.to_vec();
            Ok(())
        }

        fn launch(
            &mut self,
            context: &mut AdapterContext<'_>,
            device_id: &str,
            application: &str,
        ) -> Result<(), AdapterError> {
            self.execute(
                context,
                device_id,
                SimulatorOperation::Launch {
                    bundle_id: application.into(),
                },
            )
            .map_err(simulator_adapter_error)?;
            self.application = Some(application.into());
            Ok(())
        }

        fn stop(
            &mut self,
            context: &mut AdapterContext<'_>,
            device_id: &str,
        ) -> Result<(), AdapterError> {
            let application = self.application.clone().unwrap_or_default();
            self.execute(
                context,
                device_id,
                SimulatorOperation::Terminate {
                    bundle_id: application,
                },
            )
            .map_err(simulator_adapter_error)?;
            Ok(())
        }

        fn logs(
            &mut self,
            context: &mut AdapterContext<'_>,
            device_id: &str,
        ) -> Result<Vec<u8>, AdapterError> {
            context.authorize_adapter(Operation::ReadDeviceLogs { device_id }, || {
                self.application
                    .as_ref()
                    .map(|app| format!("{app} launched").into_bytes())
                    .unwrap_or_default()
            })
        }

        fn artifact(
            &mut self,
            context: &mut AdapterContext<'_>,
            device_id: &str,
        ) -> Result<Vec<u8>, AdapterError> {
            context.authorize_adapter(Operation::ReadArtifact { device_id }, || {
                self.installed.clone()
            })
        }

        fn attach_debugger(
            &mut self,
            context: &mut AdapterContext<'_>,
            device_id: &str,
        ) -> Result<(), AdapterError> {
            context.authorize_adapter(Operation::AttachDebugger { device_id }, || ())?;
            Err(AdapterError::UnsupportedCapability)
        }
    }

    fn simulator_adapter_error(error: SimulatorError) -> AdapterError {
        match error {
            SimulatorError::CapabilityDenied => AdapterError::CapabilityDenied,
            SimulatorError::LeaseInactive => AdapterError::LeaseInactive,
            SimulatorError::Detached => AdapterError::WaitingForDevice,
            _ => AdapterError::UnsupportedCapability,
        }
    }
}

pub mod workspace {
    use cap_std::ambient_authority;
    use cap_std::fs::Dir;
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;
    use std::fs;
    use std::fs::OpenOptions;
    use std::io::{ErrorKind, Write};
    use std::path::{Component, Path, PathBuf};

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum WorkspaceError {
        PathEscape,
        WriteLeaseConflict,
        WriteLeaseRequired,
        Io,
    }

    pub struct ManifestEntry {
        path: PathBuf,
        contents: Vec<u8>,
    }

    impl ManifestEntry {
        pub fn new(path: impl Into<PathBuf>, contents: Vec<u8>) -> Self {
            Self {
                path: path.into(),
                contents,
            }
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    pub struct ManifestHash {
        path: String,
        sha256: String,
    }

    impl ManifestHash {
        pub fn path(&self) -> &str {
            &self.path
        }

        pub fn sha256(&self) -> &str {
            &self.sha256
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    pub struct Manifest {
        entries: Vec<ManifestHash>,
    }

    impl Manifest {
        pub fn entries(&self) -> &[ManifestHash] {
            &self.entries
        }
    }

    pub struct WorkspaceManager {
        root: PathBuf,
        root_dir: Dir,
        write_leases: HashMap<(String, String), String>,
    }

    impl WorkspaceManager {
        pub fn new(root: impl AsRef<Path>) -> Result<Self, WorkspaceError> {
            fs::create_dir_all(root.as_ref()).map_err(|_| WorkspaceError::Io)?;
            let root = fs::canonicalize(root.as_ref()).map_err(|_| WorkspaceError::Io)?;
            let root_dir = Dir::open_ambient_dir(&root, ambient_authority())
                .map_err(|_| WorkspaceError::Io)?;
            Ok(Self {
                root,
                root_dir,
                write_leases: HashMap::new(),
            })
        }

        pub fn acquire_write_lease(
            &mut self,
            agent_id: &str,
            session_id: &str,
            client_id: &str,
        ) -> Result<(), WorkspaceError> {
            validate_agent_name(agent_id)?;
            validate_name(session_id)?;
            let key = (agent_id.to_owned(), session_id.to_owned());
            if self
                .write_leases
                .get(&key)
                .is_some_and(|holder| holder != client_id)
            {
                return Err(WorkspaceError::WriteLeaseConflict);
            }
            let session = self.root.join(agent_id).join(session_id);
            fs::create_dir_all(&session).map_err(|_| WorkspaceError::Io)?;
            if !fs::canonicalize(&session)
                .map_err(|_| WorkspaceError::Io)?
                .starts_with(&self.root)
            {
                return Err(WorkspaceError::PathEscape);
            }
            let lease = self.root.join(".leases").join(agent_id).join(session_id);
            fs::create_dir_all(lease.parent().unwrap()).map_err(|_| WorkspaceError::Io)?;
            match OpenOptions::new().write(true).create_new(true).open(&lease) {
                Ok(mut file) => file
                    .write_all(client_id.as_bytes())
                    .map_err(|_| WorkspaceError::Io)?,
                Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                    if fs::read_to_string(&lease).map_err(|_| WorkspaceError::Io)? != client_id {
                        return Err(WorkspaceError::WriteLeaseConflict);
                    }
                }
                Err(_) => return Err(WorkspaceError::Io),
            }
            self.write_leases.insert(key, client_id.to_owned());
            Ok(())
        }

        pub fn upload_manifest(
            &self,
            agent_id: &str,
            session_id: &str,
            client_id: &str,
            entries: Vec<ManifestEntry>,
        ) -> Result<Manifest, WorkspaceError> {
            validate_agent_name(agent_id)?;
            validate_name(session_id)?;
            if self
                .write_leases
                .get(&(agent_id.to_owned(), session_id.to_owned()))
                .map(String::as_str)
                != Some(client_id)
            {
                return Err(WorkspaceError::WriteLeaseRequired);
            }
            let session = fs::canonicalize(self.root.join(agent_id).join(session_id))
                .map_err(|_| WorkspaceError::Io)?;
            let session_dir = self
                .root_dir
                .open_dir(Path::new(agent_id).join(session_id))
                .map_err(|_| WorkspaceError::PathEscape)?;
            let mut hashes = Vec::with_capacity(entries.len());
            for entry in entries {
                validate_relative_path(&entry.path)?;
                let destination = session.join(&entry.path);
                let mut ancestor = destination.parent().ok_or(WorkspaceError::PathEscape)?;
                while !ancestor.exists() {
                    ancestor = ancestor.parent().ok_or(WorkspaceError::PathEscape)?;
                }
                if !fs::canonicalize(ancestor)
                    .map_err(|_| WorkspaceError::Io)?
                    .starts_with(&session)
                {
                    return Err(WorkspaceError::PathEscape);
                }
                if fs::symlink_metadata(&destination)
                    .is_ok_and(|metadata| metadata.file_type().is_symlink())
                {
                    return Err(WorkspaceError::PathEscape);
                }
                session_dir
                    .create_dir_all(entry.path.parent().unwrap())
                    .map_err(|_| WorkspaceError::PathEscape)?;
                session_dir
                    .write(&entry.path, &entry.contents)
                    .map_err(|_| WorkspaceError::PathEscape)?;
                hashes.push(ManifestHash {
                    path: entry.path.to_string_lossy().replace('\\', "/"),
                    sha256: format!("{:x}", Sha256::digest(&entry.contents)),
                });
            }
            Ok(Manifest { entries: hashes })
        }
    }

    fn validate_name(name: &str) -> Result<(), WorkspaceError> {
        validate_relative_path(Path::new(name))
    }

    fn validate_agent_name(name: &str) -> Result<(), WorkspaceError> {
        if name.eq_ignore_ascii_case(".leases") {
            return Err(WorkspaceError::PathEscape);
        }
        validate_name(name)
    }

    fn validate_relative_path(path: &Path) -> Result<(), WorkspaceError> {
        if path.as_os_str().is_empty()
            || path.is_absolute()
            || path
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(WorkspaceError::PathEscape);
        }
        Ok(())
    }
}

pub mod artifacts {
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;
    use std::fs;
    use std::path::{Component, Path, PathBuf};

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct ArtifactMetadata {
        pub sha256: String,
        pub size: u64,
        pub mime_type: String,
        pub job_id: String,
        pub expires_at: u64,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct ArtifactRegistration {
        id: String,
        metadata: ArtifactMetadata,
    }

    impl ArtifactRegistration {
        pub fn id(&self) -> String {
            self.id.clone()
        }

        pub fn metadata(&self) -> &ArtifactMetadata {
            &self.metadata
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum ArtifactError {
        PathTraversal,
        Expired,
        SessionDenied,
        ChunkHashMismatch,
        ChunkConflict,
        NotPublished,
        InvalidMetadata,
        Io,
    }

    struct Entry {
        metadata: ArtifactMetadata,
        chunk_hashes: Vec<String>,
        chunks: Vec<Option<Vec<u8>>>,
        published: bool,
    }

    pub struct ArtifactStore {
        root: PathBuf,
        entries: HashMap<(String, String), Entry>,
    }

    impl ArtifactStore {
        pub fn new(root: impl AsRef<Path>) -> Result<Self, ArtifactError> {
            fs::create_dir_all(root.as_ref()).map_err(|_| ArtifactError::Io)?;
            Ok(Self {
                root: root.as_ref().to_owned(),
                entries: HashMap::new(),
            })
        }

        pub fn register(
            &mut self,
            session: &str,
            metadata: ArtifactMetadata,
            chunk_hashes: Vec<String>,
            now: u64,
        ) -> Result<ArtifactRegistration, ArtifactError> {
            validate_name(session)?;
            if metadata.expires_at <= now {
                return Err(ArtifactError::Expired);
            }
            if metadata.sha256.len() != 64 || chunk_hashes.is_empty() {
                return Err(ArtifactError::InvalidMetadata);
            }
            let id = metadata.sha256.clone();
            let entry = Entry {
                metadata: metadata.clone(),
                chunks: vec![None; chunk_hashes.len()],
                chunk_hashes,
                published: false,
            };
            self.entries.insert((session.to_owned(), id.clone()), entry);
            Ok(ArtifactRegistration { id, metadata })
        }

        pub fn missing_chunks(
            &self,
            session: &str,
            id: &str,
            now: u64,
        ) -> Result<Vec<usize>, ArtifactError> {
            let entry = self.entry(session, id, now)?;
            Ok(entry
                .chunks
                .iter()
                .enumerate()
                .filter_map(|(index, chunk)| chunk.is_none().then_some(index))
                .collect())
        }

        pub fn write_chunk(
            &mut self,
            session: &str,
            id: &str,
            index: usize,
            contents: &[u8],
            now: u64,
        ) -> Result<(), ArtifactError> {
            let key = self.key(session, id)?;
            let entry = self.entries.get_mut(&key).unwrap();
            if entry.metadata.expires_at <= now {
                return Err(ArtifactError::Expired);
            }
            let slot = entry
                .chunks
                .get_mut(index)
                .ok_or(ArtifactError::ChunkHashMismatch)?;
            if let Some(existing) = slot {
                return if existing == contents {
                    Ok(())
                } else {
                    Err(ArtifactError::ChunkConflict)
                };
            }
            if format!("{:x}", Sha256::digest(contents)) != entry.chunk_hashes[index] {
                return Err(ArtifactError::ChunkHashMismatch);
            }
            let completes_upload = entry
                .chunks
                .iter()
                .enumerate()
                .all(|(chunk_index, chunk)| chunk_index == index || chunk.is_some());
            if completes_upload {
                let complete = entry
                    .chunks
                    .iter()
                    .enumerate()
                    .flat_map(|(chunk_index, chunk)| {
                        if chunk_index == index {
                            contents.iter().copied()
                        } else {
                            chunk.as_ref().unwrap().iter().copied()
                        }
                    })
                    .collect::<Vec<_>>();
                if complete.len() as u64 != entry.metadata.size
                    || format!("{:x}", Sha256::digest(&complete)) != entry.metadata.sha256
                {
                    return Err(ArtifactError::ChunkHashMismatch);
                }
                let published = self.root.join(&entry.metadata.sha256);
                let temporary = self.root.join(format!("{}.tmp", entry.metadata.sha256));
                fs::write(&temporary, complete).map_err(|_| ArtifactError::Io)?;
                fs::rename(temporary, published).map_err(|_| ArtifactError::Io)?;
                *entry.chunks.get_mut(index).unwrap() = Some(contents.to_vec());
                entry.published = true;
            } else {
                *entry.chunks.get_mut(index).unwrap() = Some(contents.to_vec());
            }
            Ok(())
        }

        pub fn read(&self, session: &str, id: &str, now: u64) -> Result<Vec<u8>, ArtifactError> {
            let entry = self.entry(session, id, now)?;
            if !entry.published {
                return Err(ArtifactError::NotPublished);
            }
            fs::read(self.root.join(&entry.metadata.sha256)).map_err(|_| ArtifactError::Io)
        }

        fn entry(&self, session: &str, id: &str, now: u64) -> Result<&Entry, ArtifactError> {
            let key = self.key(session, id)?;
            let entry = self.entries.get(&key).unwrap();
            if entry.metadata.expires_at <= now {
                Err(ArtifactError::Expired)
            } else {
                Ok(entry)
            }
        }

        fn key(&self, session: &str, id: &str) -> Result<(String, String), ArtifactError> {
            validate_name(session)?;
            let key = (session.to_owned(), id.to_owned());
            if self.entries.contains_key(&key) {
                Ok(key)
            } else {
                Err(ArtifactError::SessionDenied)
            }
        }
    }

    fn validate_name(name: &str) -> Result<(), ArtifactError> {
        let path = Path::new(name);
        if name.is_empty()
            || path.is_absolute()
            || path
                .components()
                .any(|part| !matches!(part, Component::Normal(_)))
        {
            Err(ArtifactError::PathTraversal)
        } else {
            Ok(())
        }
    }
}

pub mod sessions {
    use crate::protocol::Event;
    use std::collections::HashMap;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum ResumeError {
        CursorAhead,
    }

    pub struct Client {
        job_id: String,
        last_acknowledged_sequence: u64,
    }

    impl Client {
        pub fn new(job_id: impl Into<String>) -> Self {
            Self {
                job_id: job_id.into(),
                last_acknowledged_sequence: 0,
            }
        }

        pub fn acknowledge(&mut self, sequence: u64) {
            self.last_acknowledged_sequence = sequence;
        }

        pub fn connect(&self, journal: &JobJournal) -> Result<Connection, ResumeError> {
            Ok(Connection {
                events: journal
                    .resume(&self.job_id, self.last_acknowledged_sequence)?
                    .into_iter(),
            })
        }
    }

    #[derive(Debug)]
    pub struct Connection {
        events: std::vec::IntoIter<Event>,
    }

    impl Connection {
        pub fn disconnect(self) {}
    }

    impl Iterator for Connection {
        type Item = Event;

        fn next(&mut self) -> Option<Self::Item> {
            self.events.next()
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct RequestResult {
        job_id: String,
    }

    impl RequestResult {
        pub fn new(job_id: impl Into<String>) -> Self {
            Self {
                job_id: job_id.into(),
            }
        }

        pub fn job_id(&self) -> &str {
            &self.job_id
        }
    }

    pub struct JobJournal {
        events: HashMap<String, Vec<Event>>,
        requests: HashMap<String, RequestResult>,
    }

    impl JobJournal {
        pub fn new() -> Self {
            Self {
                events: HashMap::new(),
                requests: HashMap::new(),
            }
        }

        pub fn append(&mut self, job_id: &str, kind: &str, payload: Vec<u8>) {
            let events = self.events.entry(job_id.to_owned()).or_default();
            events.push(Event {
                version: None,
                job_id: job_id.to_owned(),
                sequence: events.len() as u64 + 1,
                kind: kind.to_owned(),
                payload,
            });
        }

        pub fn resume(
            &self,
            job_id: &str,
            last_seen_sequence: u64,
        ) -> Result<Vec<Event>, ResumeError> {
            let events = self
                .events
                .get(job_id)
                .map(Vec::as_slice)
                .unwrap_or_default();
            if last_seen_sequence > events.len() as u64 {
                return Err(ResumeError::CursorAhead);
            }
            Ok(events
                .iter()
                .filter(|event| event.sequence > last_seen_sequence)
                .cloned()
                .collect())
        }

        pub fn execute_once(
            &mut self,
            request_id: &str,
            operation: impl FnOnce() -> RequestResult,
        ) -> RequestResult {
            if let Some(result) = self.requests.get(request_id) {
                return result.clone();
            }
            let result = operation();
            self.requests.insert(request_id.to_owned(), result.clone());
            result
        }
    }

    impl Default for JobJournal {
        fn default() -> Self {
            Self::new()
        }
    }
}

pub mod network_processes {
    use crate::remote_apple_protocol::AppleRequest;
    use serde::{Deserialize, Serialize};

    #[derive(Clone, Debug, Deserialize, Serialize)]
    pub struct ManifestUpload {
        pub path: String,
        pub contents: String,
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    pub struct RunRequest {
        pub principal_id: String,
        pub host_id: String,
        pub device_id: String,
        pub workspace_id: String,
        pub request_id: String,
        pub manifest: Vec<ManifestUpload>,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    pub struct NetworkEvent {
        pub sequence: u64,
        pub kind: String,
        pub payload: String,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    pub struct AuditRecord {
        pub principal_id: String,
        pub host_id: String,
        pub device_id: String,
        pub workspace_id: String,
        pub job_id: String,
        pub result: String,
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    pub struct DeviceSnapshot {
        pub id: String,
        pub platform: String,
        pub state: String,
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    pub struct HostSnapshot {
        pub id: String,
        pub operating_system: String,
        pub architecture: String,
        pub status: String,
        pub capabilities: Vec<String>,
        pub devices: Vec<DeviceSnapshot>,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    pub struct NetworkArtifactMetadata {
        pub id: String,
        pub job_id: String,
        pub name: String,
        pub media_type: String,
        pub total_size: u64,
        pub sha256: String,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    pub struct ArtifactChunk {
        pub offset: u64,
        pub total_size: u64,
        pub sha256: String,
        pub bytes: Vec<u8>,
    }

    #[derive(Deserialize, Serialize)]
    #[serde(tag = "request", rename_all = "snake_case")]
    pub enum Request {
        Heartbeat {
            host: HostSnapshot,
        },
        Complete {
            job_id: String,
            artifact: String,
            events: Vec<NetworkEvent>,
        },
        List,
        Run {
            operation: RunRequest,
        },
        Events {
            job_id: String,
            after: u64,
        },
        AppleRun {
            operation: AppleRequest,
        },
        AppleProgress {
            job_id: String,
            events: Vec<NetworkEvent>,
            terminal: bool,
        },
        AppleCancel {
            job_id: String,
        },
        ArtifactRegister {
            job_id: String,
            name: String,
            media_type: String,
            total_size: u64,
            sha256: String,
        },
        ArtifactWrite {
            artifact_id: String,
            offset: u64,
            total_size: u64,
            sha256: String,
            chunk_sha256: String,
            bytes: Vec<u8>,
        },
        ArtifactRead {
            artifact_id: String,
            offset: u64,
            length: u64,
            total_size: u64,
            sha256: String,
        },
        ArtifactInfo {
            artifact_id: String,
        },
    }

    #[derive(Deserialize, Serialize)]
    pub struct Response {
        pub accepted: bool,
        pub hosts: Vec<HostSnapshot>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub job_id: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub events: Vec<NetworkEvent>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub audit: Vec<AuditRecord>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub artifact: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub operation: Option<RunRequest>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub apple_operation: Option<AppleRequest>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub cancel_jobs: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub artifact_metadata: Option<NetworkArtifactMetadata>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub artifact_chunk: Option<ArtifactChunk>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub confirmed_offset: Option<u64>,
    }
}

pub mod preflight {
    use crate::process_execution::{
        CancellationToken, ProcessError, ProcessEvent, ProcessExecutor, ProcessRequest,
    };
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum PreflightError {
        UnsupportedHost,
        CommandFailed,
        InvalidOutput,
    }

    pub struct CommandOutput {
        stdout: String,
        stderr: String,
        success: bool,
    }

    impl CommandOutput {
        pub fn success(stdout: impl Into<String>) -> Self {
            Self {
                stdout: stdout.into(),
                stderr: String::new(),
                success: true,
            }
        }

        pub fn new(success: bool, stdout: impl Into<String>, stderr: impl Into<String>) -> Self {
            Self {
                stdout: stdout.into(),
                stderr: stderr.into(),
                success,
            }
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum ApplePreflightState {
        Ready,
        NeedsRepair,
        UnsupportedHost,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum AppleCheckState {
        Ready,
        MissingTool,
        LicenseNotAccepted,
        InvalidDeveloperDirectory,
        UnsupportedHost,
    }

    #[derive(Debug, PartialEq, Eq)]
    pub struct AppleCheck {
        pub name: &'static str,
        pub state: AppleCheckState,
        pub value: Option<String>,
        pub repair: Option<&'static str>,
    }

    #[derive(Debug, PartialEq, Eq)]
    pub struct ApplePreflightReport {
        pub state: ApplePreflightState,
        pub checks: Vec<AppleCheck>,
    }

    impl ApplePreflightReport {
        pub fn check(&self, name: &str) -> Option<&AppleCheck> {
            self.checks.iter().find(|check| check.name == name)
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    pub struct AppleCapabilitySnapshot {
        pub xcode: String,
        pub sdk: String,
        pub devicectl: String,
        pub simctl: String,
    }

    pub struct ApplePreflight;

    impl ApplePreflight {
        pub fn inspect(
            host: &str,
            mut command: impl FnMut(&str, &[&str]) -> Result<CommandOutput, PreflightError>,
        ) -> ApplePreflightReport {
            if host != "macos" {
                return ApplePreflightReport {
                    state: ApplePreflightState::UnsupportedHost,
                    checks: vec![AppleCheck {
                        name: "macos",
                        state: AppleCheckState::UnsupportedHost,
                        value: None,
                        repair: Some("Run Apple tooling on a macOS host."),
                    }],
                };
            }

            let developer = command("xcode-select", &["-p"])
                .unwrap_or_else(|_| CommandOutput::new(false, "", "command failed"));
            let xcode = command("xcodebuild", &["-version"])
                .unwrap_or_else(|_| CommandOutput::new(false, "", "command failed"));
            let mut checks = vec![ready_check("macos", None)];
            let developer_ready = developer.success
                && developer
                    .stdout
                    .trim()
                    .ends_with("Xcode.app/Contents/Developer");
            checks.push(if developer_ready {
                ready_check("developer_directory", Some(developer.stdout.trim().to_owned()))
            } else {
                failed_check(
                    "developer_directory",
                    AppleCheckState::InvalidDeveloperDirectory,
                    "Select full Xcode with: sudo xcode-select --switch /Applications/Xcode.app/Contents/Developer",
                )
            });
            let xcode_installed =
                xcode.success || xcode.stderr.to_ascii_lowercase().contains("license");
            checks.push(if developer_ready && xcode_installed {
                ready_check("full_xcode", token_after(&xcode.stdout, "Xcode").ok())
            } else {
                failed_check(
                    "full_xcode",
                    AppleCheckState::InvalidDeveloperDirectory,
                    "Install full Xcode and select it with xcode-select --switch.",
                )
            });
            checks.push(if xcode.success {
                ready_check("xcodebuild", token_after(&xcode.stdout, "Xcode").ok())
            } else if xcode.stderr.to_ascii_lowercase().contains("license") {
                failed_check(
                    "xcodebuild",
                    AppleCheckState::LicenseNotAccepted,
                    "Accept the license with: sudo xcodebuild -license accept",
                )
            } else {
                failed_check(
                    "xcodebuild",
                    AppleCheckState::MissingTool,
                    "Install full Xcode from Apple and select its developer directory.",
                )
            });
            for tool in ["devicectl", "simctl", "xcresulttool", "xctrace", "lldb-dap"] {
                let output = command("xcrun", &["--find", tool])
                    .unwrap_or_else(|_| CommandOutput::new(false, "", "command failed"));
                checks.push(if output.success {
                    ready_check(tool, Some(output.stdout.trim().to_owned()))
                } else {
                    failed_check(
                        tool,
                        AppleCheckState::MissingTool,
                        "Install or update full Xcode, then select its developer directory.",
                    )
                });
            }
            let state = if checks
                .iter()
                .all(|check| check.state == AppleCheckState::Ready)
            {
                ApplePreflightState::Ready
            } else {
                ApplePreflightState::NeedsRepair
            };
            ApplePreflightReport { state, checks }
        }

        pub fn run(
            host: &str,
            mut command: impl FnMut(&str, &[&str]) -> Result<CommandOutput, PreflightError>,
        ) -> Result<AppleCapabilitySnapshot, PreflightError> {
            if host != "macos" {
                return Err(PreflightError::UnsupportedHost);
            }
            let xcode = command("xcodebuild", &["-version"])?;
            let sdk = command("xcrun", &["--sdk", "iphoneos", "--show-sdk-version"])?;
            let devicectl = command("xcrun", &["devicectl", "--version"])?;
            let simctl = command("xcrun", &["simctl", "--version"])?;
            Ok(AppleCapabilitySnapshot {
                xcode: token_after(&xcode.stdout, "Xcode")?,
                sdk: sdk.stdout.trim().to_owned(),
                devicectl: token_after(&devicectl.stdout, "version:")?,
                simctl: token_after(&simctl.stdout, "SimulatorKit")?,
            })
        }
    }

    fn ready_check(name: &'static str, value: Option<String>) -> AppleCheck {
        AppleCheck {
            name,
            state: AppleCheckState::Ready,
            value,
            repair: None,
        }
    }

    fn failed_check(
        name: &'static str,
        state: AppleCheckState,
        repair: &'static str,
    ) -> AppleCheck {
        AppleCheck {
            name,
            state,
            value: None,
            repair: Some(repair),
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub enum AppleTool {
        Xcodebuild,
        Devicectl,
        Simctl,
        Xcresulttool,
        Xctrace,
        LldbDap,
    }

    impl AppleTool {
        pub const ALL: [Self; 6] = [
            Self::Xcodebuild,
            Self::Devicectl,
            Self::Simctl,
            Self::Xcresulttool,
            Self::Xctrace,
            Self::LldbDap,
        ];
    }

    pub struct AppleToolRunner {
        executor: ProcessExecutor,
        programs: HashMap<AppleTool, PathBuf>,
    }

    impl AppleToolRunner {
        pub fn new(
            workspace: impl AsRef<Path>,
            programs: impl IntoIterator<Item = (AppleTool, PathBuf)>,
        ) -> Result<Self, ProcessError> {
            let programs: HashMap<_, _> = programs.into_iter().collect();
            let executor = ProcessExecutor::new(
                workspace,
                programs.values().cloned(),
                ["DEVELOPER_DIR", "SDKROOT", "TMPDIR"],
            )?;
            Ok(Self { executor, programs })
        }

        pub fn execute(
            &self,
            tool: AppleTool,
            args: Vec<String>,
            working_directory: impl Into<PathBuf>,
            environment: HashMap<String, String>,
            timeout: Duration,
            cancellation: CancellationToken,
        ) -> Result<Vec<ProcessEvent>, ProcessError> {
            let program = self
                .programs
                .get(&tool)
                .ok_or(ProcessError::ProgramDenied)?;
            self.executor.execute(
                ProcessRequest {
                    program: program.clone(),
                    args,
                    working_directory: working_directory.into(),
                    environment,
                },
                timeout,
                cancellation,
            )
        }

        pub(crate) fn workspace(&self) -> &Path {
            self.executor.workspace()
        }
    }

    fn token_after(output: &str, marker: &str) -> Result<String, PreflightError> {
        output
            .lines()
            .find_map(|line| line.split_once(marker).map(|(_, rest)| rest))
            .and_then(|rest| rest.split_whitespace().next())
            .map(str::to_owned)
            .ok_or(PreflightError::InvalidOutput)
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum AdbDeviceState {
        Authorized,
        Unauthorized,
        Offline,
    }

    #[derive(Debug, PartialEq, Eq)]
    pub struct AdbDevice {
        pub id: String,
        pub state: AdbDeviceState,
    }

    #[derive(Debug, PartialEq, Eq)]
    pub struct AndroidCapabilitySnapshot {
        pub adb_version: String,
        pub devices: Vec<AdbDevice>,
    }

    pub struct AndroidPreflight;

    impl AndroidPreflight {
        pub fn run(
            mut command: impl FnMut(&str, &[&str]) -> Result<CommandOutput, PreflightError>,
        ) -> Result<AndroidCapabilitySnapshot, PreflightError> {
            let version = command("adb", &["version"])?;
            let devices = command("adb", &["devices", "-l"])?;
            Self::from_outputs(&version.stdout, &devices.stdout)
        }

        pub fn from_outputs(
            version_output: &str,
            devices_output: &str,
        ) -> Result<AndroidCapabilitySnapshot, PreflightError> {
            let adb_version = token_after(version_output, "Version")?;
            let devices = devices_output
                .lines()
                .skip(1)
                .filter(|line| !line.trim().is_empty())
                .map(|line| {
                    let mut fields = line.split_whitespace();
                    let id = fields.next().ok_or(PreflightError::InvalidOutput)?;
                    let state = match fields.next() {
                        Some("device") => AdbDeviceState::Authorized,
                        Some("unauthorized") => AdbDeviceState::Unauthorized,
                        Some("offline") => AdbDeviceState::Offline,
                        _ => return Err(PreflightError::InvalidOutput),
                    };
                    Ok(AdbDevice {
                        id: id.to_owned(),
                        state,
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(AndroidCapabilitySnapshot {
                adb_version,
                devices,
            })
        }
    }
}

pub mod apple_project_discovery {
    use crate::preflight::{AppleTool, AppleToolRunner};
    use crate::process_execution::{CancellationToken, EventKind, TerminalStatus};
    use serde_json::Value;
    use std::collections::HashMap;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum ContainerKind {
        Project,
        Workspace,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct ProjectContainer {
        pub id: String,
        pub path: String,
        pub kind: ContainerKind,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct NamedItem {
        pub id: String,
        pub name: String,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Destination {
        pub id: String,
        pub name: String,
        pub platform: String,
        pub os: Option<String>,
        pub available: bool,
        pub repair: Option<String>,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct ProjectSnapshot {
        pub container: ProjectContainer,
        pub schemes: Vec<NamedItem>,
        pub configurations: Vec<NamedItem>,
        pub destinations: Vec<Destination>,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct SelectionResponse {
        pub kind: &'static str,
        pub options: Vec<NamedItem>,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum DiscoveryOutcome {
        Ready(ProjectSnapshot),
        Selection(SelectionResponse),
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum ProjectDiscoveryError {
        OutsideWorkspace,
        MalformedToolOutput,
        ToolExecutionFailed,
        ContainerNotFound,
        InvalidSelection,
    }

    pub struct AppleProjectDiscovery;

    impl AppleProjectDiscovery {
        pub fn from_outputs(
            path: &str,
            kind: ContainerKind,
            list_output: &str,
            destinations_output: &str,
        ) -> Result<ProjectSnapshot, ProjectDiscoveryError> {
            let value: Value = serde_json::from_str(list_output)
                .map_err(|_| ProjectDiscoveryError::MalformedToolOutput)?;
            let container_value = match kind {
                ContainerKind::Project => value.get("project"),
                ContainerKind::Workspace => value.get("workspace"),
            }
            .ok_or(ProjectDiscoveryError::MalformedToolOutput)?;
            let schemes = named_items(container_value, "schemes", "scheme")?;
            let configurations = named_items(container_value, "configurations", "configuration")?;
            Ok(ProjectSnapshot {
                container: container(path, kind),
                schemes,
                configurations,
                destinations: parse_destinations(destinations_output)?,
            })
        }

        pub fn discover(
            runner: &AppleToolRunner,
            working_directory: impl AsRef<Path>,
            container_id: Option<&str>,
            scheme_id: Option<&str>,
            timeout: Duration,
        ) -> Result<DiscoveryOutcome, ProjectDiscoveryError> {
            let directory = fs::canonicalize(runner.workspace().join(working_directory.as_ref()))
                .map_err(|_| ProjectDiscoveryError::OutsideWorkspace)?;
            if !directory.starts_with(runner.workspace()) {
                return Err(ProjectDiscoveryError::OutsideWorkspace);
            }
            let mut containers = find_containers(runner.workspace(), &directory)?;
            containers.sort_by(|a, b| a.id.cmp(&b.id));
            let selected = match (container_id, containers.as_slice()) {
                (None, []) => return Err(ProjectDiscoveryError::ContainerNotFound),
                (None, [only]) => only.clone(),
                (None, _) => {
                    return Ok(DiscoveryOutcome::Selection(SelectionResponse {
                        kind: "container",
                        options: containers
                            .into_iter()
                            .map(|item| NamedItem {
                                id: item.id,
                                name: item.path,
                            })
                            .collect(),
                    }));
                }
                (Some(id), _) => containers
                    .into_iter()
                    .find(|item| item.id == id)
                    .ok_or(ProjectDiscoveryError::InvalidSelection)?,
            };
            let flag = container_flag(selected.kind);
            let list = run(
                runner,
                vec![
                    flag.into(),
                    selected.path.clone(),
                    "-list".into(),
                    "-json".into(),
                ],
                runner.workspace(),
                timeout,
            )?;
            let mut snapshot = Self::from_outputs(&selected.path, selected.kind, &list, "")?;
            let scheme = match snapshot.select_scheme(scheme_id) {
                Ok(scheme) => scheme.name.clone(),
                Err(selection) => return Ok(DiscoveryOutcome::Selection(selection)),
            };
            let destinations = run(
                runner,
                vec![
                    flag.into(),
                    selected.path,
                    "-scheme".into(),
                    scheme,
                    "-showdestinations".into(),
                ],
                runner.workspace(),
                timeout,
            )?;
            snapshot.destinations = parse_destinations(&destinations)?;
            Ok(DiscoveryOutcome::Ready(snapshot))
        }

        pub fn resolve_outputs(
            path: &str,
            kind: ContainerKind,
            list_output: &str,
            destinations_output: &str,
            scheme_id: Option<&str>,
        ) -> Result<DiscoveryOutcome, ProjectDiscoveryError> {
            let snapshot = Self::from_outputs(path, kind, list_output, destinations_output)?;
            match snapshot.select_scheme(scheme_id) {
                Ok(_) => Ok(DiscoveryOutcome::Ready(snapshot)),
                Err(selection) => Ok(DiscoveryOutcome::Selection(selection)),
            }
        }
    }

    impl ProjectSnapshot {
        pub fn select_scheme(&self, id: Option<&str>) -> Result<&NamedItem, SelectionResponse> {
            if let Some(id) = id {
                return self
                    .schemes
                    .iter()
                    .find(|scheme| scheme.id == id)
                    .ok_or_else(|| SelectionResponse {
                        kind: "scheme",
                        options: self.schemes.clone(),
                    });
            }
            match self.schemes.as_slice() {
                [scheme] => Ok(scheme),
                _ => Err(SelectionResponse {
                    kind: "scheme",
                    options: self.schemes.clone(),
                }),
            }
        }

        pub fn xcodebuild_arguments(&self, scheme: &str) -> Vec<String> {
            vec![
                container_flag(self.container.kind).into(),
                self.container.path.clone(),
                "-scheme".into(),
                scheme.into(),
            ]
        }
    }

    fn find_containers(
        root: &Path,
        directory: &Path,
    ) -> Result<Vec<ProjectContainer>, ProjectDiscoveryError> {
        Ok(fs::read_dir(directory)
            .map_err(|_| ProjectDiscoveryError::OutsideWorkspace)?
            .filter_map(Result::ok)
            .filter_map(|entry| {
                let path = entry.path();
                let extension = path.extension()?.to_str()?;
                let kind = match extension {
                    "xcodeproj" => ContainerKind::Project,
                    "xcworkspace" => ContainerKind::Workspace,
                    _ => return None,
                };
                let canonical = fs::canonicalize(&path).ok()?;
                if !canonical.starts_with(root) {
                    return None;
                }
                let relative = path
                    .strip_prefix(root)
                    .ok()?
                    .to_string_lossy()
                    .replace('\\', "/");
                Some(container(&relative, kind))
            })
            .collect())
    }

    fn container(path: &str, kind: ContainerKind) -> ProjectContainer {
        let prefix = match kind {
            ContainerKind::Project => "project",
            ContainerKind::Workspace => "workspace",
        };
        ProjectContainer {
            id: format!("{prefix}:{}", encode_id(path)),
            path: path.into(),
            kind,
        }
    }

    fn named_items(
        value: &Value,
        key: &str,
        prefix: &str,
    ) -> Result<Vec<NamedItem>, ProjectDiscoveryError> {
        value
            .get(key)
            .and_then(Value::as_array)
            .ok_or(ProjectDiscoveryError::MalformedToolOutput)?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(|name| NamedItem {
                        id: format!("{prefix}:{}", encode_id(name)),
                        name: name.into(),
                    })
                    .ok_or(ProjectDiscoveryError::MalformedToolOutput)
            })
            .collect()
    }

    fn parse_destinations(output: &str) -> Result<Vec<Destination>, ProjectDiscoveryError> {
        output.lines().filter(|line| line.trim().starts_with('{')).map(|line| {
            let fields: HashMap<_, _> = line.trim().trim_matches(['{', '}']).split(',')
                .filter_map(|field| field.trim().split_once(':'))
                .map(|(key, value)| (key.trim(), value.trim())).collect();
            let id = fields.get("id").ok_or(ProjectDiscoveryError::MalformedToolOutput)?.to_string();
            let name = fields.get("name").ok_or(ProjectDiscoveryError::MalformedToolOutput)?.to_string();
            let platform = fields.get("platform").ok_or(ProjectDiscoveryError::MalformedToolOutput)?.to_string();
            let error = fields.get("error");
            Ok(Destination {
                id, name, platform, os: fields.get("OS").map(|value| value.to_string()),
                available: error.is_none(),
                repair: error.map(|_| "Install the required platform or runtime in Xcode Settings > Platforms, then choose a compatible destination.".into()),
            })
        }).collect()
    }

    fn run(
        runner: &AppleToolRunner,
        args: Vec<String>,
        directory: &Path,
        timeout: Duration,
    ) -> Result<String, ProjectDiscoveryError> {
        let relative: PathBuf = directory
            .strip_prefix(runner.workspace())
            .map_err(|_| ProjectDiscoveryError::OutsideWorkspace)?
            .into();
        let events = runner
            .execute(
                AppleTool::Xcodebuild,
                args,
                relative,
                HashMap::new(),
                timeout,
                CancellationToken::new(),
            )
            .map_err(|_| ProjectDiscoveryError::ToolExecutionFailed)?;
        if !matches!(
            events.last().map(|event| &event.kind),
            Some(EventKind::Terminal(TerminalStatus::Exited(0)))
        ) {
            return Err(ProjectDiscoveryError::ToolExecutionFailed);
        }
        let bytes = events
            .iter()
            .filter(|event| event.kind == EventKind::Stdout)
            .flat_map(|event| event.payload.iter().copied())
            .collect();
        String::from_utf8(bytes).map_err(|_| ProjectDiscoveryError::MalformedToolOutput)
    }

    fn container_flag(kind: ContainerKind) -> &'static str {
        match kind {
            ContainerKind::Project => "-project",
            ContainerKind::Workspace => "-workspace",
        }
    }

    fn encode_id(value: &str) -> String {
        value.replace('%', "%25").replace(' ', "%20")
    }
}

pub mod apple_build {
    use crate::apple_project_discovery::ContainerKind;
    use crate::artifacts::{ArtifactError, ArtifactMetadata, ArtifactStore};
    use crate::process_execution::{
        CancellationToken, EventKind, ProcessError, ProcessEvent, ProcessExecutor, ProcessRequest,
        ProcessStream, TerminalStatus,
    };
    use sha2::{Digest, Sha256};
    use std::collections::{HashMap, HashSet};
    use std::fs;
    use std::path::{Component, Path, PathBuf};
    use std::time::Duration;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum BuildAction {
        Build,
        Test,
    }

    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    pub enum SigningReference {
        Identity(String),
        ProvisioningProfile(String),
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct BuildPlan {
        pub action: BuildAction,
        pub container_kind: ContainerKind,
        pub container: String,
        pub scheme: String,
        pub configuration: String,
        pub destination: String,
        pub derived_data: String,
        pub result_bundle: String,
        pub signing: Option<SigningReference>,
        pub protected_build_settings: HashMap<String, String>,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum AppleBuildError {
        InvalidPlan,
        Process(ProcessError),
        Artifact(ArtifactError),
        Io,
    }

    impl BuildPlan {
        pub fn arguments(&self) -> Result<Vec<String>, AppleBuildError> {
            for path in [&self.container, &self.derived_data, &self.result_bundle] {
                validate_relative(path)?;
            }
            let (container_flag, action) = match (self.container_kind, self.action) {
                (ContainerKind::Project, BuildAction::Build) => ("-project", "build"),
                (ContainerKind::Project, BuildAction::Test) => ("-project", "test"),
                (ContainerKind::Workspace, BuildAction::Build) => ("-workspace", "build"),
                (ContainerKind::Workspace, BuildAction::Test) => ("-workspace", "test"),
            };
            let mut args = vec![
                action.into(),
                container_flag.into(),
                self.container.clone(),
                "-scheme".into(),
                self.scheme.clone(),
                "-configuration".into(),
                self.configuration.clone(),
                "-destination".into(),
                self.destination.clone(),
                "-derivedDataPath".into(),
                self.derived_data.clone(),
                "-resultBundlePath".into(),
                self.result_bundle.clone(),
            ];
            if let Some(signing) = &self.signing {
                match signing {
                    SigningReference::Identity(value) if !value.is_empty() => {
                        args.push(format!("CODE_SIGN_IDENTITY={value}"))
                    }
                    SigningReference::ProvisioningProfile(value) if !value.is_empty() => {
                        args.push(format!("PROVISIONING_PROFILE_SPECIFIER={value}"))
                    }
                    _ => return Err(AppleBuildError::InvalidPlan),
                }
            }
            Ok(args)
        }
    }

    pub struct AppleBuildJob {
        workspace: PathBuf,
        program: PathBuf,
        environment: Vec<&'static str>,
        prefix: Vec<String>,
        local_signing_references: HashSet<SigningReference>,
    }

    pub struct AppleBuildStream {
        inner: ProcessStream,
        secrets: Vec<String>,
        journal: Vec<ProcessEvent>,
    }

    impl AppleBuildStream {
        pub fn resume(&self, last_seen: u64) -> Vec<ProcessEvent> {
            self.journal
                .iter()
                .filter(|event| event.sequence > last_seen)
                .cloned()
                .collect()
        }
    }

    impl Iterator for AppleBuildStream {
        type Item = ProcessEvent;
        fn next(&mut self) -> Option<Self::Item> {
            let mut event = self.inner.next()?;
            if matches!(event.kind, EventKind::Stdout | EventKind::Stderr) {
                let mut output = String::from_utf8_lossy(&event.payload).into_owned();
                for secret in &self.secrets {
                    if !secret.is_empty() {
                        output = output.replace(secret, "[REDACTED]");
                    }
                }
                event.payload = output.into_bytes();
            }
            self.journal.push(event.clone());
            Some(event)
        }
    }

    impl AppleBuildJob {
        pub fn new(
            workspace: impl AsRef<Path>,
            program: PathBuf,
            environment: impl IntoIterator<Item = &'static str>,
        ) -> Result<Self, ProcessError> {
            Self::with_prefix(
                workspace,
                program,
                environment,
                std::iter::empty::<String>(),
            )
        }

        pub fn with_prefix(
            workspace: impl AsRef<Path>,
            program: PathBuf,
            environment: impl IntoIterator<Item = &'static str>,
            prefix: impl IntoIterator<Item = impl Into<String>>,
        ) -> Result<Self, ProcessError> {
            let workspace = fs::canonicalize(workspace).map_err(|_| ProcessError::Io)?;
            let program = fs::canonicalize(program).map_err(|_| ProcessError::ProgramDenied)?;
            Ok(Self {
                workspace,
                program,
                environment: environment.into_iter().collect(),
                prefix: prefix.into_iter().map(Into::into).collect(),
                local_signing_references: HashSet::new(),
            })
        }

        pub fn with_local_signing_references(
            mut self,
            references: impl IntoIterator<Item = SigningReference>,
        ) -> Self {
            self.local_signing_references = references.into_iter().collect();
            self
        }

        pub fn start(
            &self,
            plan: &BuildPlan,
            timeout: Duration,
            cancellation: CancellationToken,
        ) -> Result<AppleBuildStream, AppleBuildError> {
            if plan
                .signing
                .as_ref()
                .is_some_and(|reference| !self.local_signing_references.contains(reference))
            {
                return Err(AppleBuildError::InvalidPlan);
            }
            let mut args = self.prefix.clone();
            args.extend(plan.arguments()?);
            let executor = ProcessExecutor::new(
                &self.workspace,
                [self.program.clone()],
                self.environment.iter().copied(),
            )
            .map_err(AppleBuildError::Process)?;
            let inner = executor
                .start(
                    ProcessRequest {
                        program: self.program.clone(),
                        args,
                        working_directory: "lease/job".into(),
                        environment: plan.protected_build_settings.clone(),
                    },
                    timeout,
                    cancellation,
                )
                .map_err(AppleBuildError::Process)?;
            Ok(AppleBuildStream {
                inner,
                secrets: plan.protected_build_settings.values().cloned().collect(),
                journal: Vec::new(),
            })
        }

        #[allow(clippy::too_many_arguments)]
        pub fn execute(
            &self,
            job_id: &str,
            session: &str,
            plan: BuildPlan,
            store: &mut ArtifactStore,
            now: u64,
            expires_at: u64,
            timeout: Duration,
            cancellation: CancellationToken,
        ) -> Result<AppleBuildResult, AppleBuildError> {
            let events = self
                .start(&plan, timeout, cancellation)?
                .collect::<Vec<_>>();
            let mut artifacts = Vec::new();
            if matches!(
                events.last().map(|event| &event.kind),
                Some(EventKind::Terminal(TerminalStatus::Exited(0)))
            ) {
                let job_root = self.workspace.join("lease/job");
                for path in output_paths(&job_root).map_err(|_| AppleBuildError::Io)? {
                    let contents = pack(&path).map_err(|_| AppleBuildError::Io)?;
                    let sha256 = format!("{:x}", Sha256::digest(&contents));
                    let registration = store
                        .register(
                            session,
                            ArtifactMetadata {
                                sha256: sha256.clone(),
                                size: contents.len() as u64,
                                mime_type: "application/octet-stream".into(),
                                job_id: job_id.into(),
                                expires_at,
                            },
                            vec![sha256.clone()],
                            now,
                        )
                        .map_err(AppleBuildError::Artifact)?;
                    store
                        .write_chunk(session, &registration.id(), 0, &contents, now)
                        .map_err(AppleBuildError::Artifact)?;
                    artifacts.push(AppleBuildArtifact { sha256 });
                }
            }
            Ok(AppleBuildResult {
                events,
                artifacts,
                audit: format!("xcodebuild {:?} {}", plan.action, plan.scheme),
            })
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct AppleBuildArtifact {
        pub sha256: String,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct AppleBuildResult {
        pub events: Vec<ProcessEvent>,
        pub artifacts: Vec<AppleBuildArtifact>,
        pub audit: String,
    }

    impl AppleBuildResult {
        pub fn resume(&self, last_seen: u64) -> Vec<ProcessEvent> {
            self.events
                .iter()
                .filter(|event| event.sequence > last_seen)
                .cloned()
                .collect()
        }
    }

    fn validate_relative(value: &str) -> Result<(), AppleBuildError> {
        let path = Path::new(value);
        if value.is_empty()
            || path.is_absolute()
            || path
                .components()
                .any(|part| !matches!(part, Component::Normal(_)))
        {
            Err(AppleBuildError::InvalidPlan)
        } else {
            Ok(())
        }
    }

    fn output_paths(root: &Path) -> std::io::Result<Vec<PathBuf>> {
        fn visit(path: &Path, found: &mut Vec<PathBuf>) -> std::io::Result<()> {
            for entry in fs::read_dir(path)? {
                let path = entry?.path();
                let metadata = fs::symlink_metadata(&path)?;
                if metadata.file_type().is_symlink() {
                    continue;
                }
                if metadata.is_dir()
                    && matches!(
                        path.extension().and_then(|v| v.to_str()),
                        Some("app" | "dSYM" | "xcresult")
                    )
                {
                    found.push(path);
                } else if metadata.is_dir() {
                    visit(&path, found)?;
                }
            }
            Ok(())
        }
        let mut found = Vec::new();
        visit(root, &mut found)?;
        found.sort();
        Ok(found)
    }

    fn pack(root: &Path) -> std::io::Result<Vec<u8>> {
        fn visit(root: &Path, path: &Path, out: &mut Vec<u8>) -> std::io::Result<()> {
            let mut entries = fs::read_dir(path)?.collect::<Result<Vec<_>, _>>()?;
            entries.sort_by_key(|entry| entry.path());
            for entry in entries {
                let path = entry.path();
                let metadata = fs::symlink_metadata(&path)?;
                if metadata.file_type().is_symlink() {
                    continue;
                }
                if metadata.is_dir() {
                    visit(root, &path, out)?;
                } else {
                    let relative = path.strip_prefix(root).unwrap().to_string_lossy();
                    let bytes = fs::read(&path)?;
                    out.extend_from_slice(relative.as_bytes());
                    out.push(0);
                    out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
                    out.extend_from_slice(&bytes);
                }
            }
            Ok(())
        }
        let mut out = Vec::new();
        visit(root, root, &mut out)?;
        Ok(out)
    }
}

pub mod apple_xctest {
    use crate::artifacts::{ArtifactError, ArtifactMetadata, ArtifactStore};
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;
    use std::fs;
    use std::path::{Path, PathBuf};

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum XCTestOperation {
        BuildForTesting {
            test_plan: Option<String>,
        },
        TestWithoutBuilding {
            test_plan: Option<String>,
            only_testing: Vec<String>,
            ui_tests: Vec<String>,
        },
    }

    impl XCTestOperation {
        pub fn arguments(&self) -> Vec<String> {
            let (action, test_plan, selections) = match self {
                Self::BuildForTesting { test_plan } => ("build-for-testing", test_plan, Vec::new()),
                Self::TestWithoutBuilding {
                    test_plan,
                    only_testing,
                    ui_tests,
                } => (
                    "test-without-building",
                    test_plan,
                    only_testing.iter().chain(ui_tests).collect(),
                ),
            };
            let mut arguments = vec![action.into()];
            if let Some(test_plan) = test_plan {
                arguments.extend(["-testPlan".into(), test_plan.clone()]);
            }
            arguments.extend(
                selections
                    .into_iter()
                    .map(|selection| format!("-only-testing:{selection}")),
            );
            arguments
        }
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
    pub struct SourceReference {
        pub file: String,
        pub line: u64,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
    pub struct TestFailure {
        pub message: String,
        pub source: SourceReference,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
    pub struct TestCase {
        pub identifier: String,
        pub status: String,
        pub duration: f64,
        pub failure: Option<TestFailure>,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
    pub struct TestSuite {
        pub name: String,
        pub tests: Vec<TestCase>,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
    pub struct XCTestAttachment {
        pub name: String,
        pub path: String,
        pub kind: String,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
    pub struct CoverageResult {
        pub target: String,
        pub line_percent: f64,
        pub source: Option<SourceReference>,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
    pub struct NormalizedXCResult {
        schema_version: u64,
        pub suites: Vec<TestSuite>,
        pub attachments: Vec<XCTestAttachment>,
        pub coverage: Vec<CoverageResult>,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum XCTestError {
        IncompatibleResultSchema,
        InvalidResult,
        Io,
        Artifact(ArtifactError),
    }

    pub fn normalize_xcresult(value: &str) -> Result<NormalizedXCResult, XCTestError> {
        let result = parse_xcresult(value)?;
        if result.schema_version != 1 {
            return Err(XCTestError::IncompatibleResultSchema);
        }
        Ok(result)
    }

    fn parse_xcresult(value: &str) -> Result<NormalizedXCResult, XCTestError> {
        let raw: serde_json::Value =
            serde_json::from_str(value).map_err(|_| XCTestError::InvalidResult)?;
        let schema_version = raw["schema_version"]
            .as_u64()
            .ok_or(XCTestError::InvalidResult)?;
        let suites = values(&raw["test_summaries"])?
            .iter()
            .map(|suite| {
                let tests = values(&suite["tests"])?
                    .iter()
                    .map(|test| {
                        let failures = values(&test["failureSummaries"])?;
                        let failure = failures.first().map(|failure| TestFailure {
                            message: string_value(&failure["message"]).unwrap_or_default(),
                            source: SourceReference {
                                file: string_value(&failure["fileName"]).unwrap_or_default(),
                                line: number_value(&failure["lineNumber"]).unwrap_or_default(),
                            },
                        });
                        Ok(TestCase {
                            identifier: string_value(&test["identifier"])
                                .ok_or(XCTestError::InvalidResult)?,
                            status: string_value(&test["testStatus"])
                                .ok_or(XCTestError::InvalidResult)?,
                            duration: float_value(&test["duration"])
                                .ok_or(XCTestError::InvalidResult)?,
                            failure,
                        })
                    })
                    .collect::<Result<Vec<_>, XCTestError>>()?;
                Ok(TestSuite {
                    name: string_value(&suite["name"]).ok_or(XCTestError::InvalidResult)?,
                    tests,
                })
            })
            .collect::<Result<Vec<_>, XCTestError>>()?;
        let attachments = optional_values(&raw["attachments"])
            .iter()
            .map(|attachment| {
                Ok(XCTestAttachment {
                    name: string_value(&attachment["name"]).ok_or(XCTestError::InvalidResult)?,
                    path: string_value(&attachment["path"]).ok_or(XCTestError::InvalidResult)?,
                    kind: string_value(&attachment["kind"]).ok_or(XCTestError::InvalidResult)?,
                })
            })
            .collect::<Result<Vec<_>, XCTestError>>()?;
        let coverage = optional_values(&raw["coverage"])
            .iter()
            .map(|entry| {
                Ok(CoverageResult {
                    target: string_value(&entry["target"]).ok_or(XCTestError::InvalidResult)?,
                    line_percent: float_value(&entry["linePercent"])
                        .ok_or(XCTestError::InvalidResult)?,
                    source: string_value(&entry["file"]).map(|file| SourceReference {
                        file,
                        line: number_value(&entry["line"]).unwrap_or_default(),
                    }),
                })
            })
            .collect::<Result<Vec<_>, XCTestError>>()?;
        Ok(NormalizedXCResult {
            schema_version,
            suites,
            attachments,
            coverage,
        })
    }

    fn values(value: &serde_json::Value) -> Result<&Vec<serde_json::Value>, XCTestError> {
        value["_values"]
            .as_array()
            .ok_or(XCTestError::InvalidResult)
    }

    fn optional_values(value: &serde_json::Value) -> &[serde_json::Value] {
        value["_values"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    fn string_value(value: &serde_json::Value) -> Option<String> {
        value["_value"].as_str().map(str::to_owned)
    }

    fn number_value(value: &serde_json::Value) -> Option<u64> {
        value["_value"].as_u64()
    }

    fn float_value(value: &serde_json::Value) -> Option<f64> {
        value["_value"].as_f64()
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct XCTestArtifact {
        pub sha256: String,
    }

    #[allow(clippy::too_many_arguments)]
    pub fn register_xctest_artifacts(
        bundle: &Path,
        job_id: &str,
        session: &str,
        store: &mut ArtifactStore,
        now: u64,
        expires_at: u64,
        protected_environment: &HashMap<String, String>,
    ) -> Result<Vec<XCTestArtifact>, XCTestError> {
        let mut paths = files(bundle)?;
        paths.retain(|path| {
            matches!(
                path.extension().and_then(|extension| extension.to_str()),
                Some("png" | "jpg" | "jpeg" | "mp4" | "mov" | "log")
            )
        });
        let secrets = protected_environment.values().collect::<Vec<_>>();
        let mut payloads = paths
            .iter()
            .map(|path| fs::read(path).map_err(|_| XCTestError::Io))
            .collect::<Result<Vec<_>, _>>()?;
        payloads.push(pack(bundle, &secrets)?);

        payloads
            .into_iter()
            .map(|payload| {
                register(
                    redact(payload, &secrets),
                    job_id,
                    session,
                    store,
                    now,
                    expires_at,
                )
            })
            .collect()
    }

    fn register(
        payload: Vec<u8>,
        job_id: &str,
        session: &str,
        store: &mut ArtifactStore,
        now: u64,
        expires_at: u64,
    ) -> Result<XCTestArtifact, XCTestError> {
        let sha256 = format!("{:x}", Sha256::digest(&payload));
        let registration = store
            .register(
                session,
                ArtifactMetadata {
                    sha256: sha256.clone(),
                    size: payload.len() as u64,
                    mime_type: "application/octet-stream".into(),
                    job_id: job_id.into(),
                    expires_at,
                },
                vec![sha256.clone()],
                now,
            )
            .map_err(XCTestError::Artifact)?;
        store
            .write_chunk(session, &registration.id(), 0, &payload, now)
            .map_err(XCTestError::Artifact)?;
        Ok(XCTestArtifact { sha256 })
    }

    fn redact(mut payload: Vec<u8>, secrets: &[&String]) -> Vec<u8> {
        for secret in secrets {
            if !secret.is_empty() {
                payload = replace_bytes(&payload, secret.as_bytes(), b"[REDACTED]");
            }
        }
        payload
    }

    fn replace_bytes(value: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();
        let mut remaining = value;
        while let Some(index) = remaining
            .windows(needle.len())
            .position(|part| part == needle)
        {
            output.extend_from_slice(&remaining[..index]);
            output.extend_from_slice(replacement);
            remaining = &remaining[index + needle.len()..];
        }
        output.extend_from_slice(remaining);
        output
    }

    fn files(root: &Path) -> Result<Vec<PathBuf>, XCTestError> {
        fn visit(path: &Path, found: &mut Vec<PathBuf>) -> std::io::Result<()> {
            for entry in fs::read_dir(path)? {
                let path = entry?.path();
                if path.is_dir() {
                    visit(&path, found)?;
                } else {
                    found.push(path);
                }
            }
            Ok(())
        }
        let mut found = Vec::new();
        visit(root, &mut found).map_err(|_| XCTestError::Io)?;
        found.sort();
        Ok(found)
    }

    fn pack(root: &Path, secrets: &[&String]) -> Result<Vec<u8>, XCTestError> {
        let mut output = Vec::new();
        for path in files(root)? {
            let relative = path.strip_prefix(root).map_err(|_| XCTestError::Io)?;
            let contents = redact(fs::read(&path).map_err(|_| XCTestError::Io)?, secrets);
            output.extend_from_slice(relative.to_string_lossy().as_bytes());
            output.push(0);
            output.extend_from_slice(&(contents.len() as u64).to_le_bytes());
            output.extend_from_slice(&contents);
        }
        Ok(output)
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum XCTestTerminal {
        Succeeded,
        Cancelled,
        TestsFailed,
        RunnerCrashed,
        DeviceLost,
        IncompatibleResultSchema,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum XCTestRunEnd {
        Cancelled,
        Exited(i32),
        DeviceDisconnected,
    }

    #[derive(Clone, Debug, PartialEq)]
    pub struct XCTestOutcome {
        pub result: NormalizedXCResult,
        terminal: XCTestTerminal,
    }

    impl XCTestOutcome {
        pub fn finish(result: NormalizedXCResult, terminal: XCTestTerminal) -> Self {
            Self { result, terminal }
        }

        pub fn terminals(&self) -> impl Iterator<Item = &XCTestTerminal> {
            std::iter::once(&self.terminal)
        }
    }

    pub fn finish_xctest(
        raw_result: &str,
        end: XCTestRunEnd,
    ) -> Result<XCTestOutcome, XCTestError> {
        let result = parse_xcresult(raw_result)?;
        let terminal = if result.schema_version != 1 {
            XCTestTerminal::IncompatibleResultSchema
        } else {
            match end {
                XCTestRunEnd::Cancelled => XCTestTerminal::Cancelled,
                XCTestRunEnd::DeviceDisconnected => XCTestTerminal::DeviceLost,
                XCTestRunEnd::Exited(0) => XCTestTerminal::Succeeded,
                XCTestRunEnd::Exited(65) => XCTestTerminal::TestsFailed,
                XCTestRunEnd::Exited(_) => XCTestTerminal::RunnerCrashed,
            }
        };
        Ok(XCTestOutcome::finish(result, terminal))
    }
}

pub mod apple_diagnostics {
    use crate::artifacts::{ArtifactError, ArtifactMetadata, ArtifactStore};
    use crate::authorization::{AuthorizationError, LeaseId, Operation, PolicyEngine};
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::path::{Component, Path};
    use std::time::Duration;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum DebugBinding {
        Loopback,
        EncryptedSessionChannel,
        Public,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum DapCommand {
        Launch(String),
        Attach(u32),
        Breakpoint(String, u32),
        Continue,
        Pause,
        Stack,
        Variables(u64),
        Disconnect,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum DapEvent {
        Launched,
        Attached,
        BreakpointSet,
        Continued,
        Paused,
        Stack(Vec<String>),
        Variables(Vec<(String, String)>),
        Disconnected,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum TraceKind {
        Cpu,
        Memory,
        Energy,
        Network,
    }

    impl TraceKind {
        fn template(self) -> &'static str {
            match self {
                Self::Cpu => "Time Profiler",
                Self::Memory => "Allocations",
                Self::Energy => "Energy Log",
                Self::Network => "Network",
            }
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct TracePlan {
        pub kind: TraceKind,
        pub target: String,
        pub duration: Duration,
        pub output: String,
        pub max_megabytes: u64,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum AppleDiagnosticError {
        PublicEndpointDenied,
        CapabilityDenied,
        LeaseInactive,
        InvalidTracePlan,
        MissingTemplate { repair: &'static str },
        MissingSymbols { repair: &'static str },
        Artifact(ArtifactError),
        Io,
    }

    impl TracePlan {
        pub fn arguments(&self, workspace: &Path) -> Result<Vec<String>, AppleDiagnosticError> {
            let output = Path::new(&self.output);
            if self.target.is_empty()
                || self.duration.is_zero()
                || self.max_megabytes == 0
                || !workspace.is_dir()
                || self.output.is_empty()
                || output.is_absolute()
                || output
                    .components()
                    .any(|component| !matches!(component, Component::Normal(_)))
            {
                return Err(AppleDiagnosticError::InvalidTracePlan);
            }
            Ok(vec![
                "record".into(),
                "--template".into(),
                self.kind.template().into(),
                "--device".into(),
                self.target.clone(),
                "--time-limit".into(),
                format!("{}s", self.duration.as_secs()),
                "--output".into(),
                workspace.join(output).to_string_lossy().into_owned(),
                "--max-size".into(),
                format!("{}MB", self.max_megabytes),
            ])
        }

        pub fn template_available(
            kind: TraceKind,
            templates: &[&str],
        ) -> Result<(), AppleDiagnosticError> {
            if templates.contains(&kind.template()) {
                Ok(())
            } else {
                Err(AppleDiagnosticError::MissingTemplate {
                    repair: "install_xcode_instruments_templates",
                })
            }
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    pub struct DebugSession {
        session_id: String,
        actor: String,
        device_id: String,
        lease: LeaseId,
        terminated: bool,
    }

    impl DebugSession {
        pub fn open(
            session_id: &str,
            actor: &str,
            device_id: &str,
            lease: LeaseId,
            binding: DebugBinding,
            policy: &mut PolicyEngine,
        ) -> Result<Self, AppleDiagnosticError> {
            if binding == DebugBinding::Public {
                return Err(AppleDiagnosticError::PublicEndpointDenied);
            }
            policy
                .execute(
                    actor,
                    Operation::AppleDebug { device_id },
                    Some(lease),
                    || (),
                )
                .map_err(map_authorization)?;
            Ok(Self {
                session_id: session_id.into(),
                actor: actor.into(),
                device_id: device_id.into(),
                lease,
                terminated: false,
            })
        }

        pub fn execute(
            &mut self,
            command: DapCommand,
            policy: &mut PolicyEngine,
        ) -> Result<DapEvent, AppleDiagnosticError> {
            if self.terminated {
                return Err(AppleDiagnosticError::LeaseInactive);
            }
            if let Err(error) = policy.execute(
                &self.actor,
                Operation::AppleDebug {
                    device_id: &self.device_id,
                },
                Some(self.lease),
                || (),
            ) {
                self.terminated = true;
                return Err(map_authorization(error));
            }
            let event = match command {
                DapCommand::Launch(_) => DapEvent::Launched,
                DapCommand::Attach(_) => DapEvent::Attached,
                DapCommand::Breakpoint(_, _) => DapEvent::BreakpointSet,
                DapCommand::Continue => DapEvent::Continued,
                DapCommand::Pause => DapEvent::Paused,
                DapCommand::Stack => DapEvent::Stack(vec!["main".into()]),
                DapCommand::Variables(_) => {
                    DapEvent::Variables(vec![("self".into(), "Mesh.App".into())])
                }
                DapCommand::Disconnect => {
                    self.terminated = true;
                    DapEvent::Disconnected
                }
            };
            Ok(event)
        }

        pub fn session_id(&self) -> &str {
            &self.session_id
        }

        pub fn is_terminated(&self) -> bool {
            self.terminated
        }

        pub fn require_symbols(symbols: Option<&Path>) -> Result<(), AppleDiagnosticError> {
            if symbols.is_some_and(Path::exists) {
                Ok(())
            } else {
                Err(AppleDiagnosticError::MissingSymbols {
                    repair: "build_and_upload_matching_dsym",
                })
            }
        }
    }

    fn map_authorization(error: AuthorizationError) -> AppleDiagnosticError {
        match error {
            AuthorizationError::LeaseInactive => AppleDiagnosticError::LeaseInactive,
            _ => AppleDiagnosticError::CapabilityDenied,
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct DiagnosticArtifact {
        pub sha256: String,
    }

    pub fn register_diagnostic_artifacts(
        output: &Path,
        job_id: &str,
        session: &str,
        store: &mut ArtifactStore,
        now: u64,
        expires_at: u64,
    ) -> Result<Vec<DiagnosticArtifact>, AppleDiagnosticError> {
        let mut paths = fs::read_dir(output)
            .map_err(|_| AppleDiagnosticError::Io)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| AppleDiagnosticError::Io)?;
        paths.sort();
        paths
            .into_iter()
            .map(|path| {
                let payload = if path.is_dir() {
                    pack_directory(&path)?
                } else {
                    fs::read(path).map_err(|_| AppleDiagnosticError::Io)?
                };
                let sha256 = format!("{:x}", Sha256::digest(&payload));
                let registration = store
                    .register(
                        session,
                        ArtifactMetadata {
                            sha256: sha256.clone(),
                            size: payload.len() as u64,
                            mime_type: "application/octet-stream".into(),
                            job_id: job_id.into(),
                            expires_at,
                        },
                        vec![sha256.clone()],
                        now,
                    )
                    .map_err(AppleDiagnosticError::Artifact)?;
                store
                    .write_chunk(session, &registration.id(), 0, &payload, now)
                    .map_err(AppleDiagnosticError::Artifact)?;
                Ok(DiagnosticArtifact { sha256 })
            })
            .collect()
    }

    fn pack_directory(root: &Path) -> Result<Vec<u8>, AppleDiagnosticError> {
        fn visit(root: &Path, path: &Path, output: &mut Vec<u8>) -> std::io::Result<()> {
            let mut entries = fs::read_dir(path)?.collect::<Result<Vec<_>, _>>()?;
            entries.sort_by_key(|entry| entry.path());
            for entry in entries {
                let path = entry.path();
                if path.is_dir() {
                    visit(root, &path, output)?;
                } else {
                    let relative = path.strip_prefix(root).unwrap().to_string_lossy();
                    let payload = fs::read(&path)?;
                    output.extend_from_slice(relative.as_bytes());
                    output.push(0);
                    output.extend_from_slice(&(payload.len() as u64).to_le_bytes());
                    output.extend_from_slice(&payload);
                }
            }
            Ok(())
        }
        let mut output = Vec::new();
        visit(root, root, &mut output).map_err(|_| AppleDiagnosticError::Io)?;
        Ok(output)
    }
}

pub mod apple_discovery {
    use crate::preflight::{AppleTool, AppleToolRunner};
    use crate::process_execution::{CancellationToken, EventKind, ProcessEvent, TerminalStatus};
    use serde::{Deserialize, Serialize};
    use serde_json::Value;
    use std::collections::HashMap;
    use std::path::Path;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    const APP_CAPABILITIES: [&str; 2] = ["apple.app.install@1", "apple.app.launch@1"];
    static OUTPUT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    #[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    pub enum Connection {
        Usb,
        Network,
        Simulator,
        Disconnected,
    }

    #[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    pub enum Trust {
        Trusted,
        Untrusted,
        NotApplicable,
    }

    #[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    pub enum DeveloperMode {
        Enabled,
        Disabled,
        NotApplicable,
    }

    #[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    pub enum Availability {
        Available,
        Locked,
        Unavailable,
        RuntimeMissing,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    pub struct DeviceSnapshot {
        pub id: String,
        pub name: String,
        pub platform: String,
        pub os_version: String,
        pub connection: Connection,
        pub trust: Trust,
        pub developer_mode: DeveloperMode,
        pub availability: Availability,
        pub capabilities: Vec<String>,
        pub repair: Option<String>,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum AppleDiscoveryError {
        MalformedToolOutput,
        ToolExecutionFailed,
    }

    impl AppleDiscoveryError {
        pub fn code(self) -> &'static str {
            match self {
                Self::MalformedToolOutput => "malformed_tool_output",
                Self::ToolExecutionFailed => "tool_execution_failed",
            }
        }
    }

    pub struct AppleDiscovery;

    impl AppleDiscovery {
        pub fn from_outputs(
            devicectl_output: &str,
            simctl_output: &str,
        ) -> Result<Vec<DeviceSnapshot>, AppleDiscoveryError> {
            let physical = parse_devicectl(devicectl_output)?;
            let simulators = parse_simctl(simctl_output)?;
            Ok(physical.into_iter().chain(simulators).collect())
        }

        pub fn discover(
            runner: &AppleToolRunner,
            working_directory: impl AsRef<Path>,
            timeout: Duration,
        ) -> Result<Vec<DeviceSnapshot>, AppleDiscoveryError> {
            let output_path = runner.workspace().join(format!(
                ".mesh-devicectl-devices-{}-{}.json",
                std::process::id(),
                OUTPUT_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            let execution = run_events(
                runner,
                AppleTool::Devicectl,
                vec![
                    "list".into(),
                    "devices".into(),
                    "--json-output".into(),
                    output_path.to_string_lossy().into_owned(),
                ],
                working_directory.as_ref(),
                timeout,
            );
            let devicectl = execution.and_then(|_| {
                std::fs::read_to_string(&output_path)
                    .map_err(|_| AppleDiscoveryError::ToolExecutionFailed)
            });
            let _ = std::fs::remove_file(output_path);
            let devicectl = devicectl?;
            let simctl = run(
                runner,
                AppleTool::Simctl,
                vec!["list".into(), "devices".into(), "--json".into()],
                working_directory.as_ref(),
                timeout,
            )?;
            Self::from_outputs(&devicectl, &simctl)
        }
    }

    fn run(
        runner: &AppleToolRunner,
        tool: AppleTool,
        args: Vec<String>,
        working_directory: &Path,
        timeout: Duration,
    ) -> Result<String, AppleDiscoveryError> {
        let events = run_events(runner, tool, args, working_directory, timeout)?;
        let bytes = events
            .iter()
            .filter(|event| event.kind == EventKind::Stdout)
            .flat_map(|event: &ProcessEvent| event.payload.iter().copied())
            .collect();
        String::from_utf8(bytes).map_err(|_| AppleDiscoveryError::MalformedToolOutput)
    }

    fn run_events(
        runner: &AppleToolRunner,
        tool: AppleTool,
        args: Vec<String>,
        working_directory: &Path,
        timeout: Duration,
    ) -> Result<Vec<ProcessEvent>, AppleDiscoveryError> {
        let events = runner
            .execute(
                tool,
                args,
                working_directory,
                HashMap::new(),
                timeout,
                CancellationToken::new(),
            )
            .map_err(|_| AppleDiscoveryError::ToolExecutionFailed)?;
        if !matches!(
            events.last().map(|event| &event.kind),
            Some(EventKind::Terminal(TerminalStatus::Exited(0)))
        ) {
            return Err(AppleDiscoveryError::ToolExecutionFailed);
        }
        Ok(events)
    }

    fn parse_devicectl(output: &str) -> Result<Vec<DeviceSnapshot>, AppleDiscoveryError> {
        let value: Value =
            serde_json::from_str(output).map_err(|_| AppleDiscoveryError::MalformedToolOutput)?;
        required_array(&value, &["result", "devices"])?
            .iter()
            .map(|device| {
                let properties = required(device, &["deviceProperties"])?;
                let connection = required(device, &["connectionProperties"])?;
                let paired = required_str(connection, &["pairingState"])? == "paired";
                let tunnel_state = required_str(connection, &["tunnelState"])?;
                let locked = required_str(properties, &["lockState"])? == "locked";
                let developer_mode = match required_str(properties, &["developerModeStatus"])? {
                    "enabled" => DeveloperMode::Enabled,
                    "disabled" => DeveloperMode::Disabled,
                    _ => return Err(AppleDiscoveryError::MalformedToolOutput),
                };
                let connection = match tunnel_state {
                    "disconnected" | "unavailable" => Connection::Disconnected,
                    "connected" => match required_str(connection, &["transportType"])? {
                        "usb" => Connection::Usb,
                        "network" => Connection::Network,
                        _ => return Err(AppleDiscoveryError::MalformedToolOutput),
                    },
                    _ => return Err(AppleDiscoveryError::MalformedToolOutput),
                };
                let trust = if paired {
                    Trust::Trusted
                } else {
                    Trust::Untrusted
                };
                let availability = if tunnel_state == "unavailable" {
                    Availability::Unavailable
                } else if locked {
                    Availability::Locked
                } else {
                    Availability::Available
                };
                let repair = physical_repair(connection, trust, developer_mode, availability);
                Ok(DeviceSnapshot {
                    id: required_str(device, &["identifier"])?.into(),
                    name: required_str(properties, &["name"])?.into(),
                    platform: required_str(device, &["hardwareProperties", "platform"])?
                        .to_ascii_lowercase(),
                    os_version: required_str(properties, &["osVersionNumber"])?.into(),
                    connection,
                    trust,
                    developer_mode,
                    availability,
                    capabilities: capabilities(repair.is_none()),
                    repair,
                })
            })
            .collect()
    }

    fn parse_simctl(output: &str) -> Result<Vec<DeviceSnapshot>, AppleDiscoveryError> {
        let value: Value =
            serde_json::from_str(output).map_err(|_| AppleDiscoveryError::MalformedToolOutput)?;
        let runtimes = required(&value, &["devices"])?
            .as_object()
            .ok_or(AppleDiscoveryError::MalformedToolOutput)?;
        let mut snapshots = Vec::new();
        for (runtime, devices) in runtimes {
            let os_version = runtime
                .strip_prefix("com.apple.CoreSimulator.SimRuntime.iOS-")
                .ok_or(AppleDiscoveryError::MalformedToolOutput)?
                .replace('-', ".");
            for device in devices
                .as_array()
                .ok_or(AppleDiscoveryError::MalformedToolOutput)?
            {
                let available = device
                    .get("isAvailable")
                    .and_then(Value::as_bool)
                    .ok_or(AppleDiscoveryError::MalformedToolOutput)?;
                let availability = if available {
                    Availability::Available
                } else {
                    Availability::RuntimeMissing
                };
                let repair = (!available).then(|| {
                    "Install the missing iOS Simulator runtime in Xcode Settings > Platforms."
                        .into()
                });
                snapshots.push(DeviceSnapshot {
                    id: required_str(device, &["udid"])?.into(),
                    name: required_str(device, &["name"])?.into(),
                    platform: "ios-simulator".into(),
                    os_version: os_version.clone(),
                    connection: Connection::Simulator,
                    trust: Trust::NotApplicable,
                    developer_mode: DeveloperMode::NotApplicable,
                    availability,
                    capabilities: capabilities(available),
                    repair,
                });
            }
        }
        snapshots.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(snapshots)
    }

    fn physical_repair(
        connection: Connection,
        trust: Trust,
        developer_mode: DeveloperMode,
        availability: Availability,
    ) -> Option<String> {
        if trust == Trust::Untrusted {
            Some("Unlock the device and trust this Mac, then pair it again.".into())
        } else if availability == Availability::Locked {
            Some("Unlock the device and keep it connected to this Mac.".into())
        } else if connection == Connection::Disconnected {
            Some("Reconnect the device by USB or enable its paired network connection.".into())
        } else if developer_mode == DeveloperMode::Disabled {
            Some("Enable Developer Mode in Settings > Privacy & Security on the device.".into())
        } else {
            None
        }
    }

    fn capabilities(executable: bool) -> Vec<String> {
        if executable {
            APP_CAPABILITIES.map(str::to_owned).to_vec()
        } else {
            Vec::new()
        }
    }

    fn required<'a>(value: &'a Value, path: &[&str]) -> Result<&'a Value, AppleDiscoveryError> {
        path.iter().try_fold(value, |value, key| {
            value
                .get(key)
                .ok_or(AppleDiscoveryError::MalformedToolOutput)
        })
    }

    fn required_str<'a>(value: &'a Value, path: &[&str]) -> Result<&'a str, AppleDiscoveryError> {
        required(value, path)?
            .as_str()
            .ok_or(AppleDiscoveryError::MalformedToolOutput)
    }

    fn required_array<'a>(
        value: &'a Value,
        path: &[&str],
    ) -> Result<&'a Vec<Value>, AppleDiscoveryError> {
        required(value, path)?
            .as_array()
            .ok_or(AppleDiscoveryError::MalformedToolOutput)
    }
}

pub mod remote_apple_protocol {
    use serde::{Deserialize, Serialize};
    use serde_json::Value;
    use std::collections::{HashMap, HashSet};
    use std::fs;
    use std::path::{Component, Path, PathBuf};
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
    pub struct RemoteProtocolVersion {
        pub major: u32,
        pub minor: u32,
    }

    #[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
    #[serde(tag = "kind", rename_all = "snake_case")]
    pub enum AppleOperation {
        Discovery,
        PhysicalDevice,
        Diagnostics,
        DiscoverProject {
            container: String,
        },
        DiscoverSimulator,
        BuildApp {
            container: String,
            scheme: String,
            destination: String,
        },
        InstallApp {
            app_path: String,
        },
        LaunchApp {
            bundle_id: String,
        },
        ReadAppLogs {
            bundle_id: String,
        },
        RunXcTest {
            container: String,
            scheme: String,
            destination: String,
        },
    }

    impl AppleOperation {
        pub fn capability(&self) -> &'static str {
            match self {
                Self::Discovery => "apple.discovery@1",
                Self::PhysicalDevice => "apple.device@1",
                Self::Diagnostics => "apple.diagnostics@1",
                Self::DiscoverProject { .. } => "apple.project@1",
                Self::DiscoverSimulator => "apple.simulator@1",
                Self::BuildApp { .. } => "apple.build@1",
                Self::InstallApp { .. } | Self::LaunchApp { .. } | Self::ReadAppLogs { .. } => {
                    "apple.simulator@1"
                }
                Self::RunXcTest { .. } => "apple.xctest@1",
            }
        }

        pub fn requires_device(&self) -> bool {
            matches!(
                self,
                Self::PhysicalDevice
                    | Self::Diagnostics
                    | Self::InstallApp { .. }
                    | Self::LaunchApp { .. }
                    | Self::ReadAppLogs { .. }
                    | Self::RunXcTest { .. }
            )
        }
    }

    #[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
    #[serde(deny_unknown_fields)]
    pub struct AppleRequest {
        pub version: RemoteProtocolVersion,
        pub request_id: String,
        pub idempotency_key: String,
        pub capability: String,
        pub workspace_path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub device_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub lease_id: Option<String>,
        pub operation: AppleOperation,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct ProtocolError {
        code: &'static str,
        message: &'static str,
    }

    impl ProtocolError {
        pub fn new(code: &'static str, message: &'static str) -> Self {
            Self { code, message }
        }

        pub fn code(&self) -> &str {
            self.code
        }

        pub fn message(&self) -> &str {
            self.message
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct AcceptedJob {
        job_id: String,
    }

    impl AcceptedJob {
        pub fn job_id(&self) -> &str {
            &self.job_id
        }
    }

    #[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
    pub struct ProgressEvent {
        pub sequence: u64,
        pub kind: String,
        pub payload: String,
        pub terminal: bool,
    }

    struct AgentState {
        next_job: u64,
        request_jobs: HashMap<String, String>,
        idempotency_jobs: HashMap<String, String>,
        job_requests: HashMap<String, AppleRequest>,
        events: HashMap<String, Vec<ProgressEvent>>,
    }

    pub struct AppleAgent {
        workspace_root: PathBuf,
        capabilities: HashSet<String>,
        devices: HashSet<String>,
        state: Arc<Mutex<AgentState>>,
    }

    pub struct AppleRegistry {
        agent: AppleAgent,
    }

    impl AppleRegistry {
        pub fn new(agent: AppleAgent) -> Self {
            Self { agent }
        }

        pub fn submit<F>(
            &self,
            request: AppleRequest,
            operation: F,
        ) -> Result<AcceptedJob, ProtocolError>
        where
            F: FnOnce(&dyn Fn(&str)) -> Result<String, String> + Send + 'static,
        {
            self.agent.submit(request, operation)
        }

        pub fn events(
            &self,
            job_id: &str,
            after: u64,
        ) -> Result<Vec<ProgressEvent>, ProtocolError> {
            self.agent.events(job_id, after)
        }
    }

    impl AppleAgent {
        pub fn new(
            workspace_root: impl AsRef<Path>,
            capabilities: impl IntoIterator<Item = impl Into<String>>,
            devices: impl IntoIterator<Item = impl Into<String>>,
        ) -> Result<Self, ProtocolError> {
            let workspace_root = fs::canonicalize(workspace_root).map_err(|_| {
                ProtocolError::new("workspace_path_denied", "workspace is unavailable")
            })?;
            Ok(Self {
                workspace_root,
                capabilities: capabilities.into_iter().map(Into::into).collect(),
                devices: devices.into_iter().map(Into::into).collect(),
                state: Arc::new(Mutex::new(AgentState {
                    next_job: 1,
                    request_jobs: HashMap::new(),
                    idempotency_jobs: HashMap::new(),
                    job_requests: HashMap::new(),
                    events: HashMap::new(),
                })),
            })
        }

        pub fn parse_and_validate(&self, json: &str) -> Result<AppleRequest, ProtocolError> {
            let value: Value = serde_json::from_str(json)
                .map_err(|_| ProtocolError::new("invalid_request", "request is not valid JSON"))?;
            if value.pointer("/version/major").and_then(Value::as_u64) != Some(1)
                || value.pointer("/version/minor").and_then(Value::as_u64) != Some(0)
            {
                return Err(ProtocolError::new(
                    "unsupported_version",
                    "unsupported protocol version",
                ));
            }
            let request: AppleRequest = serde_json::from_value(value).map_err(|error| {
                if error.to_string().contains("unknown variant") {
                    ProtocolError::new("unsupported_operation", "unsupported Apple operation")
                } else {
                    ProtocolError::new("invalid_request", "request fields are invalid")
                }
            })?;
            self.validate(&request)?;
            Ok(request)
        }

        pub fn validate(&self, request: &AppleRequest) -> Result<(), ProtocolError> {
            validate_request_envelope(request)?;
            if !self.capabilities.contains(&request.capability) {
                return Err(ProtocolError::new(
                    "unsupported_capability",
                    "capability is not available",
                ));
            }
            let path = Path::new(&request.workspace_path);
            if fs::canonicalize(self.workspace_root.join(path)).is_err_and(|_| true)
                || !fs::canonicalize(self.workspace_root.join(path))
                    .is_ok_and(|resolved| resolved.starts_with(&self.workspace_root))
            {
                return Err(ProtocolError::new(
                    "workspace_path_denied",
                    "workspace path is outside the workspace",
                ));
            }
            if request
                .device_id
                .as_ref()
                .is_some_and(|device| !self.devices.contains(device))
                || request.operation.requires_device() && request.device_id.is_none()
            {
                return Err(ProtocolError::new(
                    "unknown_device",
                    "device is not available",
                ));
            }
            Ok(())
        }

        pub fn submit<F>(
            &self,
            request: AppleRequest,
            operation: F,
        ) -> Result<AcceptedJob, ProtocolError>
        where
            F: FnOnce(&dyn Fn(&str)) -> Result<String, String> + Send + 'static,
        {
            self.validate(&request)?;
            let mut state = self.state.lock().unwrap();
            let request_job = state.request_jobs.get(&request.request_id).cloned();
            let idempotency_job = state
                .idempotency_jobs
                .get(&request.idempotency_key)
                .cloned();
            if request_job.is_some() && idempotency_job.is_some() && request_job != idempotency_job
            {
                return Err(ProtocolError::new(
                    "idempotency_conflict",
                    "request identifiers refer to different jobs",
                ));
            }
            if let Some(job_id) = request_job.or(idempotency_job) {
                if !state
                    .job_requests
                    .get(&job_id)
                    .is_some_and(|original| same_operation(original, &request))
                {
                    return Err(ProtocolError::new(
                        "idempotency_conflict",
                        "request identifier was reused for a different operation",
                    ));
                }
                state
                    .request_jobs
                    .insert(request.request_id, job_id.clone());
                state
                    .idempotency_jobs
                    .insert(request.idempotency_key, job_id.clone());
                return Ok(AcceptedJob { job_id });
            }
            let job_id = format!("apple-job-{}", state.next_job);
            state.next_job += 1;
            state.job_requests.insert(job_id.clone(), request.clone());
            state
                .request_jobs
                .insert(request.request_id, job_id.clone());
            state
                .idempotency_jobs
                .insert(request.idempotency_key, job_id.clone());
            state.events.insert(
                job_id.clone(),
                vec![ProgressEvent {
                    sequence: 1,
                    kind: "accepted".into(),
                    payload: String::new(),
                    terminal: false,
                }],
            );
            drop(state);

            let thread_state = Arc::clone(&self.state);
            let thread_job_id = job_id.clone();
            std::thread::spawn(move || {
                let progress_state = Arc::clone(&thread_state);
                let progress_job_id = thread_job_id.clone();
                let progress = move |payload: &str| {
                    append_event(
                        &progress_state,
                        &progress_job_id,
                        "progress",
                        payload,
                        false,
                    );
                };
                let result =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| operation(&progress)));
                match result {
                    Ok(Ok(payload)) => {
                        append_event(&thread_state, &thread_job_id, "succeeded", &payload, true)
                    }
                    Ok(Err(payload)) => {
                        append_event(&thread_state, &thread_job_id, "failed", &payload, true)
                    }
                    Err(_) => append_event(
                        &thread_state,
                        &thread_job_id,
                        "failed",
                        "operation panicked",
                        true,
                    ),
                }
            });
            Ok(AcceptedJob { job_id })
        }

        pub fn events(
            &self,
            job_id: &str,
            after: u64,
        ) -> Result<Vec<ProgressEvent>, ProtocolError> {
            let state = self.state.lock().unwrap();
            let events = state
                .events
                .get(job_id)
                .ok_or_else(|| ProtocolError::new("unknown_job", "job is not available"))?;
            if after > events.len() as u64 {
                return Err(ProtocolError::new(
                    "invalid_event_cursor",
                    "event cursor is beyond the job",
                ));
            }
            Ok(events
                .iter()
                .filter(|event| event.sequence > after)
                .cloned()
                .collect())
        }
    }

    pub fn validate_request_envelope(request: &AppleRequest) -> Result<(), ProtocolError> {
        if request.version != (RemoteProtocolVersion { major: 1, minor: 0 }) {
            return Err(ProtocolError::new(
                "unsupported_version",
                "unsupported protocol version",
            ));
        }
        if request.request_id.is_empty() || request.idempotency_key.is_empty() {
            return Err(ProtocolError::new(
                "invalid_request",
                "request identifiers must not be empty",
            ));
        }
        if request.capability != request.operation.capability() {
            return Err(ProtocolError::new(
                "unsupported_capability",
                "capability does not match the operation",
            ));
        }
        let path = Path::new(&request.workspace_path);
        if path.as_os_str().is_empty()
            || path.is_absolute()
            || path
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(ProtocolError::new(
                "workspace_path_denied",
                "workspace path is outside the workspace",
            ));
        }
        if request.operation.requires_device() && request.device_id.is_none() {
            return Err(ProtocolError::new(
                "unknown_device",
                "device is not available",
            ));
        }
        let valid_relative = |value: &str| {
            let path = Path::new(value);
            !value.is_empty()
                && !path.is_absolute()
                && path
                    .components()
                    .all(|component| matches!(component, Component::Normal(_)))
        };
        let valid_text = |value: &str| !value.trim().is_empty();
        let valid_bundle = |value: &str| {
            value.contains('.')
                && value.chars().all(|character| {
                    character.is_ascii_alphanumeric() || matches!(character, '.' | '-')
                })
        };
        let valid_parameters = match &request.operation {
            AppleOperation::DiscoverProject { container } => valid_relative(container),
            AppleOperation::BuildApp {
                container,
                scheme,
                destination,
            }
            | AppleOperation::RunXcTest {
                container,
                scheme,
                destination,
            } => valid_relative(container) && valid_text(scheme) && valid_text(destination),
            AppleOperation::InstallApp { app_path } => valid_relative(app_path),
            AppleOperation::LaunchApp { bundle_id } | AppleOperation::ReadAppLogs { bundle_id } => {
                valid_bundle(bundle_id)
            }
            _ => true,
        };
        if !valid_parameters {
            return Err(ProtocolError::new(
                "invalid_apple_parameter",
                "apple operation parameter is invalid",
            ));
        }
        for identifier in [request.device_id.as_deref(), request.lease_id.as_deref()]
            .into_iter()
            .flatten()
        {
            if identifier.is_empty()
                || !identifier.chars().all(|character| {
                    character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
                })
            {
                return Err(ProtocolError::new(
                    "invalid_request",
                    "device or lease identifier is invalid",
                ));
            }
        }
        Ok(())
    }

    fn same_operation(left: &AppleRequest, right: &AppleRequest) -> bool {
        left.version == right.version
            && left.capability == right.capability
            && left.workspace_path == right.workspace_path
            && left.device_id == right.device_id
            && left.lease_id == right.lease_id
            && left.operation == right.operation
    }

    fn append_event(
        state: &Arc<Mutex<AgentState>>,
        job_id: &str,
        kind: &str,
        payload: &str,
        terminal: bool,
    ) {
        let mut state = state.lock().unwrap();
        let events = state.events.get_mut(job_id).unwrap();
        if events.iter().any(|event| event.terminal) {
            return;
        }
        events.push(ProgressEvent {
            sequence: events.len() as u64 + 1,
            kind: kind.into(),
            payload: payload.into(),
            terminal,
        });
    }
}

pub mod remote_apple_agent {
    use crate::process_execution::CancellationToken;
    use crate::remote_apple_protocol::{AppleAgent, AppleRequest, ProgressEvent, ProtocolError};
    use std::collections::{HashMap, HashSet};
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct AgentDiscovery {
        pub capabilities: HashSet<String>,
        pub devices: HashSet<String>,
    }

    type Discover = dyn Fn() -> AgentDiscovery + Send + Sync;
    type Execute = dyn Fn(AppleRequest, CancellationToken, &dyn Fn(&str)) -> Result<String, String>
        + Send
        + Sync;

    struct Job {
        request: AppleRequest,
        cancellation: CancellationToken,
        events: Vec<ProgressEvent>,
    }

    struct State {
        next_job: u64,
        request_jobs: HashMap<String, String>,
        idempotency_jobs: HashMap<String, String>,
        jobs: HashMap<String, Job>,
    }

    pub struct RemoteAppleAgent {
        workspace_root: PathBuf,
        discover: Arc<Discover>,
        execute: Arc<Execute>,
        state: Arc<Mutex<State>>,
    }

    pub struct RemoteAppleRegistry {
        agent: RemoteAppleAgent,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct RemoteAcceptedJob {
        job_id: String,
    }

    impl RemoteAcceptedJob {
        pub fn job_id(&self) -> &str {
            &self.job_id
        }
    }

    impl RemoteAppleAgent {
        pub fn new(
            workspace_root: impl AsRef<Path>,
            discover: impl Fn() -> AgentDiscovery + Send + Sync + 'static,
            execute: impl Fn(AppleRequest, CancellationToken, &dyn Fn(&str)) -> Result<String, String>
            + Send
            + Sync
            + 'static,
        ) -> Result<Self, ProtocolError> {
            let workspace_root = std::fs::canonicalize(workspace_root).map_err(|_| {
                ProtocolError::new("workspace_path_denied", "workspace is unavailable")
            })?;
            Ok(Self {
                workspace_root,
                discover: Arc::new(discover),
                execute: Arc::new(execute),
                state: Arc::new(Mutex::new(State {
                    next_job: 1,
                    request_jobs: HashMap::new(),
                    idempotency_jobs: HashMap::new(),
                    jobs: HashMap::new(),
                })),
            })
        }

        fn submit(&self, request: AppleRequest) -> Result<RemoteAcceptedJob, ProtocolError> {
            let discovered = (self.discover)();
            AppleAgent::new(
                &self.workspace_root,
                discovered.capabilities,
                discovered.devices,
            )?
            .validate(&request)?;

            let mut state = self.state.lock().unwrap();
            let known = state
                .request_jobs
                .get(&request.request_id)
                .or_else(|| state.idempotency_jobs.get(&request.idempotency_key))
                .cloned();
            if let Some(job_id) = known {
                if state
                    .jobs
                    .get(&job_id)
                    .is_some_and(|job| same_operation(&job.request, &request))
                {
                    return Ok(RemoteAcceptedJob { job_id });
                }
                return Err(ProtocolError::new(
                    "idempotency_conflict",
                    "request identifier was reused for a different operation",
                ));
            }

            let job_id = format!("remote-apple-job-{}", state.next_job);
            state.next_job += 1;
            let cancellation = CancellationToken::new();
            state
                .request_jobs
                .insert(request.request_id.clone(), job_id.clone());
            state
                .idempotency_jobs
                .insert(request.idempotency_key.clone(), job_id.clone());
            state.jobs.insert(
                job_id.clone(),
                Job {
                    request: request.clone(),
                    cancellation: cancellation.clone(),
                    events: vec![ProgressEvent {
                        sequence: 1,
                        kind: "accepted".into(),
                        payload: String::new(),
                        terminal: false,
                    }],
                },
            );
            drop(state);

            let execute = Arc::clone(&self.execute);
            let jobs = Arc::clone(&self.state);
            let thread_job_id = job_id.clone();
            std::thread::spawn(move || {
                let progress_jobs = Arc::clone(&jobs);
                let progress_job_id = thread_job_id.clone();
                let progress = move |payload: &str| {
                    append(&progress_jobs, &progress_job_id, "progress", payload, false)
                };
                let result = execute(request, cancellation.clone(), &progress);
                let (kind, payload) = match result {
                    Ok(payload) => ("succeeded", payload),
                    Err(payload) if cancellation.is_cancelled() => ("cancelled", payload),
                    Err(payload) => ("failed", payload),
                };
                append(&jobs, &thread_job_id, kind, &payload, true);
            });
            Ok(RemoteAcceptedJob { job_id })
        }

        fn events(&self, job_id: &str, after: u64) -> Result<Vec<ProgressEvent>, ProtocolError> {
            let state = self.state.lock().unwrap();
            let job = state
                .jobs
                .get(job_id)
                .ok_or_else(|| ProtocolError::new("unknown_job", "job is not available"))?;
            if after > job.events.len() as u64 {
                return Err(ProtocolError::new(
                    "invalid_event_cursor",
                    "event cursor is beyond the job",
                ));
            }
            Ok(job
                .events
                .iter()
                .filter(|event| event.sequence > after)
                .cloned()
                .collect())
        }

        fn cancel(&self, job_id: &str) -> Result<(), ProtocolError> {
            let state = self.state.lock().unwrap();
            let job = state
                .jobs
                .get(job_id)
                .ok_or_else(|| ProtocolError::new("unknown_job", "job is not available"))?;
            job.cancellation.cancel();
            Ok(())
        }
    }

    impl RemoteAppleRegistry {
        pub fn new(agent: RemoteAppleAgent) -> Self {
            Self { agent }
        }

        pub fn submit(&self, request: AppleRequest) -> Result<RemoteAcceptedJob, ProtocolError> {
            let wire = serde_json::to_string(&request)
                .map_err(|_| ProtocolError::new("invalid_request", "request fields are invalid"))?;
            let forwarded = serde_json::from_str(&wire)
                .map_err(|_| ProtocolError::new("invalid_request", "request fields are invalid"))?;
            self.agent.submit(forwarded)
        }

        pub fn events(
            &self,
            job_id: &str,
            after: u64,
        ) -> Result<Vec<ProgressEvent>, ProtocolError> {
            self.agent.events(job_id, after)
        }

        pub fn cancel(&self, job_id: &str) -> Result<(), ProtocolError> {
            self.agent.cancel(job_id)
        }
    }

    fn same_operation(left: &AppleRequest, right: &AppleRequest) -> bool {
        left.version == right.version
            && left.capability == right.capability
            && left.workspace_path == right.workspace_path
            && left.device_id == right.device_id
            && left.lease_id == right.lease_id
            && left.operation == right.operation
    }

    fn append(state: &Arc<Mutex<State>>, job_id: &str, kind: &str, payload: &str, terminal: bool) {
        let mut state = state.lock().unwrap();
        let events = &mut state.jobs.get_mut(job_id).unwrap().events;
        if events.iter().any(|event| event.terminal) {
            return;
        }
        events.push(ProgressEvent {
            sequence: events.len() as u64 + 1,
            kind: kind.into(),
            payload: payload.into(),
            terminal,
        });
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn workspace_package_is_available() {
        assert_eq!(env!("CARGO_PKG_NAME"), "device-development-mesh");
    }
}
