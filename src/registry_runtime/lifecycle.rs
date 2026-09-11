use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegistryRuntimeState {
    Running,
    Stopped,
    Failed { code: &'static str },
}

#[derive(Clone)]
pub struct RegistryStatus(Arc<Mutex<RegistryRuntimeState>>);

impl RegistryStatus {
    fn running() -> Self {
        Self(Arc::new(Mutex::new(RegistryRuntimeState::Running)))
    }

    pub fn snapshot(&self) -> RegistryRuntimeState {
        self.0
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }
}

// Publish before returning to socket shutdown and worker joins. Catch listener
// panics here so the owner still runs cleanup and observers never retain Running.
#[cfg(test)]
fn supervise(
    status: &RegistryStatus,
    operation: impl FnOnce() -> std::io::Result<()>,
) -> std::io::Result<()> {
    let failure_code = Mutex::new(None);
    supervise_with(&failure_code, status, operation, || {})
}

fn supervise_with(
    failure_code: &Mutex<Option<&'static str>>,
    status: &RegistryStatus,
    operation: impl FnOnce() -> std::io::Result<()>,
    before_publish: impl FnOnce(),
) -> std::io::Result<()> {
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation));
    before_publish();
    let failure_code = failure_code
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .take();
    let (state, result) = match failure_code {
        Some(code) => (
            RegistryRuntimeState::Failed { code },
            Err(std::io::Error::other(code)),
        ),
        None => match outcome {
            Ok(Ok(())) => (RegistryRuntimeState::Stopped, Ok(())),
            Ok(Err(error)) => (
                RegistryRuntimeState::Failed {
                    code: "registry_listener_failed",
                },
                Err(error),
            ),
            Err(_) => (
                RegistryRuntimeState::Failed {
                    code: "registry_listener_panicked",
                },
                Err(std::io::Error::other("registry listener panicked")),
            ),
        },
    };
    let mut current = status.0.lock().unwrap_or_else(|error| error.into_inner());
    if let RegistryRuntimeState::Failed { code } = *current {
        return Err(std::io::Error::other(code));
    }
    *current = state;
    result
}

fn supervise_dispatcher(
    status: &RegistryStatus,
    failure_code: &Mutex<Option<&'static str>>,
    stopping: &AtomicBool,
    admission: &Mutex<()>,
    operation: impl FnOnce(),
) -> std::io::Result<()> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation)) {
        Ok(()) => Ok(()),
        Err(_) => {
            let _admission = admission.lock().unwrap_or_else(|error| error.into_inner());
            stopping.store(true, Ordering::Release);
            *failure_code
                .lock()
                .unwrap_or_else(|error| error.into_inner()) = Some("registry_worker_panicked");
            let mut state = status.0.lock().unwrap_or_else(|error| error.into_inner());
            if matches!(*state, RegistryRuntimeState::Stopped) {
                *state = RegistryRuntimeState::Failed {
                    code: "registry_worker_panicked",
                };
            }
            Err(std::io::Error::other("registry worker panicked"))
        }
    }
}

pub enum RegistryRecoveryPolicy {
    ReadOnly,
    Reject,
}

/// A normal RPC listener and authority supplied by its owner. Pairing roots are
/// deliberately not part of this runtime's configuration.
pub struct RegistryRuntimeConfig {
    pub listener: TcpListener,
    pub transport: Arc<SecureTransport>,
    pub state_root: PathBuf,
    pub offline_after: Duration,
    pub agent_peers: HashSet<String>,
    pub recovery_policy: RegistryRecoveryPolicy,
}

pub struct RegistryRuntime {
    status: RegistryStatus,
    address: SocketAddr,
    identity: String,
    stopping: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<std::io::Result<()>>>,
}

struct ConnectionWorker {
    socket: TcpStream,
    deadline: Instant,
    worker: thread::JoinHandle<std::io::Result<()>>,
}

#[cfg(test)]
type DispatchHook = Arc<dyn Fn(&TcpStream, &Mutex<DurableState>) + Send + Sync>;

fn open_state_lock(path: &Path) -> std::io::Result<std::fs::File> {
    let validate = |metadata: &std::fs::Metadata| -> std::io::Result<()> {
        let invalid = !metadata.is_file() || metadata.file_type().is_symlink();
        #[cfg(windows)]
        let invalid = {
            use std::os::windows::fs::MetadataExt;
            invalid
                || metadata.file_attributes()
                    & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
                    != 0
        };
        if invalid {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "registry_state_lock_insecure",
            ))
        } else {
            Ok(())
        }
    };
    match fs::symlink_metadata(path) {
        Ok(metadata) => validate(&metadata)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = OpenOptions::new();
        options.create(true).truncate(false).read(true).write(true);
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        options.open(path)?
    };
    #[cfg(windows)]
    let file =
        crate::dashboard::audit::open_private_shared_file(path).map_err(|error| match error {
            crate::dashboard::audit::AuditError::Io(error) => error,
            _ => std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "registry_state_lock_insecure",
            ),
        })?;
    let metadata = file.metadata()?;
    validate(&metadata)?;
    #[cfg(unix)]
    let private = {
        use std::os::unix::fs::MetadataExt;
        metadata.uid() == unsafe { libc::geteuid() } && metadata.mode() & 0o077 == 0
    };
    #[cfg(windows)]
    let private =
        crate::dashboard::managed_policy::windows_file_acl_is_restrictive(&file, &HashSet::new());
    if !private {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "registry_state_lock_insecure",
        ));
    }
    Ok(file)
}

impl RegistryRuntime {
    pub fn start(config: RegistryRuntimeConfig) -> std::io::Result<Self> {
        Self::start_inner(
            config,
            #[cfg(test)]
            None,
        )
    }

    fn start_inner(
        config: RegistryRuntimeConfig,
        #[cfg(test)] dispatch_hook: Option<DispatchHook>,
    ) -> std::io::Result<Self> {
        let RegistryRuntimeConfig {
            listener,
            transport,
            state_root,
            offline_after,
            agent_peers,
            recovery_policy,
        } = config;
        let address = listener.local_addr()?;
        let identity = transport.identity_id().map_err(|error| {
            std::io::Error::other(format!("invalid registry identity: {error:?}"))
        })?;
        listener.set_nonblocking(true)?;
        let listener = Arc::new(Mutex::new(Some(listener)));
        let state_root = crate::state_paths::prepare_private_state_directory(&state_root)?;
        let state_lock = open_state_lock(&state_root.join("registry.lock"))?;
        fs2::FileExt::try_lock_exclusive(&state_lock)?;
        let entries = Arc::new(Mutex::new(HashMap::new()));
        let state_path = state_root.join("vertical-slice.json");
        let mut loaded_state = load_state(&state_path);
        if matches!(recovery_policy, RegistryRecoveryPolicy::Reject)
            && let Some(error) = &loaded_state.recovery_error
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                error.clone(),
            ));
        }
        let artifacts = Arc::new(Mutex::new(NetworkArtifacts::try_new(
            state_root.join("artifacts"),
        )?));
        let mut loaded_leases = LeaseBook::try_load(state_root.join("device-leases.json"))?;
        if reconcile_runtime_state(&mut loaded_state, &mut loaded_leases) {
            persist_state(&state_path, &loaded_state)?;
            loaded_leases.persist()?;
        }
        let state = Arc::new(Mutex::new(loaded_state));
        let leases = Arc::new(Mutex::new(loaded_leases));
        let agent_peers = Arc::new(agent_peers);
        let stopping = Arc::new(AtomicBool::new(false));
        let admission = Arc::new(Mutex::new(()));
        let failure_code = Arc::new(Mutex::new(None));
        let status = RegistryStatus::running();
        let worker_status = status.clone();
        let stop = Arc::clone(&stopping);
        let worker_admission = Arc::clone(&admission);
        let worker_failure_code = Arc::clone(&failure_code);
        let listener_for_loop = Arc::clone(&listener);
        let listener_for_close = Arc::clone(&listener);
        let worker = thread::Builder::new()
            .name("registry-listener".into())
            .spawn(move || {
                // Keep exclusive state ownership until all dispatch workers are joined.
                let _state_lock = state_lock;
                let mut workers: Vec<ConnectionWorker> = Vec::new();
                let mut result = supervise_with(
                    &failure_code,
                    &worker_status,
                    || {
                        loop {
                            let mut index = 0;
                            while index < workers.len() {
                                if Instant::now() >= workers[index].deadline {
                                    let _ = workers[index].socket.shutdown(Shutdown::Both);
                                }
                                if workers[index].worker.is_finished() {
                                    let worker = workers.swap_remove(index);
                                    worker.worker.join().unwrap_or_else(|_| {
                                        Err(std::io::Error::other("registry worker panicked"))
                                    })?;
                                } else {
                                    index += 1;
                                }
                            }
                            if stop.load(Ordering::Acquire) {
                                break Ok(());
                            }
                            let mut idle = false;
                            {
                                let _admission =
                                    admission.lock().unwrap_or_else(|error| error.into_inner());
                                if stop.load(Ordering::Acquire) {
                                    break Ok(());
                                }
                                let listener = listener_for_loop
                                    .lock()
                                    .unwrap_or_else(|error| error.into_inner());
                                let accepted = match listener.as_ref() {
                                    Some(listener) => listener.accept(),
                                    None => {
                                        break Err(std::io::Error::other(
                                            "registry listener already closed",
                                        ));
                                    }
                                };
                                match accepted {
                                    Ok((socket, _)) => {
                                        if workers.len() >= 64 {
                                            drop(socket);
                                            continue;
                                        }
                                        // Windows accepted sockets inherit the listener's mode;
                                        // the TLS dispatcher performs blocking, timed I/O.
                                        if let Err(error) = socket.set_nonblocking(false) {
                                            break Err(error);
                                        }
                                        let tracked = match socket.try_clone() {
                                            Ok(socket) => socket,
                                            Err(error) => break Err(error),
                                        };
                                        let transport = Arc::clone(&transport);
                                        let entries = Arc::clone(&entries);
                                        let state = Arc::clone(&state);
                                        let artifacts = Arc::clone(&artifacts);
                                        let leases = Arc::clone(&leases);
                                        let agent_peers = Arc::clone(&agent_peers);
                                        let state_path = state_path.clone();
                                        let stop = Arc::clone(&stop);
                                        let status = worker_status.clone();
                                        let admission = Arc::clone(&worker_admission);
                                        let failure_code = Arc::clone(&worker_failure_code);
                                        #[cfg(test)]
                                        let dispatch_hook = dispatch_hook.clone();
                                        let worker = match thread::Builder::new()
                                            .name("registry-rpc".into())
                                            .spawn(move || {
                                                supervise_dispatcher(
                                                    &status,
                                                    &failure_code,
                                                    &stop,
                                                    &admission,
                                                    || {
                                                        #[cfg(test)]
                                                        if let Some(hook) = dispatch_hook {
                                                            hook(&socket, &state);
                                                        }
                                                        handle(
                                                            socket,
                                                            &transport,
                                                            offline_after,
                                                            entries,
                                                            state,
                                                            artifacts,
                                                            leases,
                                                            agent_peers,
                                                            &state_path,
                                                            &stop,
                                                        );
                                                    },
                                                )
                                            }) {
                                            Ok(worker) => worker,
                                            Err(error) => break Err(error),
                                        };
                                        // Legacy synchronous runs wait up to 15 seconds for agents.
                                        workers.push(ConnectionWorker {
                                            socket: tracked,
                                            deadline: Instant::now() + Duration::from_secs(30),
                                            worker,
                                        });
                                    }
                                    Err(error)
                                        if error.kind() == std::io::ErrorKind::WouldBlock =>
                                    {
                                        idle = true;
                                    }
                                    Err(error)
                                        if error.kind() == std::io::ErrorKind::Interrupted =>
                                    {
                                        continue;
                                    }
                                    Err(error) => break Err(error),
                                }
                            }
                            if idle {
                                thread::sleep(Duration::from_millis(10));
                            }
                        }
                    },
                    || {
                        stop.store(true, Ordering::Release);
                        listener_for_close
                            .lock()
                            .unwrap_or_else(|error| error.into_inner())
                            .take();
                    },
                );
                stop.store(true, Ordering::Release);
                drop(listener);
                for worker in &workers {
                    let _ = worker.socket.shutdown(Shutdown::Both);
                }
                for worker in workers {
                    result = result.and(worker.worker.join().unwrap_or_else(|_| {
                        Err(std::io::Error::other("registry worker panicked"))
                    }));
                }
                result
            })?;
        Ok(Self {
            status,
            address,
            identity,
            stopping,
            worker: Some(worker),
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.address
    }
    pub fn status(&self) -> RegistryStatus {
        self.status.clone()
    }
    pub fn identity_id(&self) -> &str {
        &self.identity
    }

    pub fn shutdown(&mut self) -> std::io::Result<()> {
        self.stopping.store(true, Ordering::Release);
        self.join()
    }

    pub fn wait(mut self) -> std::io::Result<()> {
        self.join()
    }

    fn join(&mut self) -> std::io::Result<()> {
        self.worker.take().map_or(Ok(()), |worker| {
            worker
                .join()
                .unwrap_or_else(|_| Err(std::io::Error::other("registry listener panicked")))
        })
    }
}

impl Drop for RegistryRuntime {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

#[cfg(test)]
#[path = "worker_failure_tests.rs"]
mod worker_failure_tests;

#[cfg(test)]
mod root_privacy_tests {
    use super::*;

    #[test]
    fn existing_final_lock_symlink_is_rejected_before_store_creation() {
        assert_lock_redirect_rejected(false);
    }

    #[test]
    fn dangling_final_lock_symlink_is_rejected_without_creating_target() {
        assert_lock_redirect_rejected(true);
    }

    fn assert_lock_redirect_rejected(dangling: bool) {
        let root = tempfile::tempdir().unwrap();
        let state_root = root.path().join("state");
        crate::dashboard::audit::create_private_dir(&state_root).unwrap();
        // The redirect leaves the selected state root, but its destination is
        // still inside this test's owned TempDir. Cleanup touches no host data.
        let target = root.path().join("redirect-target");
        let target_bytes = b"existing outside-state fixture bytes";
        if !dangling {
            fs::write(&target, target_bytes).unwrap();
        }
        let lock_path = state_root.join("registry.lock");
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(&target, &lock_path).expect(
            "fixture requires Windows file-symlink creation permission; setup did not succeed",
        );
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &lock_path)
            .expect("fixture requires an actual final lock symlink; setup did not succeed");
        assert!(
            fs::symlink_metadata(&lock_path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read_link(&lock_path).unwrap(), target);
        let config = fixture(root.path(), state_root.clone());
        let address = config.listener.local_addr().unwrap();
        let certificate_path = root.path().join("identity/certificate.der");
        let key_path = root.path().join("identity/private-key.der");
        let certificate = fs::read(&certificate_path).unwrap();
        let key = fs::read(&key_path).unwrap();
        let rejected = match RegistryRuntime::start(config) {
            Err(_) => true,
            Ok(mut runtime) => {
                // Baseline follows the link. Release its worker and file lock
                // before assertions inspect side effects or clean the fixture.
                runtime.shutdown().unwrap();
                false
            }
        };
        let target_exists = target.exists();
        let stores_created = ["artifacts", "device-leases.json", "vertical-slice.json"]
            .iter()
            .any(|name| state_root.join(name).exists());
        let _released = TcpListener::bind(address).expect("rejected lock redirect leaked listener");
        assert!(
            rejected,
            "runtime accepted final lock symlink (dangling={dangling}, target_exists={target_exists}, stores_created={stores_created})"
        );
        if dangling {
            assert!(!target_exists, "startup created dangling lock target");
        } else {
            assert_eq!(fs::read(&target).unwrap(), target_bytes);
        }
        assert!(
            !stores_created,
            "startup opened stores before rejecting lock redirect"
        );
        assert_eq!(fs::read(&certificate_path).unwrap(), certificate);
        assert_eq!(fs::read(&key_path).unwrap(), key);
        assert!(
            fs::symlink_metadata(lock_path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    fn fixture(root: &Path, state_root: PathBuf) -> RegistryRuntimeConfig {
        RegistryRuntimeConfig {
            listener: TcpListener::bind("127.0.0.1:0").unwrap(),
            transport: Arc::new(
                SecureTransport::load_or_create(root.join("identity"), "controller-fixture")
                    .unwrap(),
            ),
            state_root,
            offline_after: Duration::from_secs(10),
            agent_peers: HashSet::new(),
            recovery_policy: RegistryRecoveryPolicy::Reject,
        }
    }

    #[test]
    fn final_state_path_file_is_rejected_without_modifying_contents() {
        let root = tempfile::tempdir().unwrap();
        let state_path = root.path().join("state");
        fs::write(&state_path, b"owned existing file").unwrap();
        let config = fixture(root.path(), state_path.clone());
        let address = config.listener.local_addr().unwrap();
        let certificate = fs::read(root.path().join("identity/certificate.der")).unwrap();
        let private_key = fs::read(root.path().join("identity/private-key.der")).unwrap();
        assert!(RegistryRuntime::start(config).is_err());
        assert_eq!(fs::read(state_path).unwrap(), b"owned existing file");
        assert_eq!(
            fs::read(root.path().join("identity/certificate.der")).unwrap(),
            certificate
        );
        assert_eq!(
            fs::read(root.path().join("identity/private-key.der")).unwrap(),
            private_key
        );
        let _released = TcpListener::bind(address).expect("invalid state root leaked listener");
    }

    #[cfg(unix)]
    #[test]
    fn owned_state_root_is_tightened_without_changing_owner_or_existing_data() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let root = tempfile::tempdir().unwrap();
        let state_root = root.path().join("state");
        fs::create_dir(&state_root).unwrap();
        fs::set_permissions(&state_root, fs::Permissions::from_mode(0o755)).unwrap();
        let before = fs::metadata(&state_root).unwrap();
        assert_eq!(before.uid(), unsafe { libc::geteuid() });
        assert_ne!(before.mode() & 0o777, 0o700);
        fs::write(state_root.join("preserve"), b"existing data").unwrap();
        let mut runtime = RegistryRuntime::start(fixture(root.path(), state_root.clone())).unwrap();
        let after = fs::metadata(&state_root).unwrap();
        assert_eq!(after.uid(), before.uid());
        assert_eq!(after.mode() & 0o777, 0o700);
        assert_eq!(
            fs::read(state_root.join("preserve")).unwrap(),
            b"existing data"
        );
        runtime.shutdown().unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn owned_state_root_null_dacl_is_rejected_without_security_or_data_changes() {
        use crate::dashboard::managed_policy::windows_acl_is_restrictive;
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Security::Authorization::{SE_FILE_OBJECT, SetNamedSecurityInfoW};
        use windows_sys::Win32::Security::{
            DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
        };
        let root = tempfile::tempdir().unwrap();
        let state_root = root.path().join("state");
        // This existing helper creates a current-user-owned directory even when
        // an elevated runner would otherwise choose Administrators as owner.
        crate::dashboard::audit::create_private_dir(&state_root).unwrap();
        assert!(windows_acl_is_restrictive(&state_root, &HashSet::new()));
        let owner = owner_sid(&state_root);
        let mut name: Vec<u16> = state_root
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect();
        // Null DACL permits everyone. Change only this owned, empty fixture root,
        // proving permissive setup independently of host inheritance settings.
        let status = unsafe {
            SetNamedSecurityInfoW(
                name.as_mut_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(status, 0);
        assert!(
            !windows_acl_is_restrictive(&state_root, &HashSet::new()),
            "fixture did not establish permissive ACL"
        );
        fs::write(state_root.join("preserve"), b"existing data").unwrap();
        let config = fixture(root.path(), state_root.clone());
        let address = config.listener.local_addr().unwrap();
        let before = security_descriptor(&state_root);
        let rejected = match RegistryRuntime::start(config) {
            Err(_) => true,
            Ok(mut runtime) => {
                runtime.shutdown().unwrap();
                false
            }
        };
        let after = security_descriptor(&state_root);
        let _released = TcpListener::bind(address).unwrap();
        assert!(
            rejected,
            "registry admitted a null-DACL state root; security_changed={}",
            before != after
        );
        assert_eq!(after, before, "rejection changed the root owner or DACL");
        assert_eq!(owner_sid(&state_root), owner);
        assert_eq!(
            fs::read(state_root.join("preserve")).unwrap(),
            b"existing data"
        );
        for name in [
            "artifacts",
            "device-leases.json",
            "vertical-slice.json",
            "registry.lock",
        ] {
            assert!(
                !state_root.join(name).exists(),
                "created store before rejecting null DACL: {name}"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn owned_state_root_read_only_extra_access_can_be_tightened() {
        let root = tempfile::tempdir().unwrap();
        let state_root = root.path().join("state");
        crate::dashboard::audit::create_private_dir(&state_root).unwrap();
        let private_security = security_descriptor(&state_root);
        let owner = owner_sid(&state_root);
        set_fixture_dacl(&state_root, &format!("{private_security}(A;;FR;;;WD)"));
        let readable_security = security_descriptor(&state_root);
        assert_ne!(
            readable_security, private_security,
            "fixture did not add read/list access"
        );
        assert!(
            crate::dashboard::managed_policy::windows_acl_is_restrictive(
                &state_root,
                &HashSet::new()
            ),
            "read-only fixture unexpectedly grants foreign write authority"
        );
        fs::write(state_root.join("preserve"), b"safe existing data").unwrap();
        let mut runtime = RegistryRuntime::start(fixture(root.path(), state_root.clone())).unwrap();
        runtime.shutdown().unwrap();
        // Windows may record AUTO_INHERITED after rewriting this protected DACL.
        // Ignore only that bookkeeping flag, retaining exact owner, protection,
        // and ACE equality (including removal of the Everyone read/list grant).
        assert_eq!(
            security_descriptor(&state_root).replace("D:PAI(", "D:P("),
            private_security.replace("D:PAI(", "D:P(")
        );
        assert_eq!(owner_sid(&state_root), owner);
        assert_eq!(
            fs::read(state_root.join("preserve")).unwrap(),
            b"safe existing data"
        );
    }

    #[cfg(windows)]
    struct LocalAllocation(*mut core::ffi::c_void);

    #[cfg(windows)]
    impl Drop for LocalAllocation {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    windows_sys::Win32::Foundation::LocalFree(self.0);
                }
            }
        }
    }

    #[cfg(windows)]
    fn security_descriptor(path: &Path) -> String {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Security::Authorization::{
            ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW,
            SDDL_REVISION_1, SE_FILE_OBJECT,
        };
        use windows_sys::Win32::Security::{DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION};
        let name: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut descriptor = std::ptr::null_mut();
        assert_eq!(
            unsafe {
                GetNamedSecurityInfoW(
                    name.as_ptr(),
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
        let _descriptor = LocalAllocation(descriptor);
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
        let _text = LocalAllocation(text.cast());
        let mut length = 0;
        while unsafe { *text.add(length) } != 0 {
            length += 1;
        }
        String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) }).unwrap()
    }

    #[cfg(windows)]
    fn set_fixture_dacl(path: &Path, sddl: &str) {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1, SE_FILE_OBJECT,
            SetNamedSecurityInfoW,
        };
        use windows_sys::Win32::Security::{
            DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl,
            PROTECTED_DACL_SECURITY_INFORMATION,
        };
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
        let _descriptor = LocalAllocation(descriptor);
        let mut present = 0;
        let mut defaulted = 0;
        let mut dacl = std::ptr::null_mut();
        assert_ne!(
            unsafe {
                GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted)
            },
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

    #[cfg(windows)]
    #[test]
    fn lock_file_privacy_new_lock_has_current_owner_and_restrictive_acl() {
        use crate::dashboard::managed_policy::windows_acl_is_restrictive;
        let root = tempfile::tempdir().unwrap();
        let state_root = root.path().join("state");
        crate::dashboard::audit::create_private_dir(&state_root).unwrap();
        assert!(windows_acl_is_restrictive(&state_root, &HashSet::new()));
        let owner = owner_sid(&state_root);
        fs::write(state_root.join("preserve"), b"existing sentinel").unwrap();
        let config = fixture(root.path(), state_root.clone());
        let certificate_path = root.path().join("identity/certificate.der");
        let key_path = root.path().join("identity/private-key.der");
        let certificate = fs::read(&certificate_path).unwrap();
        let key = fs::read(&key_path).unwrap();
        let lock_path = state_root.join("registry.lock");
        assert!(!lock_path.exists());
        let mut runtime = RegistryRuntime::start(config).unwrap();
        runtime.shutdown().unwrap();
        assert_eq!(
            owner_sid(&lock_path),
            owner,
            "new registry lock is not owned by the authenticated current user"
        );
        assert!(
            windows_acl_is_restrictive(&lock_path, &HashSet::new()),
            "new registry lock has a non-private ACL"
        );
        assert_eq!(
            fs::read(state_root.join("preserve")).unwrap(),
            b"existing sentinel"
        );
        assert_eq!(fs::read(certificate_path).unwrap(), certificate);
        assert_eq!(fs::read(key_path).unwrap(), key);
    }

    #[cfg(unix)]
    #[test]
    fn lock_file_privacy_existing_permissive_unix_lock_is_rejected_without_tightening() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let root = tempfile::tempdir().unwrap();
        let state_root = root.path().join("state");
        crate::dashboard::audit::create_private_dir(&state_root).unwrap();
        let lock_path = state_root.join("registry.lock");
        fs::write(&lock_path, b"owned existing lock").unwrap();
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o644)).unwrap();
        let before = fs::metadata(&lock_path).unwrap();
        assert_eq!(before.uid(), unsafe { libc::geteuid() });
        assert_eq!(before.mode() & 0o777, 0o644);
        let config = fixture(root.path(), state_root.clone());
        let address = config.listener.local_addr().unwrap();
        let rejected = match RegistryRuntime::start(config) {
            Err(_) => true,
            Ok(mut runtime) => {
                runtime.shutdown().unwrap();
                false
            }
        };
        let _released = TcpListener::bind(address).unwrap();
        assert!(
            rejected,
            "registry admitted group/world-accessible existing lock"
        );
        let after = fs::metadata(&lock_path).unwrap();
        assert_eq!(after.uid(), before.uid());
        assert_eq!(after.mode() & 0o777, 0o644);
        assert_eq!(fs::read(lock_path).unwrap(), b"owned existing lock");
        for name in ["artifacts", "device-leases.json", "vertical-slice.json"] {
            assert!(!state_root.join(name).exists());
        }
    }

    #[cfg(windows)]
    #[test]
    fn lock_file_privacy_existing_permissive_lock_is_rejected_without_tightening() {
        use crate::dashboard::managed_policy::windows_acl_is_restrictive;
        let root = tempfile::tempdir().unwrap();
        let state_root = root.path().join("state");
        crate::dashboard::audit::create_private_dir(&state_root).unwrap();
        assert!(windows_acl_is_restrictive(&state_root, &HashSet::new()));
        let owner = owner_sid(&state_root);
        let lock_path = state_root.join("registry.lock");
        let sentinel = b"existing owned lock bytes";
        // Public audit writer creates the fixture file with its explicit current
        // user owner and private ACL; no prior registry stores are necessary.
        crate::dashboard::audit::write_private_atomic(&lock_path, sentinel).unwrap();
        assert_eq!(owner_sid(&lock_path), owner);
        assert!(windows_acl_is_restrictive(&lock_path, &HashSet::new()));
        make_world_accessible(&lock_path);
        assert!(
            !windows_acl_is_restrictive(&lock_path, &HashSet::new()),
            "fixture did not establish permissive lock ACL"
        );
        assert_eq!(owner_sid(&lock_path), owner);
        let config = fixture(root.path(), state_root.clone());
        let address = config.listener.local_addr().unwrap();
        let certificate_path = root.path().join("identity/certificate.der");
        let key_path = root.path().join("identity/private-key.der");
        let certificate = fs::read(&certificate_path).unwrap();
        let key = fs::read(&key_path).unwrap();
        let rejected = match RegistryRuntime::start(config) {
            Err(_) => true,
            Ok(mut runtime) => {
                runtime.shutdown().unwrap();
                false
            }
        };
        let _released = TcpListener::bind(address).expect("lock ACL rejection leaked listener");
        assert!(
            rejected,
            "registry admitted an existing non-private lock file"
        );
        assert!(
            !windows_acl_is_restrictive(&lock_path, &HashSet::new()),
            "startup silently tightened existing lock ACL"
        );
        assert_eq!(owner_sid(&lock_path), owner);
        assert_eq!(fs::read(lock_path).unwrap(), sentinel);
        for name in ["artifacts", "device-leases.json", "vertical-slice.json"] {
            assert!(
                !state_root.join(name).exists(),
                "created store before rejecting lock: {name}"
            );
        }
        assert_eq!(fs::read(certificate_path).unwrap(), certificate);
        assert_eq!(fs::read(key_path).unwrap(), key);
    }

    #[cfg(windows)]
    fn make_world_accessible(path: &Path) {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Security::Authorization::{SE_FILE_OBJECT, SetNamedSecurityInfoW};
        use windows_sys::Win32::Security::{
            DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
        };
        let mut name: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let status = unsafe {
            SetNamedSecurityInfoW(
                name.as_mut_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(
            status, 0,
            "could not set permissive ACL on owned fixture file"
        );
    }

    #[cfg(windows)]
    fn owner_sid(path: &Path) -> Vec<u8> {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
        use windows_sys::Win32::Security::{
            GetLengthSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
        };
        let name: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut owner: PSID = std::ptr::null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let status = unsafe {
            GetNamedSecurityInfoW(
                name.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut descriptor,
            )
        };
        assert_eq!(status, 0);
        assert!(!owner.is_null());
        let bytes = unsafe {
            std::slice::from_raw_parts(owner.cast::<u8>(), GetLengthSid(owner) as usize).to_vec()
        };
        unsafe {
            LocalFree(descriptor);
        }
        bytes
    }
}

#[cfg(test)]
mod terminal_status_tests {
    use super::*;
    use crate::local_ipc::{
        ConnectionState, DaemonRole, DaemonSnapshot, DaemonState, DiagnosticItem,
        LocalProtocolVersion, LocalRequest, LocalResponse,
    };
    use std::sync::mpsc;

    #[test]
    fn terminal_failure_is_visible_before_cleanup_finishes() {
        let status = RegistryStatus::running();
        let observer = status.clone();
        let (cleanup_entered, entered) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let worker = thread::spawn(move || {
            let result = supervise(&status, || {
                Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "fixture accept aborted",
                ))
            });
            cleanup_entered.send(()).unwrap();
            let _ = released.recv_timeout(Duration::from_secs(3));
            result
        });
        let reached_cleanup = entered.recv_timeout(Duration::from_secs(2));
        let observed = observer.snapshot();
        let still_cleaning_up = !worker.is_finished();
        let _ = release.send(());
        let result = worker.join().unwrap();
        assert!(reached_cleanup.is_ok(), "supervision did not reach cleanup");
        assert!(still_cleaning_up, "fixture did not hold cleanup open");
        let error = result.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionAborted);
        assert_eq!(error.to_string(), "fixture accept aborted");
        assert_eq!(
            observed,
            RegistryRuntimeState::Failed {
                code: "registry_listener_failed"
            }
        );
    }

    #[test]
    fn terminal_panic_becomes_observable_failure() {
        let status = RegistryStatus::running();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            supervise(&status, || panic!("listener panic fixture"))
        }));
        assert!(
            result.is_ok(),
            "listener panic escaped supervision and skipped cleanup"
        );
        assert!(result.unwrap().is_err());
        assert_eq!(
            status.snapshot(),
            RegistryRuntimeState::Failed {
                code: "registry_listener_panicked"
            }
        );
    }

    #[test]
    fn terminal_failure_degrades_typed_daemon_status_and_diagnostics() {
        let status = RegistryStatus::running();
        let mut daemon = daemon();
        daemon.attach_registry_status(status.clone());
        assert!(supervise(&status, || Err(std::io::Error::other("accept failed"))).is_err());
        assert_degraded(&mut daemon, "registry_listener_failed");
    }

    #[test]
    fn terminal_stop_degrades_typed_daemon_status_and_diagnostics() {
        let status = RegistryStatus::running();
        let mut daemon = daemon();
        daemon.attach_registry_status(status.clone());
        supervise(&status, || Ok(())).unwrap();
        assert_eq!(status.snapshot(), RegistryRuntimeState::Stopped);
        assert_degraded(&mut daemon, "registry_listener_stopped");
    }

    pub(super) fn assert_degraded(daemon: &mut DaemonState, code: &str) {
        let LocalResponse::Snapshot(snapshot) = daemon
            .handle(LocalRequest::Status {
                version: LocalProtocolVersion::CURRENT,
            })
            .unwrap()
        else {
            panic!("expected typed daemon snapshot");
        };
        assert_eq!(snapshot.connection, ConnectionState::Degraded);
        assert!(snapshot.warnings.iter().any(|warning| warning == code));
        let LocalResponse::Diagnostics(diagnostics) = daemon
            .handle(LocalRequest::Diagnostics {
                version: LocalProtocolVersion::CURRENT,
            })
            .unwrap()
        else {
            panic!("expected typed daemon diagnostics");
        };
        assert!(
            diagnostics
                .iter()
                .any(|item| item.code == code && !item.healthy)
        );
        assert!(
            !diagnostics
                .iter()
                .any(|item| item.code == "ready" && item.healthy)
        );
    }

    pub(super) fn daemon() -> DaemonState {
        DaemonState::new(
            DaemonSnapshot {
                public_identity: "controller-fixture".into(),
                daemon_version: "test".into(),
                os: std::env::consts::OS.into(),
                architecture: std::env::consts::ARCH.into(),
                role: DaemonRole::Registry,
                endpoint: "fixture".into(),
                connection: ConnectionState::Disconnected,
                local_protocol: LocalProtocolVersion::CURRENT,
                remote_protocol: "1.0".into(),
                warnings: vec![],
                remote_access_paused: false,
                autostart: false,
                log_location: String::new(),
                features: vec![],
            },
            vec![DiagnosticItem {
                code: "ready".into(),
                message: "local daemon is ready".into(),
                healthy: true,
            }],
        )
    }
}
