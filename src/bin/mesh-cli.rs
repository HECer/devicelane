use device_development_mesh::{
    apple_discovery::AppleDiscovery,
    mac_bootstrap::validate_production_launch_agent,
    network_processes::{LeaseRequest, Request, Response, RunRequest},
    preflight::{AppleTool, AppleToolRunner},
    remote_apple_protocol::{AppleOperation, AppleRequest, RemoteProtocolVersion},
    secure_transport::SecureTransport,
};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs,
    io::{BufRead, BufReader, Write},
    net::{TcpListener, TcpStream},
    path::{Component, Path},
    process::Command,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
const NAME: &str = "mesh-cli";
fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if metadata(&a) {
        return;
    }
    if a.first().map(String::as_str) == Some("doctor") {
        doctor(Path::new(&value(&a, "--identity")));
        return;
    }
    if a.first().map(String::as_str) == Some("validate-launch-agent") {
        let plist = fs::read_to_string(value(&a, "--plist")).unwrap();
        let tools = values(&a, "--tool");
        let tool_refs: Vec<_> = tools.iter().map(String::as_str).collect();
        if let Err(error) = validate_production_launch_agent(
            &plist,
            &value(&a, "--controller-host"),
            &value(&a, "--developer-dir"),
            &tool_refs,
        ) {
            eprintln!("{error}");
            std::process::exit(1);
        }
        return;
    }
    if a.first().map(String::as_str) == Some("apple-discover") {
        let workspace = value(&a, "--workspace");
        let runner = AppleToolRunner::new(
            &workspace,
            [
                (AppleTool::Devicectl, value(&a, "--devicectl").into()),
                (AppleTool::Simctl, value(&a, "--simctl").into()),
            ],
        )
        .unwrap();
        match AppleDiscovery::discover(&runner, ".", Duration::from_secs(30)) {
            Ok(devices) => println!("{}", serde_json::to_string(&devices).unwrap()),
            Err(error) => {
                eprintln!("{}", serde_json::json!({"error": error.code()}));
                std::process::exit(1);
            }
        }
        return;
    }
    if a.first().map(String::as_str) == Some("pair") {
        let mut identity = SecureTransport::load_or_create(value(&a, "--identity"), "cli").unwrap();
        let mut reader = BufReader::new(connect(&value(&a, "--address")));
        let mut challenge = String::new();
        reader.read_line(&mut challenge).unwrap();
        let challenge: serde_json::Value = serde_json::from_str(&challenge).unwrap();
        serde_json::to_writer(reader.get_mut(), &serde_json::json!({"code": challenge["code"], "certificate": identity.certificate_der()})).unwrap();
        reader.get_mut().write_all(b"\n").unwrap();
        let mut response = String::new();
        reader.read_line(&mut response).unwrap();
        let response: serde_json::Value = serde_json::from_str(&response).unwrap();
        let certificate: Vec<u8> = serde_json::from_value(response["certificate"].clone()).unwrap();
        identity.trust("registry", &certificate).unwrap();
        return;
    }
    let transport = SecureTransport::load_or_create(value(&a, "--identity"), "cli").unwrap();
    let address = value(&a, "--registry");
    if a.iter().any(|item| item == "hardware-gate") {
        run_hardware_gate(&a, &address, &transport);
        return;
    }
    if a.iter().any(|item| item == "artifact-download") {
        let body: serde_json::Value = serde_json::from_str(&value(&a, "--json-request")).unwrap();
        let artifact_id = body["artifact_id"].as_str().unwrap();
        let metadata = registry_rpc(
            &address,
            &transport,
            Request::ArtifactInfo {
                artifact_id: artifact_id.into(),
            },
        )
        .artifact_metadata
        .unwrap();
        let mut bytes = Vec::new();
        while bytes.len() < metadata.total_size as usize {
            let response = registry_rpc(
                &address,
                &transport,
                Request::ArtifactRead {
                    artifact_id: metadata.id.clone(),
                    offset: bytes.len() as u64,
                    length: 64 * 1024,
                    total_size: metadata.total_size,
                    sha256: metadata.sha256.clone(),
                },
            );
            bytes.extend(response.artifact_chunk.unwrap().bytes);
        }
        assert_eq!(format!("{:x}", Sha256::digest(&bytes)), metadata.sha256);
        println!(
            "{}",
            serde_json::json!({"bytes": bytes, "sha256": metadata.sha256})
        );
        return;
    }
    let stream = connect(&address);
    stream
        // A legacy Run RPC may wait up to fifteen seconds for a busy agent.
        // Keep the client deadline beyond the server deadline so
        // the registry can return its structured `agent_timeout` response.
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut stream = transport.connect_tls(stream, "registry").unwrap();
    let command = a
        .iter()
        .find(|item| {
            matches!(
                item.as_str(),
                "list" | "run" | "events" | "apple-run" | "apple-cancel" | "lease"
            )
        })
        .map(String::as_str)
        .unwrap();
    let request = match command {
        "list" => Request::List,
        "run" => Request::Run {
            operation: serde_json::from_str::<RunRequest>(&value(&a, "--json-request")).unwrap(),
        },
        "events" => {
            let body: serde_json::Value =
                serde_json::from_str(&value(&a, "--json-request")).unwrap();
            Request::Events {
                job_id: body["job_id"].as_str().unwrap().into(),
                after: body["after"].as_u64().unwrap(),
            }
        }
        "apple-run" => Request::AppleRun {
            operation: serde_json::from_str(&value(&a, "--json-request")).unwrap(),
        },
        "apple-cancel" => {
            let body: serde_json::Value =
                serde_json::from_str(&value(&a, "--json-request")).unwrap();
            Request::AppleCancel {
                job_id: body["job_id"].as_str().unwrap().into(),
            }
        }
        "lease" => Request::Lease {
            operation: serde_json::from_str::<LeaseRequest>(&value(&a, "--json-request")).unwrap(),
        },
        _ => unreachable!(),
    };
    serde_json::to_writer(&mut stream, &request).unwrap();
    stream.write_all(b"\n").unwrap();
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line).unwrap();
    let r: Response = serde_json::from_str(&line).unwrap();
    if command != "list" {
        println!("{}", serde_json::to_string(&r).unwrap())
    } else if a.iter().any(|v| v == "--json") {
        println!("{}", serde_json::to_string(&r.hosts).unwrap())
    } else {
        for h in r.hosts {
            println!(
                "{} {} {} {}",
                h.id, h.operating_system, h.architecture, h.status
            );
            println!("capabilities: {}", h.capabilities.join(", "));
            for d in h.devices {
                println!("devices: {} {} {}", d.id, d.platform, d.state)
            }
        }
    }
}

fn registry_rpc(address: &str, transport: &SecureTransport, request: Request) -> Response {
    let mut stream = transport.connect_tls(connect(address), "registry").unwrap();
    serde_json::to_writer(&mut stream, &request).unwrap();
    stream.write_all(b"\n").unwrap();
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap()
}

fn run_hardware_gate(args: &[String], address: &str, transport: &SecureTransport) {
    let device_id = value(args, "--device");
    let team_id = value(args, "--team");
    let output =
        optional_value(args, "--output").unwrap_or_else(|| "mac-hardware-gate.tar.gz".into());
    let lease = registry_rpc(
        address,
        transport,
        Request::Lease {
            operation: LeaseRequest::Acquire {
                device_id: device_id.clone(),
                lifetime_ms: 120_000,
            },
        },
    );
    let grant = lease
        .lease_grant
        .unwrap_or_else(|| panic!("hardware gate lease failed: {:?}", lease.error));
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let request_id = format!("hardware-gate-{nonce}");
    let accepted = registry_rpc(
        address,
        transport,
        Request::AppleRun {
            operation: AppleRequest {
                version: RemoteProtocolVersion { major: 1, minor: 0 },
                request_id: request_id.clone(),
                idempotency_key: request_id,
                capability: "apple.hardware-gate@1".into(),
                workspace_path: "hardware-gate".into(),
                device_id: Some(device_id),
                lease_id: Some(grant.lease_id.clone()),
                operation: AppleOperation::HardwareGate {
                    team_id: team_id.clone(),
                },
            },
        },
    );
    let job_id = accepted
        .job_id
        .unwrap_or_else(|| panic!("hardware gate rejected: {:?}", accepted.error));
    let deadline = Instant::now() + Duration::from_secs(35 * 60);
    let mut renew_at = Instant::now() + Duration::from_secs(30);
    let artifact_id = loop {
        assert!(Instant::now() < deadline, "hardware gate timed out");
        if Instant::now() >= renew_at {
            let renewed = registry_rpc(
                address,
                transport,
                Request::Lease {
                    operation: LeaseRequest::Renew {
                        lease_id: grant.lease_id.clone(),
                        lifetime_ms: 120_000,
                    },
                },
            );
            assert_eq!(renewed.lease_status.as_deref(), Some("renewed"));
            renew_at = Instant::now() + Duration::from_secs(30);
        }
        let response = registry_rpc(
            address,
            transport,
            Request::Events {
                job_id: job_id.clone(),
                after: 0,
            },
        );
        if let Some(terminal) = response
            .events
            .iter()
            .rev()
            .find(|event| matches!(event.kind.as_str(), "completed" | "rejected" | "cancelled"))
        {
            if terminal.kind != "completed" {
                let repair = response
                    .events
                    .iter()
                    .rev()
                    .find(|event| event.kind == "stderr")
                    .map(|event| event.payload.as_str())
                    .unwrap_or("hardware gate did not provide a repair instruction");
                let _ = registry_rpc(
                    address,
                    transport,
                    Request::Lease {
                        operation: LeaseRequest::Release {
                            lease_id: grant.lease_id.clone(),
                        },
                    },
                );
                panic!("hardware gate did not complete: {repair}");
            }
            assert!(
                !terminal.payload.is_empty(),
                "hardware gate artifact is missing"
            );
            break terminal.payload.clone();
        }
        std::thread::sleep(Duration::from_secs(1));
    };
    let bytes = download_artifact(address, transport, &artifact_id);
    fs::write(&output, bytes).unwrap();
    let released = registry_rpc(
        address,
        transport,
        Request::Lease {
            operation: LeaseRequest::Release {
                lease_id: grant.lease_id,
            },
        },
    );
    assert_eq!(released.lease_status.as_deref(), Some("released"));
    verify_evidence_archive(Path::new(&output), &team_id, &job_id)
        .unwrap_or_else(|error| panic!("hardware gate evidence verification failed: {error}"));
    println!("job_id={job_id} artifact_id={artifact_id} output={output}");
}

fn download_artifact(address: &str, transport: &SecureTransport, artifact_id: &str) -> Vec<u8> {
    let metadata = registry_rpc(
        address,
        transport,
        Request::ArtifactInfo {
            artifact_id: artifact_id.into(),
        },
    )
    .artifact_metadata
    .unwrap();
    let mut bytes = Vec::new();
    while bytes.len() < metadata.total_size as usize {
        let response = registry_rpc(
            address,
            transport,
            Request::ArtifactRead {
                artifact_id: metadata.id.clone(),
                offset: bytes.len() as u64,
                length: 64 * 1024,
                total_size: metadata.total_size,
                sha256: metadata.sha256.clone(),
            },
        );
        bytes.extend(response.artifact_chunk.unwrap().bytes);
    }
    assert_eq!(format!("{:x}", Sha256::digest(&bytes)), metadata.sha256);
    bytes
}

fn verify_evidence_archive(
    archive: &Path,
    expected_team: &str,
    expected_job: &str,
) -> Result<(), String> {
    let tar = trusted_tar()?;
    let openssl = trusted_openssl()?;
    let temp = std::env::temp_dir().join(format!(
        "mesh-hardware-evidence-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "clock unavailable")?
            .as_nanos()
    ));
    fs::create_dir(&temp).map_err(|error| error.to_string())?;
    let result = (|| {
        let listing = Command::new(&tar)
            .args(["-tzf"])
            .arg(archive)
            .output()
            .map_err(|_| "tar is required to verify evidence")?;
        if !listing.status.success() {
            return Err("invalid evidence archive".into());
        }
        let mut archive_names = HashSet::new();
        for name in String::from_utf8(listing.stdout)
            .map_err(|_| "archive listing is not UTF-8")?
            .lines()
        {
            let path = Path::new(name.trim_end_matches('/'));
            if path.as_os_str().is_empty()
                || path.is_absolute()
                || !path
                    .components()
                    .all(|component| matches!(component, Component::Normal(_)))
                || path
                    .components()
                    .next()
                    .and_then(|value| value.as_os_str().to_str())
                    != Some("evidence")
            {
                return Err("unsafe evidence archive path".into());
            }
            if !archive_names.insert(path.to_path_buf()) {
                return Err("duplicate evidence archive path".into());
            }
        }
        let verbose = Command::new(&tar)
            .args(["-tvzf"])
            .arg(archive)
            .output()
            .map_err(|_| "tar is required to inspect evidence")?;
        if !verbose.status.success()
            || String::from_utf8_lossy(&verbose.stdout)
                .lines()
                .any(|line| !matches!(line.as_bytes().first(), Some(b'-' | b'd')))
        {
            return Err("evidence archive contains a link or special file".into());
        }
        let extracted = Command::new(&tar)
            .args(["-xzf"])
            .arg(archive)
            .arg("-C")
            .arg(&temp)
            .status()
            .map_err(|_| "tar extraction failed")?;
        if !extracted.success() {
            return Err("evidence extraction failed".into());
        }
        let evidence = temp.join("evidence");
        let hash_list = evidence.join("manifest.sha256");
        let cms = evidence.join("manifest.cms");
        let verified = temp.join("verified-manifest.sha256");
        let signer = temp.join("cms-signer.pem");
        let root = temp.join("AppleRootCA.pem");
        fs::write(
            &root,
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/assets/apple/AppleRootCA.pem"
            )),
        )
        .map_err(|error| error.to_string())?;
        let cms_status = Command::new(&openssl)
            .args(["cms", "-verify", "-binary", "-inform", "DER", "-in"])
            .arg(&cms)
            .arg("-CAfile")
            .arg(&root)
            .args(["-purpose", "any", "-signer"])
            .arg(&signer)
            .arg("-out")
            .arg(&verified)
            .status()
            .map_err(|_| "OpenSSL is required to verify the Apple CMS signature")?;
        if !cms_status.success() || fs::read(&verified).ok() != fs::read(&hash_list).ok() {
            return Err("Apple CMS signature or signed hash list is invalid".into());
        }
        let signer_pem =
            fs::read_to_string(&signer).map_err(|_| "CMS signer certificate is not valid PEM")?;
        if signer_pem.matches("-----BEGIN CERTIFICATE-----").count() != 1 {
            return Err("evidence must have exactly one CMS signer".into());
        }
        let subject_output = Command::new(&openssl)
            .args(["x509", "-in"])
            .arg(&signer)
            .args([
                "-noout",
                "-subject",
                "-nameopt",
                "sep_multiline,sname,utf8,esc_ctrl,esc_msb",
            ])
            .output()
            .map_err(|_| "OpenSSL could not inspect the signer subject")?;
        if !subject_output.status.success() {
            return Err("CMS signer subject is invalid".into());
        }
        let subject = String::from_utf8_lossy(&subject_output.stdout);
        let organizational_units: Vec<_> = subject
            .lines()
            .filter_map(|line| line.trim().strip_prefix("OU="))
            .collect();
        if organizational_units != [expected_team] {
            return Err("CMS signer does not match the expected Apple team".into());
        }
        let manifest: serde_json::Value = serde_json::from_slice(
            &fs::read(evidence.join("manifest.json")).map_err(|error| error.to_string())?,
        )
        .map_err(|_| "manifest.json is invalid")?;
        if manifest["team_id"] != expected_team || manifest["job_id"] != expected_job {
            return Err("signed evidence identity does not match the requested job".into());
        }
        let mut paths = HashSet::new();
        for line in fs::read_to_string(&hash_list)
            .map_err(|_| "signed hash list is not UTF-8")?
            .lines()
        {
            let (expected, relative) =
                line.split_once("  ").ok_or("malformed signed hash entry")?;
            if expected.len() != 64 || !expected.bytes().all(|value| value.is_ascii_hexdigit()) {
                return Err("malformed evidence hash".into());
            }
            let relative = Path::new(relative);
            if relative.is_absolute()
                || !relative
                    .components()
                    .all(|component| matches!(component, Component::Normal(_)))
                || !paths.insert(relative.to_path_buf())
            {
                return Err("unsafe or duplicate signed evidence path".into());
            }
            let actual = format!(
                "{:x}",
                Sha256::digest(
                    fs::read(evidence.join(relative))
                        .map_err(|_| "signed evidence file is missing")?
                )
            );
            if actual != expected.to_ascii_lowercase() {
                return Err("signed evidence file hash mismatch".into());
            }
        }
        for required in ["manifest.json", "device.log", "screenshot.png"] {
            if !paths.iter().any(|path| path.ends_with(required)) {
                return Err(format!("required signed evidence is missing: {required}"));
            }
        }
        if !paths
            .iter()
            .any(|path| path.to_string_lossy().contains("Test.xcresult"))
        {
            return Err("signed XCTest result is missing".into());
        }
        let mut expected_files = paths;
        expected_files.insert(Path::new("manifest.sha256").to_path_buf());
        expected_files.insert(Path::new("manifest.cms").to_path_buf());
        let mut actual_files = HashSet::new();
        collect_regular_files(&evidence, &evidence, &mut actual_files)?;
        if actual_files != expected_files {
            return Err("evidence archive contains unsigned or missing files".into());
        }
        Ok(())
    })();
    let _ = fs::remove_dir_all(&temp);
    result
}

fn collect_regular_files(
    root: &Path,
    directory: &Path,
    files: &mut HashSet<std::path::PathBuf>,
) -> Result<(), String> {
    for entry in fs::read_dir(directory).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let file_type = entry.file_type().map_err(|error| error.to_string())?;
        if file_type.is_symlink() {
            return Err("evidence contains a symbolic link".into());
        }
        if file_type.is_dir() {
            collect_regular_files(root, &entry.path(), files)?;
        } else if file_type.is_file() {
            files.insert(
                entry
                    .path()
                    .strip_prefix(root)
                    .map_err(|_| "evidence path escaped extraction root")?
                    .to_path_buf(),
            );
        } else {
            return Err("evidence contains a special file".into());
        }
    }
    Ok(())
}

#[cfg(windows)]
fn windows_directory() -> Result<std::path::PathBuf, String> {
    use std::{ffi::OsString, os::windows::ffi::OsStringExt};
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetWindowsDirectoryW(buffer: *mut u16, size: u32) -> u32;
    }
    let mut buffer = vec![0_u16; 32_768];
    // SAFETY: the buffer is writable for the advertised number of u16 values.
    let length = unsafe { GetWindowsDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
    if length == 0 || length as usize >= buffer.len() {
        return Err("unable to resolve the trusted Windows directory".into());
    }
    Ok(OsString::from_wide(&buffer[..length as usize]).into())
}

#[cfg(windows)]
fn trusted_tar() -> Result<std::path::PathBuf, String> {
    let windows = windows_directory()?
        .canonicalize()
        .map_err(|_| "trusted Windows directory is unavailable")?;
    let tar = windows.join("System32/tar.exe");
    let resolved = tar
        .canonicalize()
        .map_err(|_| "trusted Windows tar.exe is unavailable")?;
    if !resolved.starts_with(&windows) {
        return Err("trusted tar.exe escaped the Windows directory".into());
    }
    Ok(resolved)
}

#[cfg(windows)]
fn trusted_openssl() -> Result<std::path::PathBuf, String> {
    let windows = windows_directory()?
        .canonicalize()
        .map_err(|_| "trusted Windows directory is unavailable")?;
    let drive = windows
        .ancestors()
        .last()
        .ok_or("unable to resolve the Windows system drive")?;
    for candidate in [
        drive.join("Program Files/Git/usr/bin/openssl.exe"),
        drive.join("Program Files (x86)/Git/usr/bin/openssl.exe"),
    ] {
        if let Ok(resolved) = candidate.canonicalize()
            && resolved.starts_with(drive)
        {
            return Ok(resolved);
        }
    }
    Err("trusted Git for Windows OpenSSL is unavailable".into())
}

#[cfg(not(windows))]
fn trusted_tar() -> Result<std::path::PathBuf, String> {
    std::path::PathBuf::from("/usr/bin/tar")
        .canonicalize()
        .map_err(|_| "trusted /usr/bin/tar is unavailable".into())
}

#[cfg(not(windows))]
fn trusted_openssl() -> Result<std::path::PathBuf, String> {
    for candidate in ["/usr/bin/openssl", "/opt/homebrew/bin/openssl"] {
        if let Ok(resolved) = std::path::PathBuf::from(candidate).canonicalize() {
            return Ok(resolved);
        }
    }
    Err("trusted system OpenSSL is unavailable".into())
}
fn connect(address: &str) -> TcpStream {
    for _ in 0..100 {
        if let Ok(stream) = TcpStream::connect(address) {
            return stream;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    TcpStream::connect(address).unwrap()
}
fn value(a: &[String], n: &str) -> String {
    a.iter()
        .position(|v| v == n)
        .and_then(|i| a.get(i + 1))
        .unwrap()
        .clone()
}
fn optional_value(a: &[String], n: &str) -> Option<String> {
    a.iter()
        .position(|value| value == n)
        .and_then(|index| a.get(index + 1))
        .cloned()
}
fn values(a: &[String], n: &str) -> Vec<String> {
    a.windows(2)
        .filter(|pair| pair[0] == n)
        .map(|pair| pair[1].clone())
        .collect()
}
fn metadata(a: &[String]) -> bool {
    if a == ["--help"] {
        println!(
            "{NAME} doctor --identity DIRECTORY | apple-discover --workspace DIRECTORY --devicectl PATH --simctl PATH --json | pair --address ADDRESS --identity DIRECTORY | --registry ADDRESS --identity DIRECTORY list [--json] | run|events|apple-run|apple-cancel --json-request JSON"
        );
        true
    } else if a == ["--version"] {
        println!("{NAME} {}", env!("CARGO_PKG_VERSION"));
        true
    } else {
        false
    }
}

fn doctor(identity: &Path) {
    let rust = command_succeeds("cargo", &["--version"]);
    let network = loopback_works();
    let xcode = cfg!(target_os = "macos") && command_succeeds("xcodebuild", &["-version"]);
    let adb = command_succeeds("adb", &["version"]);
    let certificates = SecureTransport::load_or_create(identity, "cli").is_ok();
    let permissions = certificates && restrictive(identity);
    let checks = [
        check("rust", rust, "Install Rust with rustup: https://rustup.rs"),
        check(
            "network",
            network,
            "Allow binding and connecting to loopback TCP ports",
        ),
        check(
            "xcode",
            xcode,
            "On macOS install full Xcode and run xcode-select --switch /Applications/Xcode.app",
        ),
        check(
            "adb",
            adb,
            "Install Android SDK Platform Tools and add adb to PATH",
        ),
        check(
            "certificates",
            certificates,
            "Use a writable identity directory and rerun mesh-cli doctor",
        ),
        check(
            "file_permissions",
            permissions,
            "Restrict the identity directory and private-key.der to the current user",
        ),
    ];
    println!(
        "{}",
        serde_json::json!({"schema_version": 1, "checks": checks})
    );
}

fn command_succeeds(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .output()
        .is_ok_and(|output| output.status.success())
}

fn loopback_works() -> bool {
    let Ok(listener) = TcpListener::bind("127.0.0.1:0") else {
        return false;
    };
    listener
        .local_addr()
        .is_ok_and(|address| TcpStream::connect(address).is_ok())
}

fn check(id: &str, ok: bool, repair: &str) -> serde_json::Value {
    serde_json::json!({"id": id, "status": if ok { "ok" } else { "repair" }, "repair": repair})
}

#[cfg(unix)]
fn restrictive(identity: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    [identity, &identity.join("private-key.der")]
        .iter()
        .all(|path| {
            fs::metadata(path).is_ok_and(|metadata| metadata.permissions().mode() & 0o077 == 0)
        })
}

#[cfg(windows)]
fn restrictive(identity: &Path) -> bool {
    let key = identity.join("private-key.der");
    let Ok(account) = Command::new("whoami").output() else {
        return false;
    };
    let account = String::from_utf8_lossy(&account.stdout)
        .trim()
        .to_ascii_lowercase();
    fs::metadata(&key).is_ok()
        && [identity, key.as_path()]
            .iter()
            .all(|path| windows_acl_restrictive(path, &account))
}

#[cfg(windows)]
fn windows_acl_restrictive(path: &Path, account: &str) -> bool {
    let Ok(output) = Command::new("icacls").arg(path).output() else {
        return false;
    };
    let acl = String::from_utf8_lossy(&output.stdout).to_ascii_lowercase();
    output.status.success()
        && acl.lines().filter(|line| line.contains(":(")).all(|line| {
            line.split_once(":(").is_some_and(|(principal, _)| {
                let principal = principal.trim_end();
                principal == account
                    || principal
                        .strip_suffix(account)
                        .is_some_and(|prefix| prefix.ends_with(char::is_whitespace))
                    || principal.ends_with("\\system")
                    || principal.contains("\\logonsessionid_")
            })
        })
}
