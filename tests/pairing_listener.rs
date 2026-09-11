use device_development_mesh::secure_transport::SecureTransport;
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn rejected_output(command: &mut Command) -> std::process::Output {
    let mut child = ChildGuard(
        command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(3);
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "unsafe listener was not rejected promptly"
        );
        thread::sleep(Duration::from_millis(10));
    };
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    child
        .0
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut stdout)
        .unwrap();
    child
        .0
        .stderr
        .take()
        .unwrap()
        .read_to_end(&mut stderr)
        .unwrap();
    std::process::Output {
        status,
        stdout,
        stderr,
    }
}

#[test]
fn rejected_pairing_listener_does_not_create_identity() {
    // Occupying this port keeps the pre-guard binary from exposing a listener in RED.
    let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
    let wildcard = format!("0.0.0.0:{}", occupied.local_addr().unwrap().port());
    for address in [
        "not-an-address",
        wildcard.as_str(),
        "localhost:12345",
        "8.8.8.8:12345",
        "[::]:12345",
        "[::ffff:0.0.0.0]:12345",
        "255.255.255.255:12345",
        "224.0.0.1:12345",
        "[fe80::1]:12345",
    ] {
        let root = tempfile::tempdir().unwrap();
        let identity = root.path().join("identity");
        let output = rejected_output(
            Command::new(env!("CARGO_BIN_EXE_mesh-registry"))
                .args(["pair", "--listen", address, "--identity"])
                .arg(&identity),
        );
        assert!(!output.status.success(), "accepted {address}");
        assert!(!identity.exists(), "created credentials for {address}");
        let error: serde_json::Value = serde_json::from_slice(&output.stderr)
            .expect("listener rejection must be a structured error, not a panic");
        assert_eq!(error["error"], "invalid_pairing_listener");
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn missing_listener_is_rejected_before_identity_creation() {
    let root = tempfile::tempdir().unwrap();
    let identity = root.path().join("identity");
    let output = rejected_output(
        Command::new(env!("CARGO_BIN_EXE_mesh-registry"))
            .args(["pair", "--identity"])
            .arg(&identity),
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(!identity.exists());
    let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["error"], "invalid_pairing_listener");
}

#[test]
fn explicit_loopback_pairing_still_completes() {
    let root = tempfile::tempdir().unwrap();
    let reserved = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reserved.local_addr().unwrap();
    drop(reserved);
    let identity_path = root.path().join("registry");
    let peer = SecureTransport::load_or_create(root.path().join("peer"), "peer").unwrap();
    let mut child = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_mesh-registry"))
            .args(["pair", "--listen", &address.to_string(), "--identity"])
            .arg(&identity_path)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    let stream = loop {
        if let Ok(stream) = TcpStream::connect_timeout(&address, Duration::from_millis(100)) {
            break stream;
        }
        assert!(Instant::now() < deadline, "loopback listener did not start");
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "pairing exited early"
        );
        thread::sleep(Duration::from_millis(20));
    };
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let response: serde_json::Value = serde_json::from_str(&line).unwrap();
    serde_json::to_writer(
        reader.get_mut(),
        &serde_json::json!({
            "code": response["code"], "certificate": peer.certificate_der(),
        }),
    )
    .unwrap();
    reader.get_mut().write_all(b"\n").unwrap();
    line.clear();
    reader.read_line(&mut line).unwrap();
    let response: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert!(
        response["certificate"]
            .as_array()
            .is_some_and(|bytes| !bytes.is_empty())
    );
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(Instant::now() < deadline, "pairing listener did not exit");
        thread::sleep(Duration::from_millis(20));
    }
    assert!(
        TcpListener::bind(address).is_ok(),
        "pairing port remained bound"
    );
}
