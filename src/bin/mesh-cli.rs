use device_development_mesh::{
    network_processes::{Request, Response, RunRequest},
    secure_transport::SecureTransport,
};
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    process::Command,
    time::Duration,
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
    let stream = connect(&address);
    stream
        // A Run RPC may legitimately wait up to two seconds for an agent.
        // Keep the client deadline comfortably beyond the server deadline so
        // the registry can return its structured `agent_timeout` response.
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut stream = transport.connect_tls(stream, "registry").unwrap();
    let command = a
        .iter()
        .find(|item| matches!(item.as_str(), "list" | "run" | "events"))
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
fn metadata(a: &[String]) -> bool {
    if a == ["--help"] {
        println!(
            "{NAME} doctor --identity DIRECTORY | pair --address ADDRESS --identity DIRECTORY | --registry ADDRESS --identity DIRECTORY list [--json] | run|events --json-request JSON"
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
