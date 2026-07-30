use device_development_mesh::{
    network_processes::{DeviceSnapshot, HostSnapshot, Request, Response},
    secure_transport::SecureTransport,
};
use std::{
    io::{BufRead, BufReader, Write},
    net::TcpStream,
    thread,
    time::Duration,
};
const NAME: &str = "mesh-agent";
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if metadata(&args) {
        return;
    }
    let registry = value(&args, "--registry");
    let transport = SecureTransport::load_or_create(value(&args, "--identity"), "agent").unwrap();
    let interval = Duration::from_millis(value(&args, "--heartbeat-ms").parse().unwrap());
    let binding = value(&args, "--device");
    let d: Vec<&str> = binding.split(':').collect();
    let host = HostSnapshot {
        id: value(&args, "--id"),
        operating_system: value(&args, "--os"),
        architecture: value(&args, "--arch"),
        status: "online".into(),
        capabilities: values(&args, "--capability"),
        devices: vec![DeviceSnapshot {
            id: d[0].into(),
            platform: d[1].into(),
            state: d[2].into(),
        }],
    };
    loop {
        if let Ok(stream) = TcpStream::connect(&registry) {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
            if let Ok(mut stream) = transport.connect_tls(stream, "registry") {
                let _ =
                    serde_json::to_writer(&mut stream, &Request::Heartbeat { host: host.clone() });
                let _ = stream.write_all(b"\n");
                let mut line = String::new();
                let _ = BufReader::new(stream).read_line(&mut line);
                let _: Result<Response, _> = serde_json::from_str(&line);
            }
        }
        thread::sleep(interval)
    }
}
fn value(a: &[String], n: &str) -> String {
    a.iter()
        .position(|v| v == n)
        .and_then(|i| a.get(i + 1))
        .unwrap()
        .clone()
}
fn values(a: &[String], n: &str) -> Vec<String> {
    a.windows(2)
        .filter(|p| p[0] == n)
        .map(|p| p[1].clone())
        .collect()
}
fn metadata(a: &[String]) -> bool {
    if a == ["--help"] {
        println!(
            "{NAME} --registry ADDRESS --identity DIRECTORY --id ID --os OS --arch ARCH --capability NAME --device ID:PLATFORM:STATE --heartbeat-ms MILLISECONDS"
        );
        true
    } else if a == ["--version"] {
        println!("{NAME} {}", env!("CARGO_PKG_VERSION"));
        true
    } else {
        false
    }
}
