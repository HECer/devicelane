use device_development_mesh::{
    network_processes::{Request, Response},
    secure_transport::SecureTransport,
};
use std::{
    io::{BufRead, BufReader, Write},
    net::TcpStream,
    time::Duration,
};
const NAME: &str = "mesh-cli";
fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if metadata(&a) {
        return;
    }
    let transport = SecureTransport::load_or_create(value(&a, "--identity"), "cli").unwrap();
    let stream = TcpStream::connect(value(&a, "--registry")).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut stream = transport.connect_tls(stream, "registry").unwrap();
    serde_json::to_writer(&mut stream, &Request::List).unwrap();
    stream.write_all(b"\n").unwrap();
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line).unwrap();
    let r: Response = serde_json::from_str(&line).unwrap();
    if a.iter().any(|v| v == "--json") {
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
fn value(a: &[String], n: &str) -> String {
    a.iter()
        .position(|v| v == n)
        .and_then(|i| a.get(i + 1))
        .unwrap()
        .clone()
}
fn metadata(a: &[String]) -> bool {
    if a == ["--help"] {
        println!("{NAME} --registry ADDRESS --identity DIRECTORY list [--json]");
        true
    } else if a == ["--version"] {
        println!("{NAME} {}", env!("CARGO_PKG_VERSION"));
        true
    } else {
        false
    }
}
