use device_development_mesh::{
    network_processes::{Request, Response, RunRequest},
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
        .set_read_timeout(Some(Duration::from_secs(2)))
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
            "{NAME} pair --address ADDRESS --identity DIRECTORY | --registry ADDRESS --identity DIRECTORY list [--json] | run|events --json-request JSON"
        );
        true
    } else if a == ["--version"] {
        println!("{NAME} {}", env!("CARGO_PKG_VERSION"));
        true
    } else {
        false
    }
}
