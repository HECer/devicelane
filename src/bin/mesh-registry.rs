use device_development_mesh::network_processes::{HostSnapshot, Request, Response};
use device_development_mesh::secure_transport::SecureTransport;
use std::{
    collections::HashMap,
    io::{BufRead, BufReader, Write},
    net::{TcpListener, TcpStream},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};
const NAME: &str = "mesh-registry";
struct Entry {
    host: HostSnapshot,
    heartbeat: Instant,
}
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if metadata(&args) {
        return;
    }
    let transport =
        Arc::new(SecureTransport::load_or_create(value(&args, "--identity"), "registry").unwrap());
    let listener = TcpListener::bind(value(&args, "--listen")).unwrap();
    let offline = Duration::from_millis(value(&args, "--offline-after-ms").parse().unwrap());
    let entries = Arc::new(Mutex::new(HashMap::new()));
    for stream in listener.incoming() {
        let transport = Arc::clone(&transport);
        let entries = Arc::clone(&entries);
        thread::spawn(move || handle(stream.unwrap(), &transport, offline, entries));
    }
}
fn handle(
    stream: TcpStream,
    transport: &SecureTransport,
    offline: Duration,
    entries: Arc<Mutex<HashMap<String, Entry>>>,
) {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let Ok(mut stream) = transport.accept_tls(stream) else {
        return;
    };
    let mut line = String::new();
    if BufReader::new(&mut stream).read_line(&mut line).is_err() {
        return;
    }
    let Ok(request) = serde_json::from_str(&line) else {
        return;
    };
    let response = match request {
        Request::Heartbeat { mut host } => {
            host.status = "online".into();
            entries.lock().unwrap().insert(
                host.id.clone(),
                Entry {
                    host,
                    heartbeat: Instant::now(),
                },
            );
            Response {
                accepted: true,
                hosts: vec![],
            }
        }
        Request::List => {
            let now = Instant::now();
            let mut hosts: Vec<_> = entries
                .lock()
                .unwrap()
                .values()
                .map(|entry| {
                    let mut host = entry.host.clone();
                    host.status = if now.duration_since(entry.heartbeat) >= offline {
                        "offline"
                    } else {
                        "online"
                    }
                    .into();
                    host
                })
                .collect();
            hosts.sort_by(|a, b| a.id.cmp(&b.id));
            Response {
                accepted: true,
                hosts,
            }
        }
    };
    let _ = serde_json::to_writer(&mut stream, &response);
    let _ = stream.write_all(b"\n");
}
fn value(args: &[String], name: &str) -> String {
    args.iter()
        .position(|v| v == name)
        .and_then(|i| args.get(i + 1))
        .unwrap()
        .clone()
}
fn metadata(args: &[String]) -> bool {
    if args == ["--help"] {
        println!("{NAME} --listen ADDRESS --identity DIRECTORY --offline-after-ms MILLISECONDS");
        true
    } else if args == ["--version"] {
        println!("{NAME} {}", env!("CARGO_PKG_VERSION"));
        true
    } else {
        false
    }
}
