use device_development_mesh::{
    network_processes::{DeviceSnapshot, HostSnapshot, Request, Response},
    secure_transport::SecureTransport,
};
use std::{
    io::{BufRead, BufReader, Write},
    net::TcpStream,
    process::Command,
    thread,
    time::Duration,
};
const NAME: &str = "mesh-agent";
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if metadata(&args) {
        return;
    }
    if args.first().map(String::as_str) == Some("pair") {
        let mut identity =
            SecureTransport::load_or_create(value(&args, "--identity"), "agent").unwrap();
        let mut reader = BufReader::new(TcpStream::connect(value(&args, "--address")).unwrap());
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
    if args.first().map(String::as_str) == Some("execute") {
        let mut input = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut input).unwrap();
        let files: Vec<device_development_mesh::network_processes::ManifestUpload> =
            serde_json::from_str(&input).unwrap();
        let workspace = std::env::temp_dir().join(format!("mesh-agent-job-{}", std::process::id()));
        std::fs::create_dir_all(&workspace).unwrap();
        for file in &files {
            let path = std::path::Path::new(&file.path);
            assert!(
                !path.is_absolute()
                    && path
                        .components()
                        .all(|part| matches!(part, std::path::Component::Normal(_)))
            );
            let destination = workspace.join(path);
            std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
            std::fs::write(destination, file.contents.as_bytes()).unwrap();
        }
        println!("manifest_files={}", files.len());
        std::fs::remove_dir_all(workspace).unwrap();
        return;
    }
    let registry = value(&args, "--registry");
    let transport = SecureTransport::load_or_create(value(&args, "--identity"), "agent").unwrap();
    let interval = Duration::from_millis(value(&args, "--heartbeat-ms").parse().unwrap());
    let workspace_root = std::path::PathBuf::from(
        optional_value(&args, "--workspace-root")
            .unwrap_or_else(|| std::env::temp_dir().to_string_lossy().into_owned()),
    );
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
                let _ = BufReader::new(&mut stream).read_line(&mut line);
                if let Ok(response) = serde_json::from_str::<Response>(&line)
                    && let (Some(job_id), Some(operation)) = (response.job_id, response.operation)
                {
                    let workspace = workspace_root.join(&host.id).join(&operation.workspace_id);
                    std::fs::create_dir_all(&workspace).unwrap();
                    for file in &operation.manifest {
                        let destination = workspace.join(&file.path);
                        std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
                        std::fs::write(destination, file.contents.as_bytes()).unwrap();
                    }
                    let artifact = format!("manifest_files={}", operation.manifest.len());
                    let output = if cfg!(windows) {
                        Command::new("cmd")
                            .args(["/C", "echo", &artifact])
                            .current_dir(&workspace)
                            .output()
                            .unwrap()
                    } else {
                        Command::new("printf")
                            .args(["%s\\n", &artifact])
                            .current_dir(&workspace)
                            .output()
                            .unwrap()
                    };
                    complete(&registry, &transport, job_id, artifact, output);
                }
            }
        }
        thread::sleep(interval)
    }
}
fn complete(
    registry: &str,
    transport: &SecureTransport,
    job_id: String,
    artifact: String,
    output: std::process::Output,
) {
    let Ok(stream) = TcpStream::connect(registry) else {
        return;
    };
    let Ok(mut stream) = transport.connect_tls(stream, "registry") else {
        return;
    };
    let events = vec![
        device_development_mesh::network_processes::NetworkEvent {
            sequence: 1,
            kind: "started".into(),
            payload: String::new(),
        },
        device_development_mesh::network_processes::NetworkEvent {
            sequence: 2,
            kind: "stdout".into(),
            payload: String::from_utf8_lossy(&output.stdout).into_owned(),
        },
        device_development_mesh::network_processes::NetworkEvent {
            sequence: 3,
            kind: "exit".into(),
            payload: output.status.code().unwrap_or(-1).to_string(),
        },
    ];
    serde_json::to_writer(
        &mut stream,
        &Request::Complete {
            job_id,
            artifact,
            events,
        },
    )
    .unwrap();
    stream.write_all(b"\n").unwrap();
}
fn value(a: &[String], n: &str) -> String {
    optional_value(a, n).unwrap()
}
fn optional_value(a: &[String], n: &str) -> Option<String> {
    a.iter()
        .position(|v| v == n)
        .and_then(|i| a.get(i + 1))
        .cloned()
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
