use device_development_mesh::registry_runtime::{
    RegistryRecoveryPolicy, RegistryRuntime, RegistryRuntimeConfig,
};
use device_development_mesh::secure_transport::SecureTransport;
use device_development_mesh::state_paths::{
    prepare_private_state_directory, validate_private_state_directory,
};
use std::{
    collections::HashSet,
    io::{BufRead, BufReader, Write},
    net::{SocketAddr, TcpListener},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
const NAME: &str = "mesh-registry";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if metadata(&args) {
        return;
    }
    if args.first().map(String::as_str) == Some("pair") {
        pair(&args);
        return;
    }
    let identity = PathBuf::from(value(&args, "--identity"));
    let listen = value(&args, "--listen");
    let offline_after = Duration::from_millis(value(&args, "--offline-after-ms").parse().unwrap());
    let configured_agents = values(&args, "--agent-peer");
    let agent_peers = if configured_agents.is_empty() {
        HashSet::from(["agent".into()])
    } else {
        configured_agents.into_iter().collect()
    };
    let identity = validate_private_state_directory(&identity).unwrap();
    let listener = TcpListener::bind(listen).unwrap();
    let identity = prepare_private_state_directory(&identity).unwrap();
    let transport = Arc::new(SecureTransport::load_or_create(&identity, "registry").unwrap());
    RegistryRuntime::start(RegistryRuntimeConfig {
        listener,
        transport,
        state_root: identity,
        offline_after,
        agent_peers,
        recovery_policy: RegistryRecoveryPolicy::ReadOnly,
    })
    .unwrap()
    .wait()
    .unwrap();
}

fn pairing_listener_address(value: &str) -> Result<SocketAddr, &'static str> {
    let address: SocketAddr = value.parse().map_err(|_| "invalid_pairing_listener")?;
    let allowed_v4 =
        |ip: std::net::Ipv4Addr| ip.is_loopback() || ip.is_private() || ip.is_link_local();
    let allowed = match address {
        SocketAddr::V4(address) => allowed_v4(*address.ip()),
        SocketAddr::V6(address) => {
            let ip = address.ip();
            if let Some(ipv4) = ip.to_ipv4_mapped() {
                allowed_v4(ipv4)
            } else {
                ip.is_loopback()
                    || ip.is_unique_local()
                    || (ip.is_unicast_link_local() && address.scope_id() != 0)
            }
        }
    };
    allowed.then_some(address).ok_or("invalid_pairing_listener")
}

fn pair(args: &[String]) {
    // Validate before creating credentials or binding. A private bind limits exposure;
    // it does not authenticate the legacy pairing code exchanged on this connection.
    let address = args
        .iter()
        .position(|arg| arg == "--listen")
        .and_then(|index| args.get(index + 1))
        .ok_or("invalid_pairing_listener")
        .and_then(|value| pairing_listener_address(value));
    let address = match address {
        Ok(address) => address,
        Err(error) => {
            eprintln!("{}", serde_json::json!({ "error": error }));
            std::process::exit(2);
        }
    };
    let mut identity =
        SecureTransport::load_or_create(value(args, "--identity"), "registry").unwrap();
    let listener = TcpListener::bind(address).unwrap();
    let (stream, _) = listener.accept().unwrap();
    let mut reader = BufReader::new(stream);
    let code = identity.issue_pairing_code(Duration::from_secs(10));
    serde_json::to_writer(reader.get_mut(), &serde_json::json!({"code": code})).unwrap();
    reader.get_mut().write_all(b"\n").unwrap();
    let mut request = String::new();
    reader.read_line(&mut request).unwrap();
    let request: serde_json::Value = serde_json::from_str(&request).unwrap();
    let certificate: Vec<u8> = serde_json::from_value(request["certificate"].clone()).unwrap();
    identity
        .accept_pairing(
            request["code"].as_str().unwrap(),
            &certificate,
            Duration::ZERO,
        )
        .unwrap();
    serde_json::to_writer(
        reader.get_mut(),
        &serde_json::json!({"certificate": identity.certificate_der()}),
    )
    .unwrap();
    reader.get_mut().write_all(b"\n").unwrap();
}
fn value(args: &[String], name: &str) -> String {
    args.iter()
        .position(|v| v == name)
        .and_then(|i| args.get(i + 1))
        .unwrap()
        .clone()
}

fn values(args: &[String], name: &str) -> Vec<String> {
    args.windows(2)
        .filter(|pair| pair[0] == name)
        .map(|pair| pair[1].clone())
        .collect()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairing_listener_address_policy_boundaries() {
        // Keep generated Mac bootstrap examples aligned with the actual bind policy.
        for address in [
            "192.168.0.61:7445",
            "[fd12:3456::61]:7445",
            "[fc00:1:2:3:4:5:6:7]:7445",
        ] {
            assert!(
                pairing_listener_address(address).is_ok(),
                "rejected {address}"
            );
        }
        for address in [
            "127.0.0.1:0",
            "127.255.255.254:443",
            "10.0.0.1:443",
            "10.255.255.254:443",
            "172.16.0.1:443",
            "172.31.255.254:443",
            "192.168.0.1:443",
            "192.168.255.254:443",
            "169.254.0.1:443",
            "169.254.255.254:443",
            "[::1]:443",
            "[fc00::1]:443",
            "[fdff:ffff::1]:443",
            "[fe80::1%1]:443",
            "[febf::1%42]:443",
            "[::ffff:127.0.0.1]:443",
            "[::ffff:10.1.2.3]:443",
            "[::ffff:172.16.1.2]:443",
            "[::ffff:192.168.1.2]:443",
            "[::ffff:169.254.1.2]:443",
        ] {
            assert!(
                pairing_listener_address(address).is_ok(),
                "rejected {address}"
            );
        }
        for address in [
            "0.0.0.0:443",
            "[::]:443",
            "8.8.8.8:443",
            "100.64.0.1:443",
            "172.15.255.254:443",
            "172.32.0.1:443",
            "192.167.255.254:443",
            "192.169.0.1:443",
            "169.253.255.254:443",
            "169.255.0.1:443",
            "224.0.0.1:443",
            "255.255.255.255:443",
            "[ff02::1%1]:443",
            "[2001:4860:4860::8888]:443",
            "[fbff::1]:443",
            "[fe00::1]:443",
            "[fe80::1]:443",
            "[fe80::1%0]:443",
            "[fec0::1%1]:443",
            "[::ffff:0.0.0.0]:443",
            "[::ffff:8.8.8.8]:443",
            "[::ffff:224.0.0.1]:443",
            "[::ffff:255.255.255.255]:443",
            "[::127.0.0.1]:443",
            "localhost:443",
            "example.com:443",
            "",
            "127.0.0.1",
            "127.0.0.1:65536",
            "[fe80::1%eth0]:443",
        ] {
            assert!(
                pairing_listener_address(address).is_err(),
                "accepted {address}"
            );
        }
    }
}
