pub fn validate_production_launch_agent(
    plist: &str,
    controller_host: &str,
    developer_dir: &str,
    tool_paths: &[&str],
) -> Result<(), &'static str> {
    let normalized_host = controller_host.to_ascii_lowercase();
    let invalid_ip = normalized_host
        .parse::<std::net::IpAddr>()
        .is_ok_and(|address| address.is_loopback() || address.is_unspecified());
    if normalized_host.is_empty() || normalized_host == "localhost" || invalid_ip {
        return Err("production_controller_is_loopback");
    }
    let endpoint = if controller_host.contains(':') {
        format!("[{controller_host}]:7443")
    } else {
        format!("{controller_host}:7443")
    };
    if !plist.contains(&format!("<string>{}</string>", xml_escape(&endpoint))) {
        return Err("launch_agent_controller_mismatch");
    }
    if !developer_dir.starts_with('/') || tool_paths.len() != 6 {
        return Err("invalid_developer_directory");
    }
    let developer_prefix = format!("{}/", developer_dir.trim_end_matches('/'));
    for tool in tool_paths {
        if !tool.starts_with(&developer_prefix) || !plist.contains(&xml_escape(tool)) {
            return Err("untrusted_or_unresolved_apple_tool");
        }
    }
    if plist.contains("$PLIST_")
        || plist.contains("${")
        || plist.contains("none:ios:disconnected")
        || plist.contains("process.start@1")
        || !plist.contains("<key>ProgramArguments</key>")
        || !plist.contains("<string>--peer-id</string>")
    {
        return Err("invalid_launch_agent_configuration");
    }
    Ok(())
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
