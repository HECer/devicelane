use std::process::{Command, Stdio};

fn cli(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_devicelane"))
        .args(args)
        .output()
        .expect("run devicelane")
}

#[test]
fn dashboard_commands_are_documented_and_require_local_transport() {
    for command in ["mesh", "activities", "approvals", "policy", "audit"] {
        let output = cli(&[command, "--help"]);
        assert!(
            output.status.success(),
            "{command}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("--local"));
    }
}

#[test]
fn typed_values_and_bounds_fail_before_ipc() {
    let cases: &[&[&str]] = &[
        &["mesh", "status", "--local", "--scope", "planet"],
        &["activities", "list", "--local", "--limit", "257"],
        &["approvals", "decide", "--local", "--decision", "maybe"],
        &["policy", "delete", "--local", "--rule-id", ""],
        &["audit", "list", "--local", "--result", "unknown"],
        &[
            "policy",
            "put",
            "--local",
            "--effect",
            "allow",
            "--resource",
            "shell",
        ],
    ];
    for args in cases {
        let output = cli(args);
        assert!(!output.status.success(), "accepted {args:?}");
        assert!(!String::from_utf8_lossy(&output.stderr).contains("panicked"));
    }
}

#[test]
fn every_dashboard_query_emits_structured_json_errors() {
    #[cfg(windows)]
    let endpoint = format!(
        r"\\.\pipe\devicelane-dashboard-missing-{}",
        std::process::id()
    );
    #[cfg(unix)]
    let endpoint = "/definitely/missing/devicelane-dashboard.sock".to_owned();
    let commands: &[&[&str]] = &[
        &["mesh", "status", "--local", "--json"],
        &["activities", "list", "--local", "--json"],
        &["approvals", "list", "--local", "--json"],
        &["policy", "list", "--local", "--json"],
        &["audit", "list", "--local", "--json"],
        &["audit", "export", "--local", "--json"],
    ];
    for args in commands {
        let output = Command::new(env!("CARGO_BIN_EXE_devicelane"))
            .args(*args)
            .args(["--endpoint", &endpoint])
            .stdout(Stdio::piped())
            .output()
            .unwrap();
        assert!(!output.status.success(), "accepted {args:?}");
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["type"], "error");
        assert_eq!(value["payload"]["code"], "local_ipc_error");
    }
}

#[test]
fn raw_shell_and_implicit_json_objects_are_not_accepted() {
    for args in [
        vec!["activities", "cancel", "--local", "--shell", "rm -rf /"],
        vec![
            "policy",
            "put",
            "--local",
            "--rule",
            "{\"effect\":\"allow\"}",
        ],
    ] {
        let output = cli(&args);
        assert!(!output.status.success());
    }
}
