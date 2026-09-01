use std::process::Command;

#[test]
fn unix_lifecycle_fake_operations_restore_previous_service() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    #[cfg(windows)]
    let shell = r"C:\Program Files\Git\bin\sh.exe";
    #[cfg(unix)]
    let shell = "sh";
    let output = Command::new(shell)
        .arg(root.join("scripts/lifecycle-transaction-smoke.sh"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("transaction rollback verified"));
}
