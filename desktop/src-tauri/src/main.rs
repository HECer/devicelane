fn main() {
    if std::env::args().nth(1).as_deref() == Some("--smoke-probe") {
        match devicelane_desktop::run_smoke_probe() {
            Ok(snapshot) => {
                println!("{snapshot}");
                return;
            }
            Err(error) => {
                eprintln!("DeviceLane desktop smoke probe failed: {error}");
                std::process::exit(1);
            }
        }
    }
    devicelane_desktop::run();
}
