use sha2::{Digest, Sha256};
use std::{env, fs, path::PathBuf};

fn hash(path: &PathBuf) -> Option<String> {
    let mut file = fs::File::open(path).ok()?;
    let mut digest = Sha256::new();
    std::io::copy(&mut file, &mut digest).ok()?;
    Some(format!("{:x}", digest.finalize()))
}

fn main() {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let target = env::var("TARGET").unwrap();
    let extension = if target.contains("windows") {
        ".exe"
    } else {
        ""
    };
    let sidecar = manifest
        .join("binaries")
        .join(format!("devicelane-service-{target}{extension}"));
    let scripts = manifest.join("../..").join("scripts");
    let entries = [
        ("WINDOWS_SCRIPT_SHA256", scripts.join("setup-windows.ps1")),
        ("MACOS_SCRIPT_SHA256", scripts.join("setup-mac.sh")),
        ("LINUX_SCRIPT_SHA256", scripts.join("setup-linux.sh")),
        ("SIDECAR_SHA256", sidecar),
    ];
    let mut generated = String::new();
    for (name, path) in entries {
        println!("cargo:rerun-if-changed={}", path.display());
        let value = hash(&path).unwrap_or_default();
        generated.push_str(&format!("pub const {name}: &str = {value:?};\n"));
    }
    fs::write(
        PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("repair_integrity.rs"),
        generated,
    )
    .unwrap();
    tauri_build::build()
}
