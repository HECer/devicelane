use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimePlatform {
    Macos,
    Linux,
    Windows,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeEnvironment {
    pub home: Option<PathBuf>,
    pub xdg_runtime_dir: Option<PathBuf>,
    pub local_app_data: Option<PathBuf>,
}

fn required<'a>(value: Option<&'a Path>, name: &str) -> Result<&'a Path, String> {
    let path = value.ok_or_else(|| format!("{name} unavailable"))?;
    if !path.is_absolute() {
        return Err(format!("{name} must be absolute"));
    }
    Ok(path)
}

pub fn runtime_dir_for(
    platform: RuntimePlatform,
    environment: &RuntimeEnvironment,
) -> Result<PathBuf, String> {
    match platform {
        RuntimePlatform::Macos => Ok(required(environment.home.as_deref(), "HOME")?
            .join("Library/Application Support/DeviceLane/state/runtime")),
        RuntimePlatform::Linux => match environment
            .xdg_runtime_dir
            .as_ref()
            .filter(|path| !path.as_os_str().is_empty())
        {
            Some(path) if path.is_absolute() => Ok(path.join("devicelane")),
            Some(_) => Err("XDG_RUNTIME_DIR must be absolute".into()),
            None => Ok(required(environment.home.as_deref(), "HOME")?
                .join(".local/state/devicelane/runtime/devicelane")),
        },
        RuntimePlatform::Windows => Ok(required(
            environment.local_app_data.as_deref(),
            "LOCALAPPDATA",
        )?
        .join("DeviceLane/service/runtime")),
    }
}

pub fn installed_runtime_dir() -> Result<PathBuf, String> {
    #[cfg(target_os = "macos")]
    let platform = RuntimePlatform::Macos;
    #[cfg(target_os = "linux")]
    let platform = RuntimePlatform::Linux;
    #[cfg(windows)]
    let platform = RuntimePlatform::Windows;
    runtime_dir_for(
        platform,
        &RuntimeEnvironment {
            home: std::env::var_os("HOME").map(PathBuf::from),
            xdg_runtime_dir: std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from),
            local_app_data: std::env::var_os("LOCALAPPDATA").map(PathBuf::from),
        },
    )
}
