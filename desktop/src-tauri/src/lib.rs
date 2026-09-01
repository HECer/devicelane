use device_development_mesh::local_ipc::{
    DaemonSnapshot, DiagnosticItem, LocalProtocolVersion, LocalRequest, LocalResponse,
    local_endpoint, send_local_request,
};
use serde::Serialize;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Manager, State, WindowEvent};
use tauri_plugin_notification::NotificationExt;
use tauri_plugin_shell::ShellExt;

pub trait DaemonTransport: Send + Sync + 'static {
    fn send(&self, request: LocalRequest) -> Result<LocalResponse, String>;
}

pub struct LocalDaemonTransport;

impl DaemonTransport for LocalDaemonTransport {
    fn send(&self, request: LocalRequest) -> Result<LocalResponse, String> {
        let endpoint = local_endpoint(&runtime_dir(), "").map_err(|error| error.to_string())?;
        send_local_request(&endpoint, &request).map_err(|error| error.to_string())
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct DiagnosticsResult {
    pub path: String,
    pub items: Vec<DiagnosticItem>,
}

pub struct DesktopBridge<T> {
    transport: T,
}

impl<T: DaemonTransport> DesktopBridge<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    pub fn status(&self) -> Result<DaemonSnapshot, String> {
        match self.transport.send(LocalRequest::Status {
            version: LocalProtocolVersion::CURRENT,
        })? {
            LocalResponse::Snapshot(snapshot) => Ok(snapshot),
            response => Err(unexpected_response(response)),
        }
    }

    pub fn pause(&self) -> Result<(), String> {
        self.acknowledge(LocalRequest::PauseRemoteAccess {
            version: LocalProtocolVersion::CURRENT,
        })
    }

    pub fn resume(&self) -> Result<(), String> {
        self.acknowledge(LocalRequest::ResumeRemoteAccess {
            version: LocalProtocolVersion::CURRENT,
        })
    }

    pub fn set_autostart(&self, enabled: bool) -> Result<(), String> {
        self.acknowledge(LocalRequest::SetAutostart {
            version: LocalProtocolVersion::CURRENT,
            enabled,
        })
    }

    pub fn diagnostics(&self) -> Result<DiagnosticsResult, String> {
        match self.transport.send(LocalRequest::Diagnostics {
            version: LocalProtocolVersion::CURRENT,
        })? {
            LocalResponse::Diagnostics(items) => Ok(DiagnosticsResult {
                path: diagnostics_dir().display().to_string(),
                items,
            }),
            response => Err(unexpected_response(response)),
        }
    }

    fn acknowledge(&self, request: LocalRequest) -> Result<(), String> {
        match self.transport.send(request)? {
            LocalResponse::Acknowledged => Ok(()),
            response => Err(unexpected_response(response)),
        }
    }
}

fn unexpected_response(response: LocalResponse) -> String {
    match response {
        LocalResponse::Error { code, message } => format!("daemon error ({code}): {message}"),
        _ => "unexpected response from DeviceLane service".into(),
    }
}

fn user_home() -> PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
}

fn runtime_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    return user_home().join("Library/Application Support/DeviceLane/state/runtime");
    #[cfg(target_os = "linux")]
    return std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| user_home().join(".local/state/devicelane/runtime"))
        .join("devicelane");
    #[cfg(windows)]
    return std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| user_home().join("AppData/Local"))
        .join("DeviceLane/service/runtime");
}

fn log_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    return user_home().join("Library/Logs/DeviceLane");
    #[cfg(target_os = "linux")]
    return user_home().join(".local/state/devicelane/logs");
    #[cfg(windows)]
    return std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| user_home().join("AppData/Local"))
        .join("DeviceLane/service/logs");
}

fn diagnostics_dir() -> PathBuf {
    log_dir().join("diagnostics")
}

type AppBridge = DesktopBridge<LocalDaemonTransport>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepairSpec {
    pub program: PathBuf,
    pub arguments: Vec<OsString>,
    pub service_binary: PathBuf,
}

pub trait RepairProcess {
    fn execute(&self, spec: &RepairSpec) -> Result<(), String>;
}

struct CommandRepairProcess;

impl RepairProcess for CommandRepairProcess {
    fn execute(&self, spec: &RepairSpec) -> Result<(), String> {
        let output = Command::new(&spec.program)
            .args(&spec.arguments)
            .env("DEVICELANE_SERVICE_BINARY", &spec.service_binary)
            .output()
            .map_err(|error| format!("DeviceLane repair could not start: {error}"))?;
        if output.status.success() {
            Ok(())
        } else {
            let detail = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            Err(if detail.is_empty() {
                format!("DeviceLane repair exited with {}", output.status)
            } else {
                format!("DeviceLane repair failed: {detail}")
            })
        }
    }
}

pub fn repair_spec(
    platform: &str,
    resource_dir: &Path,
    service_binary: &Path,
) -> Result<RepairSpec, String> {
    let (program, script, mode, prefix): (PathBuf, &str, &str, Vec<OsString>) = match platform {
        "windows" => (
            PathBuf::from(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
            "setup-windows.ps1",
            "--service-repair",
            [
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
            ]
            .into_iter()
            .map(OsString::from)
            .collect(),
        ),
        "macos" => (
            PathBuf::from("/bin/sh"),
            "setup-mac.sh",
            "--repair",
            Vec::new(),
        ),
        "linux" => (
            PathBuf::from("/bin/sh"),
            "setup-linux.sh",
            "--repair",
            Vec::new(),
        ),
        _ => return Err(format!("unsupported repair platform: {platform}")),
    };
    let script = resource_dir.join("scripts").join(script);
    let mut arguments = prefix;
    arguments.push(script.into_os_string());
    arguments.push(mode.into());
    Ok(RepairSpec {
        program,
        arguments,
        service_binary: service_binary.to_owned(),
    })
}

fn run_repair(platform: &str, resource_dir: &Path, service_binary: &Path) -> Result<(), String> {
    let trusted_root = resource_dir
        .canonicalize()
        .map_err(|error| format!("DeviceLane resource directory is unavailable: {error}"))?;
    let spec = repair_spec(platform, &trusted_root, service_binary)?;
    let script_index = spec.arguments.len().saturating_sub(2);
    let script = PathBuf::from(&spec.arguments[script_index]);
    let trusted_script = script
        .canonicalize()
        .map_err(|error| format!("DeviceLane repair asset is unavailable: {error}"))?;
    if !trusted_script.starts_with(&trusted_root) || !trusted_script.is_file() {
        return Err("DeviceLane repair asset failed path validation".into());
    }
    let trusted_service = service_binary
        .canonicalize()
        .map_err(|error| format!("Bundled DeviceLane service is unavailable: {error}"))?;
    if !trusted_service.is_file() {
        return Err("Bundled DeviceLane service failed path validation".into());
    }
    let mut arguments = spec.arguments;
    arguments[script_index] = trusted_script.into_os_string();
    let trusted_spec = RepairSpec {
        arguments,
        service_binary: trusted_service,
        ..spec
    };
    CommandRepairProcess.execute(&trusted_spec)
}

async fn locate_service_sidecar(app: &AppHandle) -> Result<PathBuf, String> {
    let output = app
        .shell()
        .sidecar("devicelane-service")
        .map_err(|error| format!("DeviceLane sidecar cannot be resolved: {error}"))?
        .arg("--print-executable-path")
        .output()
        .await
        .map_err(|error| format!("DeviceLane sidecar cannot be queried: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "DeviceLane sidecar path query failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let path = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
    path.is_absolute()
        .then_some(path)
        .ok_or_else(|| "DeviceLane sidecar returned a non-absolute path".into())
}

fn notify_error(app: &AppHandle, error: &str) {
    let _ = app
        .notification()
        .builder()
        .title("DeviceLane")
        .body(error)
        .show();
}

fn report<T>(app: &AppHandle, result: Result<T, String>) -> Result<T, String> {
    if let Err(error) = &result {
        notify_error(app, error);
    }
    result
}

#[tauri::command]
fn daemon_status(app: AppHandle, bridge: State<'_, AppBridge>) -> Result<DaemonSnapshot, String> {
    report(&app, bridge.status())
}

#[tauri::command]
fn pause_remote_access(app: AppHandle, bridge: State<'_, AppBridge>) -> Result<(), String> {
    report(&app, bridge.pause())
}

#[tauri::command]
fn resume_remote_access(app: AppHandle, bridge: State<'_, AppBridge>) -> Result<(), String> {
    report(&app, bridge.resume())
}

#[tauri::command]
fn set_autostart(
    app: AppHandle,
    bridge: State<'_, AppBridge>,
    enabled: bool,
) -> Result<(), String> {
    report(&app, bridge.set_autostart(enabled))
}

#[tauri::command]
fn create_diagnostics(
    app: AppHandle,
    bridge: State<'_, AppBridge>,
) -> Result<DiagnosticsResult, String> {
    report(&app, bridge.diagnostics())
}

#[tauri::command]
async fn repair_daemon(app: AppHandle) -> Result<(), String> {
    let service_binary = locate_service_sidecar(&app).await;
    let result = app
        .path()
        .resource_dir()
        .map_err(|error| format!("DeviceLane resources cannot be resolved: {error}"))
        .and_then(|resources| {
            service_binary
                .and_then(|service| run_repair(std::env::consts::OS, &resources, &service))
        });
    report(&app, result)
}

fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.set_focus();
    }
}

pub fn run() {
    let bridge = DesktopBridge::new(LocalDaemonTransport);
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _, _| {
            show_main_window(app)
        }))
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_shell::init())
        .manage(bridge)
        .setup(|app| {
            let show = MenuItem::with_id(app, "show", "DeviceLane anzeigen", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Beenden", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show, &quit])?;
            TrayIconBuilder::new()
                .icon(
                    app.default_window_icon()
                        .cloned()
                        .ok_or("DeviceLane tray icon is missing")?,
                )
                .menu(&menu)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => show_main_window(app),
                    "quit" => app.exit(0),
                    _ => {}
                })
                .build(app)?;
            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .invoke_handler(tauri::generate_handler![
            daemon_status,
            pause_remote_access,
            resume_remote_access,
            set_autostart,
            create_diagnostics,
            repair_daemon
        ])
        .run(tauri::generate_context!())
        .expect("DeviceLane desktop runtime failed");
}
