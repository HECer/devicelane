use device_development_mesh::local_ipc::{
    DaemonRole, DaemonSnapshot, LocalProtocolVersion, LocalRequest, LocalResponse, local_endpoint,
    send_local_request,
};
use serde::Serialize;
use std::path::PathBuf;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Manager, State, WindowEvent};
use tauri_plugin_notification::NotificationExt;

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
#[serde(rename_all = "camelCase")]
pub struct DesktopSnapshot {
    pub protocol: LocalProtocolVersion,
    pub daemon_version: String,
    pub os: String,
    pub architecture: String,
    pub role: DaemonRole,
    pub connection: device_development_mesh::local_ipc::ConnectionState,
    pub paused: bool,
    pub autostart_enabled: bool,
    pub warnings: Vec<String>,
    pub log_location: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct DiagnosticsResult {
    pub path: String,
}

pub struct DesktopBridge<T> {
    transport: T,
    os: String,
    architecture: String,
    log_location: String,
}

impl<T: DaemonTransport> DesktopBridge<T> {
    pub fn new(
        transport: T,
        os: impl Into<String>,
        architecture: impl Into<String>,
        log_location: impl Into<String>,
    ) -> Self {
        Self {
            transport,
            os: os.into(),
            architecture: architecture.into(),
            log_location: log_location.into(),
        }
    }

    pub fn status(&self) -> Result<DesktopSnapshot, String> {
        match self.transport.send(LocalRequest::Status {
            version: LocalProtocolVersion::CURRENT,
        })? {
            LocalResponse::Snapshot(snapshot) => Ok(self.map_snapshot(snapshot)),
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
            LocalResponse::Diagnostics(_) => Ok(DiagnosticsResult {
                path: diagnostics_dir().display().to_string(),
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

    fn map_snapshot(&self, snapshot: DaemonSnapshot) -> DesktopSnapshot {
        DesktopSnapshot {
            protocol: snapshot.local_protocol,
            daemon_version: env!("CARGO_PKG_VERSION").into(),
            os: self.os.clone(),
            architecture: self.architecture.clone(),
            role: snapshot.role,
            connection: snapshot.connection,
            paused: snapshot.remote_access_paused,
            autostart_enabled: snapshot.autostart,
            warnings: snapshot.warnings,
            log_location: self.log_location.clone(),
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
fn daemon_status(app: AppHandle, bridge: State<'_, AppBridge>) -> Result<DesktopSnapshot, String> {
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
fn repair_daemon(app: AppHandle) -> Result<(), String> {
    let error = "Der DeviceLane-Dienst ist nicht erreichbar. Bitte führe die Reparatur über den Installer oder `devicelane` aus.".to_owned();
    notify_error(&app, &error);
    Err(error)
}

fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.set_focus();
    }
}

pub fn run() {
    let bridge = DesktopBridge::new(
        LocalDaemonTransport,
        std::env::consts::OS,
        std::env::consts::ARCH,
        log_dir().display().to_string(),
    );
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _, _| {
            show_main_window(app)
        }))
        .plugin(tauri_plugin_notification::init())
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
