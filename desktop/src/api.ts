import { invoke } from "@tauri-apps/api/core";

export type ConnectionState = "disconnected" | "connecting" | "connected" | "degraded";
export type DaemonRole = "workstation" | "agent" | "registry";

export interface DaemonSnapshot {
  public_identity: string;
  daemon_version: string;
  os: string;
  architecture: string;
  role: DaemonRole;
  endpoint: string;
  connection: ConnectionState;
  local_protocol: { major: number; minor: number };
  remote_protocol: string;
  warnings: string[];
  remote_access_paused: boolean;
  autostart: boolean;
  log_location: string;
}

export interface DiagnosticItem {
  code: string;
  message: string;
  healthy: boolean;
}

export interface DiagnosticsResult {
  path: string;
  items: DiagnosticItem[];
}

export interface DaemonClient {
  status(): Promise<DaemonSnapshot>;
  pause(): Promise<void>;
  resume(): Promise<void>;
  setAutostart(enabled: boolean): Promise<void>;
  diagnostics(): Promise<DiagnosticsResult>;
  repair(): Promise<void>;
}

export const tauriDaemonClient: DaemonClient = {
  status: () => invoke<DaemonSnapshot>("daemon_status"),
  pause: () => invoke("pause_remote_access"),
  resume: () => invoke("resume_remote_access"),
  setAutostart: (enabled) => invoke("set_autostart", { enabled }),
  diagnostics: () => invoke<DiagnosticsResult>("create_diagnostics"),
  repair: () => invoke("repair_daemon")
};
