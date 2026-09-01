import { invoke } from "@tauri-apps/api/core";

export type ConnectionState = "disconnected" | "connecting" | "connected" | "degraded";
export type DaemonRole = "workstation" | "agent" | "registry";

export interface DaemonSnapshot {
  protocol: { major: number; minor: number };
  daemonVersion: string;
  os: string;
  architecture: string;
  role: DaemonRole;
  connection: ConnectionState;
  paused: boolean;
  autostartEnabled: boolean;
  warnings: string[];
  logLocation: string;
}

export interface DiagnosticsResult {
  path: string;
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
