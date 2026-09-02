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
  features: string[];
}

export type U64Decimal = string;

export interface DiagnosticItem {
  code: string;
  message: string;
  healthy: boolean;
}

export interface DiagnosticsResult {
  path: string;
  items: DiagnosticItem[];
}

export type DashboardScope = "local" | "mesh";
export type Presence = "offline" | "connecting" | "online" | "busy" | "attention_required" | "remote_access_paused";
export type Freshness = "live" | "unknown" | { stale: { last_seen_at_ms: U64Decimal } };
export type TrustState = "local" | "trusted" | "untrusted" | "revoked";
export type ConnectionPath = "local" | "direct" | "registry" | "unavailable";
export type ResourceClass =
  | "workspace_read"
  | "workspace_write"
  | "artifact_upload"
  | "artifact_download"
  | "device_lease"
  | "application_install"
  | "application_launch"
  | "debugger"
  | "signing"
  | "microphone"
  | "screen_capture"
  | "network_endpoint"
  | "device_lane_policy"
  | "device_lane_service";
export type ActivityState = "awaiting_approval" | "queued" | "running" | "reconnecting" | "succeeded" | "failed" | "denied" | "cancelled";
export type PolicyEffect = "allow" | "deny";
export type ApprovalDecision = "allow_once" | "allow_and_remember" | "deny_once" | "deny_and_block";
export type MessageCode = "activity_started" | "registry_stale" | "observer_unavailable" | "operation_succeeded" | "operation_failed" | "access_denied" | "target_confirmation_required" | "redacted";
export type MessageParam = "local" | "remote" | "allowed" | "denied" | "unavailable";

export interface DisplayMessage {
  code: MessageCode;
  params: MessageParam[];
}

export type MetricValue = { available: { value: U64Decimal } } | { unavailable: { reason: string } };

export interface MetricSnapshot {
  current_memory_bytes: MetricValue;
  peak_memory_bytes: MetricValue;
  cpu_time_ms: MetricValue;
  process_count: MetricValue;
}

export interface DashboardDevice {
  id: string;
  host_id: string;
  display_name: string;
  platform: string;
  presence: Presence;
  freshness: Freshness;
  capabilities: string[];
  permissions: string[];
}

export interface DashboardHost {
  id: string;
  display_name: string;
  platform: string;
  architecture: string;
  presence: Presence;
  freshness: Freshness;
  trust: TrustState;
  connection_path: ConnectionPath;
  capabilities: string[];
  permissions: string[];
  devices: DashboardDevice[];
}

export interface Authorization {
  effect: PolicyEffect;
  rule_id: string | null;
  approval_id: string | null;
}

export interface ActivityEvent {
  activity_id: string;
  sequence: U64Decimal;
  occurred_at_ms: U64Decimal;
  principal_id: string;
  source_host_id: string;
  target_host_id: string;
  device_id: string | null;
  operation: string;
  resources: ResourceClass[];
  authorization: Authorization;
  state: ActivityState;
  message: DisplayMessage | null;
  metrics: MetricSnapshot;
  started_at_ms: U64Decimal | null;
  finished_at_ms: U64Decimal | null;
}

export interface ActivitySummary {
  activity_id: string;
  principal_id: string;
  source_host_id: string;
  target_host_id: string;
  device_id: string | null;
  operation: string;
  resources: ResourceClass[];
  state: ActivityState;
  started_at_ms: U64Decimal | null;
  finished_at_ms: U64Decimal | null;
}

export interface ResourceOccupancy {
  activity_id: string;
  principal_id: string;
  target_host_id: string;
  device_id: string | null;
  resource: ResourceClass;
  acquired_at_ms: U64Decimal;
}

export interface ApprovalRequest {
  id: string;
  activity_id: string;
  principal_id: string;
  source_host_id: string;
  target_host_id: string;
  device_id: string | null;
  operation: string;
  resources: ResourceClass[];
  requested_at_ms: U64Decimal;
  expires_at_ms: U64Decimal;
  risk: string;
}

export interface DashboardWarning {
  code: string;
  message: DisplayMessage;
  host_id: string | null;
}

export interface DashboardSnapshot {
  revision: U64Decimal;
  generated_at_ms: U64Decimal;
  scope: DashboardScope;
  hosts: DashboardHost[];
  activities: ActivitySummary[];
  leases: DashboardLease[];
  pending_approvals: ApprovalRequest[];
  warnings: DashboardWarning[];
}

export interface EventCursor {
  epoch: U64Decimal;
  sequence: U64Decimal;
}

export type LeaseState = "active" | "uncertain";

export interface DashboardLease {
  id: string;
  owner_host_id: string;
  device_id: string;
  state: LeaseState;
}

export type EventRead =
  | { result: "events"; events: ActivityEvent[]; next_cursor: EventCursor }
  | { result: "cursor_ahead"; newest_available: EventCursor }
  | { result: "resync_required"; oldest_available: EventCursor; snapshot_revision: U64Decimal }
  | { result: "limit_exceeded" };

export interface DaemonClient {
  status(): Promise<DaemonSnapshot>;
  pause(): Promise<void>;
  resume(): Promise<void>;
  setAutostart(enabled: boolean): Promise<void>;
  diagnostics(): Promise<DiagnosticsResult>;
  repair(): Promise<void>;
  dashboardSnapshot(scope: DashboardScope, signal?: AbortSignal): Promise<DashboardSnapshot>;
  activityEvents(scope: DashboardScope, cursor: EventCursor, limit: number, signal?: AbortSignal): Promise<EventRead>;
  acknowledgeEvents(subscriberId: string, cursor: EventCursor, signal?: AbortSignal): Promise<void>;
}

async function invokeWithSignal<T>(command: string, args: Record<string, unknown>, signal?: AbortSignal): Promise<T> {
  signal?.throwIfAborted();
  const value = await invoke<T>(command, args);
  signal?.throwIfAborted();
  return value;
}

export const tauriDaemonClient: DaemonClient = {
  status: () => invoke<DaemonSnapshot>("daemon_status"),
  pause: () => invoke("pause_remote_access"),
  resume: () => invoke("resume_remote_access"),
  setAutostart: (enabled) => invoke("set_autostart", { enabled }),
  diagnostics: () => invoke<DiagnosticsResult>("create_diagnostics"),
  repair: () => invoke("repair_daemon"),
  dashboardSnapshot: (scope, signal) => invokeWithSignal("dashboard_snapshot", { scope }, signal),
  activityEvents: (scope, cursor, limit, signal) => invokeWithSignal("activity_events", { scope, cursor, limit }, signal),
  acknowledgeEvents: (subscriberId, cursor, signal) => invokeWithSignal("acknowledge_events", { subscriberId, cursor }, signal)
};
