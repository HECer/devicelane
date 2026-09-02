import type {
  ActivityEvent,
  ActivityState,
  ConnectionPath,
  Freshness,
  MessageCode,
  MetricValue,
  Presence,
  ResourceClass,
  ResourceOccupancy,
  TrustState
} from "./api";

export interface DisplayValue {
  label: string;
  icon: string;
  sortOrder: number;
}

export function assertNever(value: never): never {
  throw new Error(`Unbekannter Dashboard-Wert: ${String(value)}`);
}

export function presenceDisplay(value: Presence): DisplayValue {
  switch (value) {
    case "offline": return { label: "Offline", icon: "○", sortOrder: 5 };
    case "connecting": return { label: "Verbindet", icon: "↻", sortOrder: 3 };
    case "online": return { label: "Online", icon: "●", sortOrder: 1 };
    case "busy": return { label: "Beschäftigt", icon: "■", sortOrder: 0 };
    case "attention_required": return { label: "Aktion erforderlich", icon: "!", sortOrder: 2 };
    case "remote_access_paused": return { label: "Remotezugriff pausiert", icon: "Ⅱ", sortOrder: 4 };
    default: return assertNever(value);
  }
}

export function activityStateDisplay(value: ActivityState): DisplayValue {
  switch (value) {
    case "awaiting_approval": return { label: "Wartet auf Freigabe", icon: "?", sortOrder: 1 };
    case "queued": return { label: "Eingereiht", icon: "…", sortOrder: 2 };
    case "running": return { label: "Läuft", icon: "▶", sortOrder: 0 };
    case "reconnecting": return { label: "Verbindet erneut", icon: "↻", sortOrder: 3 };
    case "succeeded": return { label: "Erfolgreich", icon: "✓", sortOrder: 4 };
    case "failed": return { label: "Fehlgeschlagen", icon: "×", sortOrder: 5 };
    case "denied": return { label: "Abgelehnt", icon: "−", sortOrder: 6 };
    case "cancelled": return { label: "Abgebrochen", icon: "□", sortOrder: 7 };
    default: return assertNever(value);
  }
}

export function resourceLabel(value: ResourceClass): string {
  switch (value) {
    case "workspace_read": return "Arbeitsbereich lesen";
    case "workspace_write": return "Arbeitsbereich schreiben";
    case "artifact_upload": return "Artefakt hochladen";
    case "artifact_download": return "Artefakt laden";
    case "device_lease": return "Geräte-Lease";
    case "application_install": return "App installieren";
    case "application_launch": return "App starten";
    case "debugger": return "Debugger";
    case "signing": return "Signieren";
    case "microphone": return "Mikrofon";
    case "screen_capture": return "Bildschirmaufnahme";
    case "network_endpoint": return "Netzwerk-Endpunkt";
    case "device_lane_policy": return "DeviceLane-Regel";
    case "device_lane_service": return "DeviceLane-Dienst";
    default: return assertNever(value);
  }
}

export function trustLabel(value: TrustState): string {
  switch (value) {
    case "local": return "Lokal";
    case "trusted": return "Vertrauenswürdig";
    case "untrusted": return "Nicht vertrauenswürdig";
    case "revoked": return "Vertrauen widerrufen";
    default: return assertNever(value);
  }
}

export function connectionPathLabel(value: ConnectionPath): string {
  switch (value) {
    case "local": return "Lokale Verbindung";
    case "direct": return "Direkte Verbindung";
    case "registry": return "Verbindung über Registry";
    case "unavailable": return "Verbindung nicht verfügbar";
    default: return assertNever(value);
  }
}

export function messageCodeLabel(value: MessageCode): string {
  switch (value) {
    case "activity_started": return "Aktivität gestartet";
    case "registry_stale": return "Registry-Daten sind veraltet";
    case "observer_unavailable": return "Prozessbeobachtung nicht verfügbar";
    case "operation_succeeded": return "Vorgang erfolgreich";
    case "operation_failed": return "Vorgang fehlgeschlagen";
    case "access_denied": return "Zugriff abgelehnt";
    case "target_confirmation_required": return "Bestätigung am Ziel erforderlich";
    case "redacted": return "Inhalt redigiert";
    default: return assertNever(value);
  }
}

export function freshnessLabel(value: Freshness): string {
  if (value === "live") return "Live";
  if (value === "unknown") return "Aktualität unbekannt";
  if ("stale" in value) return `Zuletzt gesehen: ${formatTimestamp(value.stale.last_seen_at_ms)}`;
  return assertNever(value);
}

export function compareU64(left: string, right: string): number {
  const leftValue = BigInt(left);
  const rightValue = BigInt(right);
  return leftValue < rightValue ? -1 : leftValue > rightValue ? 1 : 0;
}

export function formatMetric(metric: MetricValue, formatter: (value: string) => string = String): string {
  if ("available" in metric) return formatter(metric.available.value);
  if ("unavailable" in metric) return `Nicht verfügbar: ${metric.unavailable.reason}`;
  return assertNever(metric);
}

export function formatBytes(value: string): string {
  const bytes = BigInt(value);
  const kibibyte = 1024n;
  const mebibyte = kibibyte * kibibyte;
  const formatUnit = (divisor: bigint, unit: string) => {
    const tenths = bytes * 10n / divisor;
    return `${tenths / 10n}.${tenths % 10n} ${unit}`;
  };
  if (bytes < kibibyte) return `${value} B`;
  if (bytes < mebibyte) return formatUnit(kibibyte, "KiB");
  return formatUnit(mebibyte, "MiB");
}

export function timestampDate(value: string): Date | undefined {
  const milliseconds = BigInt(value);
  if (milliseconds > BigInt(Number.MAX_SAFE_INTEGER)) return undefined;
  const date = new Date(Number(milliseconds));
  return Number.isNaN(date.getTime()) ? undefined : date;
}

export function formatTimestamp(value: string): string {
  const date = timestampDate(value);
  return date
    ? new Intl.DateTimeFormat("de-DE", { dateStyle: "medium", timeStyle: "short" }).format(date)
    : "Zeitstempel nicht darstellbar";
}

export function isoTimestamp(value: string): string | undefined {
  return timestampDate(value)?.toISOString();
}

export function eventKey(event: ActivityEvent): string {
  return `${event.activity_id}:${event.sequence}`;
}

export function mergeActivityEvents(current: ActivityEvent[], incoming: ActivityEvent[], maximum = 256): ActivityEvent[] {
  const merged = new Map<string, ActivityEvent>();
  for (const event of [...current, ...incoming]) merged.set(eventKey(event), event);
  return [...merged.values()]
    .sort((left, right) => compareU64(right.occurred_at_ms, left.occurred_at_ms) || compareU64(right.sequence, left.sequence))
    .slice(0, maximum);
}

export function activeOccupancies(events: ActivityEvent[]): ResourceOccupancy[] {
  const newestByActivity = new Map<string, ActivityEvent>();
  for (const event of events) {
    const previous = newestByActivity.get(event.activity_id);
    if (!previous || compareU64(event.sequence, previous.sequence) > 0) newestByActivity.set(event.activity_id, event);
  }
  return [...newestByActivity.values()]
    .filter((event) => event.state === "running" || event.state === "reconnecting")
    .flatMap((event) => event.resources.map((resource) => ({
      activity_id: event.activity_id,
      principal_id: event.principal_id,
      target_host_id: event.target_host_id,
      device_id: event.device_id,
      resource,
      acquired_at_ms: event.started_at_ms ?? event.occurred_at_ms
    })));
}

export function reconnectDelayMs(attempt: number): number {
  return Math.min(30_000, 1_000 * 2 ** Math.max(0, attempt));
}
