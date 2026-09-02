import { useEffect, useMemo, useRef, useState } from "react";
import type { ActivityEvent, DaemonClient, DaemonSnapshot, DashboardScope, DashboardSnapshot, EventCursor } from "./api";
import { tauriDaemonClient } from "./api";
import { ActivityFeed } from "./components/ActivityFeed";
import { ResourceOccupancy } from "./components/ResourceOccupancy";
import { ScopeSwitcher } from "./components/ScopeSwitcher";
import { TopologyView } from "./components/TopologyView";
import { activeOccupancies, compareU64, mergeActivityEvents, messageCodeLabel, reconnectDelayMs } from "./dashboard-model";
import { usePretext } from "./usePretext";

const connectionLabels = {
  connected: "Verbunden",
  connecting: "Verbindung wird hergestellt",
  degraded: "Eingeschränkt",
  disconnected: "Getrennt"
} as const;

const roleLabels = { workstation: "Arbeitsstation", agent: "Agent", registry: "Registry" } as const;

export function App({ client = tauriDaemonClient }: { client?: DaemonClient }) {
  const [snapshot, setSnapshot] = useState<DaemonSnapshot>();
  const [unavailable, setUnavailable] = useState(false);
  const [diagnosticsPath, setDiagnosticsPath] = useState("");
  const [diagnostics, setDiagnostics] = useState<Awaited<ReturnType<DaemonClient["diagnostics"]>>["items"]>([]);
  const [busy, setBusy] = useState(false);
  const [errorMessage, setErrorMessage] = useState("");
  const [streamError, setStreamError] = useState("");
  const [scope, setScope] = useState<DashboardScope>("local");
  const [dashboard, setDashboard] = useState<DashboardSnapshot>();
  const [events, setEvents] = useState<ActivityEvent[]>([]);
  const [selectedHostId, setSelectedHostId] = useState<string>();
  const [streamReconnecting, setStreamReconnecting] = useState(false);
  const [meshAvailable, setMeshAvailable] = useState(false);
  const meshAvailabilityKnown = useRef(false);
  const dashboardRevision = useRef<string | undefined>(undefined);
  const subscriberId = useRef(`desktop-${globalThis.crypto?.randomUUID?.() ?? Date.now().toString(36)}`);
  usePretext();
  const occupancies = useMemo(() => activeOccupancies(events), [events]);
  const activeJobCount = dashboard?.activities.filter(({ state }) =>
    state === "awaiting_approval" || state === "queued" || state === "running" || state === "reconnecting"
  ).length ?? 0;

  const applyDashboard = (next: DashboardSnapshot) => {
    if (dashboardRevision.current && compareU64(next.revision, dashboardRevision.current) < 0) return;
    dashboardRevision.current = next.revision;
    setDashboard(next);
    setSelectedHostId((selected) => next.hosts.some((host) => host.id === selected)
      ? selected
      : next.hosts[0]?.id);
  };

  const refresh = async () => {
    try {
      setSnapshot(await client.status());
      setUnavailable(false);
    } catch {
      setUnavailable(true);
    }
  };

  useEffect(() => {
    void refresh();
  }, [client]);

  useEffect(() => {
    const controller = new AbortController();
    let timer: number | undefined;
    const updateSnapshot = async () => {
      try {
        const requestedScope = meshAvailabilityKnown.current ? scope : "mesh";
        const next = await client.dashboardSnapshot(requestedScope, controller.signal);
        if (controller.signal.aborted) return;
        applyDashboard(next);
        if (!meshAvailabilityKnown.current || requestedScope === "mesh") {
          setMeshAvailable(next.scope === "mesh");
          meshAvailabilityKnown.current = true;
        }
        if (next.scope !== scope) setScope(next.scope);
      } catch (error) {
        if (!controller.signal.aborted) {
          setErrorMessage(error instanceof Error ? error.message : String(error));
        }
      } finally {
        if (!controller.signal.aborted) timer = window.setTimeout(() => void updateSnapshot(), 10_000);
      }
    };
    void updateSnapshot();
    return () => {
      controller.abort();
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [client, scope]);

  useEffect(() => {
    const controller = new AbortController();
    let timer: number | undefined;
    let cursor: EventCursor = { epoch: "0", sequence: "0" };
    let reconnectAttempt = 0;
    let lastResyncRevision: string | undefined;

    const schedule = (callback: () => void, delay: number) => {
      timer = window.setTimeout(callback, delay);
    };

    const pump = async (): Promise<void> => {
      try {
        const page = await client.activityEvents(cursor, 100, controller.signal);
        if (controller.signal.aborted) return;
        switch (page.result) {
          case "events":
            setEvents((current) => mergeActivityEvents(current, page.events));
            await client.acknowledgeEvents(subscriberId.current, page.next_cursor, controller.signal);
            cursor = page.next_cursor;
            reconnectAttempt = 0;
            setStreamReconnecting(false);
            setStreamError("");
            schedule(() => void pump(), page.events.length === 100 ? 0 : 1_000);
            return;
          case "resync_required": {
            if (lastResyncRevision === page.snapshot_revision) {
              throw new Error("Aktivitätsstream benötigt erneut eine Synchronisierung");
            }
            lastResyncRevision = page.snapshot_revision;
            const freshSnapshot = await client.dashboardSnapshot(scope, controller.signal);
            if (controller.signal.aborted) return;
            applyDashboard(freshSnapshot);
            setScope(freshSnapshot.scope);
            cursor = page.oldest_available;
            await pump();
            return;
          }
          case "cursor_ahead":
            cursor = page.newest_available;
            schedule(() => void pump(), 0);
            return;
          case "limit_exceeded":
            throw new Error("Aktivitätsseite überschreitet das sichere Größenlimit");
          default:
            page satisfies never;
        }
      } catch (error) {
        if (controller.signal.aborted) return;
        setStreamReconnecting(true);
        const delay = reconnectDelayMs(reconnectAttempt++);
        setStreamError(error instanceof Error ? error.message : String(error));
        schedule(() => void pump(), delay);
      }
    };

    void pump();
    return () => {
      controller.abort();
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [client, scope]);

  const run = async <T,>(action: () => Promise<T>, onSuccess?: (value: T) => void) => {
    setBusy(true);
    try {
      const value = await action();
      onSuccess?.(value);
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : String(error));
    } finally {
      await refresh();
      setBusy(false);
    }
  };

  if (unavailable) {
    return (
      <main className="shell shell--centered">
        <section className="empty-state" aria-labelledby="offline-title">
          <span className="status-mark status-mark--offline" aria-hidden="true" />
          <p className="eyebrow">Lokaler Dienst</p>
          <h1 id="offline-title" data-pretext>Dienst nicht erreichbar</h1>
          <p data-pretext>DeviceLane kann den Hintergrunddienst nicht erreichen. Deine Identität bleibt dabei erhalten.</p>
          <button className="primary-action" onClick={() => void run(client.repair)} disabled={busy}>Dienst reparieren</button>
        </section>
      </main>
    );
  }

  if (!snapshot) return <main className="shell shell--centered" aria-busy="true">DeviceLane wird geladen…</main>;

  const toggleRemoteAccess = snapshot.remote_access_paused ? client.resume : client.pause;
  return (
    <div className="app-frame">
      <aside className="sidebar" aria-label="Hauptnavigation">
        <div className="brand"><span aria-hidden="true">DL</span><strong>DeviceLane</strong></div>
        <nav><a href="#overview" aria-current="page">Geräte</a></nav>
        <p className="sidebar-foot">Dienst {snapshot.daemon_version}</p>
      </aside>
      <main className="shell" id="overview">
        {errorMessage && <p className="error-banner" role="alert" aria-live="assertive">{errorMessage}</p>}
        {streamError && <p className="error-banner" role="alert" aria-live="assertive">{streamError}</p>}
        <header className="page-header">
          <div><p className="eyebrow">Lokales Netzwerk</p><h1 data-pretext>Geräteübersicht</h1><p className="active-job-count">{activeJobCount} {activeJobCount === 1 ? "aktiver Job" : "aktive Jobs"}</p></div>
          <span className={`connection-pill connection-pill--${snapshot.connection}`}>
            <span className="status-mark" aria-hidden="true" />{connectionLabels[snapshot.connection]}
          </span>
        </header>

        <ScopeSwitcher scope={scope} meshAvailable={meshAvailable} onChange={setScope} />

        <div id="mesh-dashboard-panel" role="tabpanel" aria-labelledby={scope === "local" ? "scope-local-tab" : "scope-mesh-tab"} className="dashboard-layout" aria-busy={!dashboard}>
          {dashboard ? <>
            <TopologyView hosts={dashboard.hosts} leases={dashboard.leases} selectedHostId={selectedHostId} onSelectHost={setSelectedHostId} />
            <div className="dashboard-side">
              <ResourceOccupancy occupancies={occupancies} />
              <ActivityFeed events={events} reconnecting={streamReconnecting} />
            </div>
          </> : <p className="dashboard-loading">Topologie wird geladen…</p>}
        </div>

        <section className="host-card" aria-labelledby="host-title">
          <div className="host-icon" aria-hidden="true">{snapshot.os === "macOS" ? "M" : "PC"}</div>
          <div className="host-summary">
            <p className="eyebrow">Dieser Computer</p>
            <h2 id="host-title" data-pretext>{snapshot.os} · {snapshot.architecture}</h2>
            <p>{roleLabels[snapshot.role]}</p>
          </div>
          <div className="host-state"><span className="status-mark" aria-hidden="true" />{connectionLabels[snapshot.connection]}</div>
        </section>

        {snapshot.warnings.length > 0 && <section className="warnings" aria-labelledby="warnings-title">
          <h2 id="warnings-title">Hinweise</h2>
          <ul>{snapshot.warnings.map((warning) => <li key={warning} data-pretext>{warning}</li>)}</ul>
        </section>}

        {dashboard && dashboard.warnings.length > 0 && <section className="warnings" aria-labelledby="mesh-warnings-title">
          <h2 id="mesh-warnings-title">Mesh-Hinweise</h2>
          <ul>{dashboard.warnings.map((warning) => <li key={`${warning.code}:${warning.host_id ?? "mesh"}`} data-pretext>{messageCodeLabel(warning.message.code)}</li>)}</ul>
        </section>}

        <section className="control-grid" aria-label="Diensteinstellungen">
          <article className="control-card">
            <div><h2>Remotezugriff</h2><p data-pretext>{snapshot.remote_access_paused ? "Neue Zugriffe sind pausiert." : "Autorisierte Geräte können Ressourcen anfragen."}</p></div>
            <button onClick={() => void run(toggleRemoteAccess)} disabled={busy}>
              {snapshot.remote_access_paused ? "Remotezugriff fortsetzen" : "Remotezugriff pausieren"}
            </button>
          </article>
          <article className="control-card">
            <div><h2>Autostart</h2><p data-pretext>DeviceLane startet im Hintergrund, sobald du dich anmeldest.</p></div>
            <button className="switch" role="switch" aria-checked={snapshot.autostart} aria-label="Beim Anmelden starten" onClick={() => void run(() => client.setAutostart(!snapshot.autostart))} disabled={busy}>
              <span aria-hidden="true" />
            </button>
          </article>
          <article className="control-card control-card--wide">
            <div><h2>Diagnose</h2><p data-pretext>Erstellt eine lokale Zusammenfassung mit Status und Logpfad für die Fehlersuche.</p><p className="path" aria-live="polite">{diagnosticsPath || snapshot.log_location}</p>{diagnostics.length > 0 && <ul className="diagnostic-list">{diagnostics.map((item) => <li key={item.code} data-healthy={item.healthy}><strong>{item.healthy ? "OK" : "Fehler"}</strong> {item.message}</li>)}</ul>}</div>
            <button onClick={() => void run(client.diagnostics, (result) => { setDiagnosticsPath(result.path); setDiagnostics(result.items); })} disabled={busy}>Diagnosepaket erstellen</button>
          </article>
        </section>
      </main>
    </div>
  );
}
