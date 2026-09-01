import { useEffect, useState } from "react";
import type { DaemonClient, DaemonSnapshot } from "./api";
import { tauriDaemonClient } from "./api";
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
  usePretext();

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

  const run = async (action: () => Promise<void>) => {
    setBusy(true);
    try {
      await action();
    } catch {
      // Rust displays the native error notification; the UI still refreshes below.
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
        <header className="page-header">
          <div><p className="eyebrow">Lokales Netzwerk</p><h1 data-pretext>Geräteübersicht</h1></div>
          <span className={`connection-pill connection-pill--${snapshot.connection}`}>
            <span className="status-mark" aria-hidden="true" />{connectionLabels[snapshot.connection]}
          </span>
        </header>

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
            <button onClick={async () => { setBusy(true); try { const result = await client.diagnostics(); setDiagnosticsPath(result.path); setDiagnostics(result.items); } finally { setBusy(false); } }} disabled={busy}>Diagnosepaket erstellen</button>
          </article>
        </section>
      </main>
    </div>
  );
}
