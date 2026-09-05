import { useEffect, useState } from "react";
import type { ConnectionSettings, DaemonClient } from "../api";

const labels = {
  connected: "Verbunden",
  connecting: "Verbindung wird hergestellt",
  disconnected: "Getrennt",
  degraded: "Eingeschränkt"
};

export function ConnectionSettingsCard({ client }: { client: Pick<DaemonClient, "connectionSettings"> }) {
  const [settings, setSettings] = useState<ConnectionSettings>();
  const [failed, setFailed] = useState(false);
  const [busy, setBusy] = useState(true);
  const [refresh, setRefresh] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    setSettings(undefined);
    const update = async () => {
      setBusy(true);
      try {
        const next = await client.connectionSettings(controller.signal);
        if (controller.signal.aborted) return;
        setSettings(next);
        setFailed(false);
      } catch {
        if (controller.signal.aborted) return;
        setSettings(undefined);
        setFailed(true);
      } finally {
        if (!controller.signal.aborted) {
          setBusy(false);
          timer = setTimeout(() => void update(), 5_000);
        }
      }
    };
    void update();
    return () => { controller.abort(); clearTimeout(timer); };
  }, [client, refresh]);

  return <article className="control-card control-card--wide" aria-labelledby="connection-settings-title">
    <div aria-busy={busy}>
      <h2 id="connection-settings-title">Mesh-Verbindung</h2>
      <p>Aktive Einstellungen des Dienstes. Eine konfigurierte Adresse allein erteilt keine Zugriffsfreigabe.</p>
      {failed ? <p role="status">Verbindungsdaten nicht verfügbar. Bitte Dienstversion und Verbindung prüfen.</p>
        : !settings ? <p role="status">Verbindungsdaten werden geladen…</p>
        : settings.registry_address === null ? <p>Keine Registry konfiguriert</p>
        : <dl>
          <dt>Registry-Adresse</dt><dd className="path">{settings.registry_address}</dd>
          <dt>Erwartete Gegenstelle</dt><dd className="path">{settings.registry_peer_id}</dd>
          <dt>Stand der letzten Abfrage</dt><dd>{labels[settings.connection]}</dd>
        </dl>}
    </div>
    <button type="button" disabled={busy} onClick={() => setRefresh((value) => value + 1)}>Verbindung aktualisieren</button>
  </article>;
}
