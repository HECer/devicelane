import { useEffect, useRef, useState } from "react";
import type { ConnectionSettings, DaemonClient } from "../api";
import { Modal } from "./Modal";

const labels = {
  connected: "Verbunden",
  connecting: "Verbindung wird hergestellt",
  disconnected: "Getrennt",
  degraded: "Eingeschränkt"
};

type ConnectionClient = Pick<DaemonClient, "connectionSettings" | "setConnection">;

function ConnectionEditor({ client, initial, onClose, onSaved }: { client: ConnectionClient; initial: ConnectionSettings; onClose: (draft: ConnectionSettings) => void; onSaved: () => void }) {
  const [address, setAddress] = useState(initial.registry_address ?? "");
  const [peer, setPeer] = useState(initial.registry_peer_id ?? "");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const pending = useRef(false);
  const request = useRef<AbortController | undefined>(undefined);
  useEffect(() => {
    const controller = new AbortController();
    request.current = controller;
    return () => controller.abort();
  }, [client]);
  const save = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (pending.current || !request.current || !address.trim() || !peer.trim()) return;
    const controller = request.current;
    pending.current = true;
    setSaving(true);
    setError("");
    try {
      await client.setConnection({ version: 1, registry_address: address, registry_peer_id: peer }, controller.signal);
      if (!controller.signal.aborted) onSaved();
    } catch (failure) {
      if (!controller.signal.aborted) {
        const message = failure instanceof Error ? failure.message : String(failure);
        setError(message.includes("Administratorfreigabe angefordert")
          ? "Freigabe angefordert. Schließe dieses Fenster und prüfe die Änderung unter Freigaben. Danach dieselben Werte erneut speichern."
          : "Speichern nicht bestätigt. Prüfe Adresse und Peer-ID sowie den aktuellen Dienststand, bevor du es erneut versuchst.");
      }
    } finally {
      if (!controller.signal.aborted) { pending.current = false; setSaving(false); }
    }
  };
  const close = () => onClose({ ...initial, registry_address: address, registry_peer_id: peer });
  return <Modal titleId="connection-edit-title" className="rule-form" onClose={close}>
    <form onSubmit={(event) => void save(event)}>
      <h3 id="connection-edit-title">Verbindung bearbeiten</h3>
      <p>Diese Einstellungen werden dauerhaft gespeichert. Die Gegenstelle muss bereits gekoppelt sein; hier wird kein neues Vertrauen erteilt.</p>
      <label>Registry-Adresse<input data-modal-initial required maxLength={260} autoComplete="off" spellCheck={false} disabled={saving} value={address} onChange={(event) => setAddress(event.currentTarget.value)} placeholder="mac.local:7443" /></label>
      <label>Erwartete Peer-ID<input required maxLength={128} autoComplete="off" spellCheck={false} disabled={saving} value={peer} onChange={(event) => setPeer(event.currentTarget.value)} /></label>
      {error && <p role="alert">{error}</p>}
      {saving && <p role="status">Speichern läuft. Schließen macht eine bereits gesendete Änderung nicht rückgängig.</p>}
      <div className="dialog-actions"><button type="button" onClick={close}>Schließen</button><button className="primary-action" type="submit" disabled={saving || !address.trim() || !peer.trim()}>Verbindung speichern</button></div>
    </form>
  </Modal>;
}

export function ConnectionSettingsCard({ client }: { client: ConnectionClient }) {
  const [settings, setSettings] = useState<ConnectionSettings>();
  const [failed, setFailed] = useState(false);
  const [busy, setBusy] = useState(true);
  const [refresh, setRefresh] = useState(0);
  const [editing, setEditing] = useState<{ client: ConnectionClient; initial: ConnectionSettings }>();
  const [draft, setDraft] = useState<{ client: ConnectionClient; initial: ConnectionSettings }>();
  const [savedFor, setSavedFor] = useState<ConnectionClient>();

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
    <button type="button" disabled={!settings} onClick={() => { if (settings) { setSavedFor(undefined); setEditing({ client, initial: draft?.client === client ? draft.initial : settings }); } }}>Verbindung bearbeiten</button>
    {savedFor === client && <p role="status">Einstellungen gespeichert. Der Verbindungsstatus wird neu abgefragt.</p>}
    {editing?.client === client && <ConnectionEditor client={client} initial={editing.initial}
      onClose={(initial) => { setDraft({ client, initial }); setEditing(undefined); setRefresh((value) => value + 1); }}
      onSaved={() => { setSavedFor(client); setDraft(undefined); setEditing(undefined); setRefresh((value) => value + 1); }} />}
  </article>;
}
