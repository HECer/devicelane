import { useRef, useState } from "react";
import type { PolicyRule } from "../api";
import { resourceLabel } from "../dashboard-model";

interface PolicyRulesProps {
  rules: PolicyRule[];
  onPut: (rule: PolicyRule) => Promise<void>;
  onDelete: (ruleId: string, expectedRevision: string) => Promise<void>;
  onRefresh: () => Promise<void>;
}

function specificity(rule: PolicyRule) {
  return Number(rule.principal_id !== null) + Number(rule.source_host_id !== null) + Number(rule.target_host_id !== null)
    + Number(rule.device_id !== null || rule.match_device_exact) + Number(rule.operation !== null)
    + Number(rule.resources.length > 0 || rule.match_resources_exact) + Number(rule.require_user_presence || rule.user_presence !== null)
    + Number(rule.physical_device !== null);
}

export function PolicyRules({ rules, onPut, onDelete, onRefresh }: PolicyRulesProps) {
  const inFlight = useRef(false);
  const [editing, setEditing] = useState<PolicyRule>();
  const [deleting, setDeleting] = useState<PolicyRule>();
  const [deleteConfirmed, setDeleteConfirmed] = useState(false);
  const [announcement, setAnnouncement] = useState("");

  const execute = async (action: () => Promise<void>, success: string) => {
    if (inFlight.current) return;
    inFlight.current = true;
    setAnnouncement("");
    try {
      await action();
      setAnnouncement(success);
      setEditing(undefined);
      setDeleting(undefined);
      setDeleteConfirmed(false);
    } catch (error) {
      setAnnouncement(`Regeländerung fehlgeschlagen: ${error instanceof Error ? error.message : String(error)}`);
    } finally {
      try { await onRefresh(); } catch (error) {
        setAnnouncement(`Regeln konnten nicht aktualisiert werden: ${error instanceof Error ? error.message : String(error)}`);
      }
      inFlight.current = false;
    }
  };

  const save = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!editing) return;
    const form = new FormData(event.currentTarget);
    const expiry = String(form.get("expiry") ?? "").trim();
    const next = {
      ...editing,
      revision: (BigInt(editing.revision) + 1n).toString(),
      effect: form.get("effect") as PolicyRule["effect"],
      expires_at_ms: expiry || null,
      require_user_presence: form.get("require_presence") === "on",
      enabled: form.get("enabled") === "on"
    };
    void execute(() => onPut(next), "Regel gespeichert. Die Ansicht zeigt den aktuellen Dienststand.");
  };

  return <section className="dashboard-section management-section policy-rules" aria-labelledby="rules-title">
    <div className="section-heading"><div><p className="eyebrow">Zugriffssteuerung</p><h2 id="rules-title">Richtlinien</h2></div><span>{rules.length}</span></div>
    <p className="policy-precedence"><strong>Ablehnen hat immer Vorrang.</strong> Innerhalb derselben Wirkung gewinnt die spezifischste passende Regel.</p>
    <p className="sr-only" role="status" aria-live="polite">{announcement}</p>
    {rules.length === 0 ? <p className="section-empty">Keine gespeicherten Regeln.</p> : <ul className="management-list">{rules.map((rule) => <li key={rule.id}><article className="rule-card" aria-label={`Regel ${rule.id}`}>
      <header><div><strong>{rule.id}</strong><span className={`rule-effect rule-effect--${rule.effect}`}>{rule.effect === "deny" ? "Ablehnen" : "Erlauben"}</span></div><span>{rule.origin === "managed" ? "Verwaltet · schreibgeschützt" : "Benutzerregel"}</span></header>
      <p className="rule-meta">Revision {rule.revision} · Spezifität {specificity(rule)} · {rule.enabled ? "Aktiv" : "Deaktiviert"}</p>
      <dl className="attribution-grid"><div><dt>Prinzipal</dt><dd>{rule.principal_id ?? "Alle"}</dd></div><div><dt>Quelle</dt><dd>{rule.source_host_id ?? "Alle"}</dd></div><div><dt>Ziel</dt><dd>{rule.target_host_id ?? "Alle"}</dd></div><div><dt>Operation</dt><dd>{rule.operation ?? "Alle"}</dd></div><div><dt>Ablauf</dt><dd>{rule.expires_at_ms ? new Date(Number(rule.expires_at_ms)).toLocaleString("de-DE") : "Kein Ablauf"}</dd></div><div><dt>Präsenz</dt><dd>{rule.require_user_presence ? "Benutzerpräsenz erforderlich" : "Nicht erforderlich"}</dd></div></dl>
      <ul className="resource-tags">{rule.resources.length ? rule.resources.map((resource) => <li key={resource}>{resourceLabel(resource)}</li>) : <li>Alle Ressourcen</li>}</ul>
      <div className="rule-actions"><button disabled={rule.origin === "managed"} onClick={() => setEditing(rule)}>Regel bearbeiten</button><button className="danger-action" disabled={rule.origin === "managed"} onClick={() => { setDeleteConfirmed(false); setDeleting(rule); }}>Regel löschen</button></div>
    </article></li>)}</ul>}
    {editing && <div className="modal-backdrop"><form className="confirmation-dialog rule-form" role="dialog" aria-modal="true" aria-labelledby="edit-rule-title" onSubmit={save}>
      <h3 id="edit-rule-title">Regel {editing.id} bearbeiten</h3><p>Ausgangspunkt: Revision {editing.revision}, Spezifität {specificity(editing)}, Ursprung Benutzer.</p>
      <label>Regelwirkung<select name="effect" aria-label="Regelwirkung" defaultValue={editing.effect}><option value="allow">Erlauben</option><option value="deny">Ablehnen</option></select></label>
      <label>Ablaufzeit (Unix-Millisekunden)<input name="expiry" aria-label="Ablaufzeit (Unix-Millisekunden)" type="number" min="0" defaultValue={editing.expires_at_ms ?? ""} /></label>
      <label className="confirm-check"><input name="require_presence" type="checkbox" defaultChecked={editing.require_user_presence} /> Benutzerpräsenz erforderlich</label>
      <label className="confirm-check"><input name="enabled" type="checkbox" defaultChecked={editing.enabled} /> Regel aktiviert</label>
      <div className="dialog-actions"><button type="button" onClick={() => setEditing(undefined)}>Abbrechen</button><button className="primary-action" type="submit">Änderungen speichern</button></div>
    </form></div>}
    {deleting && <div className="modal-backdrop"><div className="confirmation-dialog" role="dialog" aria-modal="true" aria-labelledby="delete-rule-title"><h3 id="delete-rule-title">Regel löschen bestätigen</h3><p>Nur Revision {deleting.revision} von {deleting.id} wird gelöscht. Bei einer zwischenzeitlichen Änderung bricht DeviceLane ab.</p><label className="confirm-check"><input type="checkbox" checked={deleteConfirmed} onChange={(event) => setDeleteConfirmed(event.currentTarget.checked)} /> Revision {deleting.revision} geprüft</label><div className="dialog-actions"><button onClick={() => setDeleting(undefined)}>Abbrechen</button><button className="danger-action" disabled={!deleteConfirmed} onClick={() => void execute(() => onDelete(deleting.id, deleting.revision), "Regel gelöscht. Die Ansicht zeigt den aktuellen Dienststand.")}>Regel endgültig löschen</button></div></div></div>}
  </section>;
}
