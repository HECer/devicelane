import { useRef, useState } from "react";
import type { AuditDeletionScope, AuditExport, AuditFilter, AuditPage, EventCursor } from "../api";
import { messageCodeLabel, resourceLabel } from "../dashboard-model";

interface AuditHistoryProps {
  onQuery: (filter: AuditFilter, cursor: EventCursor | null, limit: number) => Promise<AuditPage>;
  onExport: (filter: AuditFilter) => Promise<AuditExport>;
  onDelete?: (scope: AuditDeletionScope, filter: AuditFilter) => Promise<void>;
}

const emptyFilter: AuditFilter = { from_ms: null, through_ms: null, principal_id: null, source_host_id: null, target_host_id: null, device_id: null, operation: null, resource: null, decision: null, result: null };
const value = (form: FormData, name: string) => String(form.get(name) ?? "").trim() || null;

export function AuditHistory({ onQuery, onExport, onDelete }: AuditHistoryProps) {
  const inFlight = useRef(false);
  const [filter, setFilter] = useState<AuditFilter>(emptyFilter);
  const [page, setPage] = useState<AuditPage>({ items: [], next_cursor: null });
  const [limit, setLimit] = useState(100);
  const [announcement, setAnnouncement] = useState("");
  const [manifest, setManifest] = useState<AuditExport["manifest"]>();
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [deleteScope, setDeleteScope] = useState<AuditDeletionScope | "">("");
  const [deleteConfirmed, setDeleteConfirmed] = useState(false);

  const read = async (nextFilter: AuditFilter, cursor: EventCursor | null) => {
    if (inFlight.current) return;
    inFlight.current = true;
    try {
      const next = await onQuery(nextFilter, cursor, limit);
      setPage(next);
      setAnnouncement(`${next.items.length} Audit-Einträge geladen.`);
    } catch (error) { setAnnouncement(`Audit-Abfrage fehlgeschlagen: ${error instanceof Error ? error.message : String(error)}`); }
    finally { inFlight.current = false; }
  };

  const submitFilter = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const next: AuditFilter = { from_ms: value(form, "from"), through_ms: value(form, "through"), principal_id: value(form, "principal"), source_host_id: value(form, "source"), target_host_id: value(form, "target"), device_id: value(form, "device"), operation: value(form, "operation"), resource: (value(form, "resource") as AuditFilter["resource"]), decision: (value(form, "decision") as AuditFilter["decision"]), result: (value(form, "result") as AuditFilter["result"]) };
    setFilter(next); setManifest(undefined); void read(next, null);
  };

  const exportAudit = async () => {
    if (inFlight.current) return;
    inFlight.current = true;
    try {
      const result = await onExport(filter); setManifest(result.manifest);
      setAnnouncement(result.manifest.signature.signature_status === "signed" ? `Export signiert mit Schlüssel ${result.manifest.signature.key_id}.` : "Export erstellt. Signatur nicht verfügbar; der Export ist nicht verifiziert.");
    } catch (error) { setAnnouncement(`Audit-Export fehlgeschlagen: ${error instanceof Error ? error.message : String(error)}`); }
    finally { inFlight.current = false; }
  };

  const deleteAudit = async () => {
    if (!onDelete || !deleteScope || !deleteConfirmed || inFlight.current) return;
    inFlight.current = true;
    try {
      await onDelete(deleteScope, filter);
      setDeleteOpen(false);
      setDeleteConfirmed(false);
      setDeleteScope("");
      setAnnouncement("Audit-Löschung angefordert und protokolliert.");
      inFlight.current = false;
      await read(filter, null);
    }
    catch (error) { setAnnouncement(`Audit-Löschung fehlgeschlagen: ${error instanceof Error ? error.message : String(error)}`); }
    finally { inFlight.current = false; }
  };

  return <section className="dashboard-section management-section audit-history" aria-labelledby="audit-title">
    <div className="section-heading"><div><p className="eyebrow">30 Tage Aufbewahrung</p><h2 id="audit-title">Audit-Verlauf</h2></div><span>max. 256 pro Seite</span></div>
    <form className="audit-filters" onSubmit={submitFilter}><label>Von (Unix-Millisekunden)<input name="from" inputMode="numeric" /></label><label>Bis (Unix-Millisekunden)<input name="through" inputMode="numeric" /></label><label>Prinzipal<input name="principal" /></label><label>Quelle<input name="source" /></label><label>Ziel<input name="target" /></label><label>Gerät<input name="device" /></label><label>Operation<input name="operation" /></label><label>Ressource<select name="resource" defaultValue=""><option value="">Alle</option><option value="workspace_read">Arbeitsbereich lesen</option><option value="device_lease">Gerät belegen</option><option value="debugger">Debugger</option><option value="signing">Signieren</option></select></label><label>Entscheidung<select name="decision" defaultValue=""><option value="">Alle</option><option value="allow">Erlauben</option><option value="deny">Ablehnen</option></select></label><label>Ergebnis<select name="result" defaultValue=""><option value="">Alle</option><option value="attempted">Versucht</option><option value="succeeded">Erfolgreich</option><option value="failed">Fehlgeschlagen</option><option value="denied">Abgelehnt</option><option value="cancelled">Abgebrochen</option><option value="deleted">Gelöscht</option></select></label><label>Seitengröße<select aria-label="Seitengröße" value={limit} onChange={(event) => setLimit(Number(event.currentTarget.value))}><option value="25">25</option><option value="100">100</option><option value="256">256</option></select></label><button className="primary-action" type="submit">Audit filtern</button></form>
    <p role="status" aria-live="polite" className="audit-status">{announcement}</p>
    <div className="audit-toolbar"><button onClick={() => void exportAudit()}>Audit exportieren</button>{onDelete && <button className="danger-action" onClick={() => setDeleteOpen(true)}>Auditdaten löschen</button>}<button disabled={!page.next_cursor} onClick={() => void read(filter, page.next_cursor)}>Nächste Seite</button></div>
    {manifest && <div className="export-manifest"><strong>{manifest.signature.signature_status === "signed" ? "Signatur vorhanden" : "Signatur nicht verfügbar"}</strong><span>SHA-256: {manifest.records_sha256}</span><span>{manifest.record_count} Einträge</span></div>}
    <div className="audit-records" role="region" aria-label="Audit-Einträge">{page.items.length === 0 ? <p className="section-empty">Keine Einträge für diesen Filter.</p> : <ol>{page.items.map((record) => <li key={record.sequence}><article><header><strong>{record.operation}</strong><time dateTime={new Date(Number(record.occurred_at_ms)).toISOString()}>{new Date(Number(record.occurred_at_ms)).toLocaleString("de-DE")}</time></header><p>{record.principal_id} · {record.source_host_id} → {record.target_host_id}</p><p>{record.decision === "deny" ? "Abgelehnt" : "Erlaubt"} · {record.result}</p><ul className="resource-tags">{record.resources.map((resource) => <li key={resource}>{resourceLabel(resource)}</li>)}</ul>{record.redacted_message && <div className="redacted-log"><strong>Redigierter Protokolltext</strong><pre>{record.redacted_message.code === "redacted" ? "redacted" : messageCodeLabel(record.redacted_message.code)}</pre></div>}</article></li>)}</ol>}</div>
    {deleteOpen && <div className="modal-backdrop"><div className="confirmation-dialog" role="dialog" aria-modal="true" aria-labelledby="delete-audit-title"><h3 id="delete-audit-title">Auditdaten löschen bestätigen</h3><p>Auditdaten werden standardmäßig 30 Tage aufbewahrt. Eine manuelle Löschung entfernt nur den gewählten Bereich und erzeugt selbst einen dauerhaften Löschvermerk.</p><label>Löschbereich<select aria-label="Löschbereich" value={deleteScope} onChange={(event) => setDeleteScope(event.currentTarget.value as AuditDeletionScope | "")}><option value="">Bitte wählen</option><option value="current_filter">Aktueller Filter</option><option value="all_retained">Alle aufbewahrten Daten</option></select></label><label className="confirm-check"><input type="checkbox" checked={deleteConfirmed} onChange={(event) => setDeleteConfirmed(event.currentTarget.checked)} /> Ich verstehe: Die Löschung wird protokolliert und kann nicht rückgängig gemacht werden.</label><div className="dialog-actions"><button onClick={() => setDeleteOpen(false)}>Abbrechen</button><button className="danger-action" disabled={!deleteScope || !deleteConfirmed} onClick={() => void deleteAudit()}>Ausgewählten Bereich löschen</button></div></div></div>}
  </section>;
}
