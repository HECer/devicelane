import { useEffect, useRef, useState } from "react";
import type { ApprovalDecision, ApprovalRequest } from "../api";
import { resourceLabel } from "../dashboard-model";
import { Modal } from "./Modal";

interface ApprovalPanelProps {
  approvals: ApprovalRequest[];
  nowMs: number;
  focusApprovalId?: string;
  onDecide: (approvalId: string, decision: ApprovalDecision) => Promise<void>;
  onRefresh: () => Promise<void>;
}

type Confirmation = { approval: ApprovalRequest; decision: "allow_and_remember" | "deny_and_block" };

export function ApprovalPanel({ approvals, nowMs, focusApprovalId, onDecide, onRefresh }: ApprovalPanelProps) {
  const submitting = useRef(new Set<string>());
  const cards = useRef(new Map<string, HTMLElement>());
  const [pendingIds, setPendingIds] = useState<string[]>([]);
  const [confirmation, setConfirmation] = useState<Confirmation>();
  const [confirmed, setConfirmed] = useState(false);
  const [announcement, setAnnouncement] = useState("");

  useEffect(() => {
    if (!focusApprovalId) return;
    const card = cards.current.get(focusApprovalId);
    card?.scrollIntoView?.({ block: "center" });
    card?.focus();
  }, [focusApprovalId, approvals]);

  useEffect(() => {
    if (!confirmation) return;
    const current = approvals.find(({ id }) => id === confirmation.approval.id);
    if (current && Number(current.expires_at_ms) > nowMs) return;
    setConfirmation(undefined);
    setConfirmed(false);
    setAnnouncement(current ? "Freigabe ist abgelaufen; die Bestätigung wurde geschlossen." : "Freigabe ist nicht mehr ausstehend; die Bestätigung wurde geschlossen.");
  }, [approvals, confirmation, nowMs]);

  const decide = async (approval: ApprovalRequest, decision: ApprovalDecision) => {
    if (submitting.current.has(approval.id)) return;
    if (!approvals.some(({ id }) => id === approval.id) || Number(approval.expires_at_ms) <= nowMs) {
      setAnnouncement("Freigabe ist nicht mehr ausstehend oder abgelaufen.");
      return;
    }
    submitting.current.add(approval.id);
    setPendingIds((ids) => [...ids, approval.id]);
    setAnnouncement("");
    try {
      await onDecide(approval.id, decision);
      setAnnouncement("Entscheidung gespeichert. Status wurde mit dem Dienst abgeglichen.");
    } catch (error) {
      setAnnouncement(`Entscheidung fehlgeschlagen: ${error instanceof Error ? error.message : String(error)}`);
    } finally {
      try { await onRefresh(); } catch (error) {
        setAnnouncement(`Statusaktualisierung fehlgeschlagen: ${error instanceof Error ? error.message : String(error)}`);
      }
      submitting.current.delete(approval.id);
      setPendingIds((ids) => ids.filter((id) => id !== approval.id));
      setConfirmation(undefined);
      setConfirmed(false);
    }
  };

  return (
    <section className="dashboard-section management-section approval-panel" aria-labelledby="approvals-title">
      <div className="section-heading"><div><p className="eyebrow">Zielbestätigung</p><h2 id="approvals-title">Ausstehende Freigaben</h2></div><span>{approvals.length}</span></div>
      <p className="sr-only" role="status" aria-live="polite">{announcement}</p>
      {approvals.length === 0 ? <p className="section-empty">Keine Freigabe wartet auf diesem Gerät.</p> : (
        <ul className="management-list">
          {approvals.map((approval) => {
            const expired = Number(approval.expires_at_ms) <= nowMs;
            const busy = pendingIds.includes(approval.id);
            return <li key={approval.id}>
              <article
                ref={(node) => { if (node) cards.current.set(approval.id, node); else cards.current.delete(approval.id); }}
                className={`approval-card${focusApprovalId === approval.id ? " approval-card--selected" : ""}`}
                aria-label={`Freigabe ${approval.id}`}
                tabIndex={-1}
              >
                <header><div><strong>{approval.operation}</strong><span className="decision-state decision-state--pending">Risiko: {approval.risk}</span>{expired && <span className="decision-state decision-state--expired">Abgelaufen</span>}</div><time dateTime={new Date(Number(approval.expires_at_ms)).toISOString()}>Läuft ab: {new Date(Number(approval.expires_at_ms)).toLocaleString("de-DE")}</time></header>
                <dl className="attribution-grid">
                  <div><dt>Prinzipal</dt><dd>{approval.principal_id}</dd></div>
                  <div><dt>Quelle</dt><dd>{approval.source_host_id}</dd></div>
                  <div><dt>Ziel</dt><dd>{approval.target_host_id}</dd></div>
                  <div><dt>Gerät</dt><dd>{approval.device_id ?? "Kein physisches Gerät"}</dd></div>
                  <div><dt>Aktivität</dt><dd>{approval.activity_id}</dd></div>
                  <div><dt>Angefragt</dt><dd>{new Date(Number(approval.requested_at_ms)).toLocaleString("de-DE")}</dd></div>
                </dl>
                <ul className="resource-tags" aria-label="Angefragte Ressourcen">{approval.resources.map((resource) => <li key={resource}>{resourceLabel(resource)}</li>)}</ul>
                {approval.remote_operation_sha256 && <p className="activity-operation-digest">Grant SHA-256: {approval.remote_operation_sha256}</p>}
                <div className="approval-actions" aria-label={`Entscheidung für ${approval.id}`}>
                  <button disabled={expired || busy} onClick={() => void decide(approval, "allow_once")}>Einmal erlauben</button>
                  <button disabled={expired || busy} onClick={() => { setConfirmed(false); setConfirmation({ approval, decision: "allow_and_remember" }); }}>Erlauben und merken</button>
                  <button disabled={expired || busy} onClick={() => void decide(approval, "deny_once")}>Einmal ablehnen</button>
                  <button className="danger-action" disabled={expired || busy} onClick={() => { setConfirmed(false); setConfirmation({ approval, decision: "deny_and_block" }); }}>Ablehnen und blockieren</button>
                </div>
              </article>
            </li>;
          })}
        </ul>
      )}
      {confirmation && <Modal titleId="approval-confirm-title" onClose={() => setConfirmation(undefined)}>
        <h3 id="approval-confirm-title">Dauerhafte Regel bestätigen</h3>
        <p>{confirmation.decision === "allow_and_remember" ? "DeviceLane erstellt eine exakte, möglichst eingeschränkte Regel für diese Anfrage." : "DeviceLane erstellt eine exakte Sperrregel. Ablehnungen haben Vorrang vor Erlaubnissen."}</p>
        <label className="confirm-check"><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.currentTarget.checked)} /> Auswirkung verstanden</label>
        <div className="dialog-actions"><button data-modal-initial onClick={() => setConfirmation(undefined)}>Abbrechen</button><button className={confirmation.decision === "deny_and_block" ? "danger-action" : "primary-action"} disabled={!confirmed} onClick={() => void decide(confirmation.approval, confirmation.decision)}>{confirmation.decision === "allow_and_remember" ? "Dauerhaft erlauben" : "Dauerhaft blockieren"}</button></div>
      </Modal>}
    </section>
  );
}
