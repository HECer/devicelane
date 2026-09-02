import { useEffect, useMemo, useRef, useState } from "react";
import type { ActivityEvent } from "../api";
import {
  activityStateDisplay,
  eventKey,
  formatBytes,
  formatMetric,
  formatTimestamp,
  isoTimestamp,
  messageParamLabel,
  messageCodeLabel,
  policyEffectLabel,
  mergeActivityEvents,
} from "../dashboard-model";

export interface ActivityFeedProps {
  events: ActivityEvent[];
  reconnecting?: boolean;
}

export function ActivityFeed({ events, reconnecting = false }: ActivityFeedProps) {
  const visibleEvents = useMemo(() => mergeActivityEvents([], events), [events]);
  const previousKeys = useRef(new Set<string>());
  const [announcement, setAnnouncement] = useState({ text: "", sequence: 0 });

  useEffect(() => {
    const keys = new Set(visibleEvents.map(eventKey));
    const newCount = [...keys].filter((key) => !previousKeys.current.has(key)).length;
    previousKeys.current = keys;
    if (newCount > 0) {
      const text = newCount === 1 ? "1 neues Aktivitätsereignis" : `${newCount} neue Aktivitätsereignisse`;
      setAnnouncement((current) => ({ text, sequence: current.sequence + 1 }));
    }
  }, [visibleEvents]);

  return (
    <section className="dashboard-section activity-feed" aria-labelledby="activity-title">
      <div className="section-heading">
        <div><p className="eyebrow">Live</p><h2 id="activity-title">Live-Aktivitäten</h2></div>
        <span>{reconnecting ? "Stream verbindet erneut" : `${visibleEvents.length} Ereignisse`}</span>
      </div>
      <p className="sr-only" role="status" aria-live="polite" aria-atomic="true">
        {announcement.text && `${announcement.text} · Aktualisierung ${announcement.sequence}`}
      </p>
      {visibleEvents.length === 0 ? <p className="section-empty">Noch keine Ressourcenaktivität erfasst.</p> : (
        <ol className="activity-list" aria-label="Aktivitätsereignisse">
          {visibleEvents.map((event) => {
            const state = activityStateDisplay(event.state);
            return (
              <li key={eventKey(event)} className="activity-item">
                <header>
                  <span className={`presence presence--${event.state}`}>
                    <span className="presence__icon" aria-hidden="true">{state.icon}</span>{state.label}
                  </span>
                  <time dateTime={isoTimestamp(event.occurred_at_ms)}>{formatTimestamp(event.occurred_at_ms)}</time>
                </header>
                <strong className="activity-id">{event.activity_id}</strong>
                <p className="activity-operation"><strong>{event.principal_id}</strong> · {event.operation}</p>
                <p>{event.source_host_id} → {event.target_host_id}{event.device_id ? ` / ${event.device_id}` : ""}</p>
                <p className="activity-authorization">
                  <strong>{policyEffectLabel(event.authorization.effect)}</strong>
                  {event.authorization.rule_id && <> · Regel: {event.authorization.rule_id}</>}
                  {event.authorization.approval_id && <> · Freigabe: {event.authorization.approval_id}</>}
                </p>
                {event.message && <p className="activity-message">
                  {event.message.code === "redacted" && <><strong>Redigierte Ausgabe</strong> · </>}
                  <span>{messageCodeLabel(event.message.code)}</span>
                  {event.message.params.length > 0 && <span className="message-params">
                    {event.message.params.map(messageParamLabel).join(", ")}
                  </span>}
                </p>}
                <p className="activity-duration">
                  Gestartet: {event.started_at_ms ? formatTimestamp(event.started_at_ms) : "Nicht gemeldet"}
                  {event.finished_at_ms && <> · Beendet: {formatTimestamp(event.finished_at_ms)}</>}
                </p>
                <ul className="resource-tags" aria-label="Verwendete Ressourcen">
                  {event.resources.map((resource) => <li key={resource}>{resource}</li>)}
                </ul>
                {event.remote_operation_sha256 && <p className="activity-operation-digest">
                  Grant SHA-256: {event.remote_operation_sha256}
                </p>}
                <dl className="metric-grid">
                  <div><dt>Arbeitsspeicher</dt><dd>{formatMetric(event.metrics.current_memory_bytes, formatBytes)}</dd></div>
                  <div><dt>Spitze</dt><dd>{formatMetric(event.metrics.peak_memory_bytes, formatBytes)}</dd></div>
                  <div><dt>CPU-Zeit</dt><dd>{formatMetric(event.metrics.cpu_time_ms, (value) => `${value} ms`)}</dd></div>
                  <div><dt>Prozesse</dt><dd>{formatMetric(event.metrics.process_count)}</dd></div>
                </dl>
              </li>
            );
          })}
        </ol>
      )}
    </section>
  );
}
