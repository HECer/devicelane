import type { ResourceOccupancy as ResourceOccupancyModel } from "../api";
import { formatTimestamp, isoTimestamp, resourceLabel } from "../dashboard-model";

export interface ResourceOccupancyProps {
  occupancies: ResourceOccupancyModel[];
}

export function ResourceOccupancy({ occupancies }: ResourceOccupancyProps) {
  return (
    <section className="dashboard-section occupancy" aria-labelledby="occupancy-title">
      <div className="section-heading">
        <div><p className="eyebrow">Belegung</p><h2 id="occupancy-title">Verwendete Ressourcen</h2></div>
        <span>{occupancies.length} aktiv</span>
      </div>
      {occupancies.length === 0 ? <p className="section-empty">Keine Ressource ist derzeit belegt.</p> : (
        <ul className="occupancy-list" aria-label="Ressourcennutzung">
          {occupancies.map((occupancy) => (
            <li key={`${occupancy.activity_id}:${occupancy.resource}`}>
              <span className="occupancy-edge" data-pretext>
                {occupancy.principal_id} → {occupancy.target_host_id}{occupancy.device_id ? ` / ${occupancy.device_id}` : ""}
              </span>
              <strong>{resourceLabel(occupancy.resource)}</strong>
              <time dateTime={isoTimestamp(occupancy.acquired_at_ms)}>Seit {formatTimestamp(occupancy.acquired_at_ms)}</time>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
