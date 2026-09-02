import type { DashboardDevice, DashboardHost, DashboardLease, Presence } from "../api";
import {
  connectionPathLabel,
  freshnessLabel,
  presenceDisplay,
  trustLabel
} from "../dashboard-model";

interface PresenceTextProps {
  presence: Presence;
}

function PresenceText({ presence }: PresenceTextProps) {
  const display = presenceDisplay(presence);
  return (
    <span className={`presence presence--${presence}`} data-testid={`presence-${presence}`}>
      <span className="presence__icon" aria-hidden="true">{display.icon}</span>
      {display.label}
    </span>
  );
}

function TagList({ label, values }: { label: string; values: string[] }) {
  return (
    <div className="topology-tags">
      <span>{label}</span>
      {values.length > 0
        ? <ul aria-label={label}>{values.map((value) => <li key={value}>{value}</li>)}</ul>
        : <span>Nicht gemeldet</span>}
    </div>
  );
}

function DeviceRow({ device, leases }: { device: DashboardDevice; leases: DashboardLease[] }) {
  return (
    <li className="device-row">
      <div>
        <strong data-pretext>{device.display_name}</strong>
        <span>{device.platform}</span>
      </div>
      <PresenceText presence={device.presence} />
      <span className="freshness">{freshnessLabel(device.freshness)}</span>
      {leases.map((lease) => <span key={lease.id} className={`lease-state lease-state--${lease.state}`}>
        <span aria-hidden="true">{lease.state === "active" ? "✓" : "!"}</span>
        {lease.state === "active" ? "Lease aktiv" : "Lease unsicher – keine neue Autorisierung"}
      </span>)}
      <TagList label="Gerätefähigkeiten" values={device.capabilities} />
      <TagList label="Geräteberechtigungen" values={device.permissions} />
    </li>
  );
}

export interface TopologyViewProps {
  hosts: DashboardHost[];
  leases: DashboardLease[];
  selectedHostId?: string;
  onSelectHost: (hostId: string) => void;
}

export function TopologyView({ hosts, leases, selectedHostId, onSelectHost }: TopologyViewProps) {
  const sorted = [...hosts].sort((left, right) => {
    const state = presenceDisplay(left.presence).sortOrder - presenceDisplay(right.presence).sortOrder;
    return state || left.display_name.localeCompare(right.display_name, "de");
  });

  return (
    <section className="dashboard-section topology" aria-labelledby="topology-title">
      <div className="section-heading">
        <div><p className="eyebrow">Topologie</p><h2 id="topology-title">Geräte im Netzwerk</h2></div>
        <span>{hosts.length} Hosts</span>
      </div>
      {sorted.length === 0 ? <p className="section-empty">In diesem Bereich wurden noch keine Hosts erkannt.</p> : (
        <ul className="topology-list" aria-label="Hosts">
          {sorted.map((host) => (
            <li key={host.id} className="topology-item">
              <button
                type="button"
                className="topology-host"
                aria-pressed={selectedHostId === host.id}
                onClick={() => onSelectHost(host.id)}
              >
                <span className="host-glyph" aria-hidden="true">{host.platform === "macos" ? "M" : "H"}</span>
                <span className="topology-host__identity">
                  <strong data-pretext>{host.display_name}</strong>
                  <span>{host.platform} · {host.architecture}</span>
                </span>
                <PresenceText presence={host.presence} />
                <span className="freshness">{freshnessLabel(host.freshness)}</span>
                <span className="connection-path">{connectionPathLabel(host.connection_path)}</span>
                <span className="trust-state">{trustLabel(host.trust)}</span>
              </button>
              <div className="topology-details" data-selected={selectedHostId === host.id}>
                <TagList label="Fähigkeiten" values={host.capabilities} />
                <TagList label="Berechtigungen" values={host.permissions} />
                {host.devices.length > 0 && <ul className="device-list" aria-label={`Geräte an ${host.display_name}`}>
                  {host.devices.map((device) => <DeviceRow key={device.id} device={device} leases={leases.filter((lease) => lease.device_id === device.id)} />)}
                </ul>}
              </div>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
