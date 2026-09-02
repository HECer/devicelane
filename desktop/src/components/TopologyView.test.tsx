import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type { DashboardHost, Presence } from "../api";
import { TopologyView } from "./TopologyView";

const states: Presence[] = [
  "offline",
  "connecting",
  "online",
  "busy",
  "attention_required",
  "remote_access_paused"
];

function host(presence: Presence, index: number): DashboardHost {
  return {
    id: `host-${index}`,
    display_name: index === 0 ? "Hermanns sehr lang benanntes MacBook Pro für mobile Builds" : `Host ${index}`,
    platform: index === 0 ? "macos" : "linux",
    architecture: "arm64",
    presence,
    freshness: presence === "offline" ? { stale: { last_seen_at_ms: "1725000000000" } } : "live",
    trust: index === 5 ? "untrusted" : "trusted",
    connection_path: index === 0 ? "registry" : "direct",
    capabilities: ["xcode", "debugger"],
    permissions: ["workspace_read"],
    devices: index === 3 ? [{
      id: "iphone-1",
      host_id: `host-${index}`,
      display_name: "iPhone 17 Pro",
      platform: "ios",
      presence: "busy",
      freshness: "live",
      capabilities: ["physical_device"],
      permissions: ["device_lease"]
    }] : []
  };
}

describe("TopologyView", () => {
  it("renders topology landmarks and all states with visible text and decorative icons", () => {
    const hosts = states.map(host);
    render(<TopologyView hosts={hosts} leases={[{ id: "lease-1", owner_host_id: "host-3", device_id: "iphone-1", state: "uncertain" }]} selectedHostId="host-0" onSelectHost={vi.fn()} />);

    expect(screen.getByRole("region", { name: "Geräte im Netzwerk" })).toBeVisible();
    expect(screen.getByRole("list", { name: "Hosts" }).children).toHaveLength(6);
    for (const label of ["Offline", "Verbindet", "Online", "Beschäftigt", "Aktion erforderlich", "Remotezugriff pausiert"]) {
      expect(screen.getAllByText(label).length).toBeGreaterThan(0);
    }
    for (const state of states) {
      const visibleStatus = screen.getAllByTestId(`presence-${state}`)[0];
      expect(visibleStatus).toHaveTextContent(/\S/);
      expect(visibleStatus.querySelector("[aria-hidden='true']")).not.toBeNull();
    }
    expect(screen.getByText(/Zuletzt gesehen:/)).toBeVisible();
    expect(screen.getByText("Verbindung über Registry")).toBeVisible();
    expect(screen.getByText("iPhone 17 Pro")).toBeVisible();
    expect(screen.getByText("Lease unsicher – keine neue Autorisierung")).toBeVisible();
    expect(screen.getByText("Hermanns sehr lang benanntes MacBook Pro für mobile Builds")).toBeVisible();
  });

  it("keeps host selection keyboard reachable and reports trust, capabilities and permissions", async () => {
    const user = userEvent.setup();
    const onSelectHost = vi.fn();
    render(<TopologyView hosts={[host("online", 0), host("offline", 1)]} leases={[]} selectedHostId="host-0" onSelectHost={onSelectHost} />);

    const offlineHost = screen.getByRole("button", { name: /Host 1/ });
    await user.tab();
    await user.tab();
    expect(offlineHost).toHaveFocus();
    await user.keyboard("{Enter}");

    expect(onSelectHost).toHaveBeenCalledWith("host-1");
    expect(screen.getAllByText("Vertrauenswürdig").length).toBeGreaterThan(0);
    expect(screen.getAllByText("xcode").length).toBeGreaterThan(0);
    expect(screen.getAllByText("workspace_read").length).toBeGreaterThan(0);
  });
});
