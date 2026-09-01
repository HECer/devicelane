import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { App } from "./App";
import type { DaemonClient, DaemonSnapshot } from "./api";

const connected: DaemonSnapshot = {
  public_identity: "mac-agent",
  endpoint: "local",
  local_protocol: { major: 1, minor: 0 },
  remote_protocol: "mesh/1",
  daemon_version: "0.1.0-service",
  os: "macOS",
  architecture: "arm64",
  role: "agent",
  connection: "connected",
  remote_access_paused: false,
  autostart: true,
  warnings: ["Xcode license requires confirmation"],
  log_location: "/Users/hecer/Library/Logs/DeviceLane/service.log"
};

function fakeClient(overrides: Partial<DaemonClient> = {}): DaemonClient {
  let state = { ...connected };
  const client: DaemonClient = {
    status: vi.fn(() => Promise.resolve({ ...state })),
    pause: vi.fn(() => { state = { ...state, remote_access_paused: true }; return Promise.resolve(); }),
    resume: vi.fn(() => { state = { ...state, remote_access_paused: false }; return Promise.resolve(); }),
    setAutostart: vi.fn((enabled) => { state = { ...state, autostart: enabled }; return Promise.resolve(); }),
    diagnostics: vi.fn().mockResolvedValue({
      path: "/tmp/devicelane-diagnostics",
      items: [{ code: "ready", message: "Lokaler Dienst ist bereit", healthy: true }]
    }),
    repair: vi.fn().mockResolvedValue(undefined),
    ...overrides
  };
  return client;
}

describe("DeviceLane desktop foundation", () => {
  it("shows daemon, host, role, warning, autostart and remote access state", async () => {
    render(<App client={fakeClient()} />);

    expect(await screen.findByRole("heading", { name: "Geräteübersicht" })).toBeVisible();
    expect(screen.getAllByText("Verbunden")).toHaveLength(2);
    expect(screen.getByText("macOS · arm64")).toBeVisible();
    expect(screen.getByText("Agent")).toBeVisible();
    expect(screen.getByText("Xcode license requires confirmation")).toBeVisible();
    expect(screen.getByRole("switch", { name: "Beim Anmelden starten" })).toBeChecked();
    expect(screen.getByRole("button", { name: "Remotezugriff pausieren" })).toBeEnabled();
  });

  it("invokes typed pause, resume, autostart and diagnostics actions", async () => {
    const user = userEvent.setup();
    const client = fakeClient();
    render(<App client={client} />);

    await user.click(await screen.findByRole("button", { name: "Remotezugriff pausieren" }));
    expect(client.pause).toHaveBeenCalledOnce();
    await user.click(screen.getByRole("button", { name: "Remotezugriff fortsetzen" }));
    expect(client.resume).toHaveBeenCalledOnce();
    await user.click(screen.getByRole("switch", { name: "Beim Anmelden starten" }));
    expect(client.setAutostart).toHaveBeenCalledWith(false);
    await user.click(screen.getByRole("button", { name: "Diagnosepaket erstellen" }));
    expect(client.diagnostics).toHaveBeenCalledOnce();
    expect(await screen.findByText("/tmp/devicelane-diagnostics")).toBeVisible();
    expect(screen.getByText("Lokaler Dienst ist bereit")).toBeVisible();
  });

  it("refreshes daemon state after a failed control action", async () => {
    const user = userEvent.setup();
    const status = vi.fn().mockResolvedValue(connected);
    const client = fakeClient({ status, pause: vi.fn().mockRejectedValue(new Error("denied")) });
    render(<App client={client} />);

    await user.click(await screen.findByRole("button", { name: "Remotezugriff pausieren" }));

    expect(status).toHaveBeenCalledTimes(2);
    expect(screen.getAllByText("Verbunden")).toHaveLength(2);
  });

  it("offers repair when the daemon cannot be reached", async () => {
    const user = userEvent.setup();
    const client = fakeClient({ status: vi.fn().mockRejectedValue(new Error("offline")) });
    render(<App client={client} />);

    const repair = await screen.findByRole("button", { name: "Dienst reparieren" });
    expect(screen.getByText("Dienst nicht erreichbar")).toBeVisible();
    await user.click(repair);
    expect(client.repair).toHaveBeenCalledOnce();
  });

  it("keeps every interactive control keyboard reachable with a visible semantic name", async () => {
    const user = userEvent.setup();
    render(<App client={fakeClient()} />);
    await screen.findAllByText("Verbunden");

    await user.tab();
    expect(screen.getByRole("link", { name: "Geräte" })).toHaveFocus();
    await user.tab();
    expect(screen.getByRole("button", { name: "Remotezugriff pausieren" })).toHaveFocus();
    await user.tab();
    expect(screen.getByRole("switch", { name: "Beim Anmelden starten" })).toHaveFocus();
    await user.tab();
    expect(screen.getByRole("button", { name: "Diagnosepaket erstellen" })).toHaveFocus();
  });
});
