import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { App } from "./App";
import type { DaemonClient, DaemonSnapshot } from "./api";

const connected: DaemonSnapshot = {
  protocol: { major: 1, minor: 0 },
  daemonVersion: "0.1.0",
  os: "macOS",
  architecture: "arm64",
  role: "agent",
  connection: "connected",
  paused: false,
  autostartEnabled: true,
  warnings: ["Xcode license requires confirmation"],
  logLocation: "/Users/hecer/Library/Logs/DeviceLane/service.log"
};

function fakeClient(overrides: Partial<DaemonClient> = {}): DaemonClient {
  let state = { ...connected };
  const client: DaemonClient = {
    status: vi.fn(() => Promise.resolve({ ...state })),
    pause: vi.fn(() => { state = { ...state, paused: true }; return Promise.resolve(); }),
    resume: vi.fn(() => { state = { ...state, paused: false }; return Promise.resolve(); }),
    setAutostart: vi.fn((enabled) => { state = { ...state, autostartEnabled: enabled }; return Promise.resolve(); }),
    diagnostics: vi.fn().mockResolvedValue({ path: "/tmp/devicelane-diagnostics" }),
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
