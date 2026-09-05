import { act, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import type { ConnectionSettings } from "../api";
import { ConnectionSettingsCard } from "./ConnectionSettingsCard";

const connected: ConnectionSettings = { registry_address: "registry.local:7443", registry_peer_id: "registry", connection: "connected" };
afterEach(() => { vi.useRealTimers(); });

it("recovers from a settings error through the refresh control", async () => {
  const client = { connectionSettings: vi.fn()
    .mockRejectedValueOnce(new Error("offline"))
    .mockResolvedValue(connected) };
  render(<ConnectionSettingsCard client={client} />);
  expect(await screen.findByText(/Verbindungsdaten nicht verfügbar/)).toBeVisible();
  fireEvent.click(screen.getByRole("button", { name: "Verbindung aktualisieren" }));
  expect(await screen.findByText(connected.registry_address!)).toBeVisible();
  expect(screen.queryByText(/Verbindungsdaten nicht verfügbar/)).not.toBeInTheDocument();
  expect(client.connectionSettings).toHaveBeenCalledTimes(2);
});

it("serializes polling and removes old connection data after a failed refresh", async () => {
  vi.useFakeTimers();
  let resolve!: (value: ConnectionSettings) => void;
  const client = { connectionSettings: vi.fn()
    .mockImplementationOnce(() => new Promise<ConnectionSettings>((done) => { resolve = done; }))
    .mockRejectedValue(new Error("offline")) };
  const view = render(<ConnectionSettingsCard client={client} />);
  await act(async () => { await vi.advanceTimersByTimeAsync(15_000); });
  expect(client.connectionSettings).toHaveBeenCalledTimes(1);
  await act(async () => { resolve(connected); });
  expect(screen.getByText(connected.registry_address!)).toBeVisible();
  await act(async () => { await vi.advanceTimersByTimeAsync(5_000); });
  expect(client.connectionSettings).toHaveBeenCalledTimes(2);
  expect(screen.queryByText(connected.registry_address!)).not.toBeInTheDocument();
  expect(screen.getByRole("status")).toHaveTextContent("Verbindungsdaten nicht verfügbar");
  view.unmount();
  await act(async () => { await vi.advanceTimersByTimeAsync(15_000); });
  expect(client.connectionSettings).toHaveBeenCalledTimes(2);
});

it("ignores late replies from a replaced client and aborts its request", async () => {
  let resolve!: (value: ConnectionSettings) => void;
  const oldClient = { connectionSettings: vi.fn((_signal?: AbortSignal) => new Promise<ConnectionSettings>((done) => { resolve = done; })) };
  const view = render(<ConnectionSettingsCard client={oldClient} />);
  view.rerender(<ConnectionSettingsCard client={{ connectionSettings: vi.fn().mockResolvedValue({ ...connected, registry_address: "new.local:7443" }) }} />);
  expect(await screen.findByText("new.local:7443")).toBeVisible();
  expect(oldClient.connectionSettings.mock.calls[0][0]?.aborted).toBe(true);
  await act(async () => { resolve(connected); });
  expect(screen.queryByText(connected.registry_address!)).not.toBeInTheDocument();
  expect(screen.getByText("new.local:7443")).toBeVisible();
});
