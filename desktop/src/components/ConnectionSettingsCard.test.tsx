import { act, fireEvent, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, it, vi } from "vitest";
import type { ConnectionSettings } from "../api";
import { ConnectionSettingsCard } from "./ConnectionSettingsCard";

const connected: ConnectionSettings = { registry_address: "registry.local:7443", registry_peer_id: "registry", connection: "connected" };
afterEach(() => { vi.useRealTimers(); });

it("edits settings with keyboard and refreshes only after an acknowledged save", async () => {
  const user = userEvent.setup();
  const client = { connectionSettings: vi.fn().mockResolvedValue(connected), setConnection: vi.fn().mockResolvedValue(undefined) };
  render(<ConnectionSettingsCard client={client} />);
  const edit = await screen.findByRole("button", { name: "Verbindung bearbeiten" });
  await user.click(edit);
  const dialog = screen.getByRole("dialog");
  const address = within(dialog).getByLabelText("Registry-Adresse");
  expect(address).toHaveFocus();
  await user.clear(address);
  await user.type(address, "mac.local:7443");
  await user.tab();
  const peer = within(dialog).getByLabelText("Erwartete Peer-ID");
  expect(peer).toHaveFocus();
  await user.clear(peer);
  await user.type(peer, "mac-registry");
  await user.click(within(dialog).getByRole("button", { name: "Verbindung speichern" }));
  expect(client.setConnection).toHaveBeenCalledExactlyOnceWith({ version: 1, registry_address: "mac.local:7443", registry_peer_id: "mac-registry" }, expect.any(AbortSignal));
  expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  expect(await screen.findByText(/Einstellungen gespeichert/)).toBeVisible();
  expect(client.connectionSettings).toHaveBeenCalledTimes(2);
});

it("preserves the draft through polling and approval errors without claiming success", async () => {
  vi.useFakeTimers();
  const client = { connectionSettings: vi.fn().mockResolvedValue(connected), setConnection: vi.fn().mockRejectedValue(new Error("Exakte Administratorfreigabe angefordert. Nach der Bestätigung erneut ausführen.")) };
  render(<ConnectionSettingsCard client={client} />);
  await act(async () => { await Promise.resolve(); });
  fireEvent.click(screen.getByRole("button", { name: "Verbindung bearbeiten" }));
  const address = screen.getByLabelText("Registry-Adresse");
  fireEvent.change(address, { target: { value: "draft.local:7443" } });
  await act(async () => { await vi.advanceTimersByTimeAsync(5000); });
  expect(address).toHaveValue("draft.local:7443");
  fireEvent.click(screen.getByRole("button", { name: "Verbindung speichern" }));
  await act(async () => { await Promise.resolve(); });
  expect(screen.getByRole("dialog")).toBeVisible();
  expect(screen.getByRole("alert")).toHaveTextContent(/Freigaben/);
  expect(screen.queryByText(/Einstellungen gespeichert/)).not.toBeInTheDocument();
  expect(address).toHaveValue("draft.local:7443");
  expect(client.setConnection).toHaveBeenCalledTimes(1);
  fireEvent.click(screen.getByRole("button", { name: "Schließen" }));
  await act(async () => { await Promise.resolve(); });
  fireEvent.click(screen.getByRole("button", { name: "Verbindung bearbeiten" }));
  expect(screen.getByLabelText("Registry-Adresse")).toHaveValue("draft.local:7443");
});

it("aborts observation on close, prevents duplicate submits and ignores late success", async () => {
  let resolve!: () => void;
  const client = { connectionSettings: vi.fn().mockResolvedValue(connected), setConnection: vi.fn((_config, _signal?: AbortSignal) => new Promise<void>((done) => { resolve = done; })) };
  render(<ConnectionSettingsCard client={client} />);
  await act(async () => { await Promise.resolve(); });
  fireEvent.click(screen.getByRole("button", { name: "Verbindung bearbeiten" }));
  const form = screen.getByRole("button", { name: "Verbindung speichern" }).closest("form")!;
  fireEvent.submit(form);
  fireEvent.submit(form);
  expect(client.setConnection).toHaveBeenCalledTimes(1);
  fireEvent.click(screen.getByRole("button", { name: "Schließen" }));
  expect(client.setConnection.mock.calls[0][1]?.aborted).toBe(true);
  await act(async () => { resolve(); });
  expect(screen.queryByText(/Einstellungen gespeichert/)).not.toBeInTheDocument();
});

it("recovers from a settings error through the refresh control", async () => {
  const client = { setConnection: vi.fn(), connectionSettings: vi.fn()
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
  const client = { setConnection: vi.fn(), connectionSettings: vi.fn()
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
  const oldClient = { setConnection: vi.fn(), connectionSettings: vi.fn((_signal?: AbortSignal) => new Promise<ConnectionSettings>((done) => { resolve = done; })) };
  const view = render(<ConnectionSettingsCard client={oldClient} />);
  view.rerender(<ConnectionSettingsCard client={{ setConnection: vi.fn(), connectionSettings: vi.fn().mockResolvedValue({ ...connected, registry_address: "new.local:7443" }) }} />);
  expect(await screen.findByText("new.local:7443")).toBeVisible();
  expect(oldClient.connectionSettings.mock.calls[0][0]?.aborted).toBe(true);
  await act(async () => { resolve(connected); });
  expect(screen.queryByText(connected.registry_address!)).not.toBeInTheDocument();
  expect(screen.getByText("new.local:7443")).toBeVisible();
});
