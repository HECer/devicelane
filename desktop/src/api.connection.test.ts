import { beforeEach, describe, expect, it, vi } from "vitest";
import { invoke } from "@tauri-apps/api/core";
import { tauriDaemonClient } from "./api";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));

describe("connection settings native client", () => {
  beforeEach(() => { vi.mocked(invoke).mockReset(); });

  it("requests the effective public settings without caller-controlled paths", async () => {
    const settings = {
      registry_address: "registry.local:7443",
      registry_peer_id: "registry",
      connection: "connecting"
    };
    vi.mocked(invoke).mockResolvedValue(settings);
    await expect(tauriDaemonClient.connectionSettings()).resolves.toEqual(settings);
    expect(invoke).toHaveBeenCalledExactlyOnceWith("connection_settings", {});
  });

  it("preserves errors instead of pretending the daemon is local-only", async () => {
    vi.mocked(invoke).mockRejectedValue(new Error("feature_unavailable"));
    await expect(tauriDaemonClient.connectionSettings()).rejects.toThrow("feature_unavailable");
  });

  it("does not invoke native code after cancellation", async () => {
    const controller = new AbortController();
    controller.abort();
    await expect(tauriDaemonClient.connectionSettings(controller.signal)).rejects.toThrow();
    expect(invoke).not.toHaveBeenCalled();
  });

  it("requests approval for the exact immutable settings without retrying the write", async () => {
    let reject!: (reason: Error) => void;
    vi.mocked(invoke).mockImplementationOnce(() => new Promise((_resolve, fail) => { reject = fail; })).mockResolvedValueOnce(undefined);
    const configuration = { version: 1 as const, registry_address: "mac.local:7443", registry_peer_id: "registry" };
    const pending = tauriDaemonClient.setConnection(configuration);
    configuration.registry_peer_id = "substituted";
    reject(new Error("permission_denied"));
    await expect(pending).rejects.toThrow("Administratorfreigabe");
    const exact = { configuration: { version: 1, registry_address: "mac.local:7443", registry_peer_id: "registry" } };
    expect(invoke).toHaveBeenNthCalledWith(1, "set_connection", exact);
    expect(invoke).toHaveBeenNthCalledWith(2, "request_admin_connection_set", exact);
    expect(invoke).toHaveBeenCalledTimes(2);
  });

  it("does not request approval after storage failure or cancellation", async () => {
    const configuration = { version: 1 as const, registry_address: "mac.local:7443", registry_peer_id: "registry" };
    vi.mocked(invoke).mockRejectedValueOnce(new Error("local IPC I/O failed"));
    await expect(tauriDaemonClient.setConnection(configuration)).rejects.toThrow("I/O failed");
    expect(invoke).toHaveBeenCalledTimes(1);
    vi.mocked(invoke).mockClear();
    const controller = new AbortController();
    controller.abort();
    await expect(tauriDaemonClient.setConnection(configuration, controller.signal)).rejects.toThrow();
    expect(invoke).not.toHaveBeenCalled();
  });
});
