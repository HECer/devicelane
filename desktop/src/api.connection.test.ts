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
});
