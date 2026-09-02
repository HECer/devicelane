import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";
import type { ActivityEvent, ApprovalRequest, DaemonClient, DaemonSnapshot, DashboardSnapshot, PolicyRule } from "./api";

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
  ,features: ["dashboard_v1"]
};

const dashboard: DashboardSnapshot = {
  revision: "7",
  generated_at_ms: "1725000000000",
  scope: "local",
  hosts: [{
    id: "mac-agent",
    display_name: "Hermanns MacBook Pro",
    platform: "macos",
    architecture: "arm64",
    presence: "online",
    freshness: "live",
    trust: "trusted",
    connection_path: "registry",
    capabilities: ["xcode"],
    permissions: ["workspace_read"],
    devices: []
  }],
  activities: [],
  leases: [],
  pending_approvals: [],
  warnings: []
};

const streamedEvent: ActivityEvent = {
  activity_id: "activity-streamed",
  sequence: "1",
  occurred_at_ms: "1725000000100",
  principal_id: "agent-codex",
  source_host_id: "windows-workstation",
  target_host_id: "mac-agent",
  device_id: null,
  operation: "xcode.build",
  resources: ["workspace_read"],
  authorization: { effect: "allow", rule_id: null, approval_id: "approval-1" },
  state: "running",
  message: null,
  metrics: {
    current_memory_bytes: { available: { value: "1024" } },
    peak_memory_bytes: { available: { value: "2048" } },
    cpu_time_ms: { unavailable: { reason: "observer_pending" } },
    process_count: { available: { value: "1" } }
  },
  started_at_ms: "1725000000100",
  finished_at_ms: null
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
    dashboardSnapshot: vi.fn().mockResolvedValue(dashboard),
    activityEvents: vi.fn().mockResolvedValue({
      result: "events",
      events: [],
      next_cursor: { epoch: "1", sequence: "0" }
    }),
    acknowledgeEvents: vi.fn().mockResolvedValue(undefined),
    pendingApprovals: vi.fn().mockResolvedValue([]),
    decideApproval: vi.fn().mockResolvedValue(undefined),
    policyRules: vi.fn().mockResolvedValue([]),
    putPolicyRule: vi.fn().mockResolvedValue(undefined),
    deletePolicyRule: vi.fn().mockResolvedValue(undefined),
    auditQuery: vi.fn().mockResolvedValue({ items: [], next_cursor: null }),
    auditExport: vi.fn().mockResolvedValue({ records: [], records_json: [], manifest: { format_version: "1", record_count: "0", records_sha256: "empty", signature: { signature_status: "unavailable" } } }),
    deleteAudit: vi.fn().mockResolvedValue(undefined),
    notifyPendingApproval: vi.fn().mockResolvedValue(undefined),
    onOpenApproval: vi.fn().mockResolvedValue(() => undefined),
    ...overrides
  };
  return client;
}

describe("DeviceLane desktop foundation", () => {
  afterEach(() => vi.useRealTimers());
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
    expect(screen.getByRole("alert")).toHaveTextContent("denied");
  });

  it("keeps a diagnostics rejection in the shared accessible error region", async () => {
    const user = userEvent.setup();
    const client = fakeClient({ diagnostics: vi.fn().mockRejectedValue(new Error("diagnostics unavailable")) });
    render(<App client={client} />);

    await user.click(await screen.findByRole("button", { name: "Diagnosepaket erstellen" }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveAttribute("aria-live", "assertive");
    expect(alert).toHaveTextContent("diagnostics unavailable");
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
    expect(screen.getByRole("tab", { name: "Dieser Computer" })).toHaveFocus();
    await user.tab();
    expect(screen.getByRole("button", { name: /Hermanns MacBook Pro/ })).toHaveFocus();
    await user.tab();
    expect(screen.getByRole("button", { name: "Remotezugriff pausieren" })).toHaveFocus();
    await user.tab();
    expect(screen.getByRole("switch", { name: "Beim Anmelden starten" })).toHaveFocus();
    await user.tab();
    expect(screen.getByRole("button", { name: "Diagnosepaket erstellen" })).toHaveFocus();
  });

  it("resyncs once, deduplicates replayed events and acknowledges the consumed cursor", async () => {
    const activityEvents = vi.fn()
      .mockResolvedValueOnce({
        result: "resync_required",
        oldest_available: { epoch: "4", sequence: "8" },
        snapshot_revision: "8"
      })
      .mockResolvedValueOnce({
        result: "events",
        events: [streamedEvent, streamedEvent],
        next_cursor: { epoch: "4", sequence: "9" }
      })
      .mockResolvedValue({
        result: "events",
        events: [],
        next_cursor: { epoch: "4", sequence: "9" }
      });
    const client = fakeClient({ activityEvents });

    render(<App client={client} />);

    expect(await screen.findByText("Hermanns MacBook Pro")).toBeVisible();
    expect(await screen.findByText("activity-streamed")).toBeVisible();
    expect(screen.getByRole("list", { name: "Aktivitätsereignisse" }).children).toHaveLength(1);
    await waitFor(() => expect(client.acknowledgeEvents).toHaveBeenCalledWith(
      expect.any(String),
      { epoch: "4", sequence: "9" },
      expect.any(AbortSignal)
    ));
    expect(client.dashboardSnapshot).toHaveBeenCalledTimes(2);
    expect(activityEvents).toHaveBeenNthCalledWith(1, "local", { epoch: "0", sequence: "0" }, 100, expect.any(AbortSignal));
    expect(activityEvents).toHaveBeenNthCalledWith(2, "local", { epoch: "4", sequence: "8" }, 100, expect.any(AbortSignal));
  });

  it("allows the same resync revision again after a successful events page", async () => {
    const activityEvents = vi.fn()
      .mockResolvedValueOnce({
        result: "resync_required",
        oldest_available: { epoch: "4", sequence: "8" },
        snapshot_revision: "8"
      })
      .mockResolvedValueOnce({
        result: "events",
        events: [streamedEvent],
        next_cursor: { epoch: "4", sequence: "9" }
      })
      .mockResolvedValueOnce({
        result: "resync_required",
        oldest_available: { epoch: "4", sequence: "9" },
        snapshot_revision: "8"
      })
      .mockImplementation(() => new Promise<never>(() => undefined));
    const client = fakeClient({ activityEvents });
    render(<App client={client} />);

    expect(await screen.findByText("activity-streamed")).toBeVisible();
    await act(async () => { await new Promise((resolve) => window.setTimeout(resolve, 1_050)); });
    await waitFor(() => expect(client.dashboardSnapshot).toHaveBeenCalledTimes(3));
    expect(screen.queryByText(/erneut eine Synchronisierung/)).not.toBeInTheDocument();
  }, 4_000);

  it("resyncs the same snapshot revision again when the daemon epoch changes directly", async () => {
    const activityEvents = vi.fn()
      .mockResolvedValueOnce({
        result: "resync_required",
        oldest_available: { epoch: "2", sequence: "0" },
        snapshot_revision: "8"
      })
      .mockResolvedValueOnce({
        result: "resync_required",
        oldest_available: { epoch: "3", sequence: "0" },
        snapshot_revision: "8"
      })
      .mockImplementation(() => new Promise<never>(() => undefined));
    const client = fakeClient({ activityEvents });

    render(<App client={client} />);

    await waitFor(() => expect(client.dashboardSnapshot).toHaveBeenCalledTimes(3));
    expect(screen.queryByText(/erneut eine Synchronisierung/)).not.toBeInTheDocument();
  });

  it("accepts a lower snapshot revision after the activity stream enters a new epoch", async () => {
    const oldEpoch = {
      ...dashboard,
      revision: "10",
      hosts: [{ ...dashboard.hosts[0], display_name: "Host aus Epoche 1" }]
    };
    const newEpoch = {
      ...dashboard,
      revision: "1",
      hosts: [{ ...dashboard.hosts[0], display_name: "Host aus Epoche 2" }]
    };
    const dashboardSnapshot = vi.fn()
      .mockResolvedValueOnce(oldEpoch)
      .mockResolvedValue(newEpoch);
    const activityEvents = vi.fn()
      .mockResolvedValueOnce({
        result: "resync_required",
        oldest_available: { epoch: "2", sequence: "0" },
        snapshot_revision: "1"
      })
      .mockImplementation(() => new Promise<never>(() => undefined));

    render(<App client={fakeClient({ dashboardSnapshot, activityEvents })} />);

    expect(await screen.findByText("Host aus Epoche 2")).toBeVisible();
    expect(screen.queryByText("Host aus Epoche 1")).not.toBeInTheDocument();
  });

  it("shows a reconnect state and clears the transient error after the stream recovers", async () => {
    const activityEvents = vi.fn()
      .mockRejectedValueOnce(new Error("stream interrupted"))
      .mockResolvedValue({
        result: "events",
        events: [streamedEvent],
        next_cursor: { epoch: "1", sequence: "1" }
      });
    render(<App client={fakeClient({ activityEvents })} />);

    expect(await screen.findByText("Stream verbindet erneut")).toBeVisible();
    expect(screen.getByRole("alert")).toHaveTextContent("stream interrupted");
    await act(async () => { await new Promise((resolve) => window.setTimeout(resolve, 1_050)); });

    expect(await screen.findByText("activity-streamed")).toBeVisible();
    expect(screen.queryByText("Stream verbindet erneut")).not.toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  }, 4_000);

  it("derives mesh availability from an authenticated probe without changing the selected local tab", async () => {
    const localOnly = { ...dashboard, scope: "local" as const };
    const { unmount } = render(<App client={fakeClient({ dashboardSnapshot: vi.fn().mockResolvedValue(localOnly) })} />);
    expect(await screen.findByRole("tab", { name: "Alle autorisierten Geräte" })).toBeDisabled();
    unmount();

    const mesh = { ...dashboard, scope: "mesh" as const };
    const dashboardSnapshot = vi.fn().mockResolvedValueOnce(mesh).mockResolvedValue(dashboard);
    render(<App client={fakeClient({ dashboardSnapshot })} />);
    expect(await screen.findByRole("tab", { name: "Alle autorisierten Geräte" })).toBeEnabled();
    expect(screen.getByRole("tab", { name: "Dieser Computer" })).toHaveAttribute("aria-selected", "true");
  });

  it("discovers mesh authorization on a later serialized poll", async () => {
    vi.useFakeTimers();
    const localOnly = { ...dashboard, scope: "local" as const };
    const mesh = { ...dashboard, revision: "8", scope: "mesh" as const };
    const responses = [localOnly, mesh, { ...localOnly, revision: "8" }];
    let inFlight = 0;
    let maximumInFlight = 0;
    const dashboardSnapshot = vi.fn(async () => {
      inFlight += 1;
      maximumInFlight = Math.max(maximumInFlight, inFlight);
      await Promise.resolve();
      inFlight -= 1;
      return responses.shift() ?? { ...localOnly, revision: "8" };
    });
    const activityEvents = vi.fn(() => new Promise<never>(() => undefined));
    const { unmount } = render(<App client={fakeClient({ dashboardSnapshot, activityEvents })} />);
    await act(async () => Promise.resolve());
    expect(screen.getByRole("tab", { name: "Alle autorisierten Geräte" })).toBeDisabled();

    await act(async () => {
      await vi.advanceTimersByTimeAsync(10_000);
      await Promise.resolve();
    });
    expect(screen.getByRole("tab", { name: "Alle autorisierten Geräte" })).toBeEnabled();
    expect(screen.getByRole("tab", { name: "Dieser Computer" })).toHaveAttribute("aria-selected", "true");
    expect(dashboardSnapshot).toHaveBeenNthCalledWith(2, "mesh", expect.any(AbortSignal));
    expect(maximumInFlight).toBe(1);
    unmount();
  });

  it("does not retain mesh activity when returning to the local scope", async () => {
    const dashboardSnapshot = vi.fn((requestedScope: "local" | "mesh") => Promise.resolve({
      ...dashboard,
      revision: requestedScope === "mesh" ? "8" : "7",
      scope: requestedScope
    }));
    let meshDelivered = false;
    const activityEvents = vi.fn((requestedScope: "local" | "mesh") => Promise.resolve({
      result: "events" as const,
      events: requestedScope === "mesh" && !meshDelivered
        ? (meshDelivered = true, [streamedEvent])
        : [],
      next_cursor: { epoch: "1", sequence: requestedScope === "mesh" ? "1" : "0" }
    }));
    render(<App client={fakeClient({ dashboardSnapshot, activityEvents })} />);
    const user = userEvent.setup();

    const meshTab = await screen.findByRole("tab", { name: "Alle autorisierten Geräte" });
    await waitFor(() => expect(meshTab).toBeEnabled());
    await user.click(meshTab);
    expect(await screen.findByText("activity-streamed")).toBeVisible();

    await user.click(screen.getByRole("tab", { name: "Dieser Computer" }));
    await waitFor(() => expect(screen.queryByText("activity-streamed")).not.toBeInTheDocument());
  });

  it("does not overlap an authenticated probe when the user changes scope", async () => {
    vi.useFakeTimers();
    const mesh = { ...dashboard, revision: "8", scope: "mesh" as const };
    let resolveProbe!: (value: DashboardSnapshot) => void;
    const pendingProbe = new Promise<DashboardSnapshot>((resolve) => { resolveProbe = resolve; });
    const dashboardSnapshot = vi.fn()
      .mockResolvedValueOnce(mesh)
      .mockResolvedValueOnce(dashboard)
      .mockReturnValueOnce(pendingProbe)
      .mockResolvedValue(mesh);
    const activityEvents = vi.fn(() => new Promise<never>(() => undefined));
    const { unmount } = render(<App client={fakeClient({ dashboardSnapshot, activityEvents })} />);
    await act(async () => { await Promise.resolve(); await Promise.resolve(); });
    expect(screen.getByRole("tab", { name: "Alle autorisierten Geräte" })).toBeEnabled();

    await act(async () => { await vi.advanceTimersByTimeAsync(10_000); });
    expect(dashboardSnapshot).toHaveBeenCalledTimes(3);
    fireEvent.click(screen.getByRole("tab", { name: "Alle autorisierten Geräte" }));
    expect(dashboardSnapshot).toHaveBeenCalledTimes(3);

    await act(async () => { resolveProbe(mesh); await Promise.resolve(); });
    expect(dashboardSnapshot).toHaveBeenCalledTimes(4);
    unmount();
  });

  it("treats repeated cursor-ahead and limit-exceeded stream results as terminal", async () => {
    const repeatedCursorAhead = vi.fn()
      .mockResolvedValueOnce({ result: "cursor_ahead", newest_available: { epoch: "4", sequence: "9" } })
      .mockResolvedValueOnce({ result: "cursor_ahead", newest_available: { epoch: "4", sequence: "9" } })
      .mockImplementation(() => new Promise<never>(() => undefined));
    const { unmount } = render(<App client={fakeClient({ activityEvents: repeatedCursorAhead })} />);
    await waitFor(() => expect(repeatedCursorAhead).toHaveBeenCalledTimes(2));
    expect(await screen.findByRole("alert")).toHaveTextContent(/Cursor/);
    expect(screen.queryByText("Stream verbindet erneut")).not.toBeInTheDocument();
    unmount();

    const limitExceeded = vi.fn().mockResolvedValue({ result: "limit_exceeded" });
    render(<App client={fakeClient({ activityEvents: limitExceeded })} />);
    expect(await screen.findByRole("alert")).toHaveTextContent(/Größenlimit/);
    await new Promise((resolve) => window.setTimeout(resolve, 20));
    expect(limitExceeded).toHaveBeenCalledOnce();
    expect(screen.queryByText("Stream verbindet erneut")).not.toBeInTheDocument();
  });

  it("serializes snapshot polls and never replaces a newer revision with an older response", async () => {
    vi.useFakeTimers();
    let resolveFirst!: (value: DashboardSnapshot) => void;
    const first = new Promise<DashboardSnapshot>((resolve) => { resolveFirst = resolve; });
    const old = { ...dashboard, revision: "9", hosts: [{ ...dashboard.hosts[0], display_name: "Alter Host" }] };
    const dashboardSnapshot = vi.fn()
      .mockReturnValueOnce(first)
      .mockResolvedValue(old);
    const activityEvents = vi.fn(() => new Promise<never>(() => undefined));
    const { unmount } = render(<App client={fakeClient({ dashboardSnapshot, activityEvents })} />);
    await act(async () => Promise.resolve());
    await act(async () => { await vi.advanceTimersByTimeAsync(30_000); });
    expect(dashboardSnapshot).toHaveBeenCalledTimes(1);

    await act(async () => {
      resolveFirst({ ...dashboard, revision: "10", hosts: [{ ...dashboard.hosts[0], display_name: "Neuer Host" }] });
      await Promise.resolve();
    });
    expect(screen.getByText("Neuer Host")).toBeVisible();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(10_000);
      await Promise.resolve();
    });
    expect(screen.queryByText("Alter Host")).not.toBeInTheDocument();
    unmount();
  });

  it("names the active tabpanel and reports active jobs from the snapshot", async () => {
    const active = {
      ...dashboard,
      activities: [{
        activity_id: "job-1",
        principal_id: "agent-codex",
        source_host_id: "windows-workstation",
        target_host_id: "mac-agent",
        device_id: null,
        operation: "xcode.build",
        resources: ["workspace_read" as const],
        state: "running" as const,
        started_at_ms: "1725000000100",
        finished_at_ms: null
      }]
    };
    render(<App client={fakeClient({ dashboardSnapshot: vi.fn().mockResolvedValue(active) })} />);

    const panel = await screen.findByRole("tabpanel");
    expect(panel).toHaveAttribute("id", "mesh-dashboard-panel");
    expect(panel).toHaveAttribute("aria-labelledby", "scope-local-tab");
    expect(screen.getByText("1 aktiver Job")).toBeVisible();
    const occupancy = screen.getByRole("region", { name: "Verwendete Ressourcen" });
    expect(within(occupancy).getByText(/agent-codex → mac-agent/)).toBeVisible();
    expect(within(occupancy).getByText("Arbeitsbereich lesen")).toBeVisible();
  });

  it("loads approvals and policies from daemon truth and wires management actions", async () => {
    const user = userEvent.setup();
    const approval: ApprovalRequest = {
      id: "approval-ui", activity_id: "job-ui", principal_id: "agent-ui", source_host_id: "windows", target_host_id: "mac-agent", device_id: null,
      operation: "xcode.build", resources: ["workspace_read"], requested_at_ms: "1725000000000", expires_at_ms: "9725000000000", risk: "target_confirmation"
    };
    const rule: PolicyRule = {
      id: "rule-ui", revision: "2", effect: "allow", principal_id: "agent-ui", source_host_id: "windows", target_host_id: "mac-agent", device_id: null,
      operation: "xcode.build", resources: ["workspace_read"], expires_at_ms: null, require_user_presence: true, user_presence: null, physical_device: null,
      match_device_exact: false, match_resources_exact: true, enabled: true, origin: "user"
    };
    const pendingApprovals = vi.fn().mockResolvedValue([approval]);
    const policyRules = vi.fn().mockResolvedValue([rule]);
    const decideApproval = vi.fn().mockResolvedValue(undefined);
    const client = fakeClient({ pendingApprovals, policyRules, decideApproval });
    render(<App client={client} />);

    expect(await screen.findByRole("heading", { name: "Ausstehende Freigaben" })).toBeVisible();
    expect(screen.getByRole("heading", { name: "Richtlinien" })).toBeVisible();
    expect(screen.getByRole("heading", { name: "Audit-Verlauf" })).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Einmal erlauben" }));
    await waitFor(() => expect(decideApproval).toHaveBeenCalledWith("approval-ui", "allow_once"));
    await waitFor(() => expect(pendingApprovals).toHaveBeenCalledTimes(2));
  });

  it("opens the exact approval from a native notification without approving it", async () => {
    const approval: ApprovalRequest = {
      id: "approval-notification", activity_id: "job-notification", principal_id: "agent-ui", source_host_id: "windows", target_host_id: "mac-agent", device_id: null,
      operation: "xcode.build", resources: ["workspace_read"], requested_at_ms: "1725000000000", expires_at_ms: "9725000000000", risk: "target_confirmation"
    };
    let openApproval: ((approvalId: string) => void) | undefined;
    const onOpenApproval = vi.fn((listener: (approvalId: string) => void) => {
      openApproval = listener;
      return Promise.resolve(() => undefined);
    });
    const decideApproval = vi.fn().mockResolvedValue(undefined);
    const client = fakeClient({
      pendingApprovals: vi.fn().mockResolvedValue([approval]),
      decideApproval,
      onOpenApproval
    } as Partial<DaemonClient>);
    render(<App client={client} />);

    const card = await screen.findByRole("article", { name: "Freigabe approval-notification" });
    await waitFor(() => expect(onOpenApproval).toHaveBeenCalledOnce());
    act(() => openApproval?.("approval-notification"));
    expect(card).toHaveFocus();
    expect(decideApproval).not.toHaveBeenCalled();
  });
});
