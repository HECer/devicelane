import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { ActivityEvent } from "../api";
import { reconnectDelayMs } from "../dashboard-model";
import { ActivityFeed } from "./ActivityFeed";

function event(sequence: number, activityId = `activity-${sequence}`): ActivityEvent {
  return {
    activity_id: activityId,
    sequence: String(sequence),
    occurred_at_ms: String(1_725_000_000_000 + sequence),
    principal_id: "agent-codex",
    source_host_id: "windows-workstation",
    target_host_id: "mac-build-host",
    device_id: sequence % 2 ? "iphone-1" : null,
    operation: "xcode.build",
    resources: ["workspace_read", "debugger"],
    authorization: { effect: "allow", rule_id: "rule-1", approval_id: "approval-1" },
    state: sequence === 1 ? "running" : "succeeded",
    message: { code: "activity_started", params: ["remote"] },
    metrics: {
      current_memory_bytes: { unavailable: { reason: "observer_failed" } },
      peak_memory_bytes: { unavailable: { reason: "observer_failed" } },
      cpu_time_ms: { available: { value: "410" } },
      process_count: { available: { value: "3" } }
    },
    started_at_ms: "1725000000000",
    finished_at_ms: sequence === 1 ? null : "1725000001000"
  };
}

describe("ActivityFeed", () => {
  it("uses bounded exponential reconnect delays", () => {
    expect(reconnectDelayMs(0)).toBe(1_000);
    expect(reconnectDelayMs(4)).toBe(16_000);
    expect(reconnectDelayMs(20)).toBe(30_000);
  });

  it("shows attributable ordered activity and unavailable metrics as text instead of zero", () => {
    render(<ActivityFeed events={[event(2), event(1)]} />);

    expect(screen.getByRole("region", { name: "Live-Aktivitäten" })).toBeVisible();
    expect(screen.getByRole("list", { name: "Aktivitätsereignisse" }).children).toHaveLength(2);
    expect(screen.getAllByText("agent-codex")).toHaveLength(2);
    expect(screen.getAllByText(/windows-workstation → mac-build-host/)).toHaveLength(2);
    expect(screen.getAllByText("workspace_read")).toHaveLength(2);
    expect(screen.getAllByText("Nicht verfügbar: observer_failed")).toHaveLength(4);
    expect(screen.queryByText(/^0$/)).not.toBeInTheDocument();
    expect(screen.getAllByText("Erlaubt")).toHaveLength(2);
    expect(screen.getAllByText(/Regel: rule-1/)).toHaveLength(2);
    expect(screen.getAllByText(/Freigabe: approval-1/)).toHaveLength(2);
    expect(screen.getAllByText("Aktivität gestartet")).toHaveLength(2);
    expect(screen.getAllByText(/Gestartet:/)).toHaveLength(2);
    expect(screen.getByText(/Beendet:/)).toBeVisible();
  });

  it("renders a redacted message as redacted output without interpreting payload HTML", () => {
    const redacted = { ...event(2), message: { code: "redacted" as const, params: [] } };
    render(<ActivityFeed events={[redacted]} />);

    expect(screen.getByText("Redigierte Ausgabe")).toBeVisible();
    expect(screen.getByText("Inhalt redigiert")).toBeVisible();
  });

  it("formats u64 metric values from exact decimal strings", () => {
    const huge = { ...event(1), metrics: { ...event(1).metrics, process_count: { available: { value: "18446744073709551615" } } } } as ActivityEvent;
    render(<ActivityFeed events={[huge]} />);
    expect(screen.getByText("18446744073709551615")).toBeVisible();
  });

  it("does not crash when a valid u64 timestamp is outside the JavaScript Date range", () => {
    const outsideDateRange = { ...event(1), occurred_at_ms: "18446744073709551615" };
    render(<ActivityFeed events={[outsideDateRange]} />);
    expect(screen.getByText("Zeitstempel nicht darstellbar")).toBeVisible();
  });

  it("deduplicates repeated pages and announces a large batch only once", () => {
    const first = event(1, "shared-activity");
    const { rerender } = render(<ActivityFeed events={[first, first]} />);
    expect(screen.getByRole("list", { name: "Aktivitätsereignisse" }).children).toHaveLength(1);

    const batch = Array.from({ length: 100 }, (_, index) => event(index + 2));
    rerender(<ActivityFeed events={[first, ...batch]} />);

    const liveRegions = screen.getAllByRole("status");
    expect(liveRegions).toHaveLength(1);
    expect(liveRegions[0]).toHaveTextContent("100 neue Aktivitätsereignisse");
    expect(screen.queryAllByText(/neues Aktivitätsereignis$/)).toHaveLength(0);
  });
});
