import { describe, expect, it } from "vitest";
import type { ActivityEvent, ActivitySummary, LeaseState, MessageParam, PolicyEffect } from "./api";
import { activeOccupancies, leaseStateDisplay, messageParamLabel, policyEffectLabel } from "./dashboard-model";

describe("exhaustive wire enum displays", () => {
  it("keeps running snapshot occupancy when its starting event has been evicted", () => {
    const running: ActivitySummary = {
      activity_id: "running-after-eviction",
      principal_id: "agent-codex",
      source_host_id: "windows",
      target_host_id: "mac",
      device_id: null,
      operation: "xcode.build",
      resources: ["workspace_read"],
      state: "running",
      started_at_ms: "1725000000000",
      finished_at_ms: null
    };
    const unrelatedTerminalEvents = Array.from({ length: 256 }, (_, index): ActivityEvent => ({
      activity_id: `finished-${index}`,
      sequence: "2",
      occurred_at_ms: String(1725000001000 + index),
      principal_id: "agent-codex",
      source_host_id: "windows",
      target_host_id: "mac",
      device_id: null,
      operation: "xcode.build",
      resources: ["workspace_read"],
      authorization: { effect: "allow", rule_id: null, approval_id: null },
      state: "succeeded",
      message: null,
      metrics: {
        current_memory_bytes: { unavailable: { reason: "observer_pending" } },
        peak_memory_bytes: { unavailable: { reason: "observer_pending" } },
        cpu_time_ms: { unavailable: { reason: "observer_pending" } },
        process_count: { unavailable: { reason: "observer_pending" } }
      },
      started_at_ms: "1725000000000",
      finished_at_ms: "1725000001000"
    }));

    expect(activeOccupancies([running], unrelatedTerminalEvents)).toEqual([expect.objectContaining({
      activity_id: "running-after-eviction",
      resource: "workspace_read"
    })]);
  });
  it("labels every policy effect", () => {
    const values: PolicyEffect[] = ["allow", "deny"];
    expect(values.map(policyEffectLabel)).toEqual(["Erlaubt", "Abgelehnt"]);
  });

  it("labels every lease state with visible non-color information", () => {
    const values: LeaseState[] = ["active", "uncertain"];
    expect(values.map(leaseStateDisplay)).toEqual([
      { label: "Lease aktiv", icon: "✓" },
      { label: "Lease unsicher – keine neue Autorisierung", icon: "!" }
    ]);
  });

  it("labels every display-message parameter", () => {
    const values: MessageParam[] = ["local", "remote", "allowed", "denied", "unavailable"];
    expect(values.map(messageParamLabel)).toEqual(["Lokal", "Remote", "Erlaubt", "Abgelehnt", "Nicht verfügbar"]);
  });
});
