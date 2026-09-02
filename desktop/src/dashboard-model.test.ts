import { describe, expect, it } from "vitest";
import type { LeaseState, MessageParam, PolicyEffect } from "./api";
import { leaseStateDisplay, messageParamLabel, policyEffectLabel } from "./dashboard-model";

describe("exhaustive wire enum displays", () => {
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
