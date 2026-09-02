import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { ResourceOccupancy as ResourceOccupancyModel } from "../api";
import { ResourceOccupancy } from "./ResourceOccupancy";

const occupancies: ResourceOccupancyModel[] = [{
  activity_id: "activity-1",
  principal_id: "agent-codex",
  target_host_id: "mac-build-host",
  device_id: "iphone-1",
  resource: "device_lease",
  acquired_at_ms: 1_725_000_000_000
}, {
  activity_id: "activity-2",
  principal_id: "Xcode",
  target_host_id: "mac-build-host",
  device_id: null,
  resource: "workspace_read",
  acquired_at_ms: 1_725_000_000_100
}];

describe("ResourceOccupancy", () => {
  it("renders agent and app occupancy edges with explicit targets and resources", () => {
    render(<ResourceOccupancy occupancies={occupancies} />);

    expect(screen.getByRole("region", { name: "Verwendete Ressourcen" })).toBeVisible();
    expect(screen.getByRole("list", { name: "Ressourcennutzung" }).children).toHaveLength(2);
    expect(screen.getByText("agent-codex → mac-build-host / iphone-1")).toBeVisible();
    expect(screen.getByText("Xcode → mac-build-host")).toBeVisible();
    expect(screen.getByText("Geräte-Lease")).toBeVisible();
    expect(screen.getByText("Arbeitsbereich lesen")).toBeVisible();
  });

  it("shows a useful empty state without a color-only indicator", () => {
    render(<ResourceOccupancy occupancies={[]} />);

    expect(screen.getByText("Keine Ressource ist derzeit belegt.")).toBeVisible();
  });
});
