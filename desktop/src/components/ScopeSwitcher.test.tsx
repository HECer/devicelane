import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { ScopeSwitcher } from "./ScopeSwitcher";

describe("ScopeSwitcher", () => {
  it("exposes local and mesh scope as named keyboard-operable tabs", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(<ScopeSwitcher scope="local" onChange={onChange} />);

    const tabs = screen.getAllByRole("tab");
    expect(screen.getByRole("tablist", { name: "Anzeigebereich" })).toBeVisible();
    expect(tabs).toHaveLength(2);
    expect(tabs[0]).toHaveAccessibleName("Dieser Computer");
    expect(tabs[0]).toHaveAttribute("id", "scope-local-tab");
    expect(tabs[0]).toHaveAttribute("aria-controls", "mesh-dashboard-panel");
    expect(tabs[0]).toHaveAttribute("aria-selected", "true");
    expect(tabs[1]).toHaveAccessibleName("Alle autorisierten Geräte");
    expect(tabs[1]).toHaveAttribute("id", "scope-mesh-tab");

    tabs[0].focus();
    await user.keyboard("{ArrowRight}");

    expect(tabs[1]).toHaveFocus();
    expect(onChange).toHaveBeenCalledWith("mesh");
  });

  it("does not offer unavailable mesh scope as an actionable tab", () => {
    render(<ScopeSwitcher scope="local" meshAvailable={false} onChange={vi.fn()} />);

    expect(screen.getByRole("tab", { name: "Alle autorisierten Geräte" })).toBeDisabled();
    expect(screen.getByText("Registry noch nicht autorisiert")).toBeVisible();
  });
});
