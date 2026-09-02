import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type { ApprovalRequest } from "../api";
import { ApprovalPanel } from "./ApprovalPanel";

const approval: ApprovalRequest = {
  id: "approval-42",
  activity_id: "activity-42",
  principal_id: "agent-codex",
  source_host_id: "windows-workstation",
  target_host_id: "macbook-pro",
  device_id: "iphone-15",
  operation: "xcode.install",
  resources: ["application_install", "device_lease"],
  requested_at_ms: "1725000000000",
  expires_at_ms: "1725000300000",
  risk: "physical_device_install"
};

describe("ApprovalPanel", () => {
  it("shows exact request attribution, resources, risk and expiry", () => {
    render(<ApprovalPanel approvals={[approval]} nowMs={1725000001000} onDecide={vi.fn()} onRefresh={vi.fn()} />);
    const card = screen.getByRole("article", { name: "Freigabe approval-42" });
    for (const text of ["agent-codex", "windows-workstation", "macbook-pro", "iphone-15", "xcode.install", "physical_device_install", "App installieren", "Geräte-Lease"]) {
      expect(within(card).getByText(text, { exact: false })).toBeVisible();
    }
    expect(within(card).getByText(/Läuft ab/)).toBeVisible();
  });

  it("requires explicit confirmation for remembered and blocking decisions and never default-focuses destructive actions", async () => {
    const user = userEvent.setup();
    const decide = vi.fn().mockResolvedValue(undefined);
    render(<ApprovalPanel approvals={[approval]} nowMs={1725000001000} onDecide={decide} onRefresh={vi.fn()} />);
    expect(screen.getByRole("button", { name: "Einmal ablehnen" })).not.toHaveFocus();
    expect(screen.getByRole("button", { name: "Ablehnen und blockieren" })).not.toHaveAttribute("autofocus");

    await user.click(screen.getByRole("button", { name: "Erlauben und merken" }));
    expect(decide).not.toHaveBeenCalled();
    const dialog = screen.getByRole("dialog", { name: "Dauerhafte Regel bestätigen" });
    expect(within(dialog).getByText(/exakte.*Regel/i)).toBeVisible();
    await user.click(within(dialog).getByRole("checkbox", { name: /Auswirkung verstanden/ }));
    await user.click(within(dialog).getByRole("button", { name: "Dauerhaft erlauben" }));
    expect(decide).toHaveBeenCalledWith("approval-42", "allow_and_remember");
  });

  it("disables expired actions, prevents double submission, refreshes daemon truth and announces result", async () => {
    let resolve!: () => void;
    const decide = vi.fn(() => new Promise<void>((done) => { resolve = done; }));
    const refresh = vi.fn().mockResolvedValue(undefined);
    const { rerender } = render(<ApprovalPanel approvals={[approval]} nowMs={1725000001000} onDecide={decide} onRefresh={refresh} />);
    const once = screen.getByRole("button", { name: "Einmal erlauben" });
    fireEvent.click(once);
    fireEvent.click(once);
    expect(decide).toHaveBeenCalledOnce();
    expect(once).toBeDisabled();
    resolve();
    await waitFor(() => expect(refresh).toHaveBeenCalledOnce());
    expect(screen.getByRole("status")).toHaveTextContent("Entscheidung gespeichert");

    rerender(<ApprovalPanel approvals={[approval]} nowMs={1725000300000} onDecide={decide} onRefresh={refresh} />);
    expect(screen.getByText("Abgelaufen")).toBeVisible();
    for (const button of screen.getAllByRole("button")) expect(button).toBeDisabled();
  });

  it("focuses the exact approval opened from a notification without deciding it", () => {
    const decide = vi.fn();
    const second = { ...approval, id: "approval-99" };
    render(<ApprovalPanel approvals={[approval, second]} nowMs={1725000001000} focusApprovalId="approval-99" onDecide={decide} onRefresh={vi.fn()} />);

    expect(screen.getByRole("article", { name: "Freigabe approval-99" })).toHaveFocus();
    expect(decide).not.toHaveBeenCalled();
  });
});
