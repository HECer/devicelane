import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type { PolicyRule } from "../api";
import { PolicyRules } from "./PolicyRules";

const userRule: PolicyRule = {
  id: "rule-user",
  revision: "7",
  effect: "allow",
  principal_id: "agent-codex",
  source_host_id: "windows",
  target_host_id: "mac",
  device_id: null,
  operation: "xcode.build",
  resources: ["workspace_read"],
  expires_at_ms: "1726000000000",
  require_user_presence: true,
  user_presence: null,
  physical_device: null,
  match_device_exact: false,
  match_resources_exact: true,
  enabled: true,
  origin: "user"
};

const managedRule: PolicyRule = { ...userRule, id: "rule-managed", revision: "11", effect: "deny", origin: "managed" };

describe("PolicyRules", () => {
  it("shows effect, specificity, origin, revision, expiry and presence with deny precedence", () => {
    render(<PolicyRules rules={[userRule, managedRule]} onPut={vi.fn()} onDelete={vi.fn()} onRefresh={vi.fn()} />);
    expect(screen.getByText(/Ablehnen hat immer Vorrang/)).toBeVisible();
    const managed = screen.getByRole("article", { name: "Regel rule-managed" });
    for (const text of ["Ablehnen", "Verwaltet", "Revision 11", "Benutzerpräsenz erforderlich", "Spezifität 6"]) {
      expect(within(managed).getByText(text, { exact: false })).toBeVisible();
    }
    expect(within(managed).getByRole("button", { name: "Regel bearbeiten" })).toBeDisabled();
    expect(within(managed).getByRole("button", { name: "Regel löschen" })).toBeDisabled();
  });

  it("sends the next revision, prevents duplicate saves and refreshes from daemon truth", async () => {
    const user = userEvent.setup();
    let resolve!: () => void;
    const put = vi.fn<(rule: PolicyRule) => Promise<void>>(() => new Promise<void>((done) => { resolve = done; }));
    const refresh = vi.fn().mockResolvedValue(undefined);
    render(<PolicyRules rules={[userRule]} onPut={put} onDelete={vi.fn()} onRefresh={refresh} />);
    await user.click(screen.getByRole("button", { name: "Regel bearbeiten" }));
    expect(screen.getByLabelText("Regelwirkung")).toHaveValue("allow");
    expect(screen.getByLabelText("Ablaufzeit (Unix-Millisekunden)")).toHaveValue(1726000000000);
    expect(screen.getByRole("checkbox", { name: "Benutzerpräsenz erforderlich" })).toBeChecked();
    const save = screen.getByRole("button", { name: "Änderungen speichern" });
    await user.click(save);
    await user.click(save);
    expect(put).toHaveBeenCalledOnce();
    expect(put.mock.calls[0][0]).toMatchObject({ id: "rule-user", revision: "8" });
    resolve();
    await waitFor(() => expect(refresh).toHaveBeenCalledOnce());
    expect(screen.getByRole("status")).toHaveTextContent("Regel gespeichert");
  });

  it("requires confirmation before deletion and includes the observed revision", async () => {
    const user = userEvent.setup();
    const remove = vi.fn().mockResolvedValue(undefined);
    render(<PolicyRules rules={[userRule]} onPut={vi.fn()} onDelete={remove} onRefresh={vi.fn()} />);
    await user.click(screen.getByRole("button", { name: "Regel löschen" }));
    expect(remove).not.toHaveBeenCalled();
    const dialog = screen.getByRole("dialog", { name: "Regel löschen bestätigen" });
    await user.click(within(dialog).getByRole("checkbox", { name: /Revision 7/ }));
    await user.click(within(dialog).getByRole("button", { name: "Regel endgültig löschen" }));
    expect(remove).toHaveBeenCalledWith("rule-user", "7");
  });
});
