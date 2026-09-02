import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type { AuditPage, AuditRecord, AuditSaveResult } from "../api";
import { AuditHistory } from "./AuditHistory";

const record: AuditRecord = {
  sequence: "42",
  occurred_at_ms: "1725000000000",
  activity_id: "activity-42",
  principal_id: "agent-codex",
  source_host_id: "windows",
  target_host_id: "mac",
  device_id: null,
  operation: "xcode.build",
  resources: ["workspace_read"],
  decision: "allow",
  result: "succeeded",
  redacted_message: { code: "redacted", params: [] }
};
const page: AuditPage = { items: [record], next_cursor: { epoch: "1", sequence: "42" } };
const exported: AuditSaveResult = {
  status: "saved",
  file_name: "devicelane-audit.json",
  manifest: {
    format_version: "1",
    record_count: "1",
    records_sha256: "abc123",
    signature: { signature_status: "unavailable" }
  }
};

describe("AuditHistory", () => {
  it("provides keyboard-operable typed filters, bounded pages and safe redacted preformatted text", async () => {
    const user = userEvent.setup();
    const query = vi.fn().mockResolvedValue(page);
    render(<AuditHistory onQuery={query} onExport={vi.fn()} />);
    await user.type(screen.getByLabelText("Prinzipal"), "agent-codex");
    await user.selectOptions(screen.getByLabelText("Ergebnis"), "succeeded");
    await user.click(screen.getByRole("button", { name: "Audit filtern" }));
    expect(query).toHaveBeenCalledWith(expect.objectContaining({ principal_id: "agent-codex", result: "succeeded" }), null, 100);
    const log = await screen.findByRole("region", { name: "Audit-Einträge" });
    expect(within(log).getByText("Redigierter Protokolltext")).toBeVisible();
    const pre = within(log).getByText("redacted", { exact: true });
    expect(pre.tagName).toBe("PRE");
    expect(pre.querySelector("script")).toBeNull();
    expect(screen.getByRole("button", { name: "Nächste Seite" })).toBeEnabled();
    expect(screen.getByLabelText("Seitengröße")).toHaveValue("100");
    expect(screen.getByLabelText("Seitengröße").querySelectorAll("option")).toHaveLength(3);
  });

  it("reports export signature truthfully", async () => {
    const user = userEvent.setup();
    const onExport = vi.fn().mockResolvedValue(exported);
    render(<AuditHistory onQuery={vi.fn().mockResolvedValue({ items: [], next_cursor: null })} onExport={onExport} />);
    await user.click(screen.getByRole("button", { name: "Audit exportieren" }));
    await waitFor(() => expect(onExport).toHaveBeenCalledOnce());
    expect(screen.getByRole("status")).toHaveTextContent("Signatur nicht verfügbar");
    expect(screen.getByText("SHA-256: abc123")).toBeVisible();
  });

  it("requires a deletion scope and explicit retention acknowledgement", async () => {
    const user = userEvent.setup();
    const remove = vi.fn().mockResolvedValue(undefined);
    const query = vi.fn().mockResolvedValue({ items: [], next_cursor: null });
    render(<AuditHistory onQuery={query} onExport={vi.fn()} onDelete={remove} />);
    await user.click(screen.getByRole("button", { name: "Auditdaten löschen" }));
    const dialog = screen.getByRole("dialog", { name: "Auditdaten löschen bestätigen" });
    expect(within(dialog).getByText(/30 Tage/)).toBeVisible();
    const confirm = within(dialog).getByRole("button", { name: "Ausgewählten Bereich löschen" });
    expect(confirm).toBeDisabled();
    await user.selectOptions(within(dialog).getByLabelText("Löschbereich"), "current_filter");
    await user.click(within(dialog).getByRole("checkbox", { name: /Löschung wird protokolliert/ }));
    await user.click(confirm);
    expect(remove).toHaveBeenCalledWith("current_filter", expect.objectContaining({ principal_id: null }));
    await waitFor(() => expect(query).toHaveBeenCalledWith(expect.objectContaining({ principal_id: null }), null, 100));
  });
});
