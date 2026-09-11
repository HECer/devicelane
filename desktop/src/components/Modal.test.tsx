import { useState } from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { Modal } from "./Modal";

function Harness() {
  const [open, setOpen] = useState(false);
  return <><button onClick={() => setOpen(true)}>Öffnen</button>{open && <Modal titleId="modal-title" onClose={() => setOpen(false)}><h2 id="modal-title">Dialog</h2><button data-modal-initial>Abbrechen</button><button>Weiter</button></Modal>}</>;
}

describe("Modal", () => {
  it("sets safe initial focus, traps Tab, closes on Escape and restores trigger focus", async () => {
    const user = userEvent.setup();
    const { container } = render(<Harness />);
    const trigger = screen.getByRole("button", { name: "Öffnen" });
    await user.click(trigger);
    const cancel = screen.getByRole("button", { name: "Abbrechen" });
    const next = screen.getByRole("button", { name: "Weiter" });
    expect(cancel).toHaveFocus();
    expect(container).toHaveAttribute("aria-hidden", "true");
    next.focus();
    await user.tab();
    expect(cancel).toHaveFocus();
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(trigger).toHaveFocus();
  });
});
