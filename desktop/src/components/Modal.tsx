import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";

interface ModalProps { titleId: string; onClose: () => void; className?: string; children: React.ReactNode; }
const focusable = "button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [href], [tabindex]:not([tabindex='-1'])";

export function Modal({ titleId, onClose, className = "", children }: ModalProps) {
  const [host] = useState(() => { const node = document.createElement("div"); node.dataset.modalHost = "true"; return node; });
  const closeRef = useRef(onClose);
  closeRef.current = onClose;
  useEffect(() => {
    const trigger = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    document.body.append(host);
    const background = [...document.body.children].filter((node) => node !== host) as HTMLElement[];
    const previous = background.map((node) => ({ node, inert: node.inert, hidden: node.getAttribute("aria-hidden") }));
    background.forEach((node) => { node.inert = true; node.setAttribute("aria-hidden", "true"); });
    (host.querySelector<HTMLElement>("[data-modal-initial]") ?? host.querySelector<HTMLElement>(focusable))?.focus();
    const keydown = (event: KeyboardEvent) => {
      if (event.key === "Escape") { event.preventDefault(); closeRef.current(); return; }
      if (event.key !== "Tab") return;
      const items = [...host.querySelectorAll<HTMLElement>(focusable)];
      if (!items.length) { event.preventDefault(); return; }
      const first = items[0]; const last = items[items.length - 1];
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    };
    document.addEventListener("keydown", keydown);
    return () => {
      document.removeEventListener("keydown", keydown);
      previous.forEach(({ node, inert, hidden }) => { node.inert = inert; if (hidden === null) node.removeAttribute("aria-hidden"); else node.setAttribute("aria-hidden", hidden); });
      host.remove(); trigger?.focus();
    };
  }, [host]);
  return createPortal(<div className="modal-backdrop"><div className={`confirmation-dialog ${className}`.trim()} role="dialog" aria-modal="true" aria-labelledby={titleId}>{children}</div></div>, host);
}
