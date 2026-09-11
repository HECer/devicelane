import { layout, prepare, type PreparedText } from "@chenglou/pretext";
import { useEffect } from "react";

export function usePretext(selector = "[data-pretext]"): void {
  useEffect(() => {
    let observer: ResizeObserver | undefined;
    let cancelled = false;
    const prepared = new Map<HTMLElement, PreparedText>();

    const fontsReady = document.fonts?.ready ?? Promise.resolve();
    void fontsReady.then(() => {
      if (cancelled) return;
      const elements = Array.from(document.querySelectorAll<HTMLElement>(selector));
      try {
        for (const element of elements) {
          prepared.set(element, prepare(element.textContent ?? "", getComputedStyle(element).font));
        }
      } catch {
        return;
      }
      const relayout = () => {
        for (const [element, handle] of prepared) {
          const lineHeight = Number.parseFloat(getComputedStyle(element).lineHeight);
          if (element.clientWidth > 0 && Number.isFinite(lineHeight)) {
            element.style.minHeight = `${layout(handle, element.clientWidth, lineHeight).height}px`;
          }
        }
      };
      relayout();
      if (typeof ResizeObserver !== "undefined") {
        observer = new ResizeObserver(relayout);
        elements.forEach((element) => observer?.observe(element));
      }
    });

    return () => {
      cancelled = true;
      observer?.disconnect();
    };
  }, [selector]);
}
