import { useRef, type KeyboardEvent } from "react";
import type { DashboardScope } from "../api";

export interface ScopeSwitcherProps {
  scope: DashboardScope;
  onChange: (scope: DashboardScope) => void;
  meshAvailable?: boolean;
}

export function ScopeSwitcher({ scope, onChange, meshAvailable = true }: ScopeSwitcherProps) {
  const localRef = useRef<HTMLButtonElement>(null);
  const meshRef = useRef<HTMLButtonElement>(null);

  const select = (next: DashboardScope) => {
    if (next === "mesh" && !meshAvailable) return;
    onChange(next);
    (next === "local" ? localRef : meshRef).current?.focus();
  };

  const onKeyDown = (event: KeyboardEvent<HTMLButtonElement>) => {
    if (event.key === "ArrowLeft" || event.key === "ArrowRight" || event.key === "Home" || event.key === "End") {
      event.preventDefault();
      const next = event.key === "ArrowLeft" || event.key === "Home" || !meshAvailable ? "local" : "mesh";
      select(next);
    }
  };

  return (
    <div className="scope-switcher-wrap">
      <div className="scope-switcher" role="tablist" aria-label="Anzeigebereich">
        <button
          id="scope-local-tab"
          ref={localRef}
          type="button"
          role="tab"
          aria-selected={scope === "local"}
          aria-controls="mesh-dashboard-panel"
          tabIndex={scope === "local" ? 0 : -1}
          onClick={() => select("local")}
          onKeyDown={onKeyDown}
        >
          Dieser Computer
        </button>
        <button
          id="scope-mesh-tab"
          ref={meshRef}
          type="button"
          role="tab"
          aria-selected={scope === "mesh"}
          aria-controls="mesh-dashboard-panel"
          tabIndex={scope === "mesh" ? 0 : -1}
          disabled={!meshAvailable}
          onClick={() => select("mesh")}
          onKeyDown={onKeyDown}
        >
          Alle autorisierten Geräte
        </button>
      </div>
      {!meshAvailable && <p className="scope-hint">Registry noch nicht autorisiert</p>}
    </div>
  );
}
