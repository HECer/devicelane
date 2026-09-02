import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";

const styles = readFileSync("src/styles.css", "utf8");

describe("responsive and contrast contracts", () => {
  it("keeps controls touch-sized and provides deterministic narrow reflow rules", () => {
    expect(styles).toMatch(/button\s*\{[^}]*min-height:\s*44px/s);
    expect(styles).toMatch(/\.switch\s*\{[^}]*min-height:\s*44px/s);
    expect(styles).toContain("@media (max-width: 599px)");
    expect(styles).toMatch(/overflow-wrap:\s*anywhere/);
  });

  it("contains explicit reduced-motion, forced-color and dark-contrast treatments", () => {
    expect(styles).toContain("@media (prefers-reduced-motion: reduce)");
    expect(styles).toContain("@media (forced-colors: active)");
    expect(styles).toContain("@media (prefers-color-scheme: dark)");
    expect(styles).toContain("--dark-status-online: #6fe0c4");
    expect(styles).toContain("--dark-status-warning: #ffc46b");
  });
});
