import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";

const styles = readFileSync("src/styles.css", "utf8");
const tauriConfig = JSON.parse(readFileSync("src-tauri/tauri.conf.json", "utf8")) as {
  app: { windows: Array<{ minWidth: number }> };
};

function luminance(hex: string): number {
  const channels = hex.match(/[0-9a-f]{2}/gi)?.map((channel) => Number.parseInt(channel, 16) / 255) ?? [];
  const linear = channels.map((channel) => channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4);
  return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2];
}

function contrast(foreground: string, background: string): number {
  const values = [luminance(foreground), luminance(background)].sort((left, right) => right - left);
  return (values[0] + 0.05) / (values[1] + 0.05);
}

function cssVariable(name: string): string {
  const match = styles.match(new RegExp(`${name}:\\s*(#[0-9a-f]{6})`, "i"));
  if (!match) throw new Error(`missing ${name}`);
  return match[1];
}

function reflowBreakpoint(pattern: RegExp, label: string): number {
  const match = styles.match(pattern);
  if (!match) throw new Error(`missing ${label} reflow rule`);
  return Number(match[1]);
}

describe("responsive and contrast contracts", () => {
  it("keeps controls touch-sized and provides deterministic narrow reflow rules", () => {
    expect(styles).toMatch(/button\s*\{[^}]*min-height:\s*44px/s);
    expect(styles).toMatch(/\.switch\s*\{[^}]*min-height:\s*44px/s);
    expect(styles).toContain("@media (max-width: 599px)");
    expect(styles).toMatch(/overflow-wrap:\s*anywhere/);
  });

  it("keeps the dashboard fluid at 200 percent zoom and reflows before horizontal clipping", () => {
    expect(styles).toMatch(/\.shell\s*\{[^}]*width:\s*min\(1120px,\s*100%\)/s);
    expect(styles).toContain("@media (max-width: 767px)");
    expect(styles).toMatch(/@media \(max-width:\s*599px\)[\s\S]*\.dashboard-side\s*\{\s*grid-template-columns:\s*1fr/);
    expect(styles).not.toMatch(/\bzoom\s*:/);
  });

  it("contains explicit reduced-motion, forced-color and dark-contrast treatments", () => {
    expect(styles).toContain("@media (prefers-reduced-motion: reduce)");
    expect(styles).toContain("@media (forced-colors: active)");
    expect(styles).toContain("@media (prefers-color-scheme: dark)");
    expect(styles).toContain("--dark-status-online: #6fe0c4");
    expect(styles).toContain("--dark-status-warning: #ffc46b");
  });

  it("calculates WCAG AA contrast for every dark activity and occupancy status", () => {
    const darkSurface = "#1b2528";
    for (const variable of ["--dark-status-online", "--dark-status-warning", "--dark-status-error", "--dark-status-connecting", "--dark-occupancy"]) {
      expect(contrast(cssVariable(variable), darkSurface), variable).toBeGreaterThanOrEqual(4.5);
    }
    expect(styles).toMatch(/presence--offline[\s\S]*var\(--dark-status-error\)/);
    expect(styles).toMatch(/presence--connecting[\s\S]*var\(--dark-status-connecting\)/);
    expect(styles).toMatch(/occupancy-list strong[\s\S]*var\(--dark-occupancy\)/);
  });

  it("keeps the dark scope hint at WCAG AA contrast", () => {
    expect(contrast(cssVariable("--dark-scope-hint"), "#1b2528")).toBeGreaterThanOrEqual(4.5);
    expect(styles).toMatch(/scope-hint[\s\S]*var\(--dark-scope-hint\)/);
  });

  it("allows the native window and document to reflow to 280 CSS pixels", () => {
    expect(tauriConfig.app.windows[0].minWidth).toBe(280);
    expect(styles).toMatch(/body\s*\{[^}]*min-width:\s*0(?:px)?\s*;/s);
    const style = document.createElement("style");
    style.textContent = styles;
    document.head.append(style);
    expect(["0", "0px"]).toContain(getComputedStyle(document.body).minWidth);
    style.remove();
  });

  it.each([
    { width: 360, zoom: 100, dashboardColumns: 1, sidebar: false, scopeColumns: 1 },
    { width: 768, zoom: 100, dashboardColumns: 1, sidebar: true, scopeColumns: 2 },
    { width: 1440, zoom: 100, dashboardColumns: 2, sidebar: true, scopeColumns: 2 },
    { width: 360, zoom: 320, dashboardColumns: 1, sidebar: false, scopeColumns: 1 },
    { width: 768, zoom: 320, dashboardColumns: 1, sidebar: false, scopeColumns: 1 },
    { width: 1440, zoom: 320, dashboardColumns: 1, sidebar: false, scopeColumns: 1 },
    { width: 360, zoom: 400, dashboardColumns: 1, sidebar: false, scopeColumns: 1 },
    { width: 768, zoom: 400, dashboardColumns: 1, sidebar: false, scopeColumns: 1 },
    { width: 1440, zoom: 400, dashboardColumns: 1, sidebar: false, scopeColumns: 1 }
  ])("computes reflow at $width px and $zoom% zoom", ({ width, zoom, dashboardColumns, sidebar, scopeColumns }) => {
    const dashboardMax = reflowBreakpoint(/@media \(max-width: (\d+)px\) \{ \.dashboard-layout \{ grid-template-columns: 1fr;/, "dashboard");
    const sidebarMax = reflowBreakpoint(/@media \(max-width: (\d+)px\) \{ \.app-frame \{ display: block;/, "sidebar");
    const scopeMax = reflowBreakpoint(/@media \(max-width: (\d+)px\) \{ \.scope-switcher-wrap/, "scope");
    const cssWidth = width * 100 / zoom;
    expect(cssWidth > dashboardMax ? 2 : 1).toBe(dashboardColumns);
    expect(cssWidth > sidebarMax).toBe(sidebar);
    expect(cssWidth > scopeMax ? 2 : 1).toBe(scopeColumns);
  });
});
