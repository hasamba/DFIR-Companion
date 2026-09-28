// Contrast guard for the toolbar jobs chip (#1749).
//
// #1732 made the chip visible at rest ("⚙ 0 jobs"). Its text was a fixed #6aa9ff, set inline through
// data-safe-style (which safe-dom turns into !important). On the light theme that measured 2.16:1,
// and the nightly axe scan failed on both dashboard scopes. The fix paints the text with
// --text-primary and lets the accent only tint the pill.
//
// These read the shipped markup and stylesheet, so they fail on what the browser gets. Every theme
// is checked, not only dark and light: --text-primary is a role every theme holds at full contrast,
// so there is no lower floor to excuse the imported ones.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { contrast, hexToRgb, mix } from "../../scripts/theme/contrast.js";
import { readDashboardCss } from "../../scripts/theme/loadBaseline.js";
import { IMPORTED_THEMES } from "../../scripts/theme/vendor/themePalettes.js";

const html = readFileSync(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
const css = readDashboardCss();

/** The accent share of the pill's background. Must match the color-mix in #jobsBadge. */
const TINT = 0.13;

/** One theme's hex tokens, from its generated `:root[data-theme="…"]` block. */
function themeTokens(name: string): Record<string, string> {
  const at = css.indexOf(`:root[data-theme="${name}"] {`);
  expect(at, `no block for theme ${name}`).toBeGreaterThan(-1);
  const body = css.slice(at, css.indexOf("\n}", at));
  const out: Record<string, string> = {};
  for (const m of body.matchAll(/^\s*(--[-\w]+)\s*:\s*(#[0-9a-fA-F]{6})\s*;/gm)) out[m[1]] = m[2];
  return out;
}

/** Every rule body whose selector list names #jobsBadge. */
function jobsBadgeRules(): string[] {
  const bodies: string[] = [];
  for (const m of css.matchAll(/([^{}]*)\{([^{}]*)\}/g)) {
    if (/#jobsBadge\b/.test(m[1])) bodies.push(m[2]);
  }
  return bodies;
}

const THEMES = ["dark", "light", ...Object.keys(IMPORTED_THEMES)];

describe("jobs chip contrast (#1749)", () => {
  it("covers the built-in and the imported themes", () => {
    expect(THEMES.length).toBeGreaterThan(20);
  });

  it("the markup sets no colour on the chip", () => {
    const tag = html.match(/<span id="jobsBadge"[^>]*>/);
    expect(tag, "no #jobsBadge span in dashboard.html").not.toBeNull();
    expect(tag?.[0]).not.toMatch(/(^|[;"\s])(color|background)\s*:/);
  });

  it("one stylesheet rule paints the chip, with --text-primary text over an accent tint", () => {
    const rules = jobsBadgeRules();
    expect(rules).toHaveLength(1);
    const flat = rules[0].replace(/\s+/g, "");
    expect(flat).toContain("color:var(--text-primary);");
    expect(flat).toContain(`background:color-mix(inoklab,var(--accent)${TINT * 100}%,transparent);`);
  });

  // The chip sits in <header>, which paints --bg-elevated. Imported themes do not define it and
  // reach the token fallback, --bg-secondary. The translucent tint composites over that surface.
  it.each(THEMES)("%s: chip text meets 4.5:1 on the tinted pill", (theme) => {
    const t = themeTokens(theme);
    const surface = t["--bg-elevated"] ?? t["--bg-secondary"];
    expect(surface, `${theme}: no header surface token`).toBeDefined();
    expect(t["--accent"], `${theme}: no --accent`).toBeDefined();
    expect(t["--text-primary"], `${theme}: no --text-primary`).toBeDefined();
    const pill = mix(hexToRgb(surface), hexToRgb(t["--accent"]), TINT);
    expect(contrast(hexToRgb(t["--text-primary"]), pill)).toBeGreaterThanOrEqual(4.5);
  });
});
