// Contrast guard for the host-ranking badge strip (#2458).
//
// The Crit / High / Med badges and the "tech" / "IOC" counts painted literal dark-palette hex
// (`#e3b341` amber on a 13% amber tint, and so on). In the light theme the High badge measured
// 1.41:1 and the other four 1.68-1.97:1. The fix paints every one of them with theme tokens whose
// pairs already clear 4.5:1, so the light theme and the imported themes get a themed pair too.
//
// This test reads the shipped stylesheet and the renderer that emits the classes, and fails on
// what the browser gets. Dark and light only, as in iocBadgeContrast.test.ts.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { contrast, hexToRgb } from "../../scripts/theme/contrast.js";
import { readDashboardCss } from "../../scripts/theme/loadBaseline.js";

const css = readDashboardCss();
const renderer = readFileSync(
  new URL("../../../public/js/dashboard-host-ranking.js", import.meta.url),
  "utf8",
);

/** The hex tokens in the block that starts at `header`. */
function blockTokens(header: string): Record<string, string> {
  const at = css.indexOf(header);
  expect(at, `no block ${header}`).toBeGreaterThan(-1);
  const body = css.slice(at, css.indexOf("\n}", at));
  const out: Record<string, string> = {};
  for (const m of body.matchAll(/^\s*(--[-\w]+)\s*:\s*(#[0-9a-fA-F]{6})\s*;/gm)) out[m[1]] = m[2];
  return out;
}

/** A theme's tokens: the base `:root` block, overridden by the theme's own block. */
function themeTokens(name: string): Record<string, string> {
  return { ...blockTokens("\n:root {"), ...blockTokens(`:root[data-theme="${name}"] {`) };
}

/** The bodies of every rule whose selector list contains `selector` exactly. */
function ruleBodies(selector: string): string[] {
  return [...css.matchAll(/([^{}]*)\{([^{}]*)\}/g)]
    .filter((m) => m[1].split(",").some((s) => s.trim() === selector))
    .map((m) => m[2]);
}

/** The token a colour property of the one rule for `selector` reads, or undefined. */
function propToken(selector: string, prop: "color" | "background"): string | undefined {
  const bodies = ruleBodies(selector);
  expect(bodies, `rules for ${selector}`).toHaveLength(1);
  const re =
    prop === "color" ? /(?:^|;)\s*color:\s*var\((--[-\w]+)\)/ : /(?:^|;)\s*background:\s*var\((--[-\w]+)\)/;
  return bodies[0].match(re)?.[1];
}

/** The row background the tech / IOC counts sit on, read from the `.hr-row` rule. */
function rowBackground(): string {
  const tokens = ruleBodies("#sec-hostranking .hr-row")
    .map((b) => b.match(/(?:^|;)\s*background:\s*var\((--[-\w]+)\)/)?.[1])
    .filter((t): t is string => Boolean(t));
  expect(tokens, "row background token").toHaveLength(1);
  return tokens[0];
}

const BADGES = ["hr-crit", "hr-high", "hr-med"];
const COUNTS = ["hr-tech", "hr-conn"];
const ALL = [...BADGES, ...COUNTS];

/** The text token and the background token the class is painted on. */
function pair(cls: string): { color: string; background: string } {
  const selector = `#sec-hostranking .${cls}`;
  const color = propToken(selector, "color");
  const background = BADGES.includes(cls) ? propToken(selector, "background") : rowBackground();
  expect(color, `${selector}: no color token`).toBeDefined();
  expect(background, `${selector}: no background token`).toBeDefined();
  return { color: color!, background: background! };
}

describe("host-ranking badge contrast (#2458)", () => {
  it("the renderer emits the classes these rules style", () => {
    for (const cls of BADGES) expect(renderer).toContain(`class="hr-badge ${cls}"`);
    for (const cls of COUNTS) expect(renderer).toContain(`class="${cls}"`);
  });

  it.each(ALL)("%s paints theme tokens, not literal hex", (cls) => {
    const body = ruleBodies(`#sec-hostranking .${cls}`)[0];
    expect(body).not.toMatch(/#[0-9a-fA-F]{3,8}\b/);
  });

  for (const theme of ["dark", "light"]) {
    it.each(ALL)(`${theme}: %s text meets 4.5:1 on its background`, (cls) => {
      const t = themeTokens(theme);
      const { color, background } = pair(cls);
      expect(t[color], `${theme}: no ${color}`).toBeDefined();
      expect(t[background], `${theme}: no ${background}`).toBeDefined();
      expect(contrast(hexToRgb(t[color]), hexToRgb(t[background]))).toBeGreaterThanOrEqual(4.5);
    });
  }
});
