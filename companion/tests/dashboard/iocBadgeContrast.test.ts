// Contrast guard for the two grey IOC badges (#1789).
//
// The "low" composite-risk badge and the "telemetry-only" provenance badge painted --text-faint on
// --border-subtle. In the dark theme that is #818a96 on #232a33, 4.14:1, below the 4.5:1 that
// 10px bold text needs. The light theme passed by 0.04. The fix paints both with --text-muted.
//
// The nightly axe scan cannot catch this: its seeded demo case renders no "low" badge. So this test
// reads the shipped stylesheet and the renderer that emits the classes, and fails on what the
// browser gets. Dark and light only: the imported themes are held to a lower floor for their grey
// text roles by project policy (tests/theme/themeContrast.test.ts).
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { contrast, hexToRgb } from "../../scripts/theme/contrast.js";
import { readDashboardCss } from "../../scripts/theme/loadBaseline.js";

const css = readDashboardCss();
const renderer = readFileSync(
  new URL("../../../public/js/dashboard-ioc-provenance.js", import.meta.url),
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

/** The one rule body for `selector`, and the token each of its colour properties reads. */
function ruleTokens(selector: string): { color: string; background: string } {
  const bodies = [...css.matchAll(/([^{}]*)\{([^{}]*)\}/g)]
    .filter((m) => m[1].split(",").some((s) => s.trim() === selector))
    .map((m) => m[2]);
  expect(bodies, `rules for ${selector}`).toHaveLength(1);
  const color = bodies[0].match(/(?:^|;)\s*color:\s*var\((--[-\w]+)\)/)?.[1];
  const background = bodies[0].match(/background:\s*var\((--[-\w]+)\)/)?.[1];
  expect(color, `${selector}: no color token`).toBeDefined();
  expect(background, `${selector}: no background token`).toBeDefined();
  return { color: color!, background: background! };
}

const BADGES = [".ioc-risk-low", ".ioc-prov-telemetry"];

describe("grey IOC badge contrast (#1789)", () => {
  it("the renderer emits the classes these rules style", () => {
    expect(renderer).toContain('class="ioc-prov-badge ioc-prov-telemetry"');
    expect(renderer).toContain('class="ioc-risk-badge ioc-risk-${esc(r.score)}"');
  });

  it.each(BADGES)("%s paints --text-muted, not --text-faint", (selector) => {
    expect(ruleTokens(selector).color).toBe("--text-muted");
  });

  for (const theme of ["dark", "light"]) {
    it.each(BADGES)(`${theme}: %s text meets 4.5:1 on its own background`, (selector) => {
      const t = themeTokens(theme);
      const { color, background } = ruleTokens(selector);
      expect(t[color], `${theme}: no ${color}`).toBeDefined();
      expect(t[background], `${theme}: no ${background}`).toBeDefined();
      expect(contrast(hexToRgb(t[color]), hexToRgb(t[background]))).toBeGreaterThanOrEqual(4.5);
    });
  }
});
