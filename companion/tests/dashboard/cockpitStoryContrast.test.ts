// Contrast guards for the "Story so far" cards (#1616).
//
// The nightly axe scan found 14 color-contrast nodes on these cards, and nothing faster caught them:
// the axe ratchet runs only in the nightly browser job. Two CSS choices caused all of them.
//
// 1. The severity chip filled its own background with 15% of its text colour. The --sev-* tokens are
//    tuned to sit just above 4.5:1 on the plain card (--bg-secondary), so any tint behind them drops
//    them below the line (~3.6:1 measured).
// 2. The missing-stage card faded itself with `opacity:.75`, which took its muted text to ~3:1.
//
// These read the shipped stylesheet, so they fail on the CSS the browser gets.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { contrastHex } from "../../scripts/theme/contrast.js";
import { readDashboardCss } from "../../scripts/theme/loadBaseline.js";

const css = readFileSync(new URL("../../../public/css/dashboard-sections.css", import.meta.url), "utf8");
/** Declarations of the first rule whose selector is exactly `selector`. */
function ruleBody(selector: string): string {
  const at = css.indexOf(`${selector}{`);
  expect(at, `no rule for ${selector}`).toBeGreaterThan(-1);
  const open = at + selector.length + 1;
  return css.slice(open, css.indexOf("}", open));
}

// Every stylesheet part concatenated, so the built-in theme blocks are read as the browser gets them.
const dashboard = readDashboardCss();

/** One built-in theme's hex tokens. The nightly axe scan runs the light theme; dark is the default. */
function themeTokens(name: string): Record<string, string> {
  const at = dashboard.indexOf(`:root[data-theme="${name}"] {`);
  expect(at, `no block for theme ${name}`).toBeGreaterThan(-1);
  const body = dashboard.slice(at, dashboard.indexOf("\n}", at));
  const out: Record<string, string> = {};
  for (const m of body.matchAll(/^\s*(--[-\w]+)\s*:\s*(#[0-9a-fA-F]{6})\s*;/gm)) out[m[1]] = m[2];
  return out;
}

// Imported themes are out of scope on purpose: their own --sev-* and --text-faint tokens are held
// to lower floors (SEVERITY_CONTRAST_FLOOR = 3.0) on every surface of the dashboard, not only here.
const BUILT_IN = ["dark", "light"];

describe("Story so far: contrast (#1616)", () => {
  it("the severity chip is outlined, never filled", () => {
    const body = ruleBody(".now-sev");
    expect(body).not.toMatch(/color-mix\([^)]*currentColor/);
    expect(body).toMatch(/background:transparent/);
  });

  const sevCases = BUILT_IN.flatMap((theme) =>
    ["--sev-critical", "--sev-high", "--sev-medium", "--sev-low", "--sev-info"].map((token) => [
      theme,
      token,
    ]),
  );
  it.each(sevCases)("%s: %s chip text meets 4.5:1 on the plain card it sits on", (theme, token) => {
    const t = themeTokens(theme);
    expect(contrastHex(t[token], t["--bg-secondary"])).toBeGreaterThanOrEqual(4.5);
  });

  // The chip takes its colour from the page-wide `.sev-<Severity>` rule, not from `.now-sev`. The
  // contrast cases above only hold while that mapping holds and nothing on the chip overrides it.
  it.each(["Critical", "High", "Medium", "Low", "Info"])(
    "the .sev-%s class still paints --sev-* text",
    (sev) => {
      const flat = dashboard.replace(/\s+/g, "");
      expect(flat).toContain(`.sev-${sev}{color:var(--sev-${sev.toLowerCase()});}`);
      expect(dashboard).not.toMatch(/\.now-sev[^{]*\{([^}]*[;\s])?color\s*:/);
    },
  );

  it("the missing-stage card is not faded with opacity", () => {
    const body = ruleBody(".now-story-cards .now-stage-missing");
    expect(body).not.toMatch(/opacity/);
    expect(body).toMatch(/background:var\(--bg-primary\)/);
  });

  // The three text roles the missing card renders: stage name and "no evidence yet" on the card,
  // the "Evidence gaps" button on its own neutral badge.
  it.each(BUILT_IN)("%s: missing-stage card text meets 4.5:1", (theme) => {
    const t = themeTokens(theme);
    expect(contrastHex(t["--text-muted"], t["--bg-primary"])).toBeGreaterThanOrEqual(4.5);
    expect(contrastHex(t["--text-faint"], t["--bg-primary"])).toBeGreaterThanOrEqual(4.5);
    expect(contrastHex(t["--text-muted"], t["--badge-bg-neutral"])).toBeGreaterThanOrEqual(4.5);
  });
});
