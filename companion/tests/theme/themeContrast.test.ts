// Contrast and ordering guards for the imported themes.
//
// The dashboard has a five-step text ramp; upstream defines three. The two extra steps
// are solved for per theme at generation time (see textRampSteps in themeCss.ts) because
// the obvious CSS derivation — mix `--text-muted` toward the background — collapses on
// themes whose muted is already near the floor. Before that fix `--text-faint` measured
// below 3:1 in 23 of the 25 themes.
//
// These assertions read the GENERATED blocks rather than recomputing from the vendored
// palettes, so they fail if the generator regresses, if a theme is hand-edited, or if
// `npm run theme:apply` was not re-run after a change.
//
// TWO FILES SINCE #415. `npm run theme:apply` writes two generated regions: the CSS tokens, now
// in public/css/dashboard.css, and the theme registry the picker reads, still in dashboard.html
// because that half is JavaScript. Keeping them in step is the invariant the registry describe
// below actually tests, and it can only be tested by reading both.

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { contrastHex as contrast, hexToRgb, relLuminance } from "../../scripts/theme/contrast.js";
import { DASHBOARD_CSS_PATH, DASHBOARD_PATH } from "../../scripts/theme/loadBaseline.js";
import {
  CANONICAL_HUE,
  deltaE,
  oklabToOklch,
  rgbToOklab,
  SEVERITY_CONTRAST_FLOOR,
  SEVERITY_HUE_BAND,
  SEVERITY_ORDER,
  SEVERITY_SEPARATION_FLOOR,
} from "../../scripts/theme/severity.js";
import { IMPORTED_THEMES } from "../../scripts/theme/vendor/themePalettes.js";

/** The stylesheet: every generated `:root[data-theme="…"]` block and the token region. */
const dashboard = readFileSync(DASHBOARD_CSS_PATH, "utf8");

/** The page: the generated DFIR_THEMES registry the theme picker reads. */
const dashboardHtml = readFileSync(DASHBOARD_PATH, "utf8");

/** Pull one generated `:root[data-theme="x"]` block's declarations out of the file. */
function themeBlock(name: string): Record<string, string> {
  const at = dashboard.indexOf(`:root[data-theme="${name}"] {`);
  expect(at, `no generated block for theme "${name}" — run \`npm run theme:apply\``).toBeGreaterThan(-1);
  const body = dashboard.slice(at, dashboard.indexOf("\n}", at));
  const out: Record<string, string> = {};
  // Anchored at line starts so this picks up plain properties (color-scheme) as well as
  // custom ones, without matching anything that merely looks like a declaration inside a value.
  for (const m of body.matchAll(/^\s*([-\w]+)\s*:\s*([^;]+);/gm)) out[m[1]] = m[2].trim();
  return out;
}

const RAMP = ["--text-bright", "--text-primary", "--text-muted", "--text-dim", "--text-faint"];
const names = Object.keys(IMPORTED_THEMES);

describe("imported theme contrast", () => {
  it("imports the themes it claims to", () => {
    expect(names.length).toBeGreaterThan(20);
  });

  it.each(names)("%s: text ramp decreases in prominence", (name) => {
    const b = themeBlock(name);
    const bg = b["--bg-primary"];
    const ratios = RAMP.map((role) => ({ role, ratio: contrast(b[role], bg) }));
    // Each step must be no more prominent than the one above it. A step that is brighter
    // than its parent inverts the hierarchy: "faint" captions would out-shout body text.
    for (let i = 1; i < ratios.length; i++) {
      expect(
        ratios[i].ratio,
        `${name}: ${ratios[i].role} (${ratios[i].ratio.toFixed(2)}:1) is more prominent than ${ratios[i - 1].role} (${ratios[i - 1].ratio.toFixed(2)}:1)`,
      ).toBeLessThanOrEqual(ratios[i - 1].ratio + 0.01);
    }
  });

  it.each(names)("%s: faintest text stays legible", (name) => {
    const b = themeBlock(name);
    const bg = b["--bg-primary"];
    const faint = contrast(b["--text-faint"], bg);
    const muted = contrast(b["--text-muted"], bg);
    // 3:1 is the floor for incidental and large text. Where the theme's OWN muted step is
    // already below that — upstream ships a few — the ramp is capped at muted rather than
    // invented brighter than the theme author chose, so the bar is the lower of the two.
    const floor = Math.min(3.0, muted);
    expect(
      faint,
      `${name}: --text-faint is ${faint.toFixed(2)}:1 against --bg-primary (floor ${floor.toFixed(2)}:1)`,
    ).toBeGreaterThanOrEqual(floor - 0.01);
  });

  it.each(names)("%s: body text clears 4.5:1", (name) => {
    const b = themeBlock(name);
    const ratio = contrast(b["--text-primary"], b["--bg-primary"]);
    expect(ratio, `${name}: --text-primary is ${ratio.toFixed(2)}:1`).toBeGreaterThanOrEqual(4.5);
  });

  it.each(names)("%s: declares color-scheme matching its own background", (name) => {
    const b = themeBlock(name);
    // The browser paints scrollbars, form controls and the caret from color-scheme. Getting
    // it backwards puts a dark scrollbar on a white page.
    const isLight = relLuminance(hexToRgb(b["--bg-primary"])) > 0.5;
    expect(b["color-scheme"], `${name} background is ${b["--bg-primary"]}`).toBe(
      isLight ? "light" : "dark",
    );
  });
});

describe("severity scale", () => {
  const ALL = [...names, "dark", "light"];

  it.each(ALL)("%s: every severity is a valid colour", (name) => {
    const b = themeBlock(name);
    for (const s of SEVERITY_ORDER) {
      // An unresolved `var()` reaching the solver produced `#NaNNaNNaN`, which browsers
      // drop silently — the chip then inherits body text colour and every severity looks
      // the same. Cheap assertion, expensive failure.
      expect(b[`--sev-${s}`], `${name} --sev-${s}`).toMatch(/^#[0-9a-f]{6}$/i);
    }
  });

  it.each(ALL)("%s: every severity clears the contrast floor", (name) => {
    const b = themeBlock(name);
    for (const s of SEVERITY_ORDER) {
      // Chips render on both the page and the panel; the worse of the two is the one
      // that matters.
      const worst = Math.min(
        contrast(b[`--sev-${s}`], b["--bg-primary"]),
        contrast(b[`--sev-${s}`], b["--bg-secondary"]),
      );
      expect(worst, `${name} --sev-${s} is ${worst.toFixed(2)}:1`).toBeGreaterThanOrEqual(
        SEVERITY_CONTRAST_FLOOR - 0.01,
      );
    }
  });

  it.each(ALL)("%s: no two severities look alike", (name) => {
    const b = themeBlock(name);
    // ALL pairs, not just adjacent. Checking only neighbours missed the worst case in the
    // imported set: --sev-medium falls back to --help-icon-color and --sev-info to
    // --accent, which 18 of 22 themes set to the same value, so Medium and Info shipped
    // as literally the same colour while every adjacent pair passed.
    const tooClose: string[] = [];
    for (let i = 0; i < SEVERITY_ORDER.length; i++) {
      for (let j = i + 1; j < SEVERITY_ORDER.length; j++) {
        const a = SEVERITY_ORDER[i];
        const c = SEVERITY_ORDER[j];
        const d = deltaE(hexToRgb(b[`--sev-${a}`]), hexToRgb(b[`--sev-${c}`]));
        if (d < SEVERITY_SEPARATION_FLOOR - 0.001) tooClose.push(`${a}/${c} ΔE ${d.toFixed(3)}`);
      }
    }
    expect(tooClose, `${name}: severities too close to tell apart`).toEqual([]);
  });

  it.each(ALL)("%s: every severity keeps the conventional hue for its rank", (name) => {
    const b = themeBlock(name);
    const off: string[] = [];
    for (const s of SEVERITY_ORDER) {
      const c = oklabToOklch(rgbToOklab(hexToRgb(b[`--sev-${s}`])));
      // Hue is meaningless below about this chroma — Vantablack and White are monochrome
      // by design, and their greys are told apart by lightness instead. Measuring the hue
      // of a grey reads pure numerical noise.
      if (c.C < 0.02) continue;
      const gap = Math.abs(c.h - CANONICAL_HUE[s]) % 360;
      const deviation = gap > 180 ? 360 - gap : gap;
      if (deviation > SEVERITY_HUE_BAND + 1) {
        off.push(`${s} is ${deviation.toFixed(0)}° from ${CANONICAL_HUE[s]}°`);
      }
    }
    // A scale reading red, orange, TEAL, green, blue passes contrast and separation and is
    // still unreadable as an ordinal scale, which is what --sev-medium did in 11 themes.
    expect(off, `${name}: severity hues off convention`).toEqual([]);
  });

  it("leaves the built-in dark theme's colours exactly as shipped", () => {
    // The solver repairs rather than replaces. A scale that already satisfies both floors
    // must pass through untouched, or every release would quietly restyle the default.
    const b = themeBlock("dark");
    expect({
      critical: b["--sev-critical"],
      high: b["--sev-high"],
      medium: b["--sev-medium"],
      low: b["--sev-low"],
      info: b["--sev-info"],
    }).toEqual({
      critical: "#ff5c5c",
      high: "#ff9f43",
      medium: "#ffd93b",
      low: "#6bcb77",
      info: "#6aa9ff",
    });
  });
});

describe("theme registry", () => {
  // The registry is JavaScript and stayed in the page when the CSS moved out (#415), so this is
  // the one describe here that reads dashboardHtml. That the two now live in different files is
  // exactly why the first assertion matters more than it did: nothing about editing one of them
  // puts the other in front of you.
  const registry = dashboardHtml.slice(
    dashboardHtml.indexOf("const DFIR_THEMES = {"),
    dashboardHtml.indexOf("/* <<< dfir-theme registry */"),
  );

  it("lists every theme that has a CSS block, and no others", () => {
    const inRegistry = [...registry.matchAll(/^\s*"?([\w-]+)"?:\s*\{/gm)].map((m) => m[1]);
    const inCss = [...dashboard.matchAll(/:root\[data-theme="([\w-]+)"\] \{/g)].map((m) => m[1]);
    // A registry entry with no block renders as the previous theme under a new name; a
    // block with no entry is unreachable from the picker. Both fail silently in a browser.
    expect([...new Set(inRegistry)].sort()).toEqual([...new Set(inCss)].sort());
  });

  it("includes the two built-in themes", () => {
    expect(registry).toContain("dark:");
    expect(registry).toContain("light:");
  });
});

describe("generated region", () => {
  // The region delimiter was once inferred from the CSS structure — the run of
  // consecutive `:root {}` rules after the opening comment. When the region grew rules
  // that were not `:root`, the walk stopped early and every run replaced a prefix while
  // re-prepending a whole copy. The region tripled in size, shipping three conflicting
  // definitions of every theme, and nothing failed: the last one simply won the cascade.
  it("is delimited exactly once", () => {
    const begins = dashboard.split("/* === dfir-theme tokens (issue #53) ===").length - 1;
    const ends = dashboard.split("/* === end dfir-theme tokens === */").length - 1;
    expect({ begins, ends }).toEqual({ begins: 1, ends: 1 });
  });

  it("declares each theme exactly once", () => {
    const counts = new Map<string, number>();
    for (const m of dashboard.matchAll(/:root\[data-theme="([\w-]+)"\] \{/g)) {
      counts.set(m[1], (counts.get(m[1]) ?? 0) + 1);
    }
    const duplicated = [...counts].filter(([, n]) => n > 1);
    expect(duplicated, "theme blocks duplicated — the region is accumulating").toEqual([]);
  });

  it("declares each theme swatch exactly once", () => {
    const counts = new Map<string, number>();
    for (const m of dashboard.matchAll(/\.theme-swatch\[data-for="([\w-]+)"\]/g)) {
      counts.set(m[1], (counts.get(m[1]) ?? 0) + 1);
    }
    const duplicated = [...counts].filter(([, n]) => n > 1);
    expect(duplicated).toEqual([]);
  });

  it("carries no theme rejected at import", () => {
    // c64 is dropped by the importer: body text at 2.26:1 and an inverted ramp. If it
    // reappears, someone bypassed the legibility gate in importThemePalettes.ts.
    expect(dashboard).not.toContain('data-theme="c64"');
  });
});
