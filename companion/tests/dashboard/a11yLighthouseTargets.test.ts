// Dashboard-wide accessibility fixes from the QA Lighthouse run (#2492).
//
// Lighthouse scored the Analyst view 85 in the light theme. These tests pin each root cause to the
// shipped files, so a regression fails here instead of waiting for the next manual audit:
//  - text colours written as dark-theme hex from script (tag pills, IOC verdicts, uncertainty and
//    next-step labels) are theme tokens, readable on the light panel surfaces;
//  - opacity fades that pushed text under 4.5:1 are gone;
//  - the setup wizard's provider selects have labels and its active step text is not white-on-light;
//  - heading levels, the Sigma coverage table header, the exposure links and the timeline control
//    spacing (24px target size, WCAG 2.2 SC 2.5.8, met by spacing so rows keep their height).
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { contrastHex } from "../../scripts/theme/contrast.js";
import { readDashboardCss } from "../../scripts/theme/loadBaseline.js";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

const css = readDashboardCss();
const read = (rel: string) => readFileSync(new URL(`../../../public/${rel}`, import.meta.url), "utf8");
const html = read("dashboard.html");

/** The `--name: value;` pairs of the block that starts at `header`. */
function block(header: string): Record<string, string> {
  const at = css.indexOf(header);
  expect(at, `no block ${header}`).toBeGreaterThan(-1);
  const body = css.slice(at, css.indexOf("\n}", at));
  const out: Record<string, string> = {};
  for (const m of body.matchAll(/^\s*(--[-\w]+)\s*:\s*([^;]+);/gm)) out[m[1]] = m[2].trim();
  return out;
}

/** Resolve a `var(--x)` chain to a hex in one built-in theme. */
function resolve(value: string, theme: "light" | "dark"): string {
  const vars = { ...block("\n:root {"), ...block(`:root[data-theme="${theme}"] {`) };
  let v = value;
  for (let i = 0; i < 8; i++) {
    const m = v.match(/^var\((--[-\w]+)\)$/);
    if (!m) break;
    v = vars[m[1]];
    expect(v, `${m[1]} undefined in ${theme}`).toBeDefined();
  }
  expect(v).toMatch(/^#[0-9a-fA-F]{6}$/);
  return v.toLowerCase();
}

// The light surfaces these labels sit on: panel, row and tertiary backgrounds.
const LIGHT_SURFACES = ["#f5f7fa", "#e4e9f2", "#e3e7f2", "#fcfcfd"];

interface ColourApi {
  tagColor(label: string): string;
}
interface IocApi {
  verdictColor(v?: string): string;
}

const glyphs = loadDashboardModule<ColourApi>("dashboard-glyphs.js");
const ioc = loadDashboardModule<IocApi>("dashboard-ioc.js");

const COLOURED: Array<[string, string, string]> = [
  ["tag confirmed-malicious", glyphs.tagColor("confirmed-malicious"), "#ff6b6b"],
  ["tag false-positive", glyphs.tagColor("false-positive"), "#6bcb77"],
  ["tag needs-review", glyphs.tagColor("needs-review"), "#ffd93b"],
  ["tag key-evidence", glyphs.tagColor("key-evidence"), "#6aa9ff"],
  ["tag other", glyphs.tagColor("anything"), "#9aa4b2"],
  ["verdict malicious", ioc.verdictColor("malicious"), "#ff6b6b"],
  ["verdict suspicious", ioc.verdictColor("suspicious"), "#ffd93b"],
  ["verdict harmless", ioc.verdictColor("harmless"), "#6bcb77"],
  ["verdict unknown", ioc.verdictColor(undefined), "#9aa4b2"],
];

describe("script-written text colours follow the theme (#2492)", () => {
  it.each(COLOURED)("%s is a theme token", (_name, colour) => {
    expect(colour).toMatch(/^var\(--[-\w]+\)$/);
  });

  it.each(COLOURED)("%s keeps its dark-theme colour", (_name, colour, darkHex) => {
    expect(resolve(colour, "dark")).toBe(darkHex);
  });

  it.each(COLOURED)("%s reads at 4.5:1 on every light surface", (_name, colour) => {
    const ink = resolve(colour, "light");
    for (const bg of LIGHT_SURFACES)
      expect(contrastHex(ink, bg), `${ink} on ${bg}`).toBeGreaterThanOrEqual(4.5);
  });

  it("uncertainty and next-step labels use tokens, not dark-theme hex", () => {
    const render = read("js/dashboard-render.js");
    const prioAt = render.indexOf("const PRIO = {");
    const prio = render.slice(prioAt, render.indexOf("};", prioAt));
    const unc = render.slice(render.indexOf("const UNC_META = {"), render.indexOf("const UNC_ORDER"));
    expect(prio).not.toMatch(/#[0-9a-fA-F]{6}/);
    expect(unc).not.toMatch(/color: "#[0-9a-fA-F]{6}"/);
  });
});

/** Every rule body whose selector list contains exactly `selector`. */
function rules(selector: string): string[] {
  const bare = css.replace(/\/\*[\s\S]*?\*\//g, ""); // a comma inside a comment is not a selector list
  return [...bare.matchAll(/([^{}]*)\{([^{}]*)\}/g)]
    .filter((m) => m[1].split(",").some((s) => s.trim() === selector))
    .map((m) => m[2]);
}

describe("faded text no longer drops below contrast (#2492)", () => {
  it.each(["#sec-adversary .adv-tech-base", ".kc-phase.kc-empty", "#sec-playbook-match .pm-step.pm-missing"])(
    "%s has no opacity",
    (selector) => {
      const bodies = rules(selector);
      expect(bodies.length, `rules for ${selector}`).toBeGreaterThan(0);
      for (const b of bodies) expect(b).not.toMatch(/opacity\s*:/);
    },
  );
});

describe("setup wizard (#2492)", () => {
  it.each(["wizProvider", "wizSynthProvider"])("the %s select has a label", (id) => {
    expect(html).toMatch(new RegExp(`<label[^>]*for="${id}"`));
  });

  it("the active step is not painted white on the light rail", () => {
    const bodies = rules(".wiz-rail-item.active");
    expect(bodies.length).toBeGreaterThan(0);
    for (const b of bodies) expect(b).not.toMatch(/color:\s*#fff\b/);
  });
});

describe("headings, tables and links (#2492)", () => {
  it("executive-summary blocks use h3 under the section h2", () => {
    const frag = read("js/dashboard-fragments.js");
    expect(frag).toContain('<div class="exec-block"><h3>');
    expect(frag).not.toContain('<div class="exec-block"><h4>');
  });

  it("host scope sub-headings use h3", () => {
    const hs = read("js/dashboard-host-scope.js");
    expect(hs).not.toMatch(/<h4>/);
    expect(hs).toContain("<h3>Scope gaps</h3>");
  });

  it("every Sigma coverage column has header text", () => {
    const sig = read("js/dashboard-sigma-coverage.js");
    const heads = sig.match(/for \(const h of \[([^\]]*)\]\)/)?.[1] ?? "";
    expect(heads.length).toBeGreaterThan(0);
    expect(heads).not.toMatch(/""/);
  });

  it("customer exposure links are underlined, not colour-only", () => {
    const fp = read("js/dashboard-exposure-fp.js");
    expect(fp).not.toMatch(/<a [^>]*text-decoration:none/);
  });
});

describe("timeline row controls meet the 24px target by spacing (#2492)", () => {
  it("controls sit in 24px slots with no gap, so seven fit the 178px column", () => {
    const ctrl = rules(".ev-col-ctrl").join(";");
    expect(ctrl).toMatch(/width:\s*178px/);
    expect(ctrl).toMatch(/gap:\s*0\b/);
    const slot = rules(".ev-col-ctrl > *").join(";");
    expect(slot).toMatch(/min-width:\s*24px/);
    expect(slot).not.toMatch(/min-height/); // rows keep their height
  });
});

describe("IOC actions and sort arrows meet the 24px target by spacing (#2492)", () => {
  it("IOC action controls sit in 24px slots with no gap", () => {
    expect(rules(".ioc-actions-cell").join(";")).toMatch(/gap:\s*0\b/);
    expect(rules(".ioc-actions-cell > *").join(";")).toMatch(/min-width:\s*24px/);
  });

  it("sort arrows sit side by side in 24px slots", () => {
    expect(rules(".tl-sortarrows").join(";")).toMatch(/flex-direction:\s*row/);
    expect(rules(".tl-sortarrows .tl-arrow").join(";")).toMatch(/min-width:\s*24px/);
  });
});

describe("Codex review follow-ups (#2492)", () => {
  it("an empty kill-chain count uses a theme colour (a safe-style colour beats any stylesheet)", () => {
    const kc = read("js/dashboard-kill-chain.js");
    expect(kc).not.toContain("#2a2f3a");
    expect(kc).toContain('isEmpty ? "var(--text-muted)"');
  });

  it("timeline controls cannot overflow the column: margins zeroed, count chip trimmed, wrap allowed", () => {
    expect(rules(".ev-col-ctrl").join(";")).toMatch(/flex-wrap:\s*wrap/);
    expect(rules(".ev-col-ctrl > *").join(";")).toMatch(/margin-left:\s*0/);
    expect(rules(".ev-col-ctrl .comment-chip").join(";")).toMatch(/padding-left:\s*3px/);
  });
});

// The dense ATT&CK / D3FEND chip grids (#2492, option 3): the user chose to keep them compact for
// mouse users and give them 24px targets only when the primary pointer is coarse (touch screens).
describe("dense grid chips reach 24px on touch screens only (#2492)", () => {
  const SELECTORS = [
    "#sec-adversary .adv-tech",
    "#sec-d3fend .d3f-cover",
    "#sec-d3fend .mit-tech",
    "#sec-d3fend .d3f-cm",
    "#sec-d3fend .mit-name",
  ];

  const src = css.replace(/\/\*[\s\S]*?\*\//g, "");

  /** [start, end) of every `@media (pointer: coarse) { … }` block, braces included. */
  function coarseBlocks(): Array<[number, number]> {
    const out: Array<[number, number]> = [];
    for (const m of src.matchAll(/@media\s*\(\s*pointer\s*:\s*coarse\s*\)\s*\{/g)) {
      let depth = 1;
      let i = (m.index ?? 0) + m[0].length;
      while (i < src.length && depth > 0) {
        if (src[i] === "{") depth++;
        else if (src[i] === "}") depth--;
        i++;
      }
      out.push([m.index ?? 0, i]);
    }
    return out;
  }

  const bodiesFor = (text: string, selector: string) =>
    [...text.matchAll(/([^{}]*)\{([^{}]*)\}/g)]
      .filter((r) => r[1].split(",").some((s) => s.trim() === selector))
      .map((r) => r[2]);

  /** Rule bodies for `selector` inside a coarse-pointer block. */
  const coarseRules = (selector: string) =>
    coarseBlocks().flatMap(([a, b]) => bodiesFor(src.slice(src.indexOf("{", a) + 1, b - 1), selector));

  /** Rule bodies for `selector` outside every coarse-pointer block (what a mouse user gets). */
  function mouseRules(selector: string): string[] {
    let text = src;
    for (const [a, b] of coarseBlocks().reverse()) text = text.slice(0, a) + text.slice(b);
    return bodiesFor(text, selector);
  }

  it.each(SELECTORS)("%s is at least 24px tall under a coarse pointer", (selector) => {
    const body = coarseRules(selector).join(";");
    expect(body, `no pointer:coarse rule for ${selector}`).toMatch(/min-height:\s*24px/);
  });

  it.each(["#sec-adversary .adv-tech", "#sec-d3fend .d3f-cover", "#sec-d3fend .mit-tech"])(
    "%s is at least 24px wide under a coarse pointer",
    (selector) => {
      expect(coarseRules(selector).join(";")).toMatch(/min-width:\s*24px/);
    },
  );

  it.each(SELECTORS)("%s keeps its compact size for mouse users", (selector) => {
    const bodies = mouseRules(selector);
    expect(bodies.length, `rules for ${selector}`).toBeGreaterThan(0);
    for (const b of bodies) expect(b).not.toMatch(/min-(height|width)\s*:/);
  });
});

// Found while verifying the touch change in the dark theme: white text on --success (#2f8f4e) is
// 4.06:1. The two solid green buttons darken their own background instead of changing the shared
// token, which is also used as a text colour on dark panels.
describe("solid green buttons keep white text readable (#2492)", () => {
  const MIX = "color-mix(in srgb,var(--success) 80%,#000)";
  const darken = (hex: string) =>
    "#" +
    [1, 3, 5]
      .map((i) =>
        Math.round(parseInt(hex.slice(i, i + 2), 16) * 0.8)
          .toString(16)
          .padStart(2, "0"),
      )
      .join("");

  it.each(["#sec-hostranking .hr-apply", "#sec-adversary .adv-next-hunt"])(
    "%s darkens --success",
    (selector) => {
      expect(rules(selector).join(";").replace(/\s+/g, "")).toContain(
        `background:${MIX.replace(/\s+/g, "")}`,
      );
    },
  );

  it.each(["light", "dark"] as const)("white on the darkened green is at least 4.5:1 in %s", (theme) => {
    expect(contrastHex("#ffffff", darken(resolve("var(--success)", theme)))).toBeGreaterThanOrEqual(4.5);
  });
});
