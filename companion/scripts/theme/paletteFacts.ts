// Reads the ground truth out of the dashboard's client source: which `--c-<hex>` variables
// exist, what each is worth in dark and light, and — critically — which CSS properties
// each one actually feeds.
//
// Role assignment has to follow real usage. A hex sitting at lightness 20 could be a
// panel background or a card border, and only its call sites say which. So this module
// classifies by observed property, not by appearance.
//
// "The client source" was one file until #415 split it: the declarations and `var()` call
// sites are in public/css/dashboard.css, the `themeColor("--c-…")` lookups are still in
// dashboard.html's inline script. Both are read as one corpus (loadBaseline's
// THEME_SOURCES), because a usage count that saw half of them would quietly re-weight
// every role while the audit still printed a clean table.

import { readFileSync } from "node:fs";
import type { Baseline } from "./loadBaseline.js";

/** Read one path or several, concatenated. A newline join keeps line-anchored patterns honest. */
function readSources(paths: string | string[]): string {
  return (Array.isArray(paths) ? paths : [paths]).map((p) => readFileSync(p, "utf8")).join("\n");
}

export interface VarFact {
  name: string;
  dark: string;
  light: string | null;
  /** Total references: CSS `var()` plus `themeColor()` lookups from the canvas code. */
  uses: number;
  /** References from JS via themeColor(); these have no CSS property context. */
  js: number;
  /** Observed CSS properties, most frequent first. */
  props: Array<[string, number]>;
  cls: "SURFACE" | "BORDER" | "TEXT" | "CANVAS";
  hue: number;
  sat: number;
  lightness: number;
  /**
   * True when the variable is referenced but never declared. 30 such names exist:
   * `var(--c-2b3242)` and friends resolve to nothing today, so the declaration is
   * invalid at computed-value time and the property silently falls back to inherited
   * or initial. The naming convention makes the intent recoverable — the name IS the
   * hex the author wanted — so these are folded into the role layer and start working.
   * The audit reports them separately because fixing them changes rendering.
   */
  phantom: boolean;
}

function readBlock(lines: string[], startRe: RegExp): Record<string, string> {
  const start = lines.findIndex((l) => startRe.test(l));
  if (start < 0) throw new Error(`palette block not found: ${startRe}`);
  const out: Record<string, string> = {};
  for (let i = start + 1; i < lines.length; i++) {
    if (/^\s*}\s*$/.test(lines[i])) break;
    const m = lines[i].match(/^\s*(--[\w-]+)\s*:\s*([^;]+);/);
    if (m) out[m[1]] = m[2].trim();
  }
  return out;
}

function hexToRgb(h: string): [number, number, number] {
  const s = h.replace("#", "");
  return [
    parseInt(s.slice(0, 2), 16),
    parseInt(s.slice(2, 4), 16),
    parseInt(s.slice(4, 6), 16),
  ];
}

/** HSL, with hue in degrees and saturation/lightness as percentages. */
function toHsl(hex: string): { hue: number; sat: number; lightness: number } {
  const [r, g, b] = hexToRgb(hex).map((v) => v / 255);
  const mx = Math.max(r, g, b);
  const mn = Math.min(r, g, b);
  const d = mx - mn;
  let hue = 0;
  if (d !== 0) {
    if (mx === r) hue = ((g - b) / d) % 6;
    else if (mx === g) hue = (b - r) / d + 2;
    else hue = (r - g) / d + 4;
    hue = hue * 60;
    if (hue < 0) hue += 360;
  }
  const l = (mx + mn) / 2;
  const s = d === 0 ? 0 : d / (1 - Math.abs(2 * l - 1));
  return {
    hue: Math.round(hue),
    sat: Number((s * 100).toFixed(1)),
    lightness: Number((l * 100).toFixed(1)),
  };
}

export function hueName(hue: number, sat: number) {
  // Below ~12% saturation the hue reading is noise from 8-bit rounding, so a
  // #30363d reads "blue" numerically while being a plain grey to the eye.
  if (sat < 12) return "neutral" as const;
  if (hue < 15 || hue >= 345) return "red" as const;
  if (hue < 45) return "orange" as const;
  if (hue < 70) return "yellow" as const;
  if (hue < 165) return "green" as const;
  if (hue < 200) return "cyan" as const;
  if (hue < 255) return "blue" as const;
  if (hue < 290) return "violet" as const;
  return "pink" as const;
}

function classify(props: Array<[string, number]>, js: number): VarFact["cls"] {
  let text = 0;
  let bg = 0;
  let bd = 0;
  for (const [p, n] of props) {
    if (p === "color" || p === "fill" || p === "stroke") text += n;
    else if (p.startsWith("background")) bg += n;
    else if (p.startsWith("border") || p === "outline" || p === "box-shadow") bd += n;
  }
  const mx = Math.max(text, bg, bd);
  // Canvas-only variables reach the page through themeColor(), never through a
  // stylesheet declaration, so there is no property to read. They are all surfaces.
  if (mx === 0) return js > 0 ? "CANVAS" : "SURFACE";
  return text === mx ? "TEXT" : bg === mx ? "SURFACE" : "BORDER";
}

/**
 * Read the palette.
 *
 * Before the migration the two `:root` blocks hold literal hex, and that is the source
 * of truth. After it they hold `var(--role)` aliases and the original hex is gone from
 * the file entirely — so a `baseline` (scripts/theme/role-map.json, which is committed)
 * supplies the values instead. Without that, re-running the migration would read
 * `var(--bg-primary)` where a colour used to be and compute nonsense.
 *
 * Usage counts always come from the file, never the baseline, so new call sites and
 * newly-referenced names are picked up on every run.
 */
export function readPaletteFacts(sources: string | string[], baseline?: Baseline): VarFact[] {
  const src = readSources(sources);
  const lines = src.split("\n");
  const rawDark = readBlock(lines, /^\s*:root\s*\{/);
  const rawLight = readBlock(lines, /^\s*:root\[data-theme="light"\]\s*\{/);

  // Keep only declarations that still carry a real colour. After migration every
  // `--c-` entry is `var(--role)`, so both objects come back empty and the baseline
  // takes over completely.
  const isColour = (v: string) => /^#[0-9a-fA-F]{6}$/.test(v);
  const keepColours = (o: Record<string, string>) =>
    Object.fromEntries(Object.entries(o).filter(([k, v]) => !k.startsWith("--c-") || isColour(v)));
  const dark: Record<string, string> = keepColours(rawDark);
  const light: Record<string, string> = keepColours(rawLight);
  for (const [name, v] of Object.entries(baseline ?? {})) {
    if (!(name in dark) && isColour(v.dark)) {
      dark[name] = v.dark;
      if (v.light && isColour(v.light)) light[name] = v.light;
    }
  }

  const props: Record<string, Record<string, number>> = {};
  const total: Record<string, number> = {};
  const jsHits: Record<string, number> = {};

  // For each var() usage, walk back to the start of its declaration and take the
  // property name. Bounded lookbehind because a declaration is never 240 chars.
  //
  // Matches both `var(--c-xxxxxx)` and `var(--c-xxxxxx, #fallback)`. Requiring a `,`
  // or `)` after exactly six hex digits also excludes the two eight-digit RGBA names
  // (--c-6b758522, --c-6b758555), which are translucent and cannot take an opaque
  // role; readAlphaAliases() handles those separately.
  const varRe = /var\(\s*(--c-[0-9a-f]{6})\s*[,)]/g;
  let m: RegExpExecArray | null;
  while ((m = varRe.exec(src))) {
    const name = m[1];
    total[name] = (total[name] ?? 0) + 1;
    const head = src.slice(Math.max(0, m.index - 240), m.index);
    const cut = Math.max(head.lastIndexOf("{"), head.lastIndexOf(";"), head.lastIndexOf("}"));
    const pm = head.slice(cut + 1).match(/([-a-zA-Z]+)\s*:/);
    if (pm) {
      const p = pm[1].toLowerCase();
      (props[name] ??= {})[p] = ((props[name] ?? {})[p] ?? 0) + 1;
    }
  }

  const jsRe = /themeColor\(\s*"(--c-[0-9a-f]{6})"/g;
  while ((m = jsRe.exec(src))) {
    const name = m[1];
    total[name] = (total[name] ?? 0) + 1;
    jsHits[name] = (jsHits[name] ?? 0) + 1;
  }

  // Declared variables first, then the referenced-but-undeclared ones. A phantom's
  // value comes from its own name, which is the whole point of the naming convention.
  const names = [
    ...Object.keys(dark).filter((k) => k.startsWith("--c-")),
    ...Object.keys(total).filter((k) => !(k in dark)),
  ];

  return names.map((name) => {
    const prior = baseline?.[name];
    const phantom = prior ? prior.phantom : !(name in dark);
    const darkValue = name in dark ? dark[name] : `#${name.slice("--c-".length)}`;
    const sorted = Object.entries(props[name] ?? {}).sort((a, b) => b[1] - a[1]);
    const js = jsHits[name] ?? 0;
    return {
      name,
      dark: darkValue,
      // A phantom never had a light value either, so it is broken in both themes.
      light: phantom ? null : (light[name] ?? prior?.light ?? null),
      // After the migration the file shows zero call sites for everything, because they
      // all say `var(--role)` now. Usage decides which member's colour a role adopts, so
      // the pre-migration count has to survive; take whichever is larger.
      uses: Math.max(total[name] ?? 0, prior?.uses ?? 0),
      js,
      props: sorted,
      // Same reasoning: with no call sites left there is nothing to classify from.
      cls: sorted.length > 0 || !prior ? classify(sorted, js) : prior.cls,
      phantom,
      ...toHsl(darkValue),
    };
  });
}

/** Variables whose dark and light values are identical are deliberately not themed. */
export function isThemeInvariant(f: VarFact): boolean {
  return f.light !== null && f.light.toLowerCase() === f.dark.toLowerCase();
}

export interface AlphaAlias {
  /** The eight-digit name as written, e.g. `--c-6b758555`. */
  name: string;
  /** The six-digit variable it is a translucent version of, e.g. `--c-6b7585`. */
  base: string;
  /** Alpha as a percentage, from the trailing byte. */
  alphaPct: number;
}

/**
 * Eight-digit `--c-<rrggbbaa>` names — the same convention as the rest of the palette
 * but carrying an alpha byte. They cannot be assigned an opaque role, so they stay as
 * their own variables and are emitted as a colour-mix of the base variable's role
 * against `transparent`, which keeps them following the theme.
 */
export function readAlphaAliases(sources: string | string[]): AlphaAlias[] {
  const src = readSources(sources);
  const seen = new Map<string, AlphaAlias>();
  for (const m of src.matchAll(/--c-([0-9a-f]{6})([0-9a-f]{2})\b/g)) {
    const name = `--c-${m[1]}${m[2]}`;
    if (seen.has(name)) continue;
    seen.set(name, {
      name,
      base: `--c-${m[1]}`,
      alphaPct: Math.round((parseInt(m[2], 16) / 255) * 100),
    });
  }
  return [...seen.values()];
}
