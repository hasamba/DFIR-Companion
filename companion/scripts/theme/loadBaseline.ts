// Loads scripts/theme/role-map.json, the committed record of what every `--c-` variable
// was worth and which role it belongs to.
//
// WHY A BASELINE IS REQUIRED, not just convenient:
//
// Both the value and the ROLE of a variable are derived from the pre-migration file.
// The value comes from the palette block, and the role comes largely from how the
// variable is used — a hex at lightness 20 is a panel background or a card border only
// according to the CSS properties it feeds. The migration destroys both inputs: the
// palette becomes `--c-0d1117: var(--bg-primary)` and every call site becomes
// `var(--bg-primary)`, so a second run would see a variable with no colour and no call
// sites and reclassify it as something else.
//
// So role-map.json is the source of truth once written, and the tooling reads it back
// rather than re-deriving. New `--c-` names appearing after the migration are handled
// on their own terms: with no palette block to declare them, they are phantoms, and the
// naming convention means their value is recoverable from the name.

import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

export const ROLE_MAP_PATH = join(here, "role-map.json");
export const DASHBOARD_PATH = join(here, "..", "..", "..", "public", "dashboard.html");

/**
 * The file holding the generated theme registry the picker reads.
 *
 * It moved out of dashboard.html into its own script in #415, and applyRoles.ts was not moved with
 * it — so `npm run theme:apply` threw "theme registry markers not found in dashboard.html" and the
 * generator could not run at all. A generator that cannot run makes its output look hand-editable,
 * which is how a hand-edit to a generated region survives long enough to be believed.
 */
export const THEME_REGISTRY_PATH = join(here, "..", "..", "..", "public", "js", "dashboard-theme.js");

const css = (name: string): string => join(here, "..", "..", "..", "public", "css", name);

/**
 * The three GENERATED parts, in cascade order. applyRoles.ts owns their contents.
 *
 * dashboard-tokens.css keeps a hand-written docblock above the begin marker, so it is spliced;
 * the two theme files are generated end to end and are rewritten wholesale.
 */
export const THEME_CSS_PARTS = [
  css("dashboard-tokens.css"),
  css("dashboard-themes-a.css"),
  css("dashboard-themes-b.css"),
];

/**
 * All eight parts of the dashboard stylesheet, IN CASCADE ORDER — the order they are linked in
 * public/dashboard.html, which is the order they were cut from the single dashboard.css (#415).
 *
 * There is deliberately no DASHBOARD_CSS_PATH any more. That constant meant three incompatible
 * things at once — a member of the read corpus, the splice target for the generated region, and a
 * test fixture — and quietly aliasing it to one of the eight parts would have kept all three call
 * sites compiling while two of them silently read a fraction of the stylesheet.
 */
export const DASHBOARD_CSS_PARTS = [
  ...THEME_CSS_PARTS,
  css("dashboard-layout.css"),
  css("dashboard-panels.css"),
  css("dashboard-timeline.css"),
  css("dashboard-toolbar.css"),
  css("dashboard-sections.css"),
];

/**
 * The eight parts concatenated back into the byte-for-byte equivalent of the old dashboard.css.
 *
 * Joined with the EMPTY string, not a newline: the themes-b/layout boundary falls mid-line, so a
 * "\n" join would split one source line in two. Callers that match line-anchored patterns —
 * `\n:root {` in the theme tests — depend on this reproducing the original bytes exactly.
 */
export function readDashboardCss(): string {
  return DASHBOARD_CSS_PARTS.map((p) => readFileSync(p, "utf8")).join("");
}

/**
 * Every file that can hold a `--c-<hex>` reference, read as one corpus.
 *
 * Usage counts decide which member's colour a role adopts, so they have to see all of it: the CSS
 * `var()` call sites across all eight stylesheet parts and the quoted `themeColor("--c-…")` lookups
 * in dashboard.html's inline script. Counting only one file would silently re-weight every role —
 * and the audit would still print a clean table, because a variable with fewer call sites looks
 * like a variable with fewer call sites, not like a bug. That is why this lists all eight parts
 * rather than only the three the generator writes.
 */
export const THEME_SOURCES = [DASHBOARD_PATH, ...DASHBOARD_CSS_PARTS];

export interface BaselineEntry {
  dark: string;
  light: string | null;
  role: string;
  cls: "SURFACE" | "BORDER" | "TEXT" | "CANVAS";
  uses: number;
  phantom: boolean;
}

export type Baseline = Record<string, BaselineEntry>;

export function loadBaseline(): Baseline | undefined {
  if (!existsSync(ROLE_MAP_PATH)) return undefined;
  return JSON.parse(readFileSync(ROLE_MAP_PATH, "utf8")) as Baseline;
}
