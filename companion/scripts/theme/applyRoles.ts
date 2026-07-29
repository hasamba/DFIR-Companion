// Rewrites public/dashboard.html onto the semantic role layer:
//
//   1. replaces the two `--c-<hex>` palette blocks with the generated role CSS
//   2. rewrites every `var(--c-xxxxxx)` to `var(--role)`
//   3. rewrites every `themeColor("--c-xxxxxx")` to `themeColor("--role")`
//
//   npm run theme:apply           rewrite in place
//   npm run theme:apply -- --dry  report what would change, touch nothing
//
// Idempotent: running it twice is a no-op, because step 1 matches the original block
// shape and steps 2-3 have nothing left to find. Safe to re-run after a merge brings
// in new `--c-` references from another branch.

import { readFileSync, writeFileSync } from "node:fs";
import { DASHBOARD_PATH as DASHBOARD, loadBaseline } from "./loadBaseline.js";
import { readAlphaAliases, readPaletteFacts } from "./paletteFacts.js";
import { assignRoles } from "./roleMap.js";
import {
  REGISTRY_BEGIN,
  REGISTRY_END,
  renderThemeCss,
  renderThemeRegistry,
  resolveRoleValues,
} from "./themeCss.js";
import { IMPORTED_THEMES } from "./vendor/themePalettes.js";

/**
 * Bounds of the generated CSS region.
 *
 * Delimited by explicit markers rather than inferred from CSS structure. An earlier
 * version walked the run of consecutive `:root ... { }` rules from the opening comment,
 * which held only while the region contained nothing else. Once it grew `.theme-swatch`
 * rules the walk stopped at the first of them, so each run replaced a prefix and
 * re-prepended a whole copy — the region silently tripled. A delimiter that depends on
 * what the generated content happens to look like is not a delimiter.
 */
const TOKENS_BEGIN = "    /* === dfir-theme tokens (issue #53) ===";
const TOKENS_END = "    /* === end dfir-theme tokens === */";

/**
 * The hand-written rule that has always followed the generated region. Used only to
 * place the end marker the first time, on a file written before markers existed.
 */
const LEGACY_TAIL_ANCHOR = "    /* Light mode: the neutral toolbar icons are baked";

function findTokenRegion(src: string): { start: number; end: number } {
  const start = src.indexOf(TOKENS_BEGIN);
  if (start < 0) throw new Error("token region begin marker not found in dashboard.html");

  const marked = src.indexOf(TOKENS_END, start);
  if (marked >= 0) return { start, end: marked + TOKENS_END.length };

  const legacy = src.indexOf(LEGACY_TAIL_ANCHOR, start);
  if (legacy < 0) {
    throw new Error(
      "token region has no end marker and the legacy tail anchor is gone — refusing to guess",
    );
  }
  return { start, end: legacy };
}

function main() {
  const dry = process.argv.includes("--dry");
  const src = readFileSync(DASHBOARD, "utf8");

  const baseline = loadBaseline();
  const facts = readPaletteFacts(DASHBOARD, baseline);
  const map = assignRoles(facts, baseline);
  const values = resolveRoleValues(facts, map);
  const alphas = readAlphaAliases(DASHBOARD);

  const { start, end } = findTokenRegion(src);
  const css = renderThemeCss(facts, map, values, alphas);
  let out = src.slice(0, start) + css + src.slice(end);

  // Second generated region: the theme registry the picker reads. Kept in sync with the
  // CSS from one source, because the two failure modes are both silent — a menu entry
  // with no matching block renders as the previous theme under a new name, and a block
  // with no entry is unreachable.
  const rs = out.indexOf(REGISTRY_BEGIN);
  const re = out.indexOf(REGISTRY_END);
  if (rs < 0 || re < 0) throw new Error("theme registry markers not found in dashboard.html");
  out = out.slice(0, rs) + renderThemeRegistry(IMPORTED_THEMES, values) + out.slice(re + REGISTRY_END.length);

  // Call-site rewrite. Both patterns are anchored on the full 6-hex name so a partial
  // match is impossible, and an unknown name is left alone and reported rather than
  // silently rewritten to something wrong.
  const unknown = new Set<string>();
  let cssSites = 0;
  let jsSites = 0;

  // Both `var(--c-xxxxxx)` and `var(--c-xxxxxx, #fallback)`. The fallback is dropped:
  // roles are always defined, so it is unreachable, and leaving a hardcoded hex behind
  // would quietly defeat theming for anyone who later made the role conditional.
  // Requiring `,` or `)` after six hex digits leaves the eight-digit RGBA names alone —
  // those keep their own variable, defined as a colour-mix in the alias block.
  out = out.replace(/var\(\s*(--c-[0-9a-f]{6})\s*(?:,[^)]*)?\)/g, (whole, name: string) => {
    const role = map[name]?.role;
    if (!role) {
      unknown.add(name);
      return whole;
    }
    cssSites++;
    return `var(${role})`;
  });

  // Any quoted `--c-<hex>` in the script. This is deliberately broader than
  // `themeColor("...")`: the swimlane canvas keeps its tokens in lookup tables
  // (SW_SEV_TOKEN, SW_LABEL_TOKEN) and passes them to themeColor() indirectly, so
  // matching only the direct call would leave those behind. In this file a string
  // literal of that exact shape is never anything but a CSS variable name.
  out = out.replace(/(["'])(--c-[0-9a-f]{6})\1/g, (whole, quote: string, name: string) => {
    const role = map[name]?.role;
    if (!role) {
      unknown.add(name);
      return whole;
    }
    jsSites++;
    return `${quote}${role}${quote}`;
  });

  console.log(`token region   lines ${lineOf(src, start)}-${lineOf(src, end)} (${end - start} chars) -> ${css.length} chars`);
  console.log(`css call sites ${cssSites}`);
  console.log(`js  call sites ${jsSites}`);
  console.log(`roles emitted  ${values.size}`);
  if (unknown.size) console.log(`UNKNOWN (left as-is): ${[...unknown].join(", ")}`);

  // The alias block reintroduces one `--c-` occurrence per variable as a declaration.
  // Anything above that count is a real reference the rewrite failed to catch.
  // What should legitimately survive:
  //   - one alias declaration per variable
  //   - one declaration per alpha alias
  //   - the alpha call sites themselves, which keep their own variable on purpose
  const remaining = (out.match(/--c-[0-9a-f]{6}/g) ?? []).length;
  const alphaSites = (out.match(/var\(\s*--c-[0-9a-f]{8}\s*\)/g) ?? []).length;
  const expected = facts.length + alphas.length + alphaSites;
  console.log(
    `--c- occurrences left ${remaining} (expected ${expected}: ${facts.length} aliases + ${alphas.length} alpha aliases + ${alphaSites} alpha call sites)`,
  );
  if (remaining !== expected) {
    console.log("  MISMATCH — some references were not rewritten");
    process.exitCode = 1;
  }

  if (dry) {
    console.log("\n--dry: nothing written");
    return;
  }
  writeFileSync(DASHBOARD, out);
  console.log(`\nwrote ${DASHBOARD}`);
}

const lineOf = (s: string, idx: number) => s.slice(0, idx).split("\n").length;

main();
