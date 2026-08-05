// Rewrites the dashboard's client source onto the semantic role layer:
//
//   1. replaces the two `--c-<hex>` palette blocks with the generated role CSS
//   2. rewrites every `var(--c-xxxxxx)` to `var(--role)`
//   3. rewrites every `themeColor("--c-xxxxxx")` to `themeColor("--role")`
//
//   npm run theme:apply           rewrite in place
//   npm run theme:apply -- --dry  report what would change, touch nothing
//
// NINE FILES SINCE #415, and the generated CSS region now SPANS THREE of them. The CSS moved out
// of dashboard.html, and then the stylesheet itself was cut into eight parts to meet its 800-line
// limit: dashboard-tokens.css holds the region's start (below a hand-written docblock this script
// preserves), and dashboard-themes-a/-b.css are generated end to end. The theme registry the picker
// reads is JavaScript and stayed in the inline script. Keeping every region generated from one run
// is the point: a menu entry with no matching block renders as the previous theme under a new name,
// and a block with no entry is unreachable, and both failures are silent.
//
// Step 2 and step 3 are run over ALL NINE files rather than each over "its" file. The split is
// clean today (var() in the CSS, quoted names in the script) but nothing enforces that, and
// a rewrite that skipped a file would leave a live `--c-` reference behind — which the
// occurrence count at the end of this script would then report as a mismatch with no clue
// which file it was in.
//
// Idempotent: running it twice is a no-op, because step 1 matches the original block
// shape and steps 2-3 have nothing left to find. Safe to re-run after a merge brings
// in new `--c-` references from another branch.

import { readFileSync, writeFileSync } from "node:fs";
import {
  DASHBOARD_CSS_PARTS,
  DASHBOARD_PATH as DASHBOARD,
  THEME_CSS_PARTS,
  loadBaseline,
  THEME_SOURCES,
} from "./loadBaseline.js";
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
// Unindented since #415: the region used to sit four columns in, inside a <style> block, and
// now starts at column 0 in a stylesheet of its own.
const TOKENS_BEGIN = "/* === dfir-theme tokens (issue #53) ===";
const TOKENS_BEGIN_FILE = "public/css/dashboard-tokens.css";
/**
 * Where the generated region starts in dashboard-tokens.css. There is no matching END search any
 * more, and that is the point of the split: the region now RUNS TO THE END of that file and
 * continues through the two theme files, so its end marker is the last thing in
 * dashboard-themes-b.css. Hunting for an end marker inside tokens.css would never find one, and
 * the old fallback — anchoring on the first hand-written rule that used to follow the region — is
 * meaningless once no hand-written rule follows it at all.
 *
 * Everything above this marker is the file's own hand-written docblock and is preserved.
 */
function findTokenStart(src: string): number {
  const start = src.indexOf(TOKENS_BEGIN);
  if (start < 0) {
    throw new Error(
      `token region begin marker not found in ${TOKENS_BEGIN_FILE} — refusing to guess where the generated region starts`,
    );
  }
  return start;
}

function main() {
  const dry = process.argv.includes("--dry");
  const htmlSrc = readFileSync(DASHBOARD, "utf8");
  // All eight parts, in cascade order. The rewrite below has to see every one of them: the var()
  // call sites are spread across the whole stylesheet, and a rewrite that looked only at the three
  // GENERATED parts would leave live `--c-` references behind for the count at the bottom to report
  // as a bare number with no file attached.
  const cssSrcs = DASHBOARD_CSS_PARTS.map((p) => readFileSync(p, "utf8"));
  const [TOKENS_FILE] = THEME_CSS_PARTS;

  const baseline = loadBaseline();
  const facts = readPaletteFacts(THEME_SOURCES, baseline);
  const map = assignRoles(facts, baseline);
  const values = resolveRoleValues(facts, map);
  const alphas = readAlphaAliases(THEME_SOURCES);

  // First generated region: the tokens, now spanning the first THREE stylesheet parts.
  //
  // Only dashboard-tokens.css is spliced — it keeps a hand-written docblock above the begin marker,
  // and that is the file's own header, not ours to overwrite. The two theme files are generated end
  // to end, so they are written WHOLESALE: searching them for a marker that is deliberately not in
  // them would be a lie about where the region's edges are.
  const parts = renderThemeCss(facts, map, values, alphas);
  const tokensSrc = cssSrcs[0];
  const start = findTokenStart(tokensSrc);
  const outParts = [...cssSrcs];
  outParts[0] = tokensSrc.slice(0, start) + parts.tokens;
  outParts[1] = parts.themesA;
  outParts[2] = parts.themesB;

  // Second generated region: the theme registry the picker reads, in the inline script. Kept in
  // sync with the CSS from one run, because the two failure modes are both silent — a menu entry
  // with no matching block renders as the previous theme under a new name, and a block with no
  // entry is unreachable.
  const rs = htmlSrc.indexOf(REGISTRY_BEGIN);
  const re = htmlSrc.indexOf(REGISTRY_END);
  if (rs < 0 || re < 0) throw new Error("theme registry markers not found in dashboard.html");
  let outHtml =
    htmlSrc.slice(0, rs) + renderThemeRegistry(IMPORTED_THEMES, values) + htmlSrc.slice(re + REGISTRY_END.length);

  // Call-site rewrite. Both patterns are anchored on the full 6-hex name so a partial
  // match is impossible, and an unknown name is left alone and reported rather than
  // silently rewritten to something wrong.
  //
  // Both patterns run over both files. Today the var() sites are all in the stylesheet and the
  // quoted names all in the script, but nothing enforces that split and a rewrite that assumed it
  // would leave a live `--c-` reference behind for the count at the bottom to report as a bare
  // number with no file attached.
  const unknown = new Set<string>();
  let cssSites = 0;
  let jsSites = 0;

  // Both `var(--c-xxxxxx)` and `var(--c-xxxxxx, #fallback)`. The fallback is dropped:
  // roles are always defined, so it is unreachable, and leaving a hardcoded hex behind
  // would quietly defeat theming for anyone who later made the role conditional.
  // Requiring `,` or `)` after six hex digits leaves the eight-digit RGBA names alone —
  // those keep their own variable, defined as a colour-mix in the alias block.
  const rewriteVars = (text: string) =>
    text.replace(/var\(\s*(--c-[0-9a-f]{6})\s*(?:,[^)]*)?\)/g, (whole, name: string) => {
      const role = map[name]?.role;
      if (!role) {
        unknown.add(name);
        return whole;
      }
      cssSites++;
      return `var(${role})`;
    });

  // Any quoted `--c-<hex>`. This is deliberately broader than `themeColor("...")`: the swimlane
  // canvas keeps its tokens in lookup tables (SW_SEV_TOKEN, SW_LABEL_TOKEN) and passes them to
  // themeColor() indirectly, so matching only the direct call would leave those behind. In these
  // files a string literal of that exact shape is never anything but a CSS variable name.
  const rewriteQuoted = (text: string) =>
    text.replace(/(["'])(--c-[0-9a-f]{6})\1/g, (whole, quote: string, name: string) => {
      const role = map[name]?.role;
      if (!role) {
        unknown.add(name);
        return whole;
      }
      jsSites++;
      return `${quote}${role}${quote}`;
    });

  for (let i = 0; i < outParts.length; i++) outParts[i] = rewriteQuoted(rewriteVars(outParts[i]));
  outHtml = rewriteQuoted(rewriteVars(outHtml));

  const outCss = outParts.join("");
  const generatedLen = parts.tokens.length + parts.themesA.length + parts.themesB.length;
  console.log(`token region   ${TOKENS_FILE} line ${lineOf(tokensSrc, start)} to EOF, then 2 whole files -> ${generatedLen} chars across 3 parts`);
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
  const both = `${outHtml}\n${outCss}`;
  const remaining = (both.match(/--c-[0-9a-f]{6}/g) ?? []).length;
  const alphaSites = (both.match(/var\(\s*--c-[0-9a-f]{8}\s*\)/g) ?? []).length;
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
  DASHBOARD_CSS_PARTS.forEach((p, i) => writeFileSync(p, outParts[i]));
  writeFileSync(DASHBOARD, outHtml);
  console.log(`\nwrote ${DASHBOARD_CSS_PARTS.length} stylesheet parts\nwrote ${DASHBOARD}`);
}

const lineOf = (s: string, idx: number) => s.slice(0, idx).split("\n").length;

main();
