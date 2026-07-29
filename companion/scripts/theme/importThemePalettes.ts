// Re-imports theme palettes from a local checkout of the upstream theme project into
// scripts/theme/vendor/themePalettes.ts.
//
//   npm run theme:import -- <path-to-upstream-checkout>
//
// The upstream project is MIT-licensed; see the top-level NOTICE for the copyright
// holder and the full permission text, which the generated file carries too.
//
// Only top-level `[data-theme="x"] { ...custom properties only... }` blocks are taken.
// Upstream also ships component-scoped rules such as `[data-theme="sguil"] #sections th`;
// those style upstream's own markup and mean nothing here.
//
// Upstream's `dark` and `light` are skipped. Ours are tuned against this UI over many
// iterations and hold the exact pre-refactor colours; replacing them with upstream's
// would restyle the default experience for no gain.

import { mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { auditPalette } from "./contrast.js";
import { TIER_A } from "./roleMap.js";

const here = dirname(fileURLToPath(import.meta.url));
const OUT = join(here, "vendor", "themePalettes.ts");

/** Ours already; importing upstream's would change the default experience. */
const SKIP = new Set(["dark", "light"]);

/**
 * Locate a file in the checkout by what is inside it rather than by its name.
 *
 * Upstream names its bundle after its own product, and hardcoding that couples this
 * script to a name that is neither ours nor stable. Matching on content also survives a
 * rename or a split bundle upstream, which a filename never would.
 */
function findByContent(dir: string, ext: string, marker: RegExp, what: string): string {
  const candidates = readdirSync(dir).filter((f) => f.endsWith(ext));
  for (const f of candidates.sort()) {
    const body = readFileSync(join(dir, f), "utf8");
    if (marker.test(body)) return body;
  }
  throw new Error(
    `no ${ext} file in ${dir} contains ${what} — checked ${candidates.length || "none"}`,
  );
}

function main() {
  const checkout = process.argv[2];
  if (!checkout) {
    console.error("usage: npm run theme:import -- <path-to-upstream-checkout>");
    process.exit(1);
  }
  const staticDir = join(checkout, "static");
  const css = findByContent(staticDir, ".css", /\[data-theme="[a-z0-9-]+"\]\s*\{/, "theme blocks");
  const js = findByContent(staticDir, ".js", /const THEMES\s*=\s*\{/, "the theme registry");
  const licence = readFileSync(join(checkout, "LICENSE"), "utf8").trim();

  // --- registry: label + group ---
  const regSrc = js.slice(js.indexOf("const THEMES = {"), js.indexOf("const THEME_GROUP_LABELS"));
  const meta: Record<string, { label: string; group: string }> = {};
  for (const m of regSrc.matchAll(/'?([\w-]+)'?\s*:\s*\{\s*label:\s*'([^']+)',\s*group:\s*'([^']+)'\s*\}/g)) {
    meta[m[1]] = { label: m[2], group: m[3] };
  }

  // --- palettes ---
  const themes: Record<string, Record<string, string>> = {};
  for (const m of css.matchAll(/^\s*\[data-theme="([a-z0-9-]+)"\]\s*\{([^}]*)\}/gm)) {
    const [, name, body] = m;
    if (SKIP.has(name)) continue;
    const decls = [...body.matchAll(/(--[\w-]+)\s*:\s*([^;]+);/g)];
    // A palette block declares custom properties and nothing else.
    if (body.replace(/(--[\w-]+)\s*:\s*([^;]+);/g, "").trim()) continue;
    if (decls.length < 10) continue;
    const palette: Record<string, string> = {};
    for (const d of decls) {
      // Upstream's c64 carries one extra property no other theme has; drop anything
      // outside the agreed vocabulary rather than let one theme widen the contract.
      if ((TIER_A as readonly string[]).includes(d[1])) palette[d[1]] = d[2].trim();
    }
    // Upstream sometimes points one role at another (`--help-icon-color: var(--accent)`
    // in hacker and matte-black). Resolve those here so everything downstream can assume
    // a palette holds concrete colours — a `var()` reaching the contrast solver produced
    // `#NaNNaNNaN`. `rgba()` values are left alone; they are concrete already.
    for (let pass = 0; pass < 4; pass++) {
      let changed = false;
      for (const [role, value] of Object.entries(palette)) {
        const ref = value.match(/^var\(\s*(--[\w-]+)\s*\)$/);
        if (!ref) continue;
        const target = palette[ref[1]];
        if (target === undefined || target === value) continue;
        palette[role] = target;
        changed = true;
      }
      if (!changed) break;
    }
    themes[name] = palette;
  }

  // --- validate before writing ---
  // Structural problems are fatal: a palette missing a role cannot be rendered at all.
  const fatal: string[] = [];
  for (const [name, palette] of Object.entries(themes)) {
    const missing = TIER_A.filter((r) => !(r in palette));
    if (missing.length) fatal.push(`${name}: missing ${missing.join(", ")}`);
    if (!meta[name]) fatal.push(`${name}: no label/group in the upstream registry`);
  }
  if (fatal.length) {
    console.error("refusing to write:\n  " + fatal.join("\n  "));
    process.exit(1);
  }

  // Legibility problems drop the theme rather than the import. This is a forensics tool:
  // a palette whose body text sits under 4.5:1, or whose ramp inverts so secondary text
  // shouts louder than body text, is a theme in which an analyst can misread evidence.
  // Enforcing at the boundary means the rule is about the property, not about a name —
  // a future upstream theme with the same defect is caught without anyone remembering to.
  const rejected: Array<[string, string[]]> = [];
  for (const name of Object.keys(themes)) {
    const problems = auditPalette(themes[name]);
    if (problems.length) {
      rejected.push([name, problems]);
      delete themes[name];
    }
  }

  const names = Object.keys(themes).sort();
  const body = names
    .map((n) => {
      const p = themes[n];
      const decls = TIER_A.map((r) => `      "${r}": "${p[r]}",`).join("\n");
      return `  ${JSON.stringify(n)}: {\n    label: ${JSON.stringify(meta[n].label)},\n    group: ${JSON.stringify(meta[n].group)},\n    palette: {\n${decls}\n    },\n  },`;
    })
    .join("\n");

  const out = `// GENERATED by \`npm run theme:import\`. Do not hand-edit.
//
// Theme palettes imported from a third-party theme project.
//
// ---------------------------------------------------------------------------
${licence
  .split("\n")
  .map((l) => `// ${l}`.trimEnd())
  .join("\n")}
// ---------------------------------------------------------------------------
//
// Several palettes are renditions of third-party colour schemes (Nord, Gruvbox,
// Catppuccin, Tokyo Night, Rosé Pine, Everforest, Kanagawa). Colour values are not
// copyrightable and each of those upstreams is permissively licensed; they are named
// in the theme picker as a courtesy.
//
// Upstream's own \`dark\` and \`light\` are deliberately not imported — see importThemePalettes.ts.

export interface ImportedThemePalette {
  label: string;
  /** Upstream's menu grouping: "dark" | "light" | "fun". */
  group: string;
  /** The 25 tier A roles. Upstream defines exactly these, which is why they drop in. */
  palette: Record<string, string>;
}

export const IMPORTED_THEMES: Record<string, ImportedThemePalette> = {
${body}
};
`;

  mkdirSync(dirname(OUT), { recursive: true });
  writeFileSync(OUT, out);
  console.log(`imported ${names.length} themes -> ${OUT}`);
  console.log(names.join(", "));
  if (rejected.length) {
    console.log(`\nskipped ${rejected.length} theme(s) on legibility grounds:`);
    for (const [name, problems] of rejected) {
      console.log(`  ${name}`);
      for (const p of problems) console.log(`    ${p}`);
    }
  }
}

main();
