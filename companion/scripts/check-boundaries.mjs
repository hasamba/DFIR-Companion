#!/usr/bin/env node
/**
 * Module-boundary gate for src/ (issue #384). The third of the three structure ratchets, after
 * check-file-size.mjs and check-imports.mjs, and it works the same way.
 *
 * WHAT IT ENFORCES. Every file in src/ belongs to a domain (scripts/module-map.json), every domain
 * sits in a layer, and the analysis domains are additionally ordered by tier. An import may go DOWN
 * a layer or sideways within one, and within the domain layer down a tier or sideways — never up.
 * ARCHITECTURE.md is the prose half of the same rules; tests/architecture/moduleMap.test.ts asserts
 * the two agree, because a document allowed to drift from the gate is worse than no document.
 *
 * TYPE-ONLY IMPORTS COUNT HERE. check-imports.mjs ignores them and is right to: `import type` is
 * erased before the module runs, so it cannot form a runtime initialisation cycle. That reasoning
 * does not carry over. A type import still means one domain knows another's shape, which is exactly
 * the coupling this map exists to control — and 25 of the 63 recorded violations are type-only, so
 * exempting them would have hidden 40% of the problem on day one.
 *
 * THE LEDGER IS FILE-TO-FILE, NOT DOMAIN-TO-DOMAIN. scripts/boundary-violations.json records
 * `analysis/superTimeline.ts -> analysis/correlate.ts`, not `timeline -> detect`. Recording the
 * domain pair would turn one grandfathered violation into a licence to add more imports along the
 * same edge, which is how a ratchet quietly becomes a rubber stamp. It also means each entry names
 * the file to fix rather than a direction to think about.
 *
 * The list only shrinks. `--update` rewrites it and REFUSES to add an entry, so removing a violation
 * is a visible deletion in review and adding one has to be argued rather than absorbed. `--init` is
 * the one way to add, and exists for the first recording and for re-baselining after a long-lived
 * branch lands; it prints every addition so they appear in the PR conversation.
 *
 * A NEW src/analysis/*.ts FILE WITH NO MAP ENTRY IS A HARD ERROR, never a violation. "Where does
 * this belong?" is a question for review, and the ledger is not the place to answer it.
 *
 *   node scripts/check-boundaries.mjs            # gate
 *   node scripts/check-boundaries.mjs --update   # re-record after removing violations (shrink-only)
 *   node scripts/check-boundaries.mjs --init     # re-baseline; additions are printed, justify them
 *
 * No dependency: like check-imports.mjs, the graph is a regex over the import statements, because
 * the companion imports its own modules exclusively as relative specifiers ending in `.js`.
 */
import { readdirSync, readFileSync, statSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const COMPANION = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SRC = join(COMPANION, "src");
const MAP = join(COMPANION, "scripts", "module-map.json");
const LEDGER = join(COMPANION, "scripts", "boundary-violations.json");

const map = JSON.parse(readFileSync(MAP, "utf8"));

function walk(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) out.push(...walk(full));
    else if (name.endsWith(".ts") && !name.endsWith(".d.ts")) out.push(full);
  }
  return out;
}

const rel = (f) => relative(SRC, f).replace(/\\/g, "/");

/** `analysis/x/**` matches `analysis/x/a.ts` and `analysis/x/deep/a.ts`; `types.ts` matches exactly. */
function pathMatches(pattern, path) {
  if (!pattern.endsWith("/**")) return pattern === path;
  return path.startsWith(pattern.slice(0, -2));
}

/**
 * A file's domain. Directory patterns win, so a file that has already MOVED into its domain
 * directory is classified by where it is; the flat-file table is consulted only for the ones still
 * sitting loose in src/analysis/, and an entry there becomes dead the moment its file moves.
 */
function domainOf(path) {
  for (const [name, def] of Object.entries(map.domains)) {
    for (const pattern of def.paths) if (pathMatches(pattern, path)) return name;
  }
  const parts = path.split("/");
  if (parts.length === 2 && parts[0] === "analysis") {
    const assigned = map.flatAnalysisFiles[parts[1]];
    if (assigned) return assigned;
  }
  return null;
}

/** Layer rank dominates; tier orders the domain layer within it. Higher may import lower or equal. */
function rankOf(domain) {
  const def = map.domains[domain];
  return map.layerRank[def.layer] * 100 + (def.tier ?? 0);
}

// `import … from "x"` / `export … from "x"` / bare `import "x"`. Unlike check-imports.mjs the
// type-only forms are captured rather than skipped — see the header.
const IMPORT =
  /^\s*(?:import|export)\s+(type\s+)?[^;]*?from\s+["']([^"']+)["']|^\s*import\s+(type\s+)?["']([^"']+)["']/gm;

const files = walk(SRC).sort();
const unclassified = [];
const violations = [];

for (const file of files) {
  const from = rel(file);
  const fromDomain = domainOf(from);
  if (!fromDomain) {
    unclassified.push(from);
    continue;
  }
  const source = readFileSync(file, "utf8");
  for (const m of source.matchAll(IMPORT)) {
    const isType = Boolean(m[1] || m[3]);
    const spec = m[2] ?? m[4];
    if (!spec?.startsWith(".")) continue;
    const to = rel(resolve(dirname(file), spec)).replace(/\.js$/, ".ts");
    const toDomain = domainOf(to);
    // An unresolvable or unclassified target is reported against the target file itself, not here.
    if (!toDomain || toDomain === fromDomain) continue;
    if (rankOf(toDomain) <= rankOf(fromDomain)) continue;
    violations.push({
      key: `${from} -> ${to}`,
      detail: `${fromDomain} -> ${toDomain}${isType ? " (type-only)" : ""}`,
    });
  }
}

if (unclassified.length > 0) {
  console.error(`\n[boundaries] ${unclassified.length} file(s) have no domain in module-map.json:`);
  for (const f of unclassified) console.error(`  ✖ ${f}`);
  console.error(
    "\n[boundaries] Classify them. A new src/analysis/*.ts file needs a `flatAnalysisFiles` entry;\n" +
      "[boundaries] a new directory needs a domain. Do NOT record these in the violation ledger —\n" +
      "[boundaries] an unclassified file is an unanswered design question, not a known debt.",
  );
  process.exit(1);
}

const found = [...new Set(violations.map((v) => v.key))].sort();
const detailOf = new Map(violations.map((v) => [v.key, v.detail]));

if (process.argv.includes("--init")) {
  const previous = existsSync(LEDGER) ? JSON.parse(readFileSync(LEDGER, "utf8")) : [];
  const added = found.filter((v) => !previous.includes(v));
  writeFileSync(LEDGER, `${JSON.stringify(found, null, 2)}\n`);
  console.log(`[boundaries] recorded ${found.length} violation(s) in ${relative(COMPANION, LEDGER)}`);
  if (added.length > 0) {
    console.log(`[boundaries] ${added.length} of them are NEW — justify each in the PR:`);
    for (const v of added) console.log(`  + ${v}  (${detailOf.get(v)})`);
  }
  process.exit(0);
}

const baseline = existsSync(LEDGER) ? JSON.parse(readFileSync(LEDGER, "utf8")) : [];
const known = new Set(baseline);
const added = found.filter((v) => !known.has(v));
const removed = baseline.filter((v) => !found.includes(v));

if (process.argv.includes("--update")) {
  if (added.length > 0) {
    console.error(`\n[boundaries] --update refuses to ADD ${added.length} violation(s):`);
    for (const v of added) console.error(`  ✖ ${v}  (${detailOf.get(v)})`);
    console.error(
      "\n[boundaries] The ledger only shrinks. Fix the import, or use --init and say why in the PR.",
    );
    process.exit(1);
  }
  writeFileSync(LEDGER, `${JSON.stringify(found, null, 2)}\n`);
  console.log(`[boundaries] recorded ${found.length} violation(s) — ${removed.length} fewer`);
  process.exit(0);
}

if (removed.length > 0) {
  console.log(`[boundaries] ${removed.length} recorded violation(s) are gone — nice:`);
  for (const v of removed) console.log(`  - ${v}`);
  console.log("[boundaries] run `npm run check:boundaries -- --update` to shrink the ledger.");
}

if (added.length > 0) {
  console.error(`\n[boundaries] ${added.length} NEW boundary violation(s):`);
  for (const v of added) console.error(`  ✖ ${v}\n      ${detailOf.get(v)}`);
  console.error(
    "\n[boundaries] An import may go DOWN a layer or sideways within one, never up. See ARCHITECTURE.md.\n" +
      "[boundaries] Usual fixes: move the shared helper down to the domain both callers already depend\n" +
      "[boundaries] on, invert the call so the higher layer drives, or — if the module is simply filed\n" +
      "[boundaries] in the wrong domain — correct its entry in scripts/module-map.json.",
  );
  process.exit(1);
}

console.log(`[boundaries] ok — ${found.length} known violation(s), none new`);
