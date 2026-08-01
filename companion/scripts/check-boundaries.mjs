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
 * the coupling this map exists to control — a third of the recorded violations are type-only, so
 * exempting them would have hidden a third of the problem on day one. (The exact split is in
 * boundary-violations.json, where every entry carries its kind; no count is repeated here, because
 * a number written into a comment is a number that goes stale.)
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
 * this belong?" is a question for review, and the ledger is not the place to answer it. The reverse
 * is an error too: a map entry naming a file that no longer exists is a classification left behind
 * by a move, and it makes the map look like it still describes the tree after it has drifted.
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

// Two domains must not be able to claim the same file. domainOf returns the FIRST pattern that
// matches, so an overlap does not fail — it silently picks a winner by object key order, and the
// loser's rules stop applying to files nobody realises moved out from under them. Adding
// `analysis/**` alongside `analysis/detect/**` would do exactly that.
const owners = Object.entries(map.domains).flatMap(([name, def]) => def.paths.map((p) => [name, p]));
for (const [aName, a] of owners) {
  for (const [bName, b] of owners) {
    if (aName === bName) continue;
    const aPrefix = a.endsWith("/**") ? a.slice(0, -2) : null;
    const bPrefix = b.endsWith("/**") ? b.slice(0, -2) : null;
    const overlaps = a === b || (aPrefix && b.startsWith(aPrefix)) || (bPrefix && a.startsWith(bPrefix));
    if (overlaps) {
      console.error(
        `\n[boundaries] module-map.json: "${aName}" (${a}) and "${bName}" (${b}) can both claim the\n` +
          "[boundaries] same file. Ownership must be unambiguous — narrow one of the patterns.",
      );
      process.exit(1);
    }
  }
}

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
const STATIC_IMPORT =
  /^\s*(?:import|export)\s+(type\s+)?[^;]*?from\s+["']([^"']+)["']|^\s*import\s+(type\s+)?["']([^"']+)["']/gm;

// `import("x")` in either of its two guises, neither of which the static form above can see:
//
//   const m = await import("./thing.js");                    // runtime dynamic import
//   let x: import("./thing.js").SomeType;                    // type query
//
// Both are real dependencies and both were invisible to this gate. The type-query form is not
// hypothetical — pipeline.ts and routes/findings.ts both use it today. A dynamic import is the more
// dangerous omission, because it is exactly how someone works around a boundary error: the static
// import fails the gate, `await import()` does not.
const EXPRESSION_IMPORT = /(await\s+)?\bimport\s*\(\s*["']([^"']+)["']\s*\)(\s*\.\s*\w+)?/g;

/**
 * Every relative dependency in one file, as {spec, isType}.
 *
 * KIND CLASSIFICATION IS DELIBERATE, not cosmetic: the ledger records it (see below), so a
 * grandfathered type-only edge that later becomes a runtime edge reads as a NEW violation instead
 * of passing silently. `import("x").Member` is a type query — erased. `await import("x")`, and a
 * bare `import("x")` used as a value, are runtime. When the two are ambiguous the answer is
 * "runtime", because that is the stricter ledger entry.
 */
function dependenciesOf(source) {
  const out = [];
  for (const m of source.matchAll(STATIC_IMPORT)) {
    out.push({ spec: m[2] ?? m[4], isType: Boolean(m[1] || m[3]) });
  }
  for (const m of source.matchAll(EXPRESSION_IMPORT)) {
    const awaited = Boolean(m[1]);
    const member = Boolean(m[3]);
    out.push({ spec: m[2], isType: member && !awaited });
  }
  return out.filter((d) => d.spec);
}

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
  for (const { spec, isType } of dependenciesOf(source)) {
    if (!spec.startsWith(".")) continue;
    const to = rel(resolve(dirname(file), spec)).replace(/\.js$/, ".ts");
    const toDomain = domainOf(to);
    // An unresolvable or unclassified target is reported against the target file itself, not here.
    if (!toDomain || toDomain === fromDomain) continue;
    if (rankOf(toDomain) <= rankOf(fromDomain)) continue;
    violations.push({
      // The kind is PART OF THE KEY. Without it, a grandfathered `type` edge silently becomes a
      // runtime edge — the coupling gets strictly worse and the gate says nothing, because the
      // source and target files did not change. Encoding it means the escalation reads as a new
      // violation, while the reverse (runtime tightened to type) reads as one going away.
      key: `${from} -> ${to} [${isType ? "type" : "runtime"}]`,
      detail: `${fromDomain} -> ${toDomain}${isType ? " (type-only)" : ""}`,
    });
  }
}

// A `flatAnalysisFiles` entry whose file no longer exists is a stale classification. It is harmless
// on its own, but it makes the map look like it still describes the tree when it has drifted — and
// the entries that rot first are exactly the ones for files an extraction just moved. The map is
// only trustworthy if it is exact in both directions: every flat file classified (above), and no
// classification without a file (here).
const flatOnDisk = new Set(
  files
    .map(rel)
    .filter((p) => p.split("/").length === 2 && p.startsWith("analysis/"))
    .map((p) => p.slice("analysis/".length)),
);
const staleEntries = Object.keys(map.flatAnalysisFiles).filter((name) => !flatOnDisk.has(name));
if (staleEntries.length > 0) {
  console.error(
    `\n[boundaries] ${staleEntries.length} stale flatAnalysisFiles entr(ies) in module-map.json:`,
  );
  for (const name of staleEntries) console.error(`  ✖ analysis/${name} — classified, but no such file`);
  console.error(
    "\n[boundaries] The file moved or was deleted. Remove its entry: once a file lives in its domain\n" +
      "[boundaries] directory, the directory pattern classifies it and the flat entry is dead weight.",
  );
  process.exit(1);
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
