#!/usr/bin/env node
/**
 * Circular-import ratchet for src/ (issue #385, prerequisite for #384).
 *
 * A runtime import cycle means one of the modules in the loop sees a half-initialised copy of the
 * other at module-evaluation time. In this codebase that is currently harmless only because the
 * cycles run through `server.ts`, whose bindings are all functions consumed later — but it makes
 * decomposing a large module (the whole point of #384) unsafe to reason about, because moving a
 * top-level `const` across the seam turns a latent cycle into a `TDZ`/`undefined` crash.
 *
 * There is 1 cycle today (33 when this gate was written). This does NOT try to remove them: it
 * records them, and fails on a
 * cycle that is not on the list. The list can only shrink — `--update` rewrites it, so a PR that
 * removes a cycle shows the deletion in review, and a PR that adds one cannot pass without
 * explicitly writing the new cycle down.
 *
 *   node scripts/check-imports.mjs            # gate
 *   node scripts/check-imports.mjs --update   # re-record after removing (or knowingly adding) one
 *
 * TYPE-ONLY IMPORTS ARE IGNORED. `import type { X }` is erased before the module ever runs, so it
 * cannot form a runtime cycle; counting it would flag the many deliberate type-level back-references
 * (routes/context.ts ↔ server.ts's AppOptions) that are not a hazard at all.
 *
 * No dependency: the companion imports its own modules exclusively as explicit relative specifiers
 * ending in `.js`, so resolving the graph is a regex over the import statements rather than a job
 * for a module-resolution library.
 */
import { readdirSync, readFileSync, statSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const COMPANION = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SRC = join(COMPANION, "src");
// The dashboard's extracted feature modules. This root was wired in on the expectation that as
// features came out of dashboard.html they would start importing one another, so the first cycle
// would fail a PR. THAT IS NOT THE PATTERN #415 SETTLED ON: all of them are classic scripts
// publishing onto `window` so a feature survives a sibling 404 (see public/js/dashboard-facade.js),
// and 138 modules later not one uses import/export. A graph resolved by regex over import
// statements therefore sees 138 nodes and 0 edges, and this root cannot fail for them. It stays
// because the pre-#415 ES modules under public/js DO import, and a cycle among those is still
// worth catching — but it governs those, not the extracted features.
//
// The extracted features' real graph — ~463 edges carried by globals — is governed instead by
// tests/dashboard/dashboardLoadOrder.test.ts, which asks the question that actually bites here:
// not "is there a cycle" (harmless when every name resolves through `window` at call time) but
// "does a module call a sibling's name during load, before that sibling's <script> has run". That
// is the blank page this comment used to warn about. See #482.
const PUBLIC_JS = resolve(COMPANION, "..", "public", "js");
const BASELINE = join(COMPANION, "scripts", "import-cycles.json");

function walk(dir, ext = ".ts") {
  if (!existsSync(dir)) return [];
  const out = [];
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) out.push(...walk(full, ext));
    else if (name.endsWith(ext) && !name.endsWith(".d.ts")) out.push(full);
  }
  return out;
}

// `import … from "x"` / `export … from "x"` / bare `import "x"`, minus the type-only forms.
// `import { type A, b }` still counts: the statement itself emits, because `b` is a value.
const IMPORT_RE = /(?:^|\n)\s*(?:import|export)(\s+type\b)?([\s\S]*?)\bfrom\s*["']([^"']+)["']/g;
const BARE_RE = /(?:^|\n)\s*import\s*["']([^"']+)["']/g;

function edges(file) {
  const text = readFileSync(file, "utf8");
  const specs = [];
  for (const m of text.matchAll(IMPORT_RE)) {
    if (m[1]) continue; // `import type … from` — erased, no runtime edge
    // `import { type A, type B } from "x"` also erases entirely; only count it when at least one
    // imported binding is a value.
    const clause = m[2];
    const braced = clause.match(/\{([\s\S]*)\}/);
    if (braced) {
      const names = braced[1]
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
      const hasValue = names.some((n) => !n.startsWith("type "));
      const hasDefaultOrNamespace = /^[\s]*[A-Za-z_$*]/.test(clause.split("{")[0].trim());
      if (!hasValue && !hasDefaultOrNamespace) continue;
    }
    specs.push(m[3]);
  }
  for (const m of text.matchAll(BARE_RE)) specs.push(m[1]);

  const out = [];
  for (const spec of specs) {
    if (!spec.startsWith(".")) continue; // package import — cannot cycle back into our own trees
    // src/ writes `./x.js` and means `./x.ts`; public/js/ writes `./x.js` and means it literally.
    // Try the TypeScript rewrite first, then the specifier as written.
    const asTs = resolve(dirname(file), spec.replace(/\.js$/, ".ts"));
    const asIs = resolve(dirname(file), spec);
    if (existsSync(asTs)) out.push(asTs);
    else if (existsSync(asIs)) out.push(asIs);
  }
  return out;
}

const files = [...walk(SRC), ...walk(PUBLIC_JS, ".js")];
const graph = new Map(files.map((f) => [f, edges(f)]));
// src/ files keep their historical `analysis/x.ts` label so the recorded baseline stays valid;
// dashboard modules are labelled `public/js/x.js`, which cannot collide with a src-relative path.
const label = (f) =>
  (f.startsWith(PUBLIC_JS) ? join("public/js", relative(PUBLIC_JS, f)) : relative(SRC, f)).replace(
    /\\/g,
    "/",
  );

// Tarjan-free: DFS with an explicit stack, reporting each elementary cycle once by its rotation
// with the alphabetically smallest member first, so the recorded form is stable across runs.
const cycles = new Set();
const state = new Map(); // 0 = visiting, 1 = done
const stack = [];

function visit(node) {
  state.set(node, 0);
  stack.push(node);
  for (const next of graph.get(node) ?? []) {
    if (state.get(next) === 0) {
      const at = stack.indexOf(next);
      const loop = stack.slice(at).map(label);
      const min = loop.indexOf([...loop].sort()[0]);
      cycles.add([...loop.slice(min), ...loop.slice(0, min)].join(" -> "));
    } else if (state.get(next) === undefined) {
      visit(next);
    }
  }
  stack.pop();
  state.set(node, 1);
}
for (const f of [...files].sort()) if (state.get(f) === undefined) visit(f);

const found = [...cycles].sort();

if (process.argv.includes("--update")) {
  writeFileSync(BASELINE, `${JSON.stringify(found, null, 2)}\n`);
  console.log(`[imports] recorded ${found.length} cycle(s) in ${relative(COMPANION, BASELINE)}`);
  process.exit(0);
}

const baseline = existsSync(BASELINE) ? JSON.parse(readFileSync(BASELINE, "utf8")) : [];
const known = new Set(baseline);
const added = found.filter((c) => !known.has(c));
const removed = baseline.filter((c) => !cycles.has(c));

if (removed.length > 0) {
  console.log(`[imports] ${removed.length} recorded cycle(s) no longer exist — nice:`);
  for (const c of removed) console.log(`  - ${c}`);
  console.log("[imports] run `npm run check:imports -- --update` to shrink the list.");
}

if (added.length > 0) {
  console.error(`\n[imports] ${added.length} NEW circular import(s):`);
  for (const c of added) console.error(`  ✖ ${c}`);
  console.error(
    "\n[imports] Break the cycle — usually by moving the shared type or helper into its own module,\n" +
      "[imports] or by making the back-reference `import type` (erased, so not a runtime cycle).\n" +
      "[imports] If the cycle is genuinely intended, record it with `npm run check:imports -- --update`\n" +
      "[imports] and say why in the PR.",
  );
  process.exit(1);
}

console.log(`[imports] ok — ${found.length} known cycle(s), none new`);
