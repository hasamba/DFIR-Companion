// Keeps the browser suite's user-story mapping honest.
//
// Each E2E spec declares which stories it covers in a `// Covers: US-xxx, US-yyy` banner, and
// feature-user-stories.csv carries the reverse view in its `browser_test` column. Two sources of
// the same fact drift the moment someone edits one of them, and a coverage table that is quietly
// wrong is worse than none: it is read as "this is tested".
//
// This checks three things:
//   1. Every US id a spec claims actually exists in the CSV (catches typos and renamed stories).
//   2. The CSV column matches what the specs actually declare, in both directions.
//   3. Every spec says something — a new spec file must either map itself or state that no story
//      exists, so coverage is a decision rather than an oversight.
//
// It also WARNS (never fails) about two things it cannot reasonably demand:
//   - a branch adding an HTTP route that no user story describes (warnUndocumentedRoutes)
//   - a story with neither a spec nor an entry in tests/e2e/COVERAGE.md (warnUnexplainedGaps),
//     which is the only case where an empty browser_test cell means "nobody looked" rather than
//     "we decided this belongs elsewhere"
//
//   node scripts/check-us-map.mjs            # verify
//   node scripts/check-us-map.mjs --update   # rewrite the CSV column from the specs

import { readFileSync, writeFileSync, readdirSync, statSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const COMPANION = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const E2E = join(COMPANION, "tests", "e2e");
const CSV = join(COMPANION, "..", "feature-user-stories.csv");

function walk(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) out.push(...walk(full));
    else if (name.endsWith(".spec.ts")) out.push(full);
  }
  return out;
}

/** Minimal RFC4180 reader: the CSV has quoted fields containing commas and newlines. */
function parseCsv(text) {
  const rows = [];
  let row = [],
    field = "",
    quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quoted) {
      if (c === '"' && text[i + 1] === '"') {
        field += '"';
        i++;
      } else if (c === '"') quoted = false;
      else field += c;
    } else if (c === '"') quoted = true;
    else if (c === ",") {
      row.push(field);
      field = "";
    } else if (c === "\n") {
      row.push(field);
      rows.push(row);
      row = [];
      field = "";
    } else if (c !== "\r") field += c;
  }
  if (field !== "" || row.length > 0) {
    row.push(field);
    rows.push(row);
  }
  return rows;
}

function toCsv(rows) {
  const esc = (v) => (/[",\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v);
  return rows.map((r) => r.map(esc).join(",")).join("\n") + "\n";
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// New-feature warning (advisory only).
//
// feature-user-stories.csv is maintained by hand, so it drifts: a route ships, nobody adds a row,
// and the inventory quietly stops describing the product. This compares the routes on this branch
// against the routes at the merge base and names any that no story mentions.
//
// DELIBERATELY A WARNING, NOT A FAILURE. "What counts as a new feature" is a judgement call — a
// refactor that splits one route into two adds routes without adding features, and an internal
// endpoint may not deserve a story at all. Failing on a guess would block unrelated work and teach
// people to route around the check, which is worse than the drift it is trying to prevent. If it
// proves accurate over a few months, promoting it to an error is a one-line change.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/** Route paths declared under src/routes, e.g. /cases/:id/import-csv. */
function routesIn(text) {
  return new Set(
    [...text.matchAll(/app\.(?:get|post|put|patch|delete)\("(\/[A-Za-z0-9/:._-]+)"/g)].map((m) => m[1]),
  );
}

function gitShow(ref, file) {
  try {
    return execFileSync("git", ["show", `${ref}:${file}`], {
      cwd: COMPANION,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    });
  } catch {
    return ""; // file did not exist at that ref — every route in it is new
  }
}

function warnUndocumentedRoutes(csvText) {
  let base;
  try {
    // The merge base with master is what "this branch added" means. A shallow clone has none, in
    // which case the check simply does not run — it must never fail for an environment reason.
    base = execFileSync("git", ["merge-base", "origin/master", "HEAD"], {
      cwd: COMPANION,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
  } catch {
    return;
  }
  if (!base) return;

  const dir = join(COMPANION, "src", "routes");
  let files;
  try {
    files = readdirSync(dir).filter((f) => f.endsWith(".ts"));
  } catch {
    return;
  }

  const added = new Set();
  for (const file of files) {
    // Repo-relative, not companion-relative: `git show <ref>:<path>` resolves from the repo root,
    // and a wrong prefix makes every file look absent at the base — which reported every existing
    // route as newly added.
    const rel = `companion/src/routes/${file}`;
    const now = routesIn(readFileSync(join(dir, file), "utf8"));
    const before = routesIn(gitShow(base, rel));
    for (const route of now) if (!before.has(route)) added.add(route);
  }
  if (added.size === 0) return;

  // A story "describes" a route when it names it. The CSV already writes routes into
  // expected_behaviour ("POST /cases/:id/import-csv parses CSV, ..."), so this needs no new field.
  const undocumented = [...added].filter((route) => !csvText.includes(route)).sort();
  if (undocumented.length === 0) return;

  console.warn(`\n[us-map] WARNING — ${undocumented.length} new route(s) that no user story mentions:\n`);
  for (const route of undocumented) console.warn(`  ! ${route}`);
  console.warn(
    "\n[us-map] If these are features, add a row to feature-user-stories.csv describing each one,\n" +
      "[us-map] so the inventory keeps matching the product. If they are internal or a refactor,\n" +
      "[us-map] ignore this — it is advisory and does not fail the build.\n",
  );
}

/**
 * Warn about stories that are neither covered by a spec nor explained in COVERAGE.md.
 *
 * An empty `browser_test` cell is ambiguous — it reads the same whether someone decided the story
 * belongs in a unit test, or simply never got to it. COVERAGE.md is where that decision is written
 * down, so a story missing from BOTH is the only real gap, and this is what finds it. Advisory, like
 * the route warning: a genuinely new story arriving without a test yet is normal, and a build that
 * failed for it would just teach people to write a placeholder line.
 */
function warnUnexplainedGaps(known, declared) {
  let doc;
  try {
    doc = readFileSync(join(E2E, "COVERAGE.md"), "utf8");
  } catch {
    return; // no document to check against — never fail for an environment reason
  }
  const gaps = [...known].filter((id) => !declared.has(id) && !doc.includes(id)).sort();
  if (gaps.length === 0) return;

  console.warn(`\n[us-map] WARNING — ${gaps.length} story(ies) with no browser test and no reason given:\n`);
  for (const id of gaps) console.warn(`  ! ${id}`);
  console.warn(
    "\n[us-map] Either add a spec with a `// Covers:` banner naming it, or add it to\n" +
      "[us-map] tests/e2e/COVERAGE.md saying why it is not browser-testable (extension code,\n" +
      "[us-map] a derivation algorithm, needs a live third party, ...). Advisory — this does not\n" +
      "[us-map] fail the build.\n",
  );
}

const csvText = readFileSync(CSV, "utf8");
warnUndocumentedRoutes(csvText);

const rows = parseCsv(csvText);
const header = rows[0];
const idCol = header.indexOf("id");
const btCol = header.indexOf("browser_test");
if (idCol < 0 || btCol < 0) {
  console.error("[us-map] feature-user-stories.csv is missing an `id` or `browser_test` column.");
  process.exit(1);
}
const known = new Set(
  rows
    .slice(1)
    .filter((r) => r[idCol])
    .map((r) => r[idCol]),
);

const problems = [];
const declared = new Map(); // US id -> Set(spec paths)

for (const file of walk(E2E)) {
  const rel = relative(E2E, file).replace(/\\/g, "/");
  const src = readFileSync(file, "utf8");
  // ALL "// Covers:" lines, not just the first. A banner long enough to wrap onto a second line is
  // normal once a spec covers a dozen stories, and matching only the first silently dropped every
  // id after it — under-reporting coverage in the file whose job is to report it accurately.
  const coverLines = [...src.matchAll(/^\/\/ Covers: (.+)$/gm)].map((m) => m[1]);
  const covers = coverLines.length > 0 ? [coverLines.join(", ")] : null;
  if (!covers) {
    problems.push(
      `${rel} has no "// Covers:" banner. Declare the US ids it exercises, or state ` +
        `"// Covers: NO USER STORY EXISTS." with the reason.`,
    );
    continue;
  }
  if (/NO USER STORY EXISTS/.test(covers[0])) continue;
  const ids = covers[0].match(/US-\d+/g) ?? [];
  if (ids.length === 0) {
    problems.push(`${rel} has a "// Covers:" banner naming no US ids and no NO-USER-STORY note.`);
    continue;
  }
  for (const id of ids) {
    if (!known.has(id)) {
      problems.push(`${rel} claims ${id}, which is not in feature-user-stories.csv.`);
      continue;
    }
    if (!declared.has(id)) declared.set(id, new Set());
    declared.get(id).add(rel);
  }
}

warnUnexplainedGaps(known, declared);

const update = process.argv.includes("--update");
if (update) {
  for (const row of rows.slice(1)) {
    if (!row[idCol]) continue;
    row[btCol] = [...(declared.get(row[idCol]) ?? [])].sort().join(" ");
  }
  writeFileSync(CSV, toCsv(rows));
  console.log(`[us-map] browser_test column rewritten from ${declared.size} mapped story(ies).`);
  process.exit(problems.length > 0 ? 1 : 0);
}

// Both directions, so neither file can drift silently.
for (const row of rows.slice(1)) {
  const id = row[idCol];
  if (!id) continue;
  const inCsv = (row[btCol] ?? "").split(/\s+/).filter(Boolean).sort().join(" ");
  const inSpecs = [...(declared.get(id) ?? [])].sort().join(" ");
  if (inCsv !== inSpecs) {
    problems.push(
      `${id}: CSV says "${inCsv || "(none)"}" but the specs declare "${inSpecs || "(none)"}". ` +
        `Run \`npm run check:us-map -- --update\`.`,
    );
  }
}

if (problems.length === 0) {
  const total = rows.length - 1;
  console.log(`[us-map] ok — ${declared.size}/${total} user stories have browser coverage`);
  process.exit(0);
}

console.error(`\n[us-map] ${problems.length} mapping problem(s):\n`);
for (const p of problems) console.error(`  ✖ ${p}`);
console.error("");
process.exit(1);
