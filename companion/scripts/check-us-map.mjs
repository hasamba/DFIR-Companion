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
//   node scripts/check-us-map.mjs            # verify
//   node scripts/check-us-map.mjs --update   # rewrite the CSV column from the specs

import { readFileSync, writeFileSync, readdirSync, statSync } from "node:fs";
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

const rows = parseCsv(readFileSync(CSV, "utf8"));
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
