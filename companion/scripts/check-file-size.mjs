#!/usr/bin/env node
/**
 * File-size ratchet for src/ (issue #385, prerequisite for #384).
 *
 * A 6,166-line module is not a style problem — it is a review problem. Nobody reads the whole of
 * `analysis/pipeline.ts` before changing 20 lines of it, so nobody can see that their change
 * interacts with something 4,000 lines away. #384 decomposes it; this gate is what stops the next
 * one growing while that work is in flight, and what stops pipeline.ts creeping back up afterwards.
 *
 * TWO RULES:
 *   1. A file NOT in the ledger may not exceed SOFT_LIMIT lines. New code has a ceiling from day one.
 *   2. A file IN the ledger may not exceed the size recorded there. The 12 oversized files are
 *      frozen at today's length: you can shrink them freely, but not add to them.
 *
 * The ledger only shrinks. `--update` rewrites it and REFUSES to raise any recorded number, so
 * decomposition work re-records smaller values while a PR that inflates a big file has to explain
 * itself rather than quietly bumping a threshold.
 *
 * `--init` is the one way to raise a number, and it exists for exactly two moments: the first
 * recording, and re-baselining after merging a long-lived branch whose landed work legitimately
 * grew a ledgered file. It prints every raise it makes so they appear in the PR conversation
 * rather than only in the JSON diff. If you find yourself reaching for it during ordinary work,
 * the answer is to move the new code into its own module instead.
 *
 *   node scripts/check-file-size.mjs            # gate
 *   node scripts/check-file-size.mjs --update   # re-record after shrinking a file
 *   node scripts/check-file-size.mjs --init     # re-baseline; raises are printed, justify them
 */
import { readdirSync, readFileSync, statSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const COMPANION = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SRC = join(COMPANION, "src");
const LEDGER = join(COMPANION, "scripts", "file-size-ledger.json");

/**
 * 800 lines. Chosen from the tree, not from taste: 406 of the companion's 418 source files are
 * already under it, so it is the line that separates "how this codebase is normally written" from
 * "the dozen files that grew". A limit that most files already respect is a limit people can meet.
 */
const SOFT_LIMIT = 800;

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

const sizes = new Map();
for (const f of walk(SRC)) {
  sizes.set(relative(SRC, f).replace(/\\/g, "/"), readFileSync(f, "utf8").split("\n").length);
}

// ---------------------------------------------------------------------------------------------
// public/ — the half of the codebase that had no ceiling at all (#384).
//
// dashboard.html is 25,571 lines, of which 19,256 are JavaScript inside <script> tags and 3,231
// are CSS inside <style> tags. It is larger than pipeline.ts and server.ts combined and it lives
// outside companion/, so until now neither this gate nor check-imports.mjs had ever seen it — and
// it grew by 165 lines of script during the branch that added this paragraph.
//
// WHAT IS MEASURED IS THE CODE, NOT THE MARKUP. The ~3,000 lines of actual HTML in dashboard.html
// are not the problem; a 19k-line program hiding inside a markup file is. Budgeting the inline
// blocks separately also names the two extractions independently: script moves to public/js/
// modules, style moves to a stylesheet, and each shows up in the ledger as it shrinks.
// ---------------------------------------------------------------------------------------------
const PUBLIC = resolve(COMPANION, "..", "public");
const PUBLIC_JS = join(PUBLIC, "js");

// Extracted dashboard feature modules. All six are already under the limit, so they are held there.
for (const f of walk(PUBLIC_JS, ".js")) {
  sizes.set(
    `public/js/${relative(PUBLIC_JS, f).replace(/\\/g, "/")}`,
    readFileSync(f, "utf8").split("\n").length,
  );
}

// `<script>` without a src= is inline code; `<script src=…>` is a reference and is not counted.
const INLINE_JS = /<script(?![^>]*\ssrc=)[^>]*>([\s\S]*?)<\/script>/g;
const INLINE_CSS = /<style[^>]*>([\s\S]*?)<\/style>/g;
const countIn = (text, re) => {
  let lines = 0;
  for (const m of text.matchAll(re)) lines += m[1].split("\n").length;
  return lines;
};

for (const name of existsSync(PUBLIC) ? readdirSync(PUBLIC) : []) {
  if (!name.endsWith(".html")) continue;
  const text = readFileSync(join(PUBLIC, name), "utf8");
  sizes.set(`public/${name}#inline-js`, countIn(text, INLINE_JS));
  sizes.set(`public/${name}#inline-css`, countIn(text, INLINE_CSS));
}

const ledger = existsSync(LEDGER) ? JSON.parse(readFileSync(LEDGER, "utf8")) : {};

const init = process.argv.includes("--init");
if (init || process.argv.includes("--update")) {
  const next = {};
  const raises = [];
  const additions = [];
  for (const [path, lines] of [...sizes].sort()) {
    if (lines <= SOFT_LIMIT) continue;
    if (ledger[path] === undefined) additions.push(`${path}: ${lines}`);
    else if (lines > ledger[path]) raises.push({ path, from: ledger[path], to: lines });
    next[path] = lines;
  }
  // Never let --update be the way a file gets bigger; --init says the raise is deliberate.
  if (raises.length > 0 && !init) {
    console.error(`\n[size] refusing to update: ${raises.length} ledgered file(s) grew.`);
    for (const r of raises) console.error(`  ✖ ${r.path}: ${r.from} -> ${r.to} lines`);
    console.error(
      "\n[size] The ledger only shrinks. Split the file, or — if this is a re-baseline after merging\n" +
        "[size] landed work that legitimately grew it — use `--init` and justify each raise in the PR.",
    );
    process.exit(1);
  }
  writeFileSync(LEDGER, `${JSON.stringify(next, null, 2)}\n`);
  for (const r of raises) console.log(`[size] RAISED ${r.path}: ${r.from} -> ${r.to} lines`);
  for (const a of additions) console.log(`[size] added  ${a} lines`);
  console.log(`[size] recorded ${Object.keys(next).length} file(s) over ${SOFT_LIMIT} lines`);
  process.exit(0);
}

const failures = [];
const shrunk = [];
for (const [path, lines] of [...sizes].sort()) {
  const cap = ledger[path];
  if (cap === undefined) {
    if (lines > SOFT_LIMIT) {
      failures.push(`${path}: ${lines} lines exceeds the ${SOFT_LIMIT}-line limit for new files`);
    }
  } else if (lines > cap) {
    failures.push(`${path}: grew to ${lines} lines, ledger caps it at ${cap}`);
  } else if (lines < cap) {
    shrunk.push(`${path}: ${cap} -> ${lines}`);
  }
}
for (const path of Object.keys(ledger)) {
  if (!sizes.has(path)) shrunk.push(`${path}: deleted`);
}

if (shrunk.length > 0) {
  console.log(`[size] ${shrunk.length} ledger entr${shrunk.length === 1 ? "y" : "ies"} shrank:`);
  for (const s of shrunk) console.log(`  - ${s}`);
  console.log("[size] run `npm run check:size -- --update` to lock in the smaller numbers.");
}

if (failures.length > 0) {
  console.error(`\n[size] ${failures.length} file(s) over budget:`);
  for (const f of failures) console.error(`  ✖ ${f}`);
  console.error(
    "\n[size] Move the new code into its own module rather than growing one of these. The ledger is\n" +
      "[size] a freeze on the files that were already too big (see #384), not a budget to spend.",
  );
  process.exit(1);
}

console.log(`[size] ok — ${Object.keys(ledger).length} ledgered file(s), none grew`);
