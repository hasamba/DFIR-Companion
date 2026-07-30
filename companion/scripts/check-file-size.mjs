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
 * The ledger only shrinks. `--update` rewrites it, and it refuses to raise any recorded number —
 * so decomposition work re-records smaller values, while a PR that inflates a big file has to
 * explain itself rather than quietly bumping a threshold.
 *
 *   node scripts/check-file-size.mjs            # gate
 *   node scripts/check-file-size.mjs --update   # re-record after shrinking a file
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

function walk(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) out.push(...walk(full));
    else if (name.endsWith(".ts")) out.push(full);
  }
  return out;
}

const sizes = new Map();
for (const f of walk(SRC)) {
  sizes.set(relative(SRC, f).replace(/\\/g, "/"), readFileSync(f, "utf8").split("\n").length);
}

const ledger = existsSync(LEDGER) ? JSON.parse(readFileSync(LEDGER, "utf8")) : {};

if (process.argv.includes("--update")) {
  const next = {};
  let raised = null;
  for (const [path, lines] of [...sizes].sort()) {
    if (lines <= SOFT_LIMIT) continue;
    // Never let --update be the way a file gets bigger.
    if (ledger[path] !== undefined && lines > ledger[path]) raised = { path, from: ledger[path], to: lines };
    next[path] = lines;
  }
  if (raised) {
    console.error(
      `\n[size] refusing to update: ${raised.path} grew ${raised.from} -> ${raised.to} lines.\n` +
        "[size] The ledger only shrinks. Split the file, or argue for the growth in review and edit\n" +
        "[size] scripts/file-size-ledger.json by hand with a note in the PR.",
    );
    process.exit(1);
  }
  writeFileSync(LEDGER, `${JSON.stringify(next, null, 2)}\n`);
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
