#!/usr/bin/env node
/**
 * Prettier, applied to the files THIS branch changed — but only where it cannot make things worse
 * (issue #385).
 *
 * WHY NOT THE WHOLE TREE. Prettier disagrees with 877 of the companion's 946 TypeScript files —
 * ~60,000 lines of pure reflow, at every print width tried. Reformatting all of it in one commit
 * would rewrite the hand-wrapped layout the codebase is written in, bury the rest of #385 under
 * unreviewable churn, and rot every open branch.
 *
 * WHAT THE GATE ACTUALLY ASSERTS. For each file the branch touches, one of three things is true:
 *
 *   - the file is NEW              -> it must be formatted. New code is Prettier-clean from birth.
 *   - it was formatted before      -> it must still be formatted. You may not un-format clean code.
 *   - it was NOT formatted before  -> skipped. Your change is not the reason it is unformatted.
 *
 * The third case is what keeps the gate honest. Requiring a whole-file reformat because someone
 * deleted an unused import turns a two-line fix into a four-hundred-line diff, which is how a
 * format gate ends up disabled. The invariant here — "the set of Prettier-clean files never
 * shrinks" — needs no baseline file, has no bootstrap exception (this script's own introducing PR
 * passes under exactly the same rule as every later one), and cannot rot.
 *
 * Converting a legacy file is a deliberate act: run `npm run format` on it, ideally in its own
 * commit. Once converted, this gate keeps it converted forever.
 *
 * Usage:
 *   node scripts/format-changed.mjs --check     # CI gate
 *   node scripts/format-changed.mjs --write     # format the changed files in place
 *
 * `--write` deliberately ignores the was-it-clean-before test: when you ASK to format, you get the
 * whole file. Only the gate is conservative.
 *
 * The changed set is the union of everything differing from the merge base with the default branch
 * (the branch's own work) and everything modified or untracked in the working tree (so it works
 * before you commit). On the default branch itself there is no merge base, so only the working-tree
 * half applies — correct, since master's history is already gated.
 */
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const COMPANION = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const REPO = resolve(COMPANION, "..");
const PRETTIER = resolve(COMPANION, "node_modules/prettier/bin/prettier.cjs");

// Extensions Prettier owns here. Deliberately narrow: .md is excluded because the repo's markdown
// (README, USER_MANUAL, CHANGELOG) is hand-laid-out prose with alignment Prettier would destroy.
const EXTENSIONS = /\.(ts|tsx|mts|cts|js|mjs|cjs|jsx|json|css|html|yml|yaml)$/;

function git(args, { allowFail = false, buffer = false } = {}) {
  try {
    return execFileSync("git", args, {
      cwd: REPO,
      encoding: buffer ? "buffer" : "utf8",
      maxBuffer: 64 * 1024 * 1024,
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (err) {
    if (allowFail) return null;
    throw err;
  }
}

/** The commit this branch forked from, or null when there is nothing to compare against. */
function mergeBase() {
  const head = git(["rev-parse", "--abbrev-ref", "HEAD"], { allowFail: true })?.trim();
  for (const base of ["origin/master", "master", "origin/main", "main"]) {
    if (base === head || base.endsWith(`/${head}`)) continue; // don't diff a branch against itself
    if (!git(["rev-parse", "--verify", "--quiet", base], { allowFail: true })) continue;
    const mb = git(["merge-base", "HEAD", base], { allowFail: true });
    if (mb) return mb.trim();
  }
  return null;
}

const BASE = mergeBase();

function changedFiles() {
  const out = new Set();
  const add = (text) => {
    for (const line of (text ?? "").split("\n")) {
      const p = line.trim();
      if (p) out.add(p);
    }
  };
  // ACMR: added / copied / modified / renamed. Deleted files have nothing to format.
  if (BASE) add(git(["diff", "--name-only", "--diff-filter=ACMR", BASE, "HEAD"], { allowFail: true }));
  add(git(["diff", "--name-only", "--diff-filter=ACMR", "HEAD"], { allowFail: true })); // unstaged
  add(git(["diff", "--name-only", "--diff-filter=ACMR", "--cached"], { allowFail: true })); // staged
  add(git(["ls-files", "--others", "--exclude-standard"], { allowFail: true })); // untracked

  return [...out]
    .filter((p) => p.startsWith("companion/") && EXTENSIONS.test(p))
    .map((p) => resolve(REPO, p))
    .filter((p) => existsSync(p)) // a rename leaves the old path in the diff
    .map((p) => relative(COMPANION, p));
}

function prettier(args, { quiet = false } = {}) {
  execFileSync(process.execPath, [PRETTIER, ...args], {
    cwd: COMPANION,
    stdio: quiet ? "pipe" : "inherit",
  });
}

/**
 * Does the gate hold this file to the standard? Yes when the file is NEW (new code is
 * Prettier-clean from birth) or when it was already Prettier-clean at the merge base (you may not
 * un-format clean code). No when it was already unformatted — your change is not the reason.
 */
function mustBeFormatted(relPath) {
  if (!BASE) return true; // no baseline to appeal to; hold the file to the standard
  const repoPath = `companion/${relPath}`.replace(/\\/g, "/");
  const before = git(["show", `${BASE}:${repoPath}`], { allowFail: true, buffer: true });
  if (before === null) return true; // new file — must be formatted
  try {
    // --stdin-filepath is what tells Prettier which parser to use for the piped content.
    execFileSync(process.execPath, [PRETTIER, "--check", "--stdin-filepath", relPath], {
      cwd: COMPANION,
      input: before,
      stdio: ["pipe", "pipe", "pipe"],
    });
    return true;
  } catch {
    return false;
  }
}

const write = process.argv.includes("--write");
const files = changedFiles();

if (files.length === 0) {
  console.log(`[format] no changed files to ${write ? "format" : "check"}`);
  process.exit(0);
}

if (write) {
  console.log(`[format] formatting ${files.length} changed file(s)`);
  try {
    prettier(["--write", "--ignore-unknown", ...files]);
  } catch {
    process.exit(1);
  }
  process.exit(0);
}

// Gate: hold each file to the standard it already met.
const enforced = files.filter((f) => mustBeFormatted(f));
const grandfathered = files.length - enforced.length;

if (grandfathered > 0) {
  console.log(
    `[format] ${grandfathered} changed file(s) were already unformatted before this branch — skipped.\n` +
      "[format] Run `npm run format` to convert one; the gate then keeps it converted.",
  );
}

if (enforced.length === 0) {
  console.log("[format] ok — no new or already-formatted files to check");
  process.exit(0);
}

console.log(`[format] checking ${enforced.length} new or already-formatted file(s)`);
try {
  prettier(["--check", "--ignore-unknown", ...enforced]);
} catch {
  console.error(
    "\n[format] The files above are new, or were Prettier-clean before this branch and are not any\n" +
      "[format] more. Run `npm run format` in companion/ to fix them.",
  );
  process.exit(1);
}
