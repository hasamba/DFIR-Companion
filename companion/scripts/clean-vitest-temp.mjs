// Remove orphaned Vite/Vitest temp config files (e.g. vitest.config.ts.timestamp-<n>-<hash>.mjs).
// Vite transpiles the TS config to a temp .mjs, imports it, then unlinks it — but on Windows in a
// synced folder (Dropbox/OneDrive) the sync client/AV briefly locks the file as Vite deletes it, so
// the temp is left behind and they accumulate one-per-run. Wired as `pretest` so `npm test` clears
// last run's leftovers. Always safe — they're regenerated each run. Matches the `*.timestamp-*.mjs`
// .gitignore rule.
import { readdirSync, rmSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";

const root = fileURLToPath(new URL("..", import.meta.url)); // the package dir (scripts/ lives under it)
let removed = 0;
for (const name of readdirSync(root)) {
  if (!/\.timestamp-.*\.mjs$/.test(name)) continue;
  try {
    rmSync(join(root, name));
    removed++;
  } catch {
    // Locked right now (Dropbox/AV mid-scan) — it'll be cleared on a later run.
  }
}
if (removed) console.log(`cleaned ${removed} stale vite/vitest temp file(s)`);
