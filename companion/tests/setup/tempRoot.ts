import { rm, readdir } from "node:fs/promises";

/**
 * Vitest globalSetup — removes the per-run temp root created in vitest.config.ts (issue #173).
 *
 * ~147 test files call mkdtemp() and only 8 of them ever clean up, so every run used to strand a
 * few thousand `dfir-*` directories in the OS temp dir. They accumulated to 388,954 before this
 * was noticed. That is not what makes tests time out (measured: ~0.2ms extra per mkdtemp even at
 * that scale), but it is real garbage: ~520k files of NTFS metadata that nothing ever collects.
 *
 * Rather than migrate 139 files to a cleanup helper — a large diff that regresses the moment
 * someone writes a bare mkdtemp() — vitest.config.ts points TEMP/TMP/TMPDIR at ONE per-run
 * directory for the whole worker pool. Node's os.tmpdir() reads those on every call, so every
 * existing mkdtemp(join(tmpdir(), ...)) lands inside it with no test change at all, and future
 * tests are covered for free. This hook then deletes that single root when the run ends.
 *
 * Per-run (not shared) matters: two suites running concurrently — which is how #173 was
 * originally observed — get separate roots and cannot delete each other's directories.
 */
const REMOVE_ATTEMPTS = 5;
const RETRY_DELAY_MS = 200;

const delay = (ms: number) => new Promise((r) => setTimeout(r, ms));

export async function teardown(): Promise<void> {
  const root = process.env.DFIR_TEST_TMP_ROOT;
  if (!root) return;

  // Windows strands handles briefly after a process exits (Dropbox/AV/indexer mid-scan), so a
  // single rm can lose to ENOTEMPTY/EBUSY on a tree this size. Retry rather than fail the run —
  // a leftover temp dir must never be the reason a green suite reports failure.
  for (let attempt = 1; attempt <= REMOVE_ATTEMPTS; attempt++) {
    try {
      await rm(root, { recursive: true, force: true });
      return;
    } catch (err) {
      if (attempt === REMOVE_ATTEMPTS) {
        let leftover = "";
        try {
          leftover = ` (${(await readdir(root)).length} entries left)`;
        } catch {
          // Root is already gone or unreadable — nothing useful to report.
        }
        console.warn(
          `[tempRoot] could not remove the test temp root after ${REMOVE_ATTEMPTS} attempts: ` +
            `${root}${leftover} — ${(err as Error).message}`,
        );
        return;
      }
      await delay(RETRY_DELAY_MS * attempt);
    }
  }
}
