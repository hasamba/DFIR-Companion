import { lstat, readdir, unlink } from "node:fs/promises";
import { join } from "node:path";
import { isAtomicWriteTempPath } from "./atomicWrite.js";
import { EXPORT_STAGING_MAX_AGE_MS } from "./exportStaging.js";

/**
 * Remove atomic-write temp files left at the TOP LEVEL of `root` by a process that died mid-write
 * (#2770): a case archive killed by a crash, OOM or forced shutdown never reaches the catch that
 * unlinks its `<name>.zip.<uuid>.tmp`.
 *
 * Deliberately narrow, because the cases root holds evidence:
 * - only names matching the uuid-suffixed atomic-write shape, never a bare ".tmp";
 * - only regular files, checked with lstat, so a symlink is never followed or removed;
 * - no recursion into case folders;
 * - only files a day old or more, so a write still in flight (this or another process) is never hit.
 *
 * Best effort: an entry that cannot be removed now is left for the next start, and a missing root is
 * simply empty. Returns how many files were removed.
 */
export async function sweepStaleAtomicTemps(root: string, now = Date.now()): Promise<number> {
  const cutoff = now - EXPORT_STAGING_MAX_AGE_MS;
  let removed = 0;
  for (const name of await readdir(root).catch(() => [])) {
    if (!isAtomicWriteTempPath(name)) continue;
    const path = join(root, name);
    const info = await lstat(path).catch(() => null);
    if (!info || !info.isFile() || info.mtimeMs >= cutoff) continue;
    const ok = await unlink(path).then(
      () => true,
      () => false,
    );
    if (ok) removed++;
  }
  return removed;
}
