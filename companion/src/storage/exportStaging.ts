import { mkdir, mkdtemp, readdir, rm, stat } from "node:fs/promises";
import { join } from "node:path";

// Where an export stages the private copy it packages or sends: the database snapshot of "Archive to
// ZIP…", the encrypted export's staging, the MCP delivery snapshot, a local tool run's input copy and
// output (#1857). Dotted and a level above the cases for the same reason import staging is: nothing
// that enumerates the cases root, and nothing that walks a case, may mistake it for case content.
export const EXPORT_STAGING_DIRNAME = ".export-staging";

// Each export removes its own folder in a finally block, on every path the process survives. A kill
// or a power loss mid-export does not run that finally, and the folder — often a full copy of a case
// database — stayed for good (#1851). This is the age past which a staging folder can only be such a
// leftover. A day is far longer than any export, so a slow one running concurrently is never touched.
// Import staging (analysis/caseRestore.ts) uses the same bound for the same reason.
export const EXPORT_STAGING_MAX_AGE_MS = 24 * 60 * 60 * 1000;

/**
 * Remove every entry of `stagingRoot` last modified before the max age. Best effort: an entry that
 * cannot be removed now is left for the next sweep, and a missing root is simply empty.
 * Returns how many entries were removed.
 */
export async function sweepStaleStaging(stagingRoot: string, now = Date.now()): Promise<number> {
  const cutoff = now - EXPORT_STAGING_MAX_AGE_MS;
  let removed = 0;
  for (const name of await readdir(stagingRoot).catch(() => [])) {
    const path = join(stagingRoot, name);
    const info = await stat(path).catch(() => null);
    if (!info || info.mtimeMs >= cutoff) continue;
    const ok = await rm(path, { recursive: true, force: true }).then(
      () => true,
      () => false,
    );
    if (ok) removed++;
  }
  return removed;
}

/**
 * A unique, private folder under `stagingRoot` for one export, created after sweeping stale
 * leftovers. The caller owns it and removes it when the export ends.
 */
export async function createStagingDir(stagingRoot: string, prefix: string): Promise<string> {
  await mkdir(stagingRoot, { recursive: true });
  await sweepStaleStaging(stagingRoot);
  return mkdtemp(join(stagingRoot, prefix));
}
