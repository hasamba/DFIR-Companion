// The checkpoint of one collection (#2311): checkpoint.json beside the manifest. Written atomically
// (tmp → fsync → rename → fsync dir) as the LAST step of every page commit.
//
// The manifest is the source of truth; the checkpoint is a fast summary for the panel plus the
// state the manifest does not hold (why a sub-window failed, which pages were imported). Resume
// re-derives every cursor from the manifest (collectReplay.ts), so a crash between the manifest line
// and the checkpoint write loses nothing.

import type { CollectFs } from "./collectFs.js";
import type { CollectionPaths } from "./collectManifest.js";
import type { CollectionCheckpoint } from "./collectTypes.js";

export async function writeCheckpoint(
  fs: CollectFs,
  paths: CollectionPaths,
  checkpoint: CollectionCheckpoint,
): Promise<void> {
  const tmp = `${paths.checkpoint}.tmp`;
  await fs.writeFileSync(tmp, `${JSON.stringify(checkpoint, null, 2)}\n`);
  await fs.rename(tmp, paths.checkpoint);
  await fs.fsyncDir(paths.dir);
}

function isCheckpoint(value: unknown): value is CollectionCheckpoint {
  if (!value || typeof value !== "object") return false;
  const v = value as Partial<CollectionCheckpoint>;
  return (
    v.version === 1 &&
    typeof v.collectionId === "string" &&
    typeof v.caseId === "string" &&
    Array.isArray(v.subWindows) &&
    Array.isArray(v.imported)
  );
}

/** The checkpoint, or null when it is missing or unreadable (the manifest still has everything). */
export async function readCheckpoint(
  fs: CollectFs,
  paths: CollectionPaths,
): Promise<CollectionCheckpoint | null> {
  try {
    if (!(await fs.exists(paths.checkpoint))) return null;
    const parsed: unknown = JSON.parse((await fs.readFile(paths.checkpoint)).toString("utf8"));
    return isCheckpoint(parsed) ? parsed : null;
  } catch {
    return null;
  }
}
