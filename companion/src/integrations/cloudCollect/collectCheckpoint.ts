// The checkpoint of one collection (#2311): checkpoint.json beside the manifest. Written atomically
// (tmp → fsync → rename → fsync dir) as the LAST step of every page commit.
//
// The manifest is the source of truth; the checkpoint is a fast summary for the panel plus the
// state the manifest does not hold (why a sub-window failed, which pages were imported). Resume
// re-derives every cursor from the manifest (collectReplay.ts), so a crash between the manifest line
// and the checkpoint write loses nothing.

import { atomicTempPath } from "../../storage/atomicWrite.js";
import type { CollectFs } from "./collectFs.js";
import type { CollectionPaths } from "./collectManifest.js";
import { basename, dirname } from "node:path";
import { initialSubWindows } from "./collectReplay.js";
import type { CollectionCheckpoint, CollectWindow, ManifestHeader } from "./collectTypes.js";

export async function writeCheckpoint(
  fs: CollectFs,
  paths: CollectionPaths,
  checkpoint: CollectionCheckpoint,
): Promise<void> {
  // #2402: a unique, atomicWrite-shaped temp name — two writers never share one, and a whole-case
  // export recognises an in-flight write instead of archiving it as case content.
  const tmp = atomicTempPath(paths.checkpoint);
  await fs.writeFileSync(tmp, `${JSON.stringify(checkpoint, null, 2)}\n`);
  await fs.rename(tmp, paths.checkpoint);
  await fs.fsyncDir(paths.dir);
}

function isWindow(value: unknown): value is CollectWindow {
  const w = value as Partial<CollectWindow> | null;
  return !!w && typeof w === "object" && typeof w.start === "string" && typeof w.end === "string";
}

function isCheckpoint(value: unknown): value is CollectionCheckpoint {
  if (!value || typeof value !== "object") return false;
  const v = value as Partial<CollectionCheckpoint>;
  return (
    v.version === 1 &&
    typeof v.collectionId === "string" &&
    typeof v.caseId === "string" &&
    typeof v.accountId === "string" &&
    typeof v.provider === "string" &&
    typeof v.status === "string" &&
    isWindow(v.window) &&
    Array.isArray(v.sources) &&
    Array.isArray(v.subWindows) &&
    v.subWindows.every((sw) => !!sw && typeof sw === "object" && typeof sw.id === "string") &&
    Array.isArray(v.imported) &&
    Array.isArray(v.quarantined) &&
    Array.isArray(v.missing)
  );
}

export const REBUILT_CHECKPOINT_NOTE =
  "The collection's checkpoint file was missing or unreadable; it was rebuilt from the manifest. " +
  "Press Resume to continue — pages already in the case are not imported twice.";

/** A manifest header complete enough to rebuild a checkpoint from, for the collection in `dir`. */
function usableHeader(header: ManifestHeader | null, collectionId: string): header is ManifestHeader {
  return (
    !!header &&
    header.collectionId === collectionId &&
    typeof header.accountId === "string" &&
    typeof header.provider === "string" &&
    typeof header.startedAt === "string" &&
    Array.isArray(header.sources) &&
    header.sources.every((s) => typeof s === "string") &&
    isWindow(header.window)
  );
}

/**
 * #2402: the checkpoint rebuilt from the manifest, the collection's source of truth. Its state is
 * "interrupted" so the panel offers Resume; resume re-derives every sub-window from the manifest
 * (collectReplay.ts). `imported` starts empty, which is safe: each page's import first asks the
 * CASE whether that page already landed (collectImport.ts), so nothing is imported twice. Null
 * when the manifest header is missing, damaged, or names another collection.
 */
export function checkpointFromManifest(
  header: ManifestHeader | null,
  ids: { caseId: string; collectionId: string },
  now: string,
): CollectionCheckpoint | null {
  if (!usableHeader(header, ids.collectionId)) return null;
  return {
    version: 1,
    collectionId: header.collectionId,
    caseId: ids.caseId,
    accountId: header.accountId,
    provider: header.provider,
    sources: header.sources,
    window: header.window,
    status: "interrupted",
    stage: "network",
    subWindows: initialSubWindows(header.sources, header.window),
    imported: [],
    quarantined: [],
    missing: [],
    error: REBUILT_CHECKPOINT_NOTE,
    startedAt: header.startedAt,
    updatedAt: now,
  };
}

/** The case and collection a collection folder belongs to: <caseDir>/evidence/cloud/<id>. */
export function collectionIdsOf(dir: string): { caseId: string; collectionId: string } {
  return { caseId: basename(dirname(dirname(dirname(dir)))), collectionId: basename(dir) };
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
