// A case's collections as the collector-footprint matcher sees them (#2487): per collection, the
// identity each run talked to the cloud as and when. Built from the manifest (the evidence record)
// and the checkpoint; analysis/cloudCollectorFootprint.ts does the matching.
//
// SPANS. A run starts at the header's `startedAt` or a resume line's `at`, with the caller that line
// records (a resume line without one — written before #2487 — gives an unmatched span: credentials
// can change between runs). It ends at the end of its network stage, recorded in the checkpoint's
// `networkSpans`. Without that record (a crash mid-network, an older collection, a checkpoint rebuilt
// from the manifest): a collection still running ends at its checkpoint's `updatedAt`, which every
// sub-window change refreshes during the network stage; otherwise at the run's last saved page.
//
// CACHE. Every call re-lists the case's collections, so a new or advancing run is seen at once; a
// collection's parsed run is reused while its manifest's and checkpoint's mtime+size are unchanged.

import { stat } from "node:fs/promises";
import { join } from "node:path";
import type { CollectorRun, CollectorSpan } from "../../analysis/cloudCollectorFootprint.js";
import type { CollectFs } from "./collectFs.js";
import { collectionPaths, loadManifest, type LoadedManifest } from "./collectManifest.js";
import { readCheckpoint } from "./collectCheckpoint.js";
import { collectionsRoot, isCollectionId } from "./collectStore.js";
import type { CollectionCheckpoint } from "./collectTypes.js";

interface Segment {
  at: string;
  caller?: string;
  lastPage?: string;
}

/** The runs of one collection, in manifest order, with the pages each one saved. */
function segmentsOf(manifest: LoadedManifest): Segment[] {
  const segments: Segment[] = [];
  for (const entry of manifest.entries) {
    if (entry.type === "header") segments.push({ at: entry.startedAt, caller: entry.caller });
    else if (entry.type === "resume")
      segments.push({ at: entry.at, ...(entry.caller ? { caller: entry.caller } : {}) });
    else if (entry.type === "page" && segments.length) {
      const seg = segments[segments.length - 1];
      if (!seg.lastPage || entry.retrievedAt > seg.lastPage) seg.lastPage = entry.retrievedAt;
    }
  }
  return segments;
}

function segmentEnd(seg: Segment, last: boolean, cp: CollectionCheckpoint | null): string {
  const recorded = cp?.networkSpans?.find((s) => s.from === seg.at)?.to;
  if (recorded) return recorded;
  if (last && cp?.status === "running" && cp.updatedAt) return cp.updatedAt;
  return seg.lastPage ?? seg.at;
}

/** One collection's run spans. Null when the manifest has no usable header. Pure. */
export function collectorRunOf(
  manifest: LoadedManifest,
  cp: CollectionCheckpoint | null,
): CollectorRun | null {
  const header = manifest.header;
  if (!header || typeof header.startedAt !== "string" || typeof header.provider !== "string") return null;
  const segments = segmentsOf(manifest);
  const spans: CollectorSpan[] = [];
  segments.forEach((seg, i) => {
    const caller = typeof seg.caller === "string" ? seg.caller.trim() : "";
    if (!caller || caller === "unknown") return;
    spans.push({ from: seg.at, to: segmentEnd(seg, i === segments.length - 1, cp), caller });
  });
  return { collectionId: header.collectionId, provider: header.provider, spans };
}

/** A file's change stamp (mtime + size), or "" when it is missing. */
export type FileStamp = (path: string) => Promise<string>;

const nodeStamp: FileStamp = async (path) => {
  try {
    const s = await stat(path);
    return `${s.mtimeMs}:${s.size}`;
  } catch {
    return "";
  }
};

/** `runsFor(caseDir)`: every readable collection's runs. A damaged collection is skipped, never thrown. */
export function createCollectorRunReader(
  fs: CollectFs,
  stampOf: FileStamp = nodeStamp,
): (caseDir: string) => Promise<CollectorRun[]> {
  const cache = new Map<string, { key: string; run: CollectorRun | null }>();
  const readOne = async (dir: string): Promise<CollectorRun | null> => {
    const paths = collectionPaths(dir);
    const key = `${await stampOf(paths.manifest)}|${await stampOf(paths.checkpoint)}`;
    const hit = cache.get(dir);
    if (hit && hit.key === key) return hit.run;
    const run = collectorRunOf(await loadManifest(fs, paths), await readCheckpoint(fs, paths));
    cache.set(dir, { key, run });
    return run;
  };
  return async (caseDir) => {
    const root = collectionsRoot(caseDir);
    const out: CollectorRun[] = [];
    for (const id of (await fs.readdir(root)).filter(isCollectionId)) {
      const run = await readOne(join(root, id)).catch(() => null);
      if (run?.spans.length) out.push(run);
    }
    return out;
  };
}
