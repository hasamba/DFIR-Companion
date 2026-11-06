// Where a case's collections live and how the panel lists them (#2311).
//   <case>/evidence/cloud/<collectionId>/{manifest.jsonl, checkpoint.json, pages/, quarantine/}
// Evidence of the case being collected, beside its other evidence — never a temp folder.

import { randomBytes } from "node:crypto";
import { join } from "node:path";
import type { CollectFs } from "./collectFs.js";
import { collectionPaths, loadManifest } from "./collectManifest.js";
import { readCheckpoint, writeCheckpoint } from "./collectCheckpoint.js";
import type { CollectionCheckpoint, ManifestHeader } from "./collectTypes.js";

export const CLOUD_COLLECT_RESUME_ELSEWHERE =
  "Resume this cloud collection from the Cloud collection panel: it needs the account's credential opened again.";

const COLLECTION_ID = /^cc-\d{8}t\d{6}-[a-f0-9]{8}$/;

export function isCollectionId(value: unknown): value is string {
  return typeof value === "string" && COLLECTION_ID.test(value);
}

/** A new collection id: sortable by start time, unguessable suffix. */
export function newCollectionId(at: Date = new Date()): string {
  const stamp = at.toISOString().replace(/[-:]/g, "").slice(0, 15).toLowerCase(); // 20261105t101500
  return `cc-${stamp}-${randomBytes(4).toString("hex")}`;
}

export function collectionsRoot(caseDir: string): string {
  return join(caseDir, "evidence", "cloud");
}

/** What the panel shows for one collection. No secrets: the manifest and checkpoint hold none. */
export interface CollectionSummary {
  checkpoint: CollectionCheckpoint;
  header: Pick<ManifestHeader, "accountName" | "accountRef" | "caller" | "startedAt"> | null;
  pages: number;
  bytes: number;
}

export async function readCollection(fs: CollectFs, dir: string): Promise<CollectionSummary | null> {
  const paths = collectionPaths(dir);
  const checkpoint = await readCheckpoint(fs, paths);
  if (!checkpoint) return null;
  const manifest = await loadManifest(fs, paths).catch(() => null);
  const h = manifest?.header;
  return {
    checkpoint,
    header: h
      ? { accountName: h.accountName, accountRef: h.accountRef, caller: h.caller, startedAt: h.startedAt }
      : null,
    pages: manifest?.pages.length ?? 0,
    bytes: manifest?.pages.reduce((n, p) => n + p.bytes, 0) ?? 0,
  };
}

/** Every collection of a case, newest first. */
export async function listCollections(fs: CollectFs, caseDir: string): Promise<CollectionSummary[]> {
  const root = collectionsRoot(caseDir);
  const ids = (await fs.readdir(root)).filter(isCollectionId).sort().reverse();
  const out: CollectionSummary[] = [];
  for (const id of ids) {
    const summary = await readCollection(fs, join(root, id));
    if (summary) out.push(summary);
  }
  return out;
}

/**
 * Startup: a collection still marked running belongs to a process that is gone. It is marked
 * interrupted — never resumed here. Resume is the analyst's, from the panel, with the credential.
 */
export async function markInterruptedCollections(
  fs: CollectFs,
  caseDir: string,
  now: () => string,
): Promise<number> {
  let marked = 0;
  for (const summary of await listCollections(fs, caseDir)) {
    if (summary.checkpoint.status !== "running") continue;
    const dir = join(collectionsRoot(caseDir), summary.checkpoint.collectionId);
    await writeCheckpoint(fs, collectionPaths(dir), {
      ...summary.checkpoint,
      status: "interrupted",
      updatedAt: now(),
    });
    marked++;
  }
  return marked;
}
