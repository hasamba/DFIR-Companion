/**
 * The drop-folder batch's crash marker (#2540): `state/drop-batch-pending.jsonl`, one line per file
 * the batch has stored, removed once the batch's one settle and the rest of its tail are done.
 *
 * A batch defers the settle (dual-write → tagger → demote) until its last file is merged. A server
 * that dies in between leaves forensic rows that never crossed that seam — an Info row would stay
 * in the forensic timeline, the record the AI reads — and the next import's settle cannot see them
 * (it only settles rows new since its own snapshot). A leftover marker names those files; the next
 * sweep of the case settles their rows the way a live cloud collection recovers a page that
 * committed before a crash (routes/cloudCollectImporter.ts `settleLanded`): every step dedups by
 * id or is idempotent, so a recovery that itself dies is simply run again.
 *
 * Not recovered (best effort on the per-file path too): the batch's deferred super-row tags, its
 * coverage and weakness fold, its note for the files that added nothing, its import-meta record,
 * its undo step and its run record.
 */
import { appendFile, mkdir, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";

export const DROP_BATCH_MARKER = "drop-batch-pending.jsonl";

// A stored import name as caseStore writes it (`0001_<safe name>`); anything else is not ours.
const STORED_NAME = /^\d+_[\w.-]+$/;

export interface DropBatchMarker {
  /** Note one stored file of the batch in progress. */
  add(caseId: string, storedName: string): Promise<void>;
  /** The stored files of an unfinished batch, or null when none is pending. */
  read(caseId: string): Promise<string[] | null>;
  clear(caseId: string): Promise<void>;
}

export function createDropBatchMarker(store: CaseStore): DropBatchMarker {
  const pathOf = (caseId: string): string => join(store.stateDir(caseId), DROP_BATCH_MARKER);
  return {
    add: (caseId, storedName) => {
      const path = pathOf(caseId);
      return store.withCaseWrite(path, async () => {
        await mkdir(store.stateDir(caseId), { recursive: true });
        await appendFile(path, JSON.stringify({ storedName }) + "\n", "utf8");
      });
    },
    read: async (caseId) => {
      let text: string;
      try {
        text = await readFile(pathOf(caseId), "utf8");
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
        throw err;
      }
      return parseMarker(text);
    },
    clear: (caseId) => {
      const path = pathOf(caseId);
      return store.withCaseWrite(path, () => rm(path, { force: true }));
    },
  };
}

/** The marker's stored names; a torn last line (a crash mid-append) or a foreign line is skipped. */
export function parseMarker(text: string): string[] {
  const names: string[] = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    try {
      const v = (JSON.parse(line) as { storedName?: unknown }).storedName;
      if (typeof v === "string" && STORED_NAME.test(v) && !names.includes(v)) names.push(v);
    } catch {
      /* torn line */
    }
  }
  return names;
}
