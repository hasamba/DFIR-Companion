import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";
import type { TimelineDiff } from "./timelineDiff.js";
import type { IocsDiff } from "./iocsDiff.js";

// Lightweight per-case record of the LAST import: when it ran, the detected kind/file, and what it
// added to (or merged in) the forensic timeline. Kept in a side file (`state/import-meta.json`) so
// the dashboard can show "last import 3 min ago - +N new events" and a what-was-added view above
// the timeline. This is the timeline analog of synth-meta.json (the findings what-changed view).
// NOT part of InvestigationState; written by the unified /import route after the importer completes.

const diffEventSchema = z.object({
  timestamp: z.string().catch(""),
  description: z.string().catch(""),
  severity: z.string().catch("Info"),
});

const diffIocSchema = z.object({
  value: z.string().catch(""),
  type: z.string().catch("other"),
});

export const importMetaSchema = z.object({
  lastImportedAt: z.string().catch(""),
  lastImportKind: z.string().catch(""),
  lastImportFile: z.string().catch(""),
  // Forensic-timeline diff (events the import added / correlation absorbed).
  addedCount: z.number().catch(0),     // true total added (the detail list may be capped)
  removedCount: z.number().catch(0),   // true total absorbed/merged by correlation
  lastDiff: z.object({
    added: z.array(diffEventSchema).catch([]),
    removed: z.array(diffEventSchema).catch([]),
  }).nullable().catch(null),
  // IOC diff (indicators the import added). Older import-meta.json files predate these — the
  // .catch defaults make them load cleanly as "no IOC change".
  iocsAddedCount: z.number().catch(0),
  iocsRemovedCount: z.number().catch(0),
  iocsDiff: z.object({
    added: z.array(diffIocSchema).catch([]),
    removed: z.array(diffIocSchema).catch([]),
  }).nullable().catch(null),
});

export type ImportMeta = z.infer<typeof importMetaSchema>;

const EMPTY: ImportMeta = {
  lastImportedAt: "", lastImportKind: "", lastImportFile: "",
  addedCount: 0, removedCount: 0, lastDiff: null,
  iocsAddedCount: 0, iocsRemovedCount: 0, iocsDiff: null,
};

// Cap how many added/removed events we store in the detail list — a single import can add
// hundreds of events. The banner shows the true total (addedCount); the list (and the dashboard's
// per-row "new" highlight that reads it) covers the first N to keep the side file small.
const MAX_LISTED = 500;

export interface ImportRecord {
  kind: string;   // detected import kind: "thor" | "siem" | "chainsaw" | ...
  file: string;   // stored filename of the imported evidence
  diff: TimelineDiff;   // forensic-timeline diff
  iocsDiff: IocsDiff;   // IOC diff
}

export class ImportMetaStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "import-meta.json");
  }

  async load(caseId: string): Promise<ImportMeta> {
    try {
      return importMetaSchema.parse(JSON.parse(await readFile(this.path(caseId), "utf8")));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return { ...EMPTY };
      throw err;
    }
  }

  // Record a completed import: stamp the time, the kind/file, and the (capped) timeline diff.
  async record(caseId: string, rec: ImportRecord, at: string = new Date().toISOString()): Promise<ImportMeta> {
    const meta: ImportMeta = {
      lastImportedAt: at,
      lastImportKind: rec.kind,
      lastImportFile: rec.file,
      addedCount: rec.diff.added.length,
      removedCount: rec.diff.removed.length,
      lastDiff: {
        added: rec.diff.added.slice(0, MAX_LISTED),
        removed: rec.diff.removed.slice(0, MAX_LISTED),
      },
      iocsAddedCount: rec.iocsDiff.added.length,
      iocsRemovedCount: rec.iocsDiff.removed.length,
      iocsDiff: {
        added: rec.iocsDiff.added.slice(0, MAX_LISTED),
        removed: rec.iocsDiff.removed.slice(0, MAX_LISTED),
      },
    };
    await atomicWrite(this.path(caseId), JSON.stringify(meta, null, 2));
    return meta;
  }
}
