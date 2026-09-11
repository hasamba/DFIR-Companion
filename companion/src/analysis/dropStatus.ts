import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";
import { isSafeDropRelpath } from "../storage/dropRelpath.js";

// Per-case record of the LAST drop-folder sweep that did anything: when it ran, the absolute drop
// path (so the dashboard can tell the analyst where to drop), and the imported / failed files. Kept
// in a side file (`state/drop-status.json`) so the live "📥 Drop: N imported, M failed" banner
// survives a page reload (it's backed by GET /cases/:id/drop-status). The drop analog of
// import-meta.json. NOT part of InvestigationState; NOT in SNAPSHOT_STATE_FILES (transient/machine).

const failureSchema = z.object({
  relpath: z.string().catch(""),
  reason: z.string().catch(""),
});

// A raw binary (EVTX/PCAP) waiting on an external tool: it can't be imported as text, so instead of
// failing it we surface it as "pending" so the dashboard can offer "Run <tool>" / "Configure <tool>".
//
// `relpath` is the one field here that is not merely displayed: POST /cases/:id/drop/run-pending
// joins it onto drop/ and reads, uploads and MOVES the result. And this file is not only written
// by the sweep — it rides inside a whole-case archive and import restores it verbatim (#919), so
// the list is attacker-controlled the moment an untrusted .dfircase is opened. An entry whose
// relpath could escape drop/ is therefore DROPPED at load, not coerced: a `.catch("")` here would
// hand the consumer `join(dropDir, "")`, which is the drop folder itself.
const pendingRawSchema = z.object({
  relpath: z.string().refine(isSafeDropRelpath),
  ext: z.string().catch(""),
  suggestedTool: z.string().nullable().catch(null),
  configured: z.boolean().catch(false),
});
const pendingRawListSchema = z
  .array(z.unknown())
  .catch([])
  .transform((entries) =>
    entries.flatMap((entry) => {
      const parsed = pendingRawSchema.safeParse(entry);
      return parsed.success ? [parsed.data] : [];
    }),
  );

export const dropStatusSchema = z.object({
  lastSweepAt: z.string().catch(""),
  dropPath: z.string().catch(""),
  importedCount: z.number().catch(0),
  failedCount: z.number().catch(0),
  imported: z.array(z.string()).catch([]),
  failed: z.array(failureSchema).catch([]),
  pendingRawInputs: pendingRawListSchema,
});

export type DropFailure = z.infer<typeof failureSchema>;
export type PendingRawInput = z.infer<typeof pendingRawSchema>;
export type DropStatus = z.infer<typeof dropStatusSchema>;

const EMPTY: DropStatus = {
  lastSweepAt: "",
  dropPath: "",
  importedCount: 0,
  failedCount: 0,
  imported: [],
  failed: [],
  pendingRawInputs: [],
};

// One sweep can drop hundreds of files; cap the detail lists (the counts stay exact).
const MAX_LISTED = 200;

export interface DropSweep {
  dropPath: string;
  imported: string[]; // relpaths imported OK this sweep
  failed: DropFailure[]; // relpaths that failed + the reason
  pendingRawInputs?: PendingRawInput[]; // raw EVTX/PCAP awaiting an external tool run
}

export class DropStatusStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "drop-status.json");
  }

  async load(caseId: string): Promise<DropStatus> {
    try {
      return dropStatusSchema.parse(JSON.parse(await readFile(this.path(caseId), "utf8")));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return { ...EMPTY };
      throw err;
    }
  }

  async record(caseId: string, sweep: DropSweep, at: string = new Date().toISOString()): Promise<DropStatus> {
    const status: DropStatus = {
      lastSweepAt: at,
      dropPath: sweep.dropPath,
      importedCount: sweep.imported.length,
      failedCount: sweep.failed.length,
      imported: sweep.imported.slice(0, MAX_LISTED),
      failed: sweep.failed.slice(0, MAX_LISTED),
      pendingRawInputs: (sweep.pendingRawInputs ?? []).slice(0, MAX_LISTED),
    };
    await atomicWrite(this.path(caseId), JSON.stringify(status, null, 2));
    return status;
  }

  async clear(caseId: string): Promise<DropStatus> {
    const status: DropStatus = { ...EMPTY };
    await atomicWrite(this.path(caseId), JSON.stringify(status, null, 2));
    return status;
  }
}
