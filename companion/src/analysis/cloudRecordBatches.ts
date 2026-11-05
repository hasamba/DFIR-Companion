// Which cloud-record ledger batches are live, so Undo / Redo keep the ledger in step with the case
// (#2301). One small JSON side file per case (state/cloud-record-batches.json):
//
//  - pending: batches an import committed that no undo checkpoint has claimed yet, with the import's
//    stored file name. The import's checkpoint push (caseAppliers.ts) claims the pending batches of
//    its own file, so Undo of that checkpoint knows exactly which batches to forget.
//  - inactive: batches an Undo forgot. The ledger ignores their rows, so a re-import after Undo adds
//    the records again; Redo makes the batch live again. Rows are never deleted, so Redo needs no copy.
//
// Imports run one at a time per case (importLock), which is what makes claim-by-file-name exact.

import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";
import { StateLock } from "./stateLock.js";

interface BatchState {
  pending: Array<{ batch: string; label: string }>;
  inactive: string[];
}

// Bounds the side file: an import whose checkpoint was never pushed (a no-op) leaves its entry.
const PENDING_MAX = 64;

function normalize(raw: unknown): BatchState {
  const o = raw && typeof raw === "object" ? (raw as Record<string, unknown>) : {};
  const pending = Array.isArray(o.pending)
    ? o.pending.filter(
        (p): p is { batch: string; label: string } =>
          !!p && typeof p.batch === "string" && typeof p.label === "string",
      )
    : [];
  const inactive = Array.isArray(o.inactive)
    ? o.inactive.filter((b): b is string => typeof b === "string")
    : [];
  return { pending, inactive };
}

/** True when an undo checkpoint label (e.g. "m365 (0003_m365.json)") names this import's stored file. */
function labelNames(checkpointLabel: string, storedName: string): boolean {
  return checkpointLabel === storedName || checkpointLabel.endsWith(`(${storedName})`);
}

export class CloudRecordBatches {
  private readonly lock = new StateLock();

  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "cloud-record-batches.json");
  }

  async load(caseId: string): Promise<BatchState> {
    try {
      return normalize(JSON.parse(await readFile(this.path(caseId), "utf8")));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return { pending: [], inactive: [] };
      throw err;
    }
  }

  private async mutate<T>(
    caseId: string,
    fn: (s: BatchState) => { state: BatchState; result: T },
  ): Promise<T> {
    return this.lock.runExclusive(caseId, async () => {
      const { state, result } = fn(await this.load(caseId));
      await atomicWrite(this.path(caseId), JSON.stringify(state));
      return result;
    });
  }

  /** Notes a batch an import just committed, under the import's stored file name. */
  async notePending(caseId: string, batch: string, storedName: string): Promise<void> {
    await this.mutate(caseId, (s) => ({
      state: {
        ...s,
        pending: [...s.pending.filter((p) => p.batch !== batch), { batch, label: storedName }].slice(
          -PENDING_MAX,
        ),
      },
      result: undefined,
    }));
  }

  /** Takes the pending batches of the import a checkpoint label names. */
  async claimPending(caseId: string, checkpointLabel: string): Promise<string[]> {
    return this.mutate(caseId, (s) => {
      const claimed = s.pending.filter((p) => labelNames(checkpointLabel, p.label)).map((p) => p.batch);
      if (!claimed.length) return { state: s, result: [] };
      return {
        state: { ...s, pending: s.pending.filter((p) => !claimed.includes(p.batch)) },
        result: claimed,
      };
    });
  }

  /** Undo forgets (active false) and Redo remembers (active true) a set of batches. */
  async setActive(caseId: string, batches: readonly string[], active: boolean): Promise<void> {
    await this.mutate(caseId, (s) => {
      const rest = s.inactive.filter((b) => !batches.includes(b));
      return { state: { ...s, inactive: active ? rest : [...rest, ...batches] }, result: undefined };
    });
  }

  async inactive(caseId: string): Promise<Set<string>> {
    return new Set((await this.load(caseId)).inactive);
  }
}
