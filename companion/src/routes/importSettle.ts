import { randomUUID } from "node:crypto";
import type { ForensicEvent, InvestigationState } from "../analysis/stateTypes.js";
import { diffTimeline, type TimelineDiff } from "../analysis/timelineDiff.js";
import { diffIocs, type IocsDiff } from "../analysis/iocsDiff.js";
import { getServerLogger } from "../logging/serverLogger.js";
import { formatImportSettled } from "../logging/importLog.js";
import { carryHostRenames } from "../analysis/hostRenameCarry.js";
import {
  rehomeSuperTimeline,
  renameLedgerChanged,
  type SuperRehomeStore,
} from "./importSettleRehomeSuper.js";

/**
 * The forensic / super-timeline seam that every import must cross after the importer has merged
 * its delta (ARCHITECTURE.md → "The forensic / super-timeline boundary"): merge-all has already
 * happened, so (1) the rows this import ADDED are dual-written into the super-timeline, the
 * superset that keeps Info telemetry, (2) the deterministic tagger gets its one chance to raise
 * high-value telemetry out of Info — its promotion window is the import that collected the row,
 * never a later run — and (3) demote removes whatever is still Info from the forensic timeline,
 * which is the only record the model reads. The diffs come from the POST-demote state, so "+N
 * events" counts graded signal, not telemetry.
 *
 * This used to be six inline copies (the generic import route twice, the streamed ingest, the hunt
 * collector, the two Velociraptor external-ingest paths) and ZERO copies on the dedicated
 * `import-*` routes, which called their
 * importer and resynthesized: an Info row from a dedicated route stayed in the forensic timeline
 * and reached the model, and never entered the super-timeline at all (#932 item 12 found it on
 * `/import-leapp`; #956 tracks the rest). One function, so a route cannot half-run the seam.
 *
 * `stateBefore` is the state captured under the import lock BEFORE the importer ran
 * (routes/importSection.ts) — the diff is only honest against that snapshot.
 *
 * A hostname rename the import taught the case re-homes the rows the case already held (#1495),
 * and the super-timeline's own copies of them — dual-written earlier, or Info rows that live only
 * there — are re-homed from the store's rows in the same settle (#1508), so both records show one
 * host. That pass is non-fatal like the dual-write: it changes which host a row is filed under,
 * never whether the row is in a record.
 *
 * The post-demote diffs are also the one place that knows what an import left behind, so this is
 * where the `[import] … done — forensic +N, super +M, IOCs +K` log line is written (#1438), with
 * `{ caseId }` so it lands in the case's own log too; `label` names the file when the caller has
 * it. An all-zero settle logs at DEBUG: the Velociraptor monitors settle on every poll, and an empty
 * poll must not fill the session log.
 */
export interface SettleDeps {
  stateStore: {
    load(caseId: string): Promise<InvestigationState>;
    save(state: InvestigationState): Promise<void>;
  };
  superTimelineStore?: {
    append(caseId: string, events: ForensicEvent[]): Promise<number>;
  } & Partial<SuperRehomeStore>;
  onSuperTimeline?: (caseId: string) => void;
  // Fired right after the importedAt/importBatchId stamp save below (#1174) — without it, dashboard
  // subscribers only learn about the new stamps whenever a LATER broadcast happens to fire (the
  // tagger, demote, or the resynthesis every caller triggers after settle returns), not at the
  // instant the stamps were actually persisted.
  onState?: (state: InvestigationState) => void;
  autoTagImported: (caseId: string, added: ForensicEvent[]) => Promise<void>;
  demoteForensicForCase: (caseId: string) => Promise<InvestigationState>;
}

export interface SettledImport {
  /** The case state after demote — what the forensic timeline holds now. */
  state: InvestigationState;
  /** Rows the super-timeline RETAINED from this import (0 when no store is wired). */
  superTimelineAddedCount: number;
  /** Forensic-timeline diff against `stateBefore`, computed post-demote. */
  timelineDiff: TimelineDiff;
  iocsDiff: IocsDiff;
}

export async function settleForensicImport(
  deps: SettleDeps,
  caseId: string,
  stateBefore: InvestigationState,
  label?: string,
): Promise<SettledImport> {
  let imported = await deps.stateStore.load(caseId);
  // Rows the case already held under a name this (or any earlier) import taught it was a former
  // one are re-homed here, before they are stamped, dual-written and tagged (#1495). A pure
  // recomputation from each row's own record name against the whole ledger, so it is safe to run
  // on every settle; it returns the same object when nothing differs.
  const carried = carryHostRenames(imported);
  imported = carried.state;
  // Select the added rows BY ID — exact. The time+description diff below is case-folded, so two
  // rows that differ only by case (two paths on a case-sensitive filesystem) counted as one there,
  // and the second was neither dual-written nor offered to the tagger. Ids are exact: a re-import
  // of the same evidence is absorbed by correlation's exact-duplicate pass into the existing row's
  // id before this runs, so a new id is a genuinely new row.
  const beforeIds = new Set(stateBefore.forensicTimeline.map((e) => e.id));
  let added = imported.forensicTimeline.filter((e) => !beforeIds.has(e.id));

  // #1157: stamp rows genuinely new to this case with WHEN the case received them and WHICH import
  // action did it — distinct from `timestamp`, the artifact's own recorded time. One instant, one
  // batch id, shared by every row this import added. Persisted BEFORE dual-write/tag/demote below:
  // both `autoTagImported` and `demoteForensicForCase` independently reload state from the store,
  // so an in-memory-only stamp would be silently discarded by their own reload/save cycles.
  if (added.length) {
    const importedAt = new Date().toISOString();
    const importBatchId = randomUUID();
    const addedIds = new Set(added.map((e) => e.id));
    imported = {
      ...imported,
      forensicTimeline: imported.forensicTimeline.map((e) =>
        addedIds.has(e.id) ? { ...e, importedAt, importBatchId } : e,
      ),
    };
    added = imported.forensicTimeline.filter((e) => addedIds.has(e.id));
  }
  // Saved when anything above changed the state: new rows stamped, or older rows re-homed by a
  // rename this import taught the case (a carry-only settle still has to persist and broadcast).
  if (added.length || carried.changed) {
    await deps.stateStore.save(imported);
    deps.onState?.(imported);
  }

  // The super-timeline's own copies follow the ledger (#1508). Either signal triggers it: a rename
  // whose old-name rows were all Info changes the ledger but moves no forensic row, and a forensic
  // row the carry moved has a copy in the store that must move with it.
  if (deps.superTimelineStore && (carried.changed || renameLedgerChanged(stateBefore, imported))) {
    await rehomeSuperCopies(deps, caseId, imported);
  }

  // Dual-write FIRST, from the pre-demote (now stamped) state.
  let superTimelineAddedCount = 0;
  if (deps.superTimelineStore && added.length) {
    try {
      superTimelineAddedCount = await deps.superTimelineStore.append(caseId, added);
      deps.onSuperTimeline?.(caseId);
    } catch {
      // Non-fatal by design: demote captures every row it removes into the super-timeline in
      // its own critical section and KEEPS the row in the forensic timeline when that capture
      // fails (composition/importIngest.ts demoteForensicForCase) — a row is never in neither
      // record. What this failure costs is the count above, which stays 0.
    }
    await deps.autoTagImported(caseId, added);
  }
  const state = await deps.demoteForensicForCase(caseId);
  const timelineDiff = diffTimeline(stateBefore.forensicTimeline, state.forensicTimeline);
  const iocsDiff = diffIocs(stateBefore.iocs, state.iocs);
  logImportSettled(caseId, label, {
    forensicAdded: timelineDiff.added.length,
    forensicRemoved: timelineDiff.removed.length,
    superAdded: superTimelineAddedCount,
    iocsAdded: iocsDiff.added.length,
    iocsRemoved: iocsDiff.removed.length,
  });
  return { state, superTimelineAddedCount, timelineDiff, iocsDiff };
}

// Non-fatal by design, like the dual-write above: the forensic re-home is already saved, and a
// row the pass could not rewrite is still in the record under its former name — the next settle
// that changes the ledger tries again. A store without the method (a test fake) is skipped.
async function rehomeSuperCopies(deps: SettleDeps, caseId: string, state: InvestigationState): Promise<void> {
  const store = deps.superTimelineStore;
  if (!store?.rehome || !store.eventBatches) return;
  try {
    const rewritten = await rehomeSuperTimeline(store as SuperRehomeStore, caseId, state);
    if (rewritten) deps.onSuperTimeline?.(caseId);
  } catch (error) {
    getServerLogger().warn(
      `[import] ${caseId}: super-timeline rename re-home failed — ${error instanceof Error ? error.message : String(error)}`,
      { caseId },
    );
  }
}

export interface SettledCounts {
  forensicAdded: number;
  forensicRemoved: number;
  superAdded: number;
  iocsAdded: number;
  iocsRemoved: number;
}

/**
 * The outcome line, shared with the two seams that settle inline instead of calling
 * settleForensicImport (the job resume handler, the analysis-run replay). INFO when anything
 * changed; DEBUG when every count is zero (an empty monitor poll).
 */
export function logImportSettled(caseId: string, label: string | undefined, counts: SettledCounts): void {
  const line = formatImportSettled({ caseId, label, ...counts });
  const empty = Object.values(counts).every((n) => n === 0);
  if (empty) getServerLogger().debug(line, { caseId });
  else getServerLogger().info(line, { caseId });
}
