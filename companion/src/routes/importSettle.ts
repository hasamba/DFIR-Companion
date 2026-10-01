import { randomUUID } from "node:crypto";
import type { ForensicEvent, InvestigationState } from "../analysis/stateTypes.js";
import type { SuperEviction } from "../analysis/superTimelineStore.js";
import type { TimelineDiff } from "../analysis/timelineDiff.js";
import type { IocsDiff } from "../analysis/iocsDiff.js";
import { getServerLogger } from "../logging/serverLogger.js";
import { formatImportSettled } from "../logging/importLog.js";
import { hostRenameCarrier, rehomeEvents } from "../analysis/hostRenameCarry.js";
import { downgradeFirstPartyEgress } from "../analysis/firstPartyEgress.js";
import { SCAN_PAGE_ROWS, type ForensicRowStore } from "../analysis/forensicRows.js";
import { settleIocsDiff, settleTimelineDiff } from "./importSettleDiff.js";
import { toImportBaseline, type ImportBaseline } from "../analysis/importBaseline.js";
import { capBuildTimeScoped } from "./importSettleCap.js";
import { hasBuildTimeMark } from "../analysis/buildTimeWindow.js";
import {
  isForeignToImport,
  rewriteRows,
  runUnlocked,
  settleScope,
  type RunExclusive,
  type SettleScope,
} from "./importSettleRows.js";
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
 * The baseline is what the section captured under the import lock BEFORE the importer ran
 * (routes/importSection.ts) — the diff is only honest against that snapshot. Since #1874 it is not
 * a full copy of the case, and no step here loads or saves the whole case: each reads and writes
 * only the rows it changes (see the functions below).
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
  /** Row-level access to the case (StateStore); `load` only for a legacy `onState`-only caller. */
  stateStore: ForensicRowStore & { load?(caseId: string): Promise<InvestigationState> };
  /**
   * The case's state lock (createApp's runStateExclusive). Each settle step reads, changes and
   * writes its rows inside it, so an analyst edit, an enrichment or a synthesis — all of which save
   * through the same lock — can never interleave with a step and have its change overwritten.
   */
  runStateExclusive?: RunExclusive;
  superTimelineStore?: {
    append(caseId: string, events: ForensicEvent[]): Promise<number>;
    /** #1535 — the retained count AND what the cap dropped, from one atomic write. Optional so a
     * test fake that only implements `append` keeps working; the eviction then reports nothing. */
    appendReporting?(
      caseId: string,
      events: ForensicEvent[],
    ): Promise<{ retained: number; evicted: SuperEviction }>;
  } & Partial<SuperRehomeStore>;
  onSuperTimeline?: (caseId: string) => void;
  /**
   * Fired once when the settle changed the forensic timeline (#1174: the dashboard learns the new
   * importedAt/importBatchId stamps from this settle, not from whatever broadcast happens next). It
   * takes the case id, not a state: the app loads and pushes the state only when a dashboard is
   * watching the case (#1874).
   */
  onStateChanged?: (caseId: string) => void;
  /** Legacy callers that only wire a state broadcaster: the settle loads the case once for it. */
  onState?: (state: InvestigationState) => void;
  autoTagImported: (caseId: string, added: ForensicEvent[]) => Promise<void>;
  /** The forensic gate's demote; returns the rows it removed (composition/importDemote.ts). */
  demoteForensic?: (caseId: string) => Promise<ForensicEvent[]>;
  /** The same demote returning the whole case afterwards — legacy callers only. */
  demoteForensicForCase?: (caseId: string) => Promise<InvestigationState>;
}

export interface SettledImport {
  /** Rows the super-timeline RETAINED from this import (0 when no store is wired). */
  superTimelineAddedCount: number;
  /**
   * What the super-timeline's cap dropped to make room for this import (#1535). Undefined when no
   * store is wired or the store cannot report it; `count: 0` when the cap took nothing. This is
   * per-import; a case's complete eviction record is `SuperTimelineStore.meta().evictedTotal`,
   * which also covers evictions no import caused (unstarring a row releases protection).
   */
  superTimelineEvicted?: SuperEviction;
  /** Forensic-timeline diff against the baseline, computed post-demote. */
  timelineDiff: TimelineDiff;
  iocsDiff: IocsDiff;
  /**
   * The rows this import added that are still in the forensic timeline, read as they are now. A
   * function, so a caller that does not need them (no false-positive markers to match) reads
   * nothing; call it while the import section is still held.
   */
  addedEvents(): Promise<ForensicEvent[]>;
  /** How many rows the forensic timeline holds after the settle. */
  forensicCount: number;
  /** The case after demote — only when a legacy `demoteForensicForCase` produced it. */
  state?: InvestigationState;
}

/**
 * `before` is what the import is diffed against: the ImportBaseline its section captured
 * (analysis/importBaseline.ts), or — from a legacy caller — the full state it loaded then.
 */
export async function settleForensicImport(
  deps: SettleDeps,
  caseId: string,
  before: InvestigationState | ImportBaseline,
  label?: string,
): Promise<SettledImport> {
  const baseline = toImportBaseline(before);
  const store = deps.stateStore;
  const lock = deps.runStateExclusive ?? runUnlocked;
  const scope = await settleScope(store, caseId, baseline);
  // Its rename ledger and collector identities only (#1874): not the IOC list, as long as the timeline.
  const ledger = store.loadOverviewWithoutIocs
    ? await store.loadOverviewWithoutIocs(caseId)
    : await store.loadOverview(caseId);
  // A rename the import taught the case (or a changed collector identity) can re-home ANY old row;
  // otherwise only the rows the import added or touched can need it.
  const ledgerChanged = renameLedgerChanged(baseline.overview, ledger);
  const scanAll = ledgerChanged || !scope.touchedKnown;
  let added: ForensicEvent[] = [];
  // #1735: the always-on debug log keeps these at any live level. Counts only, never row content.
  // Silent when the import added nothing and carried no rename: a Velociraptor monitor settles on
  // every poll, and empty polls must not push real history out of the capped debug log.
  let traced = scope.addedIds.length > 0 || ledgerChanged;
  const debug = (step: string): void => {
    if (traced) getServerLogger().debug(`[import-debug] ${caseId}: settle ${step}`, { caseId });
  };

  // Rows the case already held under a name this (or any earlier) import taught it was a former one
  // are re-homed (#1495), then the rows new to this case are stamped with WHEN the case received
  // them and WHICH import action did it (#1157) — one instant, one batch id — and the first-party
  // egress downgrade (#1530) rides in the same pass. Its position is the whole argument: BEFORE the
  // dual-write, so the super-timeline keeps the Info copy the forensic record is about to lose;
  // BEFORE the tagger, so a tagger rule that matches the row raises it straight back out of Info.
  // Gated on the super-timeline store like the dual-write: demote removes a sub-threshold row from
  // the forensic timeline whether or not a capture store exists, so lowering a grade with no store
  // wired would delete evidence. Only the rows that change are written, under the state lock.
  const stamped = await lock(caseId, () =>
    carryAndStamp(deps, caseId, ledger, scope, scanAll, baseline.capturedAt),
  );
  added = stamped.added;
  traced ||= stamped.carried > 0;
  debug(
    `start forensicBefore=${baseline.outline.ids.length} merged=${scope.mergedCount} ` +
      `added=${added.length} renameCarry=${stamped.carried}`,
  );
  let changed = added.length > 0 || stamped.carried > 0;

  // The super-timeline's own copies follow the ledger (#1508). Either signal triggers it: a rename
  // whose old-name rows were all Info changes the ledger but moves no forensic row, and a forensic
  // row the carry moved has a copy in the store that must move with it.
  if (deps.superTimelineStore && (stamped.carried > 0 || ledgerChanged)) {
    await rehomeSuperCopies(deps, caseId, ledger);
  }

  // Dual-write FIRST, from the pre-demote (now stamped) rows.
  let superTimelineAddedCount = 0;
  let superTimelineEvicted: SuperEviction | undefined;
  if (deps.superTimelineStore && added.length) {
    try {
      const superStore = deps.superTimelineStore;
      if (superStore.appendReporting) {
        const result = await superStore.appendReporting(caseId, added);
        superTimelineAddedCount = result.retained;
        superTimelineEvicted = result.evicted;
      } else {
        superTimelineAddedCount = await superStore.append(caseId, added);
      }
      deps.onSuperTimeline?.(caseId);
    } catch {
      // Non-fatal by design: demote captures every row it removes into the super-timeline in
      // its own critical section and KEEPS the row in the forensic timeline when that capture
      // fails (composition/importDemote.ts) — a row is never in neither record. What this
      // failure costs is the count above, which stays 0.
    }
    await deps.autoTagImported(caseId, added);
    debug(
      `dual-write superRetained=${superTimelineAddedCount} superEvicted=${superTimelineEvicted?.count ?? 0} ` +
        `taggerOffered=${added.length}`,
    );
  } else {
    debug(`dual-write skipped store=${deps.superTimelineStore ? "yes" : "no"} added=${added.length}`);
  }
  // Merge-all → tagger → CAP → demote (#1529). The tagger has had its one promotion window above;
  // now the rows inside a corroborated provisioning window are capped at Low with a stated reason,
  // before demote decides what leaves the forensic timeline.
  // Off every rename chain, the cap can only change a row that already carries a cap mark (the
  // tagger never writes one), so only such rows of this import's own are handed on.
  const extraIds = [...added, ...stamped.touched].filter(hasBuildTimeMark).map((e) => e.id);
  const capped = await lock(caseId, () => capBuildTimeScoped(store, caseId, ledger, { scanAll, extraIds }));
  changed ||= capped > 0;
  const demoted = await demote(deps, caseId);
  changed ||= demoted.removed > 0;
  // #1874: from the rows that can change it, not a keyed read of the whole timeline (importSettleDiff.ts).
  const { timelineDiff, forensicCount } = await settleTimelineDiff(store, caseId, baseline);
  debug(
    `demote buildTimeCapped=${capped} forensicBeforeDemote=${forensicCount + demoted.removed} ` +
      `forensicAfterDemote=${forensicCount}`,
  );
  const iocsDiff = await settleIocsDiff(store, caseId, baseline);
  const addedIds = [...new Set(added.map((e) => e.id))];
  const addedEvents = async (): Promise<ForensicEvent[]> =>
    addedIds.length ? (await store.forensicRowsById(caseId, addedIds)).map((r) => r.event) : [];
  if (changed) await announceState(deps, caseId, demoted.state);
  logImportSettled(caseId, label, {
    forensicAdded: timelineDiff.added.length,
    forensicRemoved: timelineDiff.removed.length,
    superAdded: superTimelineAddedCount,
    superEvicted: superTimelineEvicted?.count ?? 0,
    iocsAdded: iocsDiff.added.length,
    iocsRemoved: iocsDiff.removed.length,
  });
  return {
    superTimelineAddedCount,
    superTimelineEvicted,
    timelineDiff,
    iocsDiff,
    addedEvents,
    forensicCount,
    ...(demoted.state ? { state: demoted.state } : {}),
  };
}

// Carry + stamp + downgrade in one read-transform-write of just the rows that can change.
async function carryAndStamp(
  deps: SettleDeps,
  caseId: string,
  ledger: InvestigationState,
  scope: SettleScope,
  scanAll: boolean,
  capturedAt: string | undefined,
): Promise<{ added: ForensicEvent[]; carried: number; touched: ForensicEvent[] }> {
  const store = deps.stateStore;
  const newIds = new Set(scope.addedIds);
  const touched = await store.forensicRowsByRowId(caseId, scope.touchedRowIds);
  const touchedIds = touched.map((r) => r.event.id);
  // With a ledger change (or no journal) any old row may need re-homing: find them page by page.
  const carryIds = new Set<string>();
  if (scanAll && ledger.hostRenames?.length) {
    for await (const batch of store.forensicTimelineBatches(caseId, { limit: SCAN_PAGE_ROWS })) {
      for (const e of rehomeEvents(batch, ledger)) carryIds.add(e.id);
    }
  }
  const ids = [...new Set([...scope.addedIds, ...touchedIds, ...carryIds])];
  const rows = ids.length ? await store.forensicRowsById(caseId, ids) : [];
  // #1904: a new row another writer added mid-import is carried like any old row, never stamped.
  const addedIds = new Set(
    rows
      .filter((r) => newIds.has(r.event.id) && !isForeignToImport(r.event, capturedAt))
      .map((r) => r.event.id),
  );
  const importedAt = new Date().toISOString();
  const importBatchId = randomUUID();
  let carried = 0;
  let downgraded = 0;
  const carry = hostRenameCarrier(ledger);
  for (const r of rows) if (carry(r.event) !== r.event) carried++;
  const transform = (e: ForensicEvent): ForensicEvent => {
    const moved = carry(e);
    if (!addedIds.has(e.id)) return moved;
    const lowered = deps.superTimelineStore ? downgradeFirstPartyEgress([moved]).events[0] : moved;
    if (lowered.severity !== moved.severity) downgraded++;
    return { ...lowered, importedAt, importBatchId };
  };
  const written = await rewriteRows(store, caseId, rows, transform);
  if (downgraded)
    getServerLogger().info(`[import] ${caseId}: ${downgraded} first-party update connection(s) graded Info`, {
      caseId,
    });
  const writtenById = new Map(written.map((r) => [r.rowId, r.event]));
  const added = rows.filter((r) => addedIds.has(r.event.id)).map((r) => writtenById.get(r.rowId) ?? r.event);
  const others = rows
    .filter((r) => !addedIds.has(r.event.id))
    .map((r) => writtenById.get(r.rowId) ?? r.event);
  return { added, carried, touched: others };
}

async function demote(
  deps: SettleDeps,
  caseId: string,
): Promise<{ removed: number; state?: InvestigationState }> {
  if (deps.demoteForensic) return { removed: (await deps.demoteForensic(caseId)).length };
  if (!deps.demoteForensicForCase) return { removed: 0 };
  // A legacy demote reports the state, not what it removed; the diff above still counts removals.
  return { removed: 0, state: await deps.demoteForensicForCase(caseId) };
}

// One broadcast per settle. A legacy caller with only a state broadcaster gets one load for it.
async function announceState(deps: SettleDeps, caseId: string, state?: InvestigationState): Promise<void> {
  if (deps.onStateChanged) return deps.onStateChanged(caseId);
  if (!deps.onState) return;
  const current = state ?? (await deps.stateStore.load?.(caseId));
  if (current) deps.onState(current);
}

// Non-fatal by design, like the dual-write above: the forensic re-home is already saved, and a
// row the pass could not rewrite is still in the record under its former name — the next settle
// that changes the ledger tries again. A store without the method (a test fake) is skipped.
async function rehomeSuperCopies(deps: SettleDeps, caseId: string, state: InvestigationState): Promise<void> {
  const superStore = deps.superTimelineStore;
  if (!superStore?.rehome || !superStore.eventBatches) return;
  try {
    const rewritten = await rehomeSuperTimeline(superStore as SuperRehomeStore, caseId, state);
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
  /** Rows the super-timeline's cap had to drop to make room for this import (#1535). */
  superEvicted?: number;
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
  const empty = Object.values(counts).every((n) => !n);
  if (empty) getServerLogger().debug(line, { caseId });
  else getServerLogger().info(line, { caseId });
}
