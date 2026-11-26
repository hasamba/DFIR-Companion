import { randomUUID } from "node:crypto";
import type { ForensicEvent, InvestigationState } from "../analysis/stateTypes.js";
import type { SuperEviction, SuperRelinkCandidate } from "../analysis/superTimelineStore.js";
import { mergeEvictions } from "../analysis/superTimelineStore.js";
import { SCAN_PAGE_ROWS, type ForensicRowStore } from "../analysis/forensicRows.js";
import { hostRenameCarrier, rehomeEvents } from "../analysis/hostRenameCarry.js";
import { downgradeFirstPartyEgress } from "../analysis/firstPartyEgress.js";
import { downgradeGenericSysmonRegistry } from "../analysis/genericSysmonRegistry.js";
import { hasBuildTimeMark } from "../analysis/buildTimeWindow.js";
import { labSetupPaths } from "../analysis/labSetupTransfer.js";
import { runHuntSettle } from "../analysis/huntSettleHook.js";
import {
  isAttackerDefenderTouch,
  isDefenderEngineWrite,
  isStartupRow,
} from "../analysis/defenderEngineBoot.js";
import { lookalikeCandidate } from "./importSettleLookalike.js";
import { labSetupCandidate } from "./importSettleCap.js";
import { principalNameCarrier } from "../analysis/principalNameCarry.js";
import { getServerLogger } from "../logging/serverLogger.js";
import { gradedIdsOf, isGradePending, withoutGradePending, type TagOutcome } from "../analysis/gradeMark.js";
import {
  isForeignToImport,
  rewriteRows,
  rowPages,
  type RunExclusive,
  type SettleScope,
} from "./importSettleRows.js";

/**
 * The settle's row passes in pages (#2713). The settle used to read every row the import added into
 * one array and hold it — full events — from the stamp to the last step, although each later step
 * reads only a few of them. A Velociraptor export of ~70k graded rows made that one array, plus the
 * steps' own reads, the heap peak that ran the server out of memory. Now:
 *
 *   stamp    — carry + stamp + downgrade (#1157, #1495, #1530, #1958) read, transformed and written a
 *              page of SCAN_PAGE_ROWS rows at a time, one instant and one batch id for every page;
 *   keep     — from each page only the added ids and, per later step, the rows that step reads —
 *              chosen with the exact test that step applies to its input (SettleCandidates);
 *   dual-write → tagger — page by page from the stamped rows, re-read by id (the order of the seam is
 *              unchanged: every row is stamped before the first is dual-written).
 *
 * A single-page import — nearly every import — makes exactly the calls it made before: one read, one
 * write, one super-timeline append, one tagger call. A larger one appends and tags once per page, the
 * per-batch contract the streamed cloud import and the bulk Velociraptor batches already have.
 */

/**
 * What each later settle step reads of this import's added and touched rows — ids or compact facts,
 * not events, except the Defender rows the engine-boot pass reads across rows (rare by nature).
 */
export interface SettleCandidates {
  /** Case-account look-alikes (#1971): row id → the new account or group member it names. */
  lookalike: Map<string, string>;
  /** Build-time cap (#1529): rows that already carry a cap mark. */
  buildTimeIds: string[];
  /** Lab-setup cap (#1946): rows in a lab folder or carrying its mark. */
  labSetupIds: string[];
  /** Defender engine start-up (#2084): start-up anchors, attacker-touch vetoes, engine writes. */
  engineBoot: ForensicEvent[];
  /** Caller names (#2490): rows the principal ledger renames. */
  nameIds: string[];
}

export interface StampedImport {
  /** The import's own new rows (foreign rows excluded, #1904), in timeline order. */
  addedIds: string[];
  carried: number;
  candidates: SettleCandidates;
}

export const emptyCandidates = (): SettleCandidates => ({
  lookalike: new Map(),
  buildTimeIds: [],
  labSetupIds: [],
  engineBoot: [],
  nameIds: [],
});

/**
 * Add `e` to every candidate list whose step would read it — each test is the one that step applies
 * to its input. The look-alike step reads only the import's own added rows; the others read the
 * added and the touched rows alike, as they always did.
 */
function collector(
  ledger: InvestigationState,
): (c: SettleCandidates, e: ForensicEvent, added: boolean) => void {
  const paths = labSetupPaths();
  const names = principalNameCarrier(ledger);
  return (c, e, added) => {
    const account = added ? lookalikeCandidate(e) : "";
    if (account) c.lookalike.set(e.id, account);
    if (hasBuildTimeMark(e)) c.buildTimeIds.push(e.id);
    if (labSetupCandidate(e, paths)) c.labSetupIds.push(e.id);
    if (isStartupRow(e) || isAttackerDefenderTouch(e) || isDefenderEngineWrite(e)) c.engineBoot.push(e);
    if (names(e) !== e) c.nameIds.push(e.id);
  };
}

/**
 * Carry + stamp + downgrade in one read-transform-write per page of the rows that can change: this
 * import's added rows, the old rows it touched, and (with a ledger change) every row a rename re-homes.
 */
export async function carryAndStampPaged(
  store: ForensicRowStore,
  caseId: string,
  ledger: InvestigationState,
  scope: SettleScope,
  scanAll: boolean,
  /** `importBatchId`: preset by a caller that must find this batch's rows again (#2888); else fresh.
   * `importedAt`: preset by a recovery that keeps the failed settle's instant; else now.
   * `gradePending`: write the grade mark with the stamp (#2891, analysis/gradeMark.ts) — only when the
   * tagger will run on these rows, so a settle without a super-timeline store marks nothing. */
  opts: {
    capturedAt: string | undefined;
    downgrade: boolean;
    importBatchId?: string;
    importedAt?: string;
    gradePending?: boolean;
  },
): Promise<StampedImport> {
  const newIds = new Set(scope.addedIds);
  const touchedIds: string[] = [];
  for (let i = 0; i < scope.touchedRowIds.length; i += SCAN_PAGE_ROWS) {
    const page = await store.forensicRowsByRowId(caseId, scope.touchedRowIds.slice(i, i + SCAN_PAGE_ROWS));
    for (const r of page) touchedIds.push(r.event.id);
  }
  const carryIds = new Set<string>();
  if (scanAll && ledger.hostRenames?.length) {
    for await (const batch of store.forensicTimelineBatches(caseId, { limit: SCAN_PAGE_ROWS })) {
      for (const e of rehomeEvents(batch, ledger)) carryIds.add(e.id);
    }
  }
  const ids = [...new Set([...scope.addedIds, ...touchedIds, ...carryIds])];
  const importedAt = opts.importedAt ?? new Date().toISOString();
  const importBatchId = opts.importBatchId ?? randomUUID();
  const stamp = opts.gradePending
    ? { importedAt, importBatchId, gradePending: true as const }
    : { importedAt, importBatchId };
  const carry = hostRenameCarrier(ledger);
  const collect = collector(ledger);
  const out: StampedImport = { addedIds: [], carried: 0, candidates: emptyCandidates() };
  const counts = { downgraded: 0, genericRegistry: 0, refused: 0 };
  for await (const rows of rowPages(store, caseId, ids)) {
    // #1904: a new row another writer added mid-import is carried like any old row, never stamped.
    const added = new Set(
      rows
        .filter((r) => newIds.has(r.event.id) && !isForeignToImport(r.event, opts.capturedAt))
        .map((r) => r.event.id),
    );
    for (const r of rows) if (carry(r.event) !== r.event) out.carried++;
    const transform = (e: ForensicEvent): ForensicEvent => {
      const moved = carry(e);
      if (!added.has(e.id)) return moved;
      if (!opts.downgrade) return { ...moved, ...stamp };
      const egress = downgradeFirstPartyEgress([moved]).events[0];
      if (egress.severity !== moved.severity) counts.downgraded++;
      // #1958: generic Sysmon registry alerts, in the same position and for the same reason.
      const lowered = downgradeGenericSysmonRegistry([egress]).events[0];
      if (lowered.severity !== egress.severity) counts.genericRegistry++;
      return { ...lowered, ...stamp };
    };
    const written = new Map(
      (await rewriteRows(store, caseId, rows, transform)).map((r) => [r.rowId, r.event]),
    );
    for (const r of rows) {
      const e = written.get(r.rowId) ?? r.event;
      if (added.has(e.id) && !written.has(r.rowId)) counts.refused++; // #2891 review: see logDowngrades
      if (added.has(e.id)) out.addedIds.push(e.id);
      collect(out.candidates, e, added.has(e.id));
    }
  }
  logDowngrades(caseId, counts);
  return out;
}

function logDowngrades(
  caseId: string,
  c: { downgraded: number; genericRegistry: number; refused: number },
): void {
  const log = getServerLogger();
  // A stamp write refused after rewriteRows' conflict rounds (only a writer outside the state lock can
  // cause it): the row carries no stamp and no grade mark, so it is treated as graded, as before #2891.
  if (c.refused)
    log.warn(`[import] ${caseId}: ${c.refused} new row(s) could not be stamped (changed by another writer)`, {
      caseId,
    });
  if (c.downgraded)
    log.info(`[import] ${caseId}: ${c.downgraded} first-party update connection(s) graded Info`, { caseId });
  if (c.genericRegistry)
    log.info(`[import] ${caseId}: ${c.genericRegistry} generic Sysmon registry alert(s) graded Info`, {
      caseId,
    });
}

export interface DualWriteDeps {
  stateStore: ForensicRowStore;
  runStateExclusive: RunExclusive;
  superTimelineStore?: {
    append(caseId: string, events: ForensicEvent[]): Promise<number>;
    appendReporting?(
      caseId: string,
      events: ForensicEvent[],
      opts?: { relinkCandidates?: boolean },
    ): Promise<{ retained: number; evicted: SuperEviction; relinkCandidates?: SuperRelinkCandidate[] }>;
  };
  onSuperTimeline?: (caseId: string) => void;
  autoTagImported: (caseId: string, added: ForensicEvent[]) => Promise<TagOutcome>;
}

/**
 * Dual-write FIRST, from the stamped (pre-demote) rows, then the tagger's one promotion window — page
 * by page. A failed append is non-fatal by design, as it always was: demote captures every row it
 * removes into the super-timeline in its own critical section and KEEPS the row when that capture
 * fails (composition/importDemote.ts) — a row is never in neither record. What a failure costs is the
 * count. Each page is read under the state lock, as every other settle read is.
 *
 * #2891: neither the super-timeline nor the tagger sees the grade mark (the raw record never carries
 * it), and `gradedIds` are the rows the tagger reported it finished on — the only ones the demote may
 * move and whose mark is removed afterwards (clearGradePending).
 */
export async function dualWriteAndTagPaged(
  deps: DualWriteDeps,
  caseId: string,
  addedIds: readonly string[],
): Promise<{
  retained: number;
  evicted?: SuperEviction;
  relinkCandidates: SuperRelinkCandidate[];
  gradedIds: string[];
}> {
  let retained = 0;
  const gradedIds: string[] = [];
  let evicted: SuperEviction | undefined;
  // #2619: rows the store content-deduped onto an older row the forensic timeline lacks (Undo + re-import).
  const relinkCandidates: SuperRelinkCandidate[] = [];
  const superStore = deps.superTimelineStore;
  if (!superStore) return { retained, relinkCandidates, gradedIds };
  for (let i = 0; i < addedIds.length; i += SCAN_PAGE_ROWS) {
    const pageIds = addedIds.slice(i, i + SCAN_PAGE_ROWS);
    const page = await deps.runStateExclusive(caseId, () =>
      deps.stateStore.forensicRowsById(caseId, pageIds),
    );
    const events = page.map((r) => withoutGradePending(r.event));
    if (!events.length) continue;
    try {
      if (superStore.appendReporting) {
        const result = await superStore.appendReporting(caseId, events, { relinkCandidates: true });
        retained += result.retained;
        relinkCandidates.push(...(result.relinkCandidates ?? []));
        evicted = evicted ? mergeEvictions(evicted, result.evicted) : result.evicted;
      } else {
        retained += await superStore.append(caseId, events);
      }
      deps.onSuperTimeline?.(caseId);
    } catch {
      /* non-fatal — see above */
    }
    gradedIds.push(...gradedIdsOf(events, await deps.autoTagImported(caseId, events)));
  }
  return { retained, relinkCandidates, gradedIds, ...(evicted ? { evicted } : {}) };
}

/**
 * Remove the grade mark from the rows of `ids` the tagger finished on and the demote kept (#2891). Runs
 * AFTER the demote, so a row the demote moved out is never rewritten — only the survivors are written.
 * Each page under the state lock. A row whose write is refused keeps its mark (start-up re-grades it).
 */
export async function clearGradePending(
  store: ForensicRowStore,
  lock: RunExclusive,
  caseId: string,
  ids: readonly string[],
): Promise<number> {
  let cleared = 0;
  for (let i = 0; i < ids.length; i += SCAN_PAGE_ROWS) {
    const pageIds = ids.slice(i, i + SCAN_PAGE_ROWS);
    cleared += await lock(caseId, async () => {
      const marked = (await store.forensicRowsById(caseId, pageIds)).filter((r) => isGradePending(r.event));
      return marked.length ? (await rewriteRows(store, caseId, marked, withoutGradePending)).length : 0;
    });
  }
  return cleared;
}

/**
 * Hunt grading (#2670) in pages (#2713): each page of this import's rows (Info still here) is handed
 * on in turn. The hunt inventory only adds what it observes, so the pages together record what one
 * call with every row did, and the last call grades the whole inventory. An import that added nothing
 * still gets its one call, as before, so a coverage change still regrades. Returns the entry changes.
 */
export async function huntSettlePaged(
  stateStore: ForensicRowStore,
  lock: RunExclusive,
  caseId: string,
  addedIds: readonly string[],
  onError: (err: Error) => void,
): Promise<number> {
  if (!addedIds.length) return lock(caseId, () => runHuntSettle(stateStore, caseId, [], onError));
  let changed = 0;
  for (let i = 0; i < addedIds.length; i += SCAN_PAGE_ROWS) {
    const pageIds = addedIds.slice(i, i + SCAN_PAGE_ROWS);
    changed += await lock(caseId, async () => {
      const events = (await stateStore.forensicRowsById(caseId, pageIds)).map((r) => r.event);
      return runHuntSettle(stateStore, caseId, events, onError);
    });
  }
  return changed;
}
