import { randomUUID } from "node:crypto";
import type { ForensicEvent, InvestigationState } from "../analysis/stateTypes.js";
import type { SuperEviction } from "../analysis/superTimelineStore.js";
import { mergeEvictions } from "../analysis/superTimelineStore.js";
import { SCAN_PAGE_ROWS, type ForensicRow, type ForensicRowStore } from "../analysis/forensicRows.js";
import { hostRenameCarrier, rehomeEvents } from "../analysis/hostRenameCarry.js";
import { downgradeFirstPartyEgress } from "../analysis/firstPartyEgress.js";
import { downgradeGenericSysmonRegistry } from "../analysis/genericSysmonRegistry.js";
import { hasBuildTimeMark } from "../analysis/buildTimeWindow.js";
import { hasLabSetupMark, labSetupFolder, labSetupPaths } from "../analysis/labSetupTransfer.js";
import {
  isAttackerDefenderTouch,
  isDefenderEngineWrite,
  isStartupRow,
} from "../analysis/defenderEngineBoot.js";
import { LOOKALIKE_ACCOUNT_MARKER, lookalikeCandidateName } from "../analysis/lookalikeCaseAccount.js";
import { principalNameCarrier } from "../analysis/principalNameCarry.js";
import { getServerLogger } from "../logging/serverLogger.js";
import { isForeignToImport, rewriteRows, type RunExclusive, type SettleScope } from "./importSettleRows.js";

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

/** What each later settle step reads of this import's added and touched rows. */
export interface SettleCandidates {
  /** Case-account look-alikes (#1971): new accounts and group members not yet noted. */
  lookalike: ForensicEvent[];
  /** Build-time cap (#1529): rows that already carry a cap mark. */
  buildTimeIds: string[];
  /** Lab-setup cap (#1946): rows in a lab folder or carrying its mark. */
  labSetup: ForensicEvent[];
  /** Defender engine start-up (#2084): start-up anchors, attacker-touch vetoes, engine writes. */
  engineBoot: ForensicEvent[];
  /** Caller names (#2490): rows the principal ledger renames. */
  names: ForensicEvent[];
}

export interface StampedImport {
  /** The import's own new rows (foreign rows excluded, #1904), in timeline order. */
  addedIds: string[];
  carried: number;
  candidates: SettleCandidates;
}

export const emptyCandidates = (): SettleCandidates => ({
  lookalike: [],
  buildTimeIds: [],
  labSetup: [],
  engineBoot: [],
  names: [],
});

/** Read `ids` a page at a time, in pages of SCAN_PAGE_ROWS. */
async function* rowPages(
  store: ForensicRowStore,
  caseId: string,
  ids: readonly string[],
): AsyncGenerator<ForensicRow[]> {
  for (let i = 0; i < ids.length; i += SCAN_PAGE_ROWS) {
    const page = await store.forensicRowsById(caseId, ids.slice(i, i + SCAN_PAGE_ROWS));
    if (page.length) yield page;
  }
}

/** rewriteRows over rows read by id, a page at a time. Returns how many rows it wrote. */
export async function rewriteByIdInPages(
  store: ForensicRowStore,
  caseId: string,
  ids: readonly string[],
  transform: (e: ForensicEvent) => ForensicEvent,
): Promise<number> {
  let written = 0;
  for await (const rows of rowPages(store, caseId, ids)) {
    written += (await rewriteRows(store, caseId, rows, transform)).length;
  }
  return written;
}

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
    if (added && !(e.description ?? "").includes(LOOKALIKE_ACCOUNT_MARKER) && lookalikeCandidateName(e))
      c.lookalike.push(e);
    if (hasBuildTimeMark(e)) c.buildTimeIds.push(e.id);
    if (hasLabSetupMark(e) || labSetupFolder(e, paths)) c.labSetup.push(e);
    if (isStartupRow(e) || isAttackerDefenderTouch(e) || isDefenderEngineWrite(e)) c.engineBoot.push(e);
    if (names(e) !== e) c.names.push(e);
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
  opts: { capturedAt: string | undefined; downgrade: boolean },
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
  const importedAt = new Date().toISOString();
  const importBatchId = randomUUID();
  const carry = hostRenameCarrier(ledger);
  const collect = collector(ledger);
  const out: StampedImport = { addedIds: [], carried: 0, candidates: emptyCandidates() };
  const counts = { downgraded: 0, genericRegistry: 0 };
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
      if (!opts.downgrade) return { ...moved, importedAt, importBatchId };
      const egress = downgradeFirstPartyEgress([moved]).events[0];
      if (egress.severity !== moved.severity) counts.downgraded++;
      // #1958: generic Sysmon registry alerts, in the same position and for the same reason.
      const lowered = downgradeGenericSysmonRegistry([egress]).events[0];
      if (lowered.severity !== egress.severity) counts.genericRegistry++;
      return { ...lowered, importedAt, importBatchId };
    };
    const written = new Map(
      (await rewriteRows(store, caseId, rows, transform)).map((r) => [r.rowId, r.event]),
    );
    for (const r of rows) {
      const e = written.get(r.rowId) ?? r.event;
      if (added.has(e.id)) out.addedIds.push(e.id);
      collect(out.candidates, e, added.has(e.id));
    }
  }
  logDowngrades(caseId, counts);
  return out;
}

function logDowngrades(caseId: string, c: { downgraded: number; genericRegistry: number }): void {
  const log = getServerLogger();
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
    ): Promise<{ retained: number; evicted: SuperEviction }>;
  };
  onSuperTimeline?: (caseId: string) => void;
  autoTagImported: (caseId: string, added: ForensicEvent[]) => Promise<void>;
}

/**
 * Dual-write FIRST, from the stamped (pre-demote) rows, then the tagger's one promotion window — page
 * by page. A failed append is non-fatal by design, as it always was: demote captures every row it
 * removes into the super-timeline in its own critical section and KEEPS the row when that capture
 * fails (composition/importDemote.ts) — a row is never in neither record. What a failure costs is the
 * count. Each page is read under the state lock, as every other settle read is.
 */
export async function dualWriteAndTagPaged(
  deps: DualWriteDeps,
  caseId: string,
  addedIds: readonly string[],
): Promise<{ retained: number; evicted?: SuperEviction }> {
  let retained = 0;
  let evicted: SuperEviction | undefined;
  const superStore = deps.superTimelineStore;
  if (!superStore) return { retained };
  for (let i = 0; i < addedIds.length; i += SCAN_PAGE_ROWS) {
    const pageIds = addedIds.slice(i, i + SCAN_PAGE_ROWS);
    const page = await deps.runStateExclusive(caseId, () =>
      deps.stateStore.forensicRowsById(caseId, pageIds),
    );
    const events = page.map((r) => r.event);
    if (!events.length) continue;
    try {
      if (superStore.appendReporting) {
        const result = await superStore.appendReporting(caseId, events);
        retained += result.retained;
        evicted = evicted ? mergeEvictions(evicted, result.evicted) : result.evicted;
      } else {
        retained += await superStore.append(caseId, events);
      }
      deps.onSuperTimeline?.(caseId);
    } catch {
      /* non-fatal — see above */
    }
    await deps.autoTagImported(caseId, events);
  }
  return { retained, ...(evicted ? { evicted } : {}) };
}
