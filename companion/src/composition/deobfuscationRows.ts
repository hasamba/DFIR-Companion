import type { StateStore } from "../analysis/stateStore.js";
import { SCAN_PAGE_ROWS } from "../analysis/forensicRows.js";
import type { ForensicEvent } from "../analysis/stateTypes.js";
import {
  applyDeobfuscation,
  wouldDeobfuscate,
  type DeobfuscationApplyOptions,
} from "../analysis/applyDeobfuscation.js";
import { rewriteRows } from "../analysis/forensicRowRewrite.js";
import { upgradeForensicEvent } from "../analysis/canonicalEvent.js";
import { hasRowFacts, refreshRowFacts, rowFactsStamp } from "../analysis/rowFacts.js";

export interface DeobfuscationOutcome {
  deobfuscated: number;
  newIocs: number;
  reanalyzed: number;
  changed: boolean;
}

/**
 * The deobfuscation pass without loading or saving the whole case (#1874). Call it inside the state
 * lock. The timeline is read a page at a time; only the events that decode are kept, and every
 * other event's indicator ids are collected, since the pass leaves those events as they are. The
 * pure pass then runs over just the decoding events with those ids as `outsideIocIds`, which gives
 * the same IOC numbering, dedupe and orphan prune as a run over the whole timeline. The events it
 * changed are written by row id; the IOC list and updatedAt through an overview save.
 */
export async function deobfuscateRows(
  stateStore: StateStore,
  caseId: string,
  options: DeobfuscationApplyOptions,
): Promise<DeobfuscationOutcome> {
  const { decoding, outsideIocIds } =
    !options.reanalyzeStale && hasRowFacts(stateStore)
      ? await candidatesFromFacts(stateStore, caseId, options)
      : await candidatesFromScan(stateStore, caseId, options);
  const none = { deobfuscated: 0, newIocs: 0, reanalyzed: 0, changed: false };
  if (!decoding.length) return none;
  const overview = await stateStore.loadOverview(caseId);
  const result = applyDeobfuscation(
    { ...overview, forensicTimeline: decoding },
    { ...options, outsideIocIds },
  );
  if (result.deobfuscated === 0 && result.newIocs === 0) return none;
  // Keyed by the row's own content, not its id: event ids are not unique in storage, and two rows
  // sharing one must each get their own result. The pass maps its input rows in order.
  const next = new Map(decoding.map((e, i) => [JSON.stringify(e), result.state.forensicTimeline[i]]));
  const rows = await stateStore.forensicRowsById(caseId, [...new Set(decoding.map((e) => e.id))]);
  await rewriteRows(stateStore, caseId, rows, (e) => next.get(JSON.stringify(e)) ?? e);
  await stateStore.saveOverview({ ...result.state, forensicTimeline: [] });
  return {
    deobfuscated: result.deobfuscated,
    newIocs: result.newIocs,
    reanalyzed: result.reanalyzed,
    changed: true,
  };
}

interface Candidates {
  decoding: ForensicEvent[];
  outsideIocIds: string[];
}

// Every row, a page at a time: the rows that decode, and every other row's indicator ids.
async function candidatesFromScan(
  stateStore: StateStore,
  caseId: string,
  options: DeobfuscationApplyOptions,
): Promise<Candidates> {
  const decoding: ForensicEvent[] = [];
  const outsideIocIds: string[] = [];
  for await (const batch of stateStore.forensicTimelineBatches(caseId, { limit: SCAN_PAGE_ROWS })) {
    for (const e of batch) {
      if (wouldDeobfuscate(e, options)) decoding.push(e);
      else outsideIocIds.push(...(e.deobfuscated?.iocs ?? []));
    }
  }
  return { decoding, outsideIocIds };
}

/**
 * The automatic sweep's rows from the row facts (#1874): the rows whose facts say the pass would decode
 * them, plus the rows written since the facts were computed, in timeline order — each checked again
 * with wouldDeobfuscate on the row as loaded. No other row can decode, and none of their indicators is
 * needed: without re-analysis a decoding row carries no prior result, so the pass has nothing it could
 * retire and `outsideIocIds` only ever protects ids nothing would drop (applyDeobfuscation.ts's prune).
 */
async function candidatesFromFacts(
  stateStore: StateStore,
  caseId: string,
  options: DeobfuscationApplyOptions,
): Promise<Candidates> {
  await refreshRowFacts(stateStore, caseId);
  const rows = await stateStore.factsCandidates(caseId, rowFactsStamp(), "deob");
  const decoding = rows
    .map((r) => upgradeForensicEvent(r.payload as ForensicEvent))
    .filter((e) => wouldDeobfuscate(e, options));
  return { decoding, outsideIocIds: [] };
}
