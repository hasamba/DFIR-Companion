import type { StateStore } from "../analysis/stateStore.js";
import { SCAN_PAGE_ROWS } from "../analysis/forensicRows.js";
import type { ForensicEvent } from "../analysis/stateTypes.js";
import {
  applyDeobfuscation,
  wouldDeobfuscate,
  type DeobfuscationApplyOptions,
} from "../analysis/applyDeobfuscation.js";
import { rewriteRows } from "../analysis/forensicRowRewrite.js";

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
  const decoding: ForensicEvent[] = [];
  const outsideIocIds: string[] = [];
  for await (const batch of stateStore.forensicTimelineBatches(caseId, { limit: SCAN_PAGE_ROWS })) {
    for (const e of batch) {
      if (wouldDeobfuscate(e, options)) decoding.push(e);
      else outsideIocIds.push(...(e.deobfuscated?.iocs ?? []));
    }
  }
  const none = { deobfuscated: 0, newIocs: 0, reanalyzed: 0, changed: false };
  if (!decoding.length) return none;
  const overview = await stateStore.loadOverview(caseId);
  const result = applyDeobfuscation(
    { ...overview, forensicTimeline: decoding },
    { ...options, outsideIocIds },
  );
  if (result.deobfuscated === 0 && result.newIocs === 0) return none;
  const next = new Map(result.state.forensicTimeline.map((e) => [e.id, e]));
  const rows = await stateStore.forensicRowsById(caseId, [...next.keys()]);
  await rewriteRows(stateStore, caseId, rows, (e) => next.get(e.id) ?? e);
  await stateStore.saveOverview({ ...result.state, forensicTimeline: [] });
  return {
    deobfuscated: result.deobfuscated,
    newIocs: result.newIocs,
    reanalyzed: result.reanalyzed,
    changed: true,
  };
}
