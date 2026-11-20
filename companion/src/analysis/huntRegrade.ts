import { huntFieldsOf } from "./huntArtifactFields.js";
import { HUNT_ENTRY_PREFIX } from "./huntEntries.js";
import { buildHostKeyIndex, resolveHostKey } from "./huntHostKey.js";
import { loadHuntJobsSafe } from "./huntFramingLoad.js";
import { recordObservations, type HuntInventory, type InventoryObservation } from "./huntInventory.js";
import { huntSettle, type HuntSettleDeps, type HuntSettleResult } from "./huntSettle.js";
import type { ForensicEvent } from "./stateTypes.js";

/**
 * "Re-grade with current baseline" (#2670) — the ANALYST-PRESSED half of hunt grading, modelled on
 * the Sigma re-grade (#2206). It re-reads this case's own rows from BOTH records — the forensic
 * timeline and the raw record (super-timeline), so rows the gate demoted are included — folds every
 * hunt observation into the inventory, re-pins the case to the client's CURRENT baseline version and
 * re-grades. Deterministic; feeds no AI; never writes promotedAt; changes no imported row.
 *
 * The raw record has a cap (DFIR_SUPERTIMELINE_MAX) and evicts its oldest rows, so a large hunt can
 * lose rows before a re-grade. Inventory observations recorded at import are KEPT (they are facts the
 * import saw), and the result discloses how many host observations the raw record no longer holds:
 * re-importing the hunt is the only way to read those rows again.
 */
export interface RowBatches {
  forensicTimelineBatches(caseId: string): AsyncIterable<ForensicEvent[]>;
}
export interface RawBatches {
  eventBatches(caseId: string): AsyncIterable<ForensicEvent[]>;
}

export interface HuntRegradeResult extends HuntSettleResult {
  baselineVersion?: number;
  rowsRead: number;
  /** Item × host observations the inventory holds that neither record holds any more. */
  evicted: number;
}

const pairKeys = (inv: HuntInventory): Set<string> =>
  new Set(Object.values(inv.items).flatMap((i) => Object.keys(i.hosts).map((h) => `${i.key}@${h}`)));

export async function regradeHuntCase(
  deps: HuntSettleDeps & { rows: RowBatches; raw?: RawBatches },
  caseId: string,
): Promise<HuntRegradeResult> {
  const jobs = await loadHuntJobsSafe(deps, caseId);
  const index = buildHostKeyIndex(jobs, deps.serverSetId?.(caseId) ?? "");
  const renames = (await deps.stateStore.loadOverview(caseId)).hostRenames ?? [];
  const seen = new Set<string>();
  const obs: InventoryObservation[] = [];
  let rowsRead = 0;
  const take = (batch: readonly ForensicEvent[]) => {
    for (const e of batch) {
      if (seen.has(e.id) || e.id.startsWith(HUNT_ENTRY_PREFIX)) continue;
      seen.add(e.id);
      rowsRead++;
      const fields = huntFieldsOf(e);
      const host = fields ? resolveHostKey(index, fields.host, renames) : null;
      if (fields && host) obs.push({ fields, host, at: e.timestamp });
    }
  };
  for await (const b of deps.rows.forensicTimelineBatches(caseId)) take(b);
  if (deps.raw) for await (const b of deps.raw.eventBatches(caseId)) take(b);

  const before = (await deps.inventoryStore.load(caseId)).inventory;
  const reread = recordObservations({ ...before, items: {} }, obs, "");
  const still = pairKeys(reread);
  const evicted = [...pairKeys(before)].filter((k) => !still.has(k)).length;
  const merged = recordObservations(before, obs, new Date().toISOString());
  const result = await huntSettle(deps, caseId, [], { useCurrentBaseline: true, replaceInventory: merged });
  const after = await deps.inventoryStore.load(caseId);
  return {
    ...result,
    rowsRead,
    evicted,
    ...(after.baselineVersion !== undefined ? { baselineVersion: after.baselineVersion } : {}),
  };
}
