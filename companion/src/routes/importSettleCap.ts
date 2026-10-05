import type { ForensicEvent, InvestigationState } from "../analysis/stateTypes.js";
import { SCAN_PAGE_ROWS, type ForensicRowStore } from "../analysis/forensicRows.js";
import {
  buildMarkerKind,
  buildTimeWindows,
  capBuildTimeRow,
  hardAttackerSignal,
  hasBuildTimeMark,
  windowFor,
} from "../analysis/buildTimeWindow.js";
import { hostBuildMarkers } from "../analysis/gapHostHistory.js";
import { rewriteRows } from "./importSettleRows.js";
import {
  capLabSetupRow,
  hasLabSetupMark,
  labSetupFolder,
  labSetupPaths,
} from "../analysis/labSetupTransfer.js";

/**
 * The build-time cap (#1529) over the rows it can change, not the whole case (#1874).
 *
 * capBuildTimeRows recomputes every row from the whole timeline. What it reads, precisely:
 *  - WINDOW DISCOVERY reads only marker rows and hard-attacker-signal rows, and only on hosts in a
 *    rename chain (a row off every chain can neither open nor veto a window);
 *  - THE PER-ROW RULE (capBuildTimeRow) changes a row only when it sits in a window or already
 *    carries a cap mark.
 * So the same result comes from reading the rows on chain hosts (found through the host index) and
 * then rewriting the ones inside a window or carrying a mark, plus this import's added rows and the
 * old rows it touched. An old row off every chain that carries a mark can only exist if the ledger
 * or the row changed since the last settle; `scanAll` covers the ledger case, the touched rows the
 * other. A case with no rename chain has no windows at all.
 */
export async function capBuildTimeScoped(
  store: ForensicRowStore,
  caseId: string,
  ledger: Pick<InvestigationState, "hostRenames">,
  opts: { scanAll: boolean; extraIds: readonly string[] },
): Promise<number> {
  const renames = ledger.hostRenames ?? [];
  const chains = hostBuildMarkers(renames);
  const discovery: ForensicEvent[] = [];
  const seen: Array<Pick<ForensicEvent, "id" | "asset" | "timestamp"> & { marked: boolean }> = [];
  const read = (batch: readonly ForensicEvent[]): void => {
    for (const e of batch) {
      if (buildMarkerKind(e) || hardAttackerSignal(e)) discovery.push(e);
      seen.push({ id: e.id, asset: e.asset, timestamp: e.timestamp, marked: hasBuildTimeMark(e) });
    }
  };
  if (opts.scanAll) {
    for await (const batch of store.forensicTimelineBatches(caseId, { limit: SCAN_PAGE_ROWS })) read(batch);
  } else if (chains.length) {
    const names = new Set(chains.flatMap((c) => c.names));
    const hosts = (await store.forensicHosts(caseId)).filter((h) =>
      names.has(h.trim().split(".")[0].toUpperCase()),
    );
    for (const host of hosts) {
      for await (const batch of store.forensicTimelineBatches(caseId, { host, limit: SCAN_PAGE_ROWS }))
        read(batch);
    }
  }
  const windows = buildTimeWindows(discovery, renames);
  const ids = new Set(opts.extraIds);
  for (const s of seen) if (s.marked || windowFor(windows, s as unknown as ForensicEvent)) ids.add(s.id);
  if (!ids.size) return 0;
  const rows = await store.forensicRowsById(caseId, [...ids]);
  return (await rewriteRows(store, caseId, rows, (e) => capBuildTimeRow(e, windows))).length;
}

/**
 * The lab-setup cap (#1946) over this import's added and touched rows. A row's own path decides it,
 * so no other row is read. `scanAll` also re-reads every row in the folders or carrying a mark, which
 * is how a narrowed DFIR_LAB_SETUP_PATHS gives an old row its grade back.
 */
export async function capLabSetupScoped(
  store: ForensicRowStore,
  caseId: string,
  opts: { scanAll: boolean; candidates: readonly ForensicEvent[] },
): Promise<number> {
  const paths = labSetupPaths();
  const ids = new Set<string>();
  const read = (batch: readonly ForensicEvent[]): void => {
    for (const e of batch) if (hasLabSetupMark(e) || labSetupFolder(e, paths)) ids.add(e.id);
  };
  read(opts.candidates);
  if (opts.scanAll) {
    for await (const batch of store.forensicTimelineBatches(caseId, { limit: SCAN_PAGE_ROWS })) read(batch);
  }
  if (!ids.size) return 0;
  const rows = await store.forensicRowsById(caseId, [...ids]);
  return (await rewriteRows(store, caseId, rows, (e) => capLabSetupRow(e, paths))).length;
}
