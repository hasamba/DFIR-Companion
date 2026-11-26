import type { ForensicEvent, InvestigationState } from "../analysis/stateTypes.js";
import { SCAN_PAGE_ROWS, type ForensicRowStore } from "../analysis/forensicRows.js";
import {
  buildMarkerKind,
  buildTimeWindows,
  capBuildTimeRow,
  hardAttackerSignal,
  hasBuildTimeMark,
  onBuildChain,
  windowFor,
} from "../analysis/buildTimeWindow.js";
import { hostBuildMarkers } from "../analysis/gapHostHistory.js";
import { rewriteByIdInPages, type RunExclusive } from "./importSettleRows.js";
import {
  capLabSetupRow,
  hasLabSetupMark,
  labSetupFolder,
  labSetupPaths,
} from "../analysis/labSetupTransfer.js";
import { engineBootOf, stampEngineBoot, withEngineBoot } from "../analysis/defenderEngineBoot.js";

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
      // Window discovery reads only rows on a rename chain (#2713): on a scan-all settle the rest of
      // the case's build-marker and hard-signal rows were collected for nothing.
      if (onBuildChain(chains, e) && (buildMarkerKind(e) || hardAttackerSignal(e))) discovery.push(e);
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
  return rewriteByIdInPages(store, caseId, [...ids], (e) => capBuildTimeRow(e, windows));
}

/**
 * The lab-setup cap (#1946) over this import's added and touched rows. A row's own path decides it,
 * so no other row is read. `scanAll` also re-reads every row in the folders or carrying a mark, which
 * is how a narrowed DFIR_LAB_SETUP_PATHS gives an old row its grade back.
 */
export async function capLabSetupScoped(
  store: ForensicRowStore,
  caseId: string,
  opts: { scanAll: boolean; candidateIds: readonly string[] },
): Promise<number> {
  const paths = labSetupPaths();
  // The candidates come pre-picked with labSetupCandidate (the paged settle keeps ids, #2713).
  const ids = new Set<string>(opts.candidateIds);
  const read = (batch: readonly ForensicEvent[]): void => {
    for (const e of batch) if (labSetupCandidate(e, paths)) ids.add(e.id);
  };
  if (opts.scanAll) {
    for await (const batch of store.forensicTimelineBatches(caseId, { limit: SCAN_PAGE_ROWS })) read(batch);
  }
  if (!ids.size) return 0;
  return rewriteByIdInPages(store, caseId, [...ids], (e) => capLabSetupRow(e, paths));
}

/** Whether the lab-setup cap reads this row: in a lab folder, or already carrying its mark. */
export function labSetupCandidate(e: ForensicEvent, paths: readonly string[]): boolean {
  return hasLabSetupMark(e) || !!labSetupFolder(e, paths);
}

/**
 * The Defender engine's start-up anchor (#2084): stamp each engine policy write in `candidates` that
 * follows a start-up record on the same host. It runs before demote because the start-up rows are
 * Info and this is the last step that still holds them. It only adds a record; no grade changes.
 */
export async function stampEngineBootScoped(
  store: ForensicRowStore,
  caseId: string,
  candidates: readonly ForensicEvent[],
): Promise<number> {
  const stamps = new Map(stampEngineBoot(candidates).map((e) => [e.id, engineBootOf(e)] as const));
  if (!stamps.size) return 0;
  return rewriteByIdInPages(store, caseId, [...stamps.keys()], (e) => withEngineBoot(e, stamps.get(e.id)));
}

/** What the three post-tagger corrections need: the ids/rows each one reads (SettleCandidates' subset). */
export interface CapCandidates {
  buildTimeIds: readonly string[];
  labSetupIds: readonly string[];
  engineBoot: readonly ForensicEvent[];
}

/**
 * The settle's three post-tagger corrections, in its order — build-time cap (#1529) → lab-setup cap
 * (#1946) → Defender engine start-up (#2084) — each under the state lock. One function so the settle
 * and every re-grade (#2909: in-process recovery, the next import's sweep, start-up) run the same
 * steps on the rows they graded, before the demote. Returns how many rows each step changed.
 */
export async function gradeCapsScoped(
  store: ForensicRowStore,
  lock: RunExclusive,
  caseId: string,
  ledger: Pick<InvestigationState, "hostRenames">,
  opts: { scanAll: boolean; candidates: CapCandidates },
): Promise<{ capped: number; labCapped: number; engineBoot: number }> {
  const { scanAll, candidates } = opts;
  const capped = await lock(caseId, () =>
    capBuildTimeScoped(store, caseId, ledger, { scanAll, extraIds: candidates.buildTimeIds }),
  );
  const labCapped = await lock(caseId, () =>
    capLabSetupScoped(store, caseId, { scanAll, candidateIds: candidates.labSetupIds }),
  );
  const engineBoot = await lock(caseId, () => stampEngineBootScoped(store, caseId, candidates.engineBoot));
  return { capped, labCapped, engineBoot };
}
