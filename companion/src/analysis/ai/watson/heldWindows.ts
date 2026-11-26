import {
  buildMarkerKind,
  buildTimeWindows,
  hardAttackerSignal,
  type BuildTimeWindow,
} from "../../buildTimeWindow.js";
import { isAttackerDefenderTouch, isDefenderEngineWrite, isStartupRow } from "../../defenderEngineBoot.js";
import { SCAN_PAGE_ROWS, type ForensicRowStore } from "../../forensicRows.js";
import { assetKey } from "../../gapEdgeClass.js";
import { hostBuildMarkers } from "../../gapHostHistory.js";
import type { ForensicEvent } from "../../stateTypes.js";

// What the held tagger's post-tagger corrections (heldTagger.ts finalizeHeld) read besides the
// candidates: the build-time windows, and the rows the Defender engine start-up stamp looks across.
// Both read the FORENSIC timeline only — never the super-timeline (CLAUDE.md §7).

type WindowStore = Pick<
  ForensicRowStore,
  "loadOverview" | "loadOverviewWithoutIocs" | "forensicHosts" | "forensicTimelineBatches"
>;

const shortName = (host: string): string => host.trim().split(".")[0].toUpperCase();

/** The forensic timeline's rows of the hosts whose short name is in `names`, filtered by `keep`. */
async function rowsOfHosts(
  store: WindowStore,
  caseId: string,
  names: ReadonlySet<string>,
  keep: (e: ForensicEvent) => boolean,
): Promise<ForensicEvent[]> {
  const out: ForensicEvent[] = [];
  const hosts = (await store.forensicHosts(caseId)).filter((h) => names.has(shortName(h)));
  for (const host of hosts) {
    for await (const batch of store.forensicTimelineBatches(caseId, { host, limit: SCAN_PAGE_ROWS })) {
      for (const e of batch) if (keep(e)) out.push(e);
    }
  }
  return out;
}

/**
 * The build-time windows the settle's cap used (routes/importSettleCap.ts). Demote may already have
 * removed the import's Info rows from the forensic timeline, so its own rows are read from what the
 * tagger saw (`offered`).
 */
export async function heldBuildWindows(
  store: WindowStore,
  caseId: string,
  offered: readonly ForensicEvent[],
): Promise<BuildTimeWindow[]> {
  const ledger = store.loadOverviewWithoutIocs
    ? await store.loadOverviewWithoutIocs(caseId)
    : await store.loadOverview(caseId);
  const renames = ledger.hostRenames ?? [];
  const chains = hostBuildMarkers(renames);
  if (!chains.length) return [];
  const signals = (e: ForensicEvent): boolean => !!(buildMarkerKind(e) || hardAttackerSignal(e));
  const discovery = offered.filter(signals);
  const seen = new Set(discovery.map((e) => e.id));
  const names = new Set(chains.flatMap((c) => c.names));
  const stored = await rowsOfHosts(store, caseId, names, (e) => signals(e) && !seen.has(e.id));
  return buildTimeWindows([...discovery, ...stored], renames);
}

/**
 * The rows the engine start-up stamp looks across for a re-grade (#2918). A re-grade's held tagger
 * runs once per page, so the page alone could miss a start-up row in another page. Every marked row
 * is still in the forensic timeline while the pages are tagged (the one demote runs after the last
 * page), so the start-up and attacker-touch rows of each candidate engine write's host are read from
 * there and added to the page. No candidate is an engine write: the page alone (nothing is read).
 */
export async function heldEngineContext(
  store: WindowStore,
  caseId: string,
  page: readonly ForensicEvent[],
  candidates: readonly ForensicEvent[],
): Promise<ForensicEvent[]> {
  const names = new Set(candidates.filter(isDefenderEngineWrite).map(assetKey).filter(Boolean));
  if (!names.size) return [...page];
  const inPage = new Set(page.map((e) => e.id));
  const anchors = await rowsOfHosts(
    store,
    caseId,
    names,
    (e) => !inPage.has(e.id) && (isStartupRow(e) || isAttackerDefenderTouch(e)),
  );
  return [...page, ...anchors];
}
