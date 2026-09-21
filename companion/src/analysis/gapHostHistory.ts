import { GAP_FINDING_ID_PREFIX } from "./responseSchema.js";
import { SEVERITY_RANK, type Finding, type ForensicEvent, type InvestigationState } from "./stateTypes.js";
import type { HostRenameRecord } from "./hostRenameRecord.js";
import { gapEnvOptions, type GapOptions } from "./gapDetect.js";
import { assetKey } from "./gapEdgeClass.js";
import { byEventTime } from "./forensicSort.js";

// A host's own history is not dwell time (#1503).
//
// A machine's timeline starts long before the intrusion: the install media's file dates, the base
// image, provisioning under a throwaway name, then the day it was first used. On a lab box those
// are months apart, and every one of those silences became a "dwell interval" finding — 532 days,
// 80 days, 255 days — with an open thread asking the analyst to explain them.
//
// The case already holds the one marker that separates that history from the host's working life:
// the rename ledger (`state.hostRenames`, #1495). A machine provisioned under WIN-UK1GV882OK6 and
// renamed to DESKTOP-16OJFO6 was not yet the host under investigation while it wore the old name.
// So rows dated before a host's EARLIEST observed rename bound are set aside FROM GAP ANALYSIS ONLY
// — they stay in the timeline — and one Info finding tells the analyst what was set aside.
//
// A rename bound is identity evidence, not a build date, so the cut is hedged three ways:
//   • PER HOST — only rows whose asset is the renamed machine (any name in its chain) move; another
//     host's rows, and rows naming no asset, never do.
//   • OBSERVED bases only — `analyst` records are one import's manual attribution, not something
//     the machine or a collector wrote, so they never mark a boundary.
//   • NO CUT PAST A GRADE — if any pre-marker row of that host is High/Critical (a rename during
//     an intrusion, or a tagger-flagged setup binary), that host is left whole and the edge rules
//     in gapEdgeClass.ts decide alone. The intrusion is never the thing set aside.

export interface HostHistoryMarker {
  host: string; // the host's current short name, for the Info row
  names: string[]; // every short name in the rename chain (former and current)
  before: string; // UTC ISO — the host's earliest observed rename bound
}

export interface HostHistorySlice {
  marker: HostHistoryMarker;
  events: ForensicEvent[]; // the rows set aside, time-ascending
}

export const HOST_HISTORY_FINDING_ID = `${GAP_FINDING_ID_PREFIX}host-history`;

const OBSERVED_BASES = new Set<HostRenameRecord["basis"]>([
  "6011",
  "machine-account",
  "sam-domain",
  "collector",
]);
const shortKey = (name: string): string => name.trim().split(".")[0].toUpperCase();

// One marker per renamed machine: records sharing a name (A→B, B→C) fold into one chain whose
// bound is the earliest `until`. The current name is the one no record renames away from.
export function hostBuildMarkers(records: readonly HostRenameRecord[] = []): HostHistoryMarker[] {
  const chains: { names: Set<string>; formers: Set<string>; currents: string[]; beforeMs: number }[] = [];
  for (const r of records) {
    if (!OBSERVED_BASES.has(r.basis)) continue;
    const untilMs = Date.parse(r.until);
    const former = shortKey(r.formerName);
    const current = shortKey(r.currentName);
    if (Number.isNaN(untilMs) || !former || !current) continue;
    let chain = chains.find((c) => c.names.has(former) || c.names.has(current));
    if (!chain) {
      chain = { names: new Set(), formers: new Set(), currents: [], beforeMs: Infinity };
      chains.push(chain);
    }
    chain.names.add(former).add(current);
    chain.formers.add(former);
    chain.currents.push(current);
    chain.beforeMs = Math.min(chain.beforeMs, untilMs);
  }
  return chains.map((c) => ({
    host: c.currents.find((n) => !c.formers.has(n)) ?? c.currents[c.currents.length - 1],
    names: [...c.names].sort(),
    before: new Date(c.beforeMs).toISOString(),
  }));
}

// Split a timeline into the rows gap analysis keeps and the per-host history it sets aside. Pure.
// The filtered set is used as-is, however small: 0 or 1 remaining rows simply means no gaps.
export function splitHostHistory(
  events: readonly ForensicEvent[],
  markers: readonly HostHistoryMarker[] = [],
): { kept: ForensicEvent[]; history: HostHistorySlice[] } {
  if (markers.length === 0) return { kept: [...events], history: [] };
  const setAside = new Set<string>();
  const history: HostHistorySlice[] = [];
  for (const marker of markers) {
    const names = new Set(marker.names);
    const beforeMs = Date.parse(marker.before);
    const rows = events
      .filter((e) => names.has(assetKey(e)) && Date.parse(e.timestamp) < beforeMs)
      .sort(byEventTime);
    if (rows.length === 0) continue;
    if (rows.some((e) => SEVERITY_RANK[e.severity] <= SEVERITY_RANK.High)) continue; // graded → left whole
    for (const e of rows) setAside.add(e.id);
    history.push({ marker, events: rows });
  }
  return { kept: events.filter((e) => !setAside.has(e.id)), history };
}

// Thresholds from the environment PLUS the case's own host markers — the options every consumer
// that holds the state should pass to detectGapsWithWaves, so the panel, the report, next steps,
// known-unknowns and synthesis all set aside the same rows.
export function gapOptionsFor(state: Pick<InvestigationState, "hostRenames">): GapOptions {
  return { ...gapEnvOptions(), hostHistory: hostBuildMarkers(state.hostRenames) };
}

// The one Info row that replaces the per-interval Medium findings: what was set aside, per host.
// Idempotent on a fixed id, like `f-waves`. Counts the FULL forensic timeline (it describes the
// host, not the analyst's current scope) and back-links the first and last set-aside row of each
// host so scope projection can still drop it.
export function backfillHostHistoryNote(
  state: InvestigationState,
  markers: readonly HostHistoryMarker[] | undefined,
  timestamp: string,
): InvestigationState {
  if (!markers?.length || state.findings.some((f) => f.id === HOST_HISTORY_FINDING_ID)) return state;
  const { history } = splitHostHistory(state.forensicTimeline, markers);
  if (history.length === 0) return state;
  const parts = history.map(
    (h) =>
      `${h.marker.host}: ${h.events.length} event${h.events.length === 1 ? "" : "s"} before ` +
      `${h.marker.before}, first ${h.events[0].timestamp}`,
  );
  const finding: Finding = {
    id: HOST_HISTORY_FINDING_ID,
    severity: "Info",
    confidence: 60,
    title: `Host history before provisioning: ${parts.join("; ")}`,
    description:
      `These rows predate the host's own provisioning boundary — the earliest point the case saw the ` +
      `machine renamed to its current name (${history.map((h) => h.marker.names.join(" → ")).join("; ")}). ` +
      `Install-media dates, base-image files and provisioning under a throwaway name are the machine's ` +
      `history, not dwell time, so the silences between them are not reported as coverage gaps or dwell ` +
      `intervals. The rows remain in the timeline; a High/Critical row before the boundary would have ` +
      `kept that host's history in gap analysis.`,
    relatedIocs: [],
    mitreTechniques: [],
    sourceScreenshots: [],
    firstSeen: history.map((h) => h.events[0].timestamp).sort()[0] || timestamp,
    lastUpdated: timestamp,
    status: "open",
  };
  const linkIds = new Set(history.flatMap((h) => [h.events[0].id, h.events[h.events.length - 1].id]));
  return {
    ...state,
    findings: [...state.findings, finding],
    forensicTimeline: state.forensicTimeline.map((e) =>
      linkIds.has(e.id) && !e.relatedFindingIds.includes(HOST_HISTORY_FINDING_ID)
        ? { ...e, relatedFindingIds: [...e.relatedFindingIds, HOST_HISTORY_FINDING_ID] }
        : e,
    ),
  };
}
