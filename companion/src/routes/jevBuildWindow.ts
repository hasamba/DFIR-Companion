import { buildTimeWindows, windowFor, BUILD_WINDOW_REACH_MS } from "../analysis/buildTimeWindow.js";
import type { ForensicEvent, InvestigationState } from "../analysis/stateTypes.js";
import type { RouteContext } from "./context.js";

/**
 * Which archive rows sit inside the host's own build window (#1700) — shared by the missed-evidence
 * review, which sets them aside before it spends anything, and the promote route, which refuses them
 * again so an older tab or a grade recorded before this check cannot bring them back.
 *
 * On INC-2026-014 the review graded 216 build-day rows (Chocolatey firewall churn, Packer script
 * blocks, the provisioning log clears) up to Critical: the grader was never told they were the
 * machine building itself. The analyst ticked them, and the next synthesis raised four High auto
 * findings on them.
 *
 * The windows are found the way the import seam finds them (buildTimeWindow.ts), from the forensic
 * timeline AND the archive around the rows in question: the build's own markers are usually Info, so
 * they live in the archive, and an archive-only hard attacker signal must veto the whole window
 * exactly as it would at import. Reading only the rows the analyst ticked would miss both.
 *
 * Bounded: nothing is read on a case with no rename chain (it can have no window), the archive is read
 * only within BUILD_WINDOW_REACH_MS of the rows asked about, nearby ranges are merged into one query,
 * and the read stops at NEIGHBOURHOOD_CAP rows. A window whose evidence lies past the cap is not seen,
 * and its rows stay reviewable — the direction a wrong answer must fall.
 */

const PAGE_ROWS = 2000;
const NEIGHBOURHOOD_CAP = 50_000;

type SuperStore = NonNullable<RouteContext["options"]["superTimelineStore"]>;

// The rows' timestamps as merged [from, to] ranges, each widened by the reach.
function ranges(rows: readonly ForensicEvent[]): Array<[number, number]> {
  const times = rows
    .map((e) => Date.parse(e.timestamp))
    .filter((t) => Number.isFinite(t))
    .sort((a, b) => a - b);
  const out: Array<[number, number]> = [];
  for (const t of times) {
    const from = t - BUILD_WINDOW_REACH_MS;
    const to = t + BUILD_WINDOW_REACH_MS;
    const last = out[out.length - 1];
    if (last && from <= last[1]) last[1] = Math.max(last[1], to);
    else out.push([from, to]);
  }
  return out;
}

async function neighbourhood(store: SuperStore, caseId: string, rows: readonly ForensicEvent[]) {
  const seen = new Map<string, ForensicEvent>();
  for (const [from, to] of ranges(rows)) {
    const window = { from: new Date(from).toISOString(), to: new Date(to).toISOString() };
    for (let offset = 0; seen.size < NEIGHBOURHOOD_CAP;) {
      const limit = Math.min(PAGE_ROWS, NEIGHBOURHOOD_CAP - seen.size);
      const page = await store.query(caseId, { ...window, offset, limit });
      for (const e of page.events) seen.set(e.id, e);
      offset += page.events.length;
      if (!page.events.length || offset >= page.total) break;
    }
  }
  return [...seen.values()];
}

/** The ids of `rows` inside a build window of this case, or an empty set when there is none. */
export async function rowsInBuildWindow(
  store: SuperStore,
  caseId: string,
  state: InvestigationState,
  rows: readonly ForensicEvent[],
): Promise<Set<string>> {
  const renames = state.hostRenames ?? [];
  if (!renames.length || !rows.length) return new Set();
  const byId = new Map<string, ForensicEvent>();
  for (const e of [...state.forensicTimeline, ...(await neighbourhood(store, caseId, rows)), ...rows])
    if (!byId.has(e.id)) byId.set(e.id, e);
  const windows = buildTimeWindows([...byId.values()], renames);
  if (!windows.length) return new Set();
  return new Set(rows.filter((e) => windowFor(windows, e)).map((e) => e.id));
}
