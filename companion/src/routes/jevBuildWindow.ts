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
 * and the read stops at NEIGHBOURHOOD_CAP rows. A row whose range was not read to the end is never
 * set aside: the part not read could hold the signal that vetoes its window. A wrong answer here must
 * fall towards showing the row.
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

interface Neighbourhood {
  rows: ForensicEvent[];
  complete: Array<[number, number]>; // the ranges read to the end; every other range failed open
}

// The archive rows around `rows`, and which ranges were read in full. A range cut short by the cap is
// NOT complete: it can hold a build's markers and miss the hard attacker signal that vetoes the window
// (Codex review of #1700), so its rows are never set aside on a partial read.
async function neighbourhood(
  store: SuperStore,
  caseId: string,
  rows: readonly ForensicEvent[],
  cap: number,
): Promise<Neighbourhood> {
  const seen = new Map<string, ForensicEvent>();
  const complete: Array<[number, number]> = [];
  for (const [from, to] of ranges(rows)) {
    const window = { from: new Date(from).toISOString(), to: new Date(to).toISOString() };
    let done = false;
    for (let offset = 0; seen.size < cap;) {
      const limit = Math.min(PAGE_ROWS, cap - seen.size);
      const page = await store.query(caseId, { ...window, offset, limit });
      for (const e of page.events) seen.set(e.id, e);
      offset += page.events.length;
      if (!page.events.length || offset >= page.total) {
        done = true;
        break;
      }
    }
    if (done) complete.push([from, to]);
  }
  return { rows: [...seen.values()], complete };
}

export interface BuildWindowSetAside {
  ids: Set<string>; // the rows inside a window, read in full
  windows: Array<{ host: string; start: string; end: string }>; // the windows they sit in, for the analyst
}

/**
 * The rows of `rows` inside a build window of this case, and those windows. Empty on a case with no
 * rename chain. The windows go back to the analyst so a set-aside row can be found and checked in
 * the super-timeline: the count alone would say rows are hidden without saying where.
 */
export async function rowsInBuildWindow(
  store: SuperStore,
  caseId: string,
  state: InvestigationState,
  rows: readonly ForensicEvent[],
  cap = NEIGHBOURHOOD_CAP,
): Promise<BuildWindowSetAside> {
  const none: BuildWindowSetAside = { ids: new Set(), windows: [] };
  const renames = state.hostRenames ?? [];
  if (!renames.length || !rows.length) return none;
  const near = await neighbourhood(store, caseId, rows, cap);
  const byId = new Map<string, ForensicEvent>();
  for (const e of [...state.forensicTimeline, ...near.rows, ...rows]) if (!byId.has(e.id)) byId.set(e.id, e);
  const windows = buildTimeWindows([...byId.values()], renames);
  if (!windows.length) return none;
  const readInFull = (e: ForensicEvent) => {
    const t = Date.parse(e.timestamp);
    return near.complete.some(([from, to]) => t >= from && t <= to);
  };
  const ids = new Set<string>();
  const used = new Map<string, { host: string; start: string; end: string }>();
  for (const e of rows) {
    const w = windowFor(windows, e);
    if (!w || !readInFull(e)) continue;
    ids.add(e.id);
    used.set(`${w.host}|${w.start}`, { host: w.host, start: w.start, end: w.end });
  }
  return { ids, windows: [...used.values()].sort((a, b) => a.start.localeCompare(b.start)) };
}
