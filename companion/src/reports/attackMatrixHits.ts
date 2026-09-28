import {
  SEVERITY_RANK,
  worstSeverity,
  type InvestigationState,
  type Severity,
} from "../analysis/stateTypes.js";
import type { MatrixHit } from "../analysis/attackMatrix.js";

// The case's ATT&CK techniques as matrix hits (#1764) — the server half of the MatrixHit contract.
//
// INPUT IS THE FILTERED STATE. Pass what reportWriter.filteredState() / loadFilteredState() return:
// scope, the false-positive filter and withEventTechniques() have already run, so
// `state.mitreTechniques` IS the List view's rows (the dashboard's deriveMitreRows() is the client
// mirror of that projection) and `state.findings` holds only surviving findings. A technique whose
// only support was a finding the analyst confirmed benign is therefore already gone, and the
// matrix cannot disagree with the List view or with the Navigator layer export, which is built
// from the very same state by buildAttackLayer().
//
// Worst severity follows buildAttackLayer() exactly: the max over the surviving findings that name
// the id and the forensic events that carry it, ids compared trimmed and upper-cased as the layer
// compares them. A row nothing supports (the analyst accepted it) is Info.
//
// Reads findings and the forensic timeline only. Never the super-timeline (CLAUDE.md §7).

/** One hit plus the name the case's MITRE table gives it (used when the catalogue lacks the id). */
export interface CaseMatrixHit extends MatrixHit {
  name: string;
}

const norm = (id: string): string =>
  String(id || "")
    .trim()
    .toUpperCase();

interface Support {
  worst?: Severity;
  events: Array<{ id: string; timestamp: string }>;
}

function supportIndex(state: InvestigationState): Map<string, Support> {
  const index = new Map<string, Support>();
  const get = (raw: string): Support => {
    const id = norm(raw);
    const cur = index.get(id) ?? { events: [] };
    index.set(id, cur);
    return cur;
  };
  const bump = (s: Support, sev: Severity): void => {
    s.worst = s.worst ? worstSeverity(s.worst, sev) : sev;
  };
  for (const f of state.findings) for (const t of f.mitreTechniques) bump(get(t), f.severity);
  for (const e of state.forensicTimeline) {
    for (const t of new Set(e.mitreTechniques.map(norm))) {
      const s = get(t);
      bump(s, e.severity);
      s.events.push({ id: e.id, timestamp: e.timestamp || "" });
    }
  }
  return index;
}

// Epoch ms, or +Infinity for a timestamp that does not parse, so undated rows sort last.
const epoch = (ts: string): number => {
  const ms = Date.parse(ts);
  return Number.isNaN(ms) ? Number.POSITIVE_INFINITY : ms;
};

// De-duplicated, oldest first, then by id — the order the popover lists them in.
function sortedEventIds(events: Support["events"]): string[] {
  const seen = new Map<string, number>();
  for (const e of events) if (!seen.has(e.id)) seen.set(e.id, epoch(e.timestamp));
  return [...seen.entries()]
    .sort((a, b) => (a[1] === b[1] ? a[0].localeCompare(b[0]) : a[1] < b[1] ? -1 : 1))
    .map(([id]) => id);
}

/** Build the matrix hits from the filtered case state, one per MITRE row, in row order. */
export function buildMatrixHits(state: InvestigationState): CaseMatrixHit[] {
  const support = supportIndex(state);
  return state.mitreTechniques.map((row) => {
    const s = support.get(norm(row.id));
    return {
      id: row.id,
      name: row.name || row.id,
      worst: s?.worst ?? "Info",
      findingIds: [...row.findingIds],
      eventIds: s ? sortedEventIds(s.events) : [],
      ...(row.analystAccepted ? { analystAccepted: true } : {}),
    };
  });
}

/** Most severe first, for a stable legend order. */
export function presentSeverities(hits: readonly MatrixHit[]): Severity[] {
  return [...new Set(hits.map((h) => h.worst))].sort((a, b) => SEVERITY_RANK[a] - SEVERITY_RANK[b]);
}
