import { AUTO_FINDING_ID_PREFIX } from "./responseSchema.js";
import type { Finding, ForensicEvent, InvestigationState, Severity } from "./stateTypes.js";

// #1943: when the model groups many rows under one finding, a High row from a different attack step
// can be absorbed — cited, so the High-row backfill counted it as covered, but never named in the
// finding's text. This module finds those rows so the backfill can give each its own finding.
//
// A row is "absorbed" when ALL of these hold:
// - it is High/Critical (one constant, so a later widening is one line);
// - it has no auto-finding link yet (keeps the backfill idempotent);
// - every finding it is linked to is a live, non-auto finding that cites it DIRECTLY in its own
//   relatedEventIds. A grouped-burst link (#1702) or a dismissed finding counts as covered;
// - for every such finding: the finding cites at least MIN_CITED_PATH_ROWS rows with a path, no
//   other cited row shares the row's parent folder, and the finding's title + description name
//   neither the row's file name, nor its folder's name, nor its full parent path.

const ABSORBABLE_SEVERITY = new Set<Severity>(["Critical", "High"]);

// With two rows in two folders, each row is an "outlier" — noise, not a change of step.
const MIN_CITED_PATH_ROWS = 3;

interface PathParts {
  basename: string;
  parent: string;
  folder: string;
}

function pathParts(path: string): PathParts | undefined {
  const segs = path.toLowerCase().replace(/\\/g, "/").split("/").filter(Boolean);
  if (segs.length < 2) return undefined;
  return {
    basename: segs[segs.length - 1],
    parent: segs.slice(0, -1).join("/"),
    folder: segs[segs.length - 2],
  };
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// Whole-token match, so the folder "auth" is not named by the word "authoring".
function namesTerm(text: string, term: string): boolean {
  return new RegExp(`(^|[^a-z0-9_])${escapeRegExp(term)}($|[^a-z0-9_])`).test(text);
}

function findingNames(f: Finding, parts: PathParts): boolean {
  const text = `${f.title}\n${f.description}`.toLowerCase().replace(/\\/g, "/");
  return [parts.basename, parts.folder, parts.parent].some((t) => namesTerm(text, t));
}

// True when `f` absorbs the row: enough cited rows with a path, the row alone in its folder, and the
// text silent about the row's file and folder.
function absorbs(f: Finding, row: PathParts, rowId: string, eventById: Map<string, ForensicEvent>): boolean {
  const others: PathParts[] = [];
  for (const eid of f.relatedEventIds ?? []) {
    const path = eventById.get(eid)?.path;
    const parts = path ? pathParts(path) : undefined;
    if (parts && eid !== rowId) others.push(parts);
  }
  if (others.length + 1 < MIN_CITED_PATH_ROWS) return false;
  if (others.some((o) => o.parent === row.parent)) return false;
  return !findingNames(f, row);
}

// Ids of High/Critical rows that a citing finding absorbed without naming them. Pure.
export function absorbedHighRowIds(state: InvestigationState): Set<string> {
  const out = new Set<string>();
  const live = new Map(
    state.findings
      .filter((f) => f.status !== "dismissed" && !f.id.startsWith(AUTO_FINDING_ID_PREFIX))
      .map((f) => [f.id, f] as const),
  );
  if (live.size === 0) return out;
  const eventById = new Map(state.forensicTimeline.map((e) => [e.id, e] as const));
  for (const e of state.forensicTimeline) {
    if (!ABSORBABLE_SEVERITY.has(e.severity) || !e.path || e.relatedFindingIds.length === 0) continue;
    const row = pathParts(e.path);
    if (!row) continue;
    const absorbed = e.relatedFindingIds.every((fid) => {
      const f = live.get(fid);
      return !!f && (f.relatedEventIds ?? []).includes(e.id) && absorbs(f, row, e.id, eventById);
    });
    if (absorbed) out.add(e.id);
  }
  return out;
}
