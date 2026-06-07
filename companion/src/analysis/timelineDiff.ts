import type { ForensicEvent, Severity } from "./stateTypes.js";

// What changed in the forensic timeline across one import — primarily what the import ADDED.
// Imports assign fresh per-import event ids (a different idPrefix each time) and correlation may
// collapse re-imported duplicates, so we diff by normalized TIME + DESCRIPTION (the same key
// correlate.ts uses for exact-duplicate matching) rather than by id: re-importing the same file
// then shows "no new events" instead of every row reappearing under a new id. This is the timeline
// analog of findingsDiff.ts (which diffs findings by normalized title).

export interface DiffEvent {
  timestamp: string;
  description: string;
  severity: Severity;
}

export interface TimelineDiff {
  added: DiffEvent[];     // events present after, not before (what the import brought in)
  removed: DiffEvent[];   // events present before, not after (absorbed by correlation — rare)
}

const norm = (s: string): string => String(s ?? "").trim().toLowerCase().replace(/\s+/g, " ");
const keyOf = (e: { timestamp: string; description: string }): string => `${norm(e.timestamp)}|${norm(e.description)}`;

// First occurrence of each normalized key wins (keeps its displayed time/description/severity).
function byKey(events: readonly ForensicEvent[]): Map<string, DiffEvent> {
  const map = new Map<string, DiffEvent>();
  for (const e of events) {
    const key = keyOf(e);
    if (key === "|" || map.has(key)) continue;   // skip fully-empty rows; first occurrence wins
    map.set(key, { timestamp: e.timestamp, description: e.description, severity: e.severity });
  }
  return map;
}

// Compute added / removed timeline events from `before` -> `after`.
export function diffTimeline(before: readonly ForensicEvent[], after: readonly ForensicEvent[]): TimelineDiff {
  const a = byKey(before);
  const b = byKey(after);
  const added: DiffEvent[] = [];
  const removed: DiffEvent[] = [];
  for (const [key, cur] of b) if (!a.has(key)) added.push(cur);
  for (const [key, prev] of a) if (!b.has(key)) removed.push(prev);
  return { added, removed };
}

// True when nothing changed — lets callers skip recording/rendering an empty diff.
export function isEmptyTimelineDiff(diff: TimelineDiff): boolean {
  return diff.added.length === 0 && diff.removed.length === 0;
}
