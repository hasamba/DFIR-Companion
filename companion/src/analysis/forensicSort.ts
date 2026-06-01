import type { ForensicEvent } from "./stateTypes.js";

// Order forensic events by their real event time. Unparseable/empty timestamps
// sort to the end so the known chronology stays intact and readable.
export function byEventTime(a: ForensicEvent, b: ForensicEvent): number {
  const ta = Date.parse(a.timestamp);
  const tb = Date.parse(b.timestamp);
  const va = Number.isNaN(ta);
  const vb = Number.isNaN(tb);
  if (va && vb) return 0;
  if (va) return 1;
  if (vb) return -1;
  return ta - tb;
}

export function sortByEventTime(events: ForensicEvent[]): ForensicEvent[] {
  return [...events].sort(byEventTime);
}
