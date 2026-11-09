// Where a coverage row sits on the forensic timeline (#2486).
//
// A coverage row ("Cloud coverage gap", "Cloud object logging is off", "Cloud object reads were not
// all examined", "Browsing evidence without an account") is advice about the evidence, not an event,
// so it has no time of its own. It used to take the time of the FIRST matching event in array order,
// which is whatever order the uploads happened to merge in: the first event in one case, the last
// in another. It now sits at the EARLIEST matching event, by time, so its place is fixed and
// documented: at the start of the evidence it describes.

import type { ForensicEvent } from "./stateTypes.js";

/**
 * The timestamp of the earliest event `pick` accepts, as that event stores it; events whose time
 * does not parse are skipped. The current time when no accepted event has a readable time.
 */
export function earliestEventTime(
  events: readonly ForensicEvent[],
  pick: (e: ForensicEvent) => boolean,
): string {
  let best: string | undefined;
  let bestMs = Infinity;
  for (const e of events) {
    const ms = Date.parse(e.timestamp ?? "");
    if (!Number.isFinite(ms) || ms >= bestMs || !pick(e)) continue;
    bestMs = ms;
    best = e.timestamp;
  }
  return best ?? new Date().toISOString();
}
