// Where a coverage row sits on the forensic timeline (#2486), and how the severity gate knows one (#2497).
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

// The four coverage rows are also exempt from the severity gate (#2497). They are graded Medium, so
// a case gated at High used to demote them on every import and synthesis lost the "nothing found is
// not absent" warning (#908). A row counts as one only when it carries one of the fixed ids the
// merge builders mint AND the "Coverage" source — never by `sources` alone, which an AI import may
// fill with any string (the same reasoning as the manual-id rule, #1919).

/** The source every coverage row carries. */
export const COVERAGE_SOURCE = "Coverage";

/** The fixed id of each coverage row, so a re-merge replaces it instead of adding another. */
export const METADATA_COVERAGE_ID = "cloud-metadata-coverage";
export const OBJECT_LOGGING_COVERAGE_ID = "cloud-object-logging-coverage";
export const BULK_READ_TRUNCATION_ID = "cloud-bulk-read-truncated";
export const BROWSING_ATTRIBUTION_ID = "shellbag-attribution-coverage";

export const COVERAGE_NOTE_IDS: ReadonlySet<string> = new Set([
  METADATA_COVERAGE_ID,
  OBJECT_LOGGING_COVERAGE_ID,
  BULK_READ_TRUNCATION_ID,
  BROWSING_ATTRIBUTION_ID,
]);

/** True for a coverage row the merge built — the rows the severity gate never demotes. */
export function isCoverageNote(e: ForensicEvent): boolean {
  return COVERAGE_NOTE_IDS.has(e.id) && (e.sources ?? []).includes(COVERAGE_SOURCE);
}
