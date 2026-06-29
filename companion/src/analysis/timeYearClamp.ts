import type { ForensicEvent } from "./stateTypes.js";

// Deterministic year-clamp for MIS-DATED events.
//
// Some sources carry a timestamp with NO YEAR — a Cisco ASA / BSD syslog line is `May 14 12:00:48`,
// a bare CSV time column may be `12:00:48`. When such a line is read through an AI-assisted import
// (analyzeLog / analyzeCsv), the model has to guess the year and gets it wrong — landing the event in
// 2023 or (defaulting to "now") the current year, instead of the real collection year. A few such
// strays corrupt the chronology (wrong kill-chain ordering) and, before the gap-detector outlier guard,
// manufactured giant false coverage gaps.
//
// This re-anchors an OUTLIER-YEAR event onto the timeline's dominant year, preserving month/day/time —
// because for a year-less source the month/day/time ARE correct; only the year was guessed. It is
// deliberately CONSERVATIVE: it acts only when one year clearly dominates the dated timeline
// (≥ `dominantFraction`, default 0.9), so a genuine multi-year case (an incident spanning a New Year, a
// super-timeline) is left untouched. Pure, immutable, idempotent (a second pass finds the dominant year
// at ~100% and no off-year events, so it is a no-op).

export const DEFAULT_YEAR_CLAMP_DOMINANT_FRACTION = 0.9;
// Below this many DATED events the dominant year isn't trustworthy — don't clamp a tiny timeline.
const YEAR_CLAMP_MIN_EVENTS = 12;

export interface YearClampOptions {
  dominantFraction?: number; // fraction of dated events one year must hold to be the anchor. Default 0.9.
  minEvents?: number;        // minimum dated events before clamping applies. Default 12.
}

// Year of an ISO timestamp in UTC, or null when unparseable/empty.
function yearOf(ts: string | undefined): number | null {
  if (!ts) return null;
  const ms = Date.parse(ts);
  return Number.isNaN(ms) ? null : new Date(ms).getUTCFullYear();
}

// Re-anchor an ISO timestamp onto `year`, preserving its month/day/time-of-day (UTC). Unparseable
// input is returned unchanged.
function setYear(ts: string, year: number): string {
  const ms = Date.parse(ts);
  if (Number.isNaN(ms)) return ts;
  const d = new Date(ms);
  return new Date(Date.UTC(
    year, d.getUTCMonth(), d.getUTCDate(),
    d.getUTCHours(), d.getUTCMinutes(), d.getUTCSeconds(), d.getUTCMilliseconds(),
  )).toISOString();
}

// Re-anchor events whose year is an outlier onto the timeline's dominant year (see module header).
// Returns a new array; events already on the dominant year (or undated) pass through unchanged. When no
// year dominates, or the timeline is too small, the input is returned as-is.
export function clampOutlierYears(events: readonly ForensicEvent[], opts: YearClampOptions = {}): ForensicEvent[] {
  const dominantFraction = opts.dominantFraction ?? DEFAULT_YEAR_CLAMP_DOMINANT_FRACTION;
  const minEvents = opts.minEvents ?? YEAR_CLAMP_MIN_EVENTS;

  const byYear = new Map<number, number>();
  let dated = 0;
  for (const e of events) {
    const y = yearOf(e.timestamp);
    if (y === null) continue;
    dated++;
    byYear.set(y, (byYear.get(y) ?? 0) + 1);
  }
  if (dated < minEvents || byYear.size < 2) return [...events];

  let dominantYear = 0;
  let dominantCount = -1;
  for (const [y, c] of byYear) if (c > dominantCount) { dominantYear = y; dominantCount = c; }
  if (dominantCount / dated < dominantFraction) return [...events]; // no clear anchor → leave untouched

  return events.map((e) => {
    const y = yearOf(e.timestamp);
    if (y === null || y === dominantYear) return e;
    const next: ForensicEvent = { ...e, timestamp: setYear(e.timestamp, dominantYear) };
    // Keep an aggregated row's end bound consistent if it too sits on an outlier year.
    if (e.endTimestamp && yearOf(e.endTimestamp) !== null && yearOf(e.endTimestamp) !== dominantYear) {
      next.endTimestamp = setYear(e.endTimestamp, dominantYear);
    }
    return next;
  });
}
