// What correlation does with the build-time cap (#1698). Filed in analysis/timeline beside
// correlate.ts, which uses it; buildTimeWindow.ts (analysis/detect) writes the cap and imports the
// marker from here, so no import runs up a layer.
//
// Correlation unions every member's derived notes but took the build-time record from the primary
// only. A member capped by one import merged with a fresh copy from the next kept the note and lost
// the record, and synthesis quoted a window that no longer existed. The note must travel with its
// record, never alone.

import { SEVERITY_RANK, worstSeverity, type ForensicEvent, type Severity } from "./stateTypes.js";

/** The derived note the build-time cap writes; registered in derivedNote.ts DERIVED_NOTE_NAMES. */
export const BUILD_TIME_MARKER = "[build-time:";

/** Is this one of the build-time cap's notes? */
export function isBuildTimeNote(note: string): boolean {
  return note.trim().startsWith(BUILD_TIME_MARKER);
}

/**
 * The build-time record a correlated row keeps: the primary's when it has one, else the first member's
 * that does, with the WORST pre-cap grade across the members as the grade to restore. Undefined when
 * no member carries a record — correlation then drops any build-time note from the union.
 */
export function mergedBuildTime(
  primary: ForensicEvent,
  members: readonly ForensicEvent[],
): ForensicEvent["buildTime"] {
  const recorded = members.find((m) => m.buildTime)?.buildTime;
  if (!recorded) return undefined;
  const base = primary.buildTime ?? recorded;
  const original = members.reduce<Severity>(
    (acc, m) => worstSeverity(acc, m.buildTime?.cappedFrom ?? m.severity),
    "Info",
  );
  return {
    marker: base.marker,
    window: base.window,
    // SEVERITY_RANK puts the most severe first: a lower rank than Low is a grade the cap lowers.
    ...(SEVERITY_RANK[original] < SEVERITY_RANK.Low ? { cappedFrom: original } : {}),
  };
}

/**
 * Every derived note across the members (deduplicated, member order), the build-time record the merged
 * row keeps, and the notes it keeps: a build-time note only beside a record. A collector grade is final
 * (#1477), so a collector-graded merge carries no record to restore later.
 */
export function mergeDerivedNotes(
  primary: ForensicEvent,
  members: readonly ForensicEvent[],
  noteRe: RegExp,
  collectorGraded: boolean,
): { buildTime: ForensicEvent["buildTime"]; allNotes: string[]; notes: string[] } {
  const allNotes = [
    ...new Set(members.flatMap((e) => Array.from(e.description.matchAll(noteRe), (m) => m[0].trim()))),
  ];
  const buildTime = collectorGraded ? undefined : mergedBuildTime(primary, members);
  return { buildTime, allNotes, notes: allNotes.filter((n) => buildTime || !isBuildTimeNote(n)) };
}
