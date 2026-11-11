// The object-logging coverage row, made time-aware (#2542 item 8).
//
// The existing row ("Cloud object logging is off") fires only when a case holds object listings and
// no object reads at all. A case where S3 data events were turned on PART-WAY — the responder
// enabling them after the incident — holds plenty of later object records, so the row stayed silent
// and the window that mattered (the encryption, the overwrites, the ransom note) read as "nothing
// happened". "No CopyObject / DeleteObject" is then a wrong conclusion resting on unlogged evidence.
//
// This builds the same row (same id, same source, same grade — so the severity gate still exempts
// it, #2497) when the case holds a CloudTrail selector change that selects S3 object activity and
// NO object-level record before it. It says what the records show, never more: "no object-level
// records before T", not "data events were off" — another trail's selectors are not in the evidence.

import type { ForensicEvent } from "./stateTypes.js";
import { COVERAGE_SOURCE, earliestEventTime, OBJECT_LOGGING_COVERAGE_ID } from "./coverageEventTime.js";

const S3_OBJECT_SELECTOR = /AWS::S3::Object/i;
const S3_OBJECT_ACTION = /object|multipartupload|uploadpart/i;
const SELECTOR_ACTIONS = new Set(["puteventselectors", "createtrail", "updatetrail"]);

const msOf = (e: ForensicEvent): number => Date.parse(e.timestamp ?? "");
const isAws = (e: ForensicEvent): boolean => e.canonical?.cloud?.provider === "aws";

/**
 * A successful CloudTrail selector change whose resulting selectors name S3 object activity. The
 * merge index marks these LOAD rows (mergeIndex.ts), so every merge sees the note's anchor (#2564).
 */
export function selectsObjects(e: ForensicEvent): boolean {
  const block = e.canonical?.loggingChange;
  if (!block || block.provider !== "aws" || block.failure || block.state === "requested") return false;
  if (!SELECTOR_ACTIONS.has((e.canonical?.event?.action ?? "").toLowerCase())) return false;
  return block.facts.some((f) => S3_OBJECT_SELECTOR.test(f.value));
}

/**
 * An object-level AWS record: an S3 object operation whose resource names a bucket AND an object
 * (`bucket/key`). The action is checked too — a role ARN (`arn:…:role/x`) also holds a slash.
 */
function isObjectRecord(e: ForensicEvent): boolean {
  const resource = e.canonical?.cloud?.resource ?? "";
  const action = e.canonical?.event?.action ?? "";
  return isAws(e) && S3_OBJECT_ACTION.test(action) && resource.indexOf("/") > 0;
}

/** The earliest selector change that selects object activity, or null. */
function firstObjectSelectorChange(events: readonly ForensicEvent[]): ForensicEvent | null {
  let change: ForensicEvent | null = null;
  for (const e of events)
    if (e.id !== OBJECT_LOGGING_COVERAGE_ID && selectsObjects(e) && Number.isFinite(msOf(e)))
      if (!change || msOf(e) < msOf(change)) change = e;
  return change;
}

const hasObjectRecordBefore = (events: readonly ForensicEvent[], at: number): boolean =>
  events.some((e) => isObjectRecord(e) && msOf(e) < at);

/** The dated variant of the coverage row ("Cloud object logging begins at T"), not "is off". */
const WINDOW_NOTE_HEAD = "Cloud object logging begins at ";
const isWindowNote = (e: ForensicEvent): boolean =>
  e.id === OBJECT_LOGGING_COVERAGE_ID && (e.description ?? "").startsWith(WINDOW_NOTE_HEAD);

/**
 * Whether the events hold a stored dated note that the evidence now contradicts: an object-level
 * record earlier than the selector change has arrived (#2564). The note claims there is none, so it
 * must be withdrawn — on the full merge and, through cloudPassWork, on the incremental one alike.
 */
export function windowNoteContradicted(events: readonly ForensicEvent[]): boolean {
  if (!events.some(isWindowNote)) return false;
  const change = firstObjectSelectorChange(events);
  return change !== null && hasObjectRecordBefore(events, msOf(change));
}

/** The events without a contradicted dated note; the same array when there is none to withdraw. */
export function withoutContradictedWindowNote(events: readonly ForensicEvent[]): readonly ForensicEvent[] {
  return windowNoteContradicted(events) ? events.filter((e) => !isWindowNote(e)) : events;
}

/**
 * The coverage row for a case whose S3 object logging began part-way, or null: there is a selector
 * change that selects object activity, and no object-level record is earlier than the first one.
 */
export function objectLoggingWindowEvent(
  events: readonly ForensicEvent[],
  marker: string,
): ForensicEvent | null {
  const change = firstObjectSelectorChange(events);
  if (!change) return null;
  const at = msOf(change);
  if (hasObjectRecordBefore(events, at)) return null;
  const start = earliestEventTime(events, (e) => e.id !== OBJECT_LOGGING_COVERAGE_ID && isAws(e));
  const t = new Date(at).toISOString().slice(0, 19);
  const from = start.slice(0, 19);
  const action = change.canonical?.event?.action ?? "a selector change";
  return {
    id: OBJECT_LOGGING_COVERAGE_ID,
    timestamp: start,
    description: `${WINDOW_NOTE_HEAD}${t}Z ${marker} No object-level (data) records in this case before ${t}Z, when ${action} set selectors that log S3 object activity. Object reads, overwrites and deletes from ${from}Z to ${t}Z cannot be seen in these logs, so no object activity in that window is not evidence that none happened. Other trails' selectors are not in this evidence.]`,
    severity: "Medium",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    sources: [COVERAGE_SOURCE],
  };
}
