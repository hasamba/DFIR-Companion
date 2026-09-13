// Pure mappers: Companion forensic timeline → Timesketch import events (JSONL). No I/O — every
// function is deterministic and unit-tested. The orchestrator (timesketchPush.ts) wires these to
// the live TimesketchClient; the report writer reuses toTimesketchJsonl for the on-demand
// "Export Timesketch JSONL" download.
//
// Timesketch's import format requires three fields per event — `message`, `datetime`,
// `timestamp_desc` — and indexes every other field as searchable. We carry the forensic event's
// structured fields through (severity, MITRE, asset, hashes, path, process chain…) and add a
// `tag` list so an analyst can filter the imported timeline in the Timesketch UI.
// https://timesketch.org/guides/user/import-from-json-csv/

import type { ForensicEvent, InvestigationState } from "../../analysis/stateTypes.js";
import { byEventTime } from "../../analysis/forensicSort.js";

const TAG = "dfir-companion";

// Timesketch parses `datetime` as ISO8601. We emit `%Y-%m-%dT%H:%M:%S.%f%z` (microseconds + an
// explicit UTC offset), normalized to UTC — e.g. "2026-06-04T13:45:09.123000+00:00". Returns null
// when the source timestamp is unparseable (the caller drops the event).
export function timesketchDate(iso: string): string | null {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return null;
  // toISOString() → "2026-06-04T13:45:09.123Z" (always 3 fractional digits). Pad to microseconds
  // and replace the trailing Z with an explicit "+00:00" offset.
  return d.toISOString().replace("Z", "000+00:00");
}

// One Timesketch import event. message/datetime/timestamp_desc are mandatory; the index-signature
// holds the searchable extras (severity, mitre, asset, sha256, tag…).
export interface TimesketchEvent {
  message: string;
  datetime: string;
  timestamp_desc: string;
  [field: string]: unknown;
}

// Map a forensic event to a Timesketch import event, or null when it has no parseable timestamp.
export function mapForensicEvent(event: ForensicEvent): TimesketchEvent | null {
  const datetime = timesketchDate(event.timestamp);
  if (!datetime) return null;

  const tags = [TAG, event.severity.toLowerCase(), ...(event.mitreTechniques ?? [])];

  const ev: TimesketchEvent = {
    message: event.description || "(event)",
    datetime,
    // The kind of time this is — the reporting tool(s) when known, else a generic label.
    timestamp_desc: event.sources?.length ? event.sources.join(", ") : "Forensic event",
    data_type: "dfir:companion:event",
    severity: event.severity,
    tag: [...new Set(tags)],
    companion_event_id: event.id,
  };

  if (event.mitreTechniques?.length) ev.mitre = event.mitreTechniques.join(", ");
  if (event.asset) ev.asset = event.asset;
  if (event.sources?.length) ev.sources = event.sources.join(", ");
  if (event.sha256) ev.sha256 = event.sha256;
  if (event.md5) ev.md5 = event.md5;
  if (event.path) ev.path = event.path;
  if (event.processName) ev.process_name = event.processName;
  if (event.parentName) ev.parent_name = event.parentName;
  if (event.count && event.count > 1) ev.occurrence_count = event.count;
  if (event.endTimestamp) {
    const end = timesketchDate(event.endTimestamp);
    if (end) ev.end_datetime = end;
  }
  if (event.relatedFindingIds?.length) ev.related_findings = event.relatedFindingIds.join(", ");

  return ev;
}

// The forensic timeline as Timesketch import events, sorted by their true event time, plus the
// count of rows left out because they carry no parseable time. Timesketch requires a datetime, so
// an undated row (an installed-app entry, a YARA hit with no clock) cannot go; the count lets every
// export and push say so rather than shrink in silence (#957). Shared by the forensic-timeline path
// (below) and the super-timeline export/push, which map a plain ForensicEvent[] the same way.
export function splitTimesketchEvents(events: ForensicEvent[]): {
  events: TimesketchEvent[];
  omitted: number;
} {
  const mapped = [...events].sort(byEventTime).map(mapForensicEvent);
  const kept = mapped.filter((e): e is TimesketchEvent => e !== null);
  return { events: kept, omitted: mapped.length - kept.length };
}

export function toTimesketchEventsFromList(events: ForensicEvent[]): TimesketchEvent[] {
  return splitTimesketchEvents(events).events;
}

// The line the push warnings and the export status carry when rows were left out.
export function timesketchOmittedWarning(omitted: number): string {
  return `${omitted} event(s) omitted: no parseable timestamp (Timesketch requires one) — they remain in the Companion timeline`;
}

export function toTimesketchEvents(state: InvestigationState): TimesketchEvent[] {
  return toTimesketchEventsFromList(state.forensicTimeline);
}

// Render a plain event list as newline-delimited JSON (one event per line) — the Timesketch
// "JSONL" import format. Empty string when there are no usable events. Shared by the
// forensic-timeline JSONL export and the super-timeline JSONL export.
export function toTimesketchJsonlFromList(events: ForensicEvent[]): string {
  const mapped = toTimesketchEventsFromList(events);
  return mapped.length ? mapped.map((e) => JSON.stringify(e)).join("\n") + "\n" : "";
}

// Render the forensic timeline as newline-delimited JSON (one event per line) — the Timesketch
// "JSONL" import format. Empty string when there are no usable events.
export function toTimesketchJsonl(state: InvestigationState): string {
  return toTimesketchJsonlFromList(state.forensicTimeline);
}
