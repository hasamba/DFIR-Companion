// The SIEM importer's field pickers, and the small value helpers they read records with.
//
// Lifted out of siemImport.ts (a ledgered oversized file, #385) so the pickers can say WHICH key
// they selected (#1736) without the ledger growing. siemImport re-exports every helper here, so each
// importer that has always taken them from that module keeps its unchanged import site. Pure.

type Row = Record<string, unknown>;

export function isObject(v: unknown): v is Row {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
export function str(v: unknown): string {
  return typeof v === "string" ? v : v == null ? "" : typeof v === "object" ? "" : String(v);
}
// Case-insensitive single-key lookup.
export function getCI(row: Row, key: string): unknown {
  if (key in row) return row[key];
  const lower = key.toLowerCase();
  for (const k of Object.keys(row)) if (k.toLowerCase() === lower) return row[k];
  return undefined;
}
// Dotted-path getter ("host.name", "event.action"), case-insensitive per segment.
export function getPath(row: Row, path: string): unknown {
  let cur: unknown = row;
  for (const seg of path.split(".")) {
    if (!isObject(cur)) return undefined;
    cur = getCI(cur, seg);
  }
  return cur;
}

/** The first candidate key holding a non-empty string (case-insensitive, dotted paths), and that string. */
export function firstKeyed(row: Row, keys: readonly string[]): { key: string; value: string } | undefined {
  for (const k of keys) {
    const s = str(k.includes(".") ? getPath(row, k) : getCI(row, k)).trim();
    if (s) return { key: k, value: s };
  }
  return undefined;
}
// First non-empty string across candidate keys (case-insensitive), supporting dotted paths.
export function firstStr(row: Row, keys: string[]): string {
  return firstKeyed(row, keys)?.value ?? "";
}

export const TIME_KEYS = [
  "@timestamp",
  "timestamp",
  "_time",
  "eventTime",
  "EventTime",
  "event_time",
  "DeviceEventTime",
  // Sentinel / Log Analytics event time (#2096). Never TimeCollected — that is the collector clock.
  "TimeGenerated",
  "createdAt",
  "created",
  "event.created",
  "ingested",
  "generated_time",
  "received_time",
  "observed_timestamp",
  "time",
  "date",
  "@time",
];

// Which key each picker SELECTED (#1736), reported during the mapper's own lookup — never by a
// second scan. A synchronous hook: the import debug tally sets it around ONE record's mapping and
// clears it after, so two imports never share it. Unset (the default), a pick costs one check.
// `undefined` is a miss: the last pick of a record wins, so a stale key never survives a later miss.
export type FieldPickSink = (target: "host" | "timestamp", key: string | undefined) => void;
let pickSink: FieldPickSink | undefined;
export function setFieldPickSink(sink: FieldPickSink | undefined): void {
  pickSink = sink;
}

/**
 * A Windows record's EventData, under any of its three spellings — or the record itself when it is
 * FLAT (#2023). NXLog's JSON output (and every OTRF/Mordor dataset built on it) writes Image,
 * CommandLine, TargetUserName… at the top level beside EventID/Channel, with no nested object.
 * Returning nothing there blanked every subject, account and process, so all events of one EID on a
 * host collapsed into a single aggregated row and the tagger never saw an image path. Readers of
 * EventData only look up named Windows fields, so the record's own envelope keys are inert here.
 */
export function windowsEventDataRaw(rec: Row): unknown {
  return (
    getCI(rec, "event_data") ??
    getPath(rec, "winlog.event_data") ??
    getCI(rec, "EventData") ??
    (isFlatWindowsRecord(rec) ? rec : undefined)
  );
}

function isFlatWindowsRecord(rec: Row): boolean {
  return getCI(rec, "EventID") !== undefined && typeof getCI(rec, "Channel") === "string";
}

// The event's own time, and the key it came from. For Sysmon prefer the structured UtcTime (the
// in-event clock — the artifact's own time); otherwise the record's @timestamp / common time fields.
// Never the import time. The value is raw: siemImport's pickTimestamp normalizes it.
// Exception (#2089): when UtcTime and the record's own time disagree by more than an hour, the
// record time wins — it is the clock every channel in the file shares, so a Sysmon row days off
// cannot move out of the attack window. UtcTime survives as the observed time and the row is flagged.
export function timestampSource(rec: Row, ed: Row | undefined): { key: string; value: string } | undefined {
  const sysmonUtc = ed ? str(getCI(ed, "UtcTime")).trim() : "";
  const dispute = sysmonUtc ? sysmonClockDispute(rec, ed) : undefined;
  const picked = dispute
    ? { key: dispute.recordKey, value: dispute.recordValue }
    : sysmonUtc
      ? { key: "UtcTime", value: sysmonUtc }
      : firstKeyed(rec, TIME_KEYS);
  pickSink?.("timestamp", picked?.key);
  return picked;
}

// Sysmon EID 3 legitimately lags its record by seconds to minutes; the disputes seen in real
// exports are 19 hours to 11 days (#2089). An hour sits well clear of both.
export const SYSMON_CLOCK_DISPUTE_MS = 60 * 60 * 1000;

export interface SysmonClockDispute {
  utc: string; // the Sysmon UtcTime as written
  recordKey: string; // the record time field that wins
  recordValue: string;
  offsetMs: number; // |UtcTime - record time|
}

const ZONED = /(Z|[+-]\d{2}:?\d{2})$/i;

// UtcTime carries no zone but is UTC by definition, the convention normalizeTime follows.
function clockMs(v: string): number {
  const t = v.trim().replace(/^(\d{4}-\d{2}-\d{2}) /, "$1T");
  return Date.parse(ZONED.test(t) ? t : `${t}Z`);
}

// Only a record time that states its zone can dispute UtcTime: NXLog's naive EventTime is the
// collector's LOCAL time, so a UTC-4 site would read as a four-hour dispute with nothing wrong.
function zonedRecordTime(rec: Row): { key: string; value: string } | undefined {
  for (const k of TIME_KEYS) {
    const hit = firstKeyed(rec, [k]);
    if (hit && ZONED.test(hit.value)) return hit;
  }
  return undefined;
}

/** A Sysmon row whose UtcTime is more than SYSMON_CLOCK_DISPUTE_MS from the record time, or undefined. */
export function sysmonClockDispute(rec: Row, ed: Row | undefined): SysmonClockDispute | undefined {
  const utc = ed ? str(getCI(ed, "UtcTime")).trim() : "";
  const record = utc ? zonedRecordTime(rec) : undefined;
  if (!record) return undefined;
  const offsetMs = Math.abs(clockMs(utc) - clockMs(record.value));
  if (!Number.isFinite(offsetMs) || offsetMs <= SYSMON_CLOCK_DISPUTE_MS) return undefined;
  return { utc, recordKey: record.key, recordValue: record.value, offsetMs };
}

function spanText(ms: number): string {
  const h = ms / 3_600_000;
  return h >= 48 ? `${Math.round(h / 24)}d` : `${Math.round(h)}h`;
}

/** The row's description with the dispute stated, so the analyst and the AI both see it. */
export function withClockDisputeNote(description: string, d: SysmonClockDispute | undefined): string {
  if (!d) return description;
  const note = `Sysmon UtcTime ${d.utc} disagrees with the record time by ${spanText(d.offsetMs)}`;
  return `${description} [${note}; dated by ${d.recordKey}]`;
}

export interface ClockDisputeSummary {
  rows: number;
  maxOffsetMs: number;
}

/** The analyst's one line for an import's disputed rows ("" when there were none). */
export function clockDisputeText(s: ClockDisputeSummary | undefined): string {
  if (!s) return "";
  return `${s.rows} Sysmon row(s) had a UtcTime up to ${spanText(s.maxOffsetMs)} from the record time; dated by the record time`;
}

/** Counts disputed Windows rows across one import; `summary()` is undefined when there were none. */
export function createClockDisputeTally(): {
  note(rec: Row): void;
  summary(): ClockDisputeSummary | undefined;
} {
  let rows = 0;
  let maxOffsetMs = 0;
  return {
    note(rec) {
      const ed = windowsEventDataRaw(rec);
      const d = sysmonClockDispute(rec, isObject(ed) ? ed : undefined);
      if (!d) return;
      rows += 1;
      maxOffsetMs = Math.max(maxOffsetMs, d.offsetMs);
    },
    summary: () => (rows ? { rows, maxOffsetMs } : undefined),
  };
}

// The machine that logged the event comes before the shipper's own host: under Windows Event
// Forwarding, Winlogbeat 7's `host.name` is the collector, and `winlog.computer_name` is the source.
const HOST_KEYS = [
  "computer_name",
  "Computer",
  "winlog.computer_name",
  "hostname",
  "host.name",
  "host",
  "host_name",
  "agent.hostname",
  "beat.hostname",
  "device.hostname",
  "endpoint.name",
  "MachineName",
  "src_host",
  "source.host",
];

/** The record's host, and the key it came from (`host.name` for an ECS host:{name} object). */
export function hostSource(rec: Row): { key: string; value: string } | undefined {
  const picked = findHost(rec);
  pickSink?.("host", picked?.key);
  return picked;
}
function findHost(rec: Row): { key: string; value: string } | undefined {
  for (const k of HOST_KEYS) {
    const v = k.includes(".") ? getPath(rec, k) : getCI(rec, k);
    if (typeof v === "string" && v.trim()) return { key: k, value: v.trim() };
    if (isObject(v)) {
      const n = str(getCI(v, "name")).trim();
      if (n) return { key: `${k}.name`, value: n };
    } // ECS host:{name}
  }
  return undefined;
}
