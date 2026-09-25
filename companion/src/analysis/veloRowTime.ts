// When a Velociraptor row happened — the artifact's OWN time, never the collection time if anything
// better exists.
//
// Every artifact names its time column differently (Mtime, KeyLastWriteTimestamp, visit_time,
// Created0x30, …), and several bury it a level down inside a stat or timestamp container. Getting
// this wrong is not a cosmetic defect: a row that falls through to `_ts` is stamped with the moment
// the collection ran, so an execution from three weeks before the incident lands in the middle of
// the intrusion window and reads as attacker activity.
//
// Lifted out of velociraptorImport.ts unchanged so the artifact mappers that need a fallback time
// can reach it without importing the importer back (an import cycle), and so new mapping work has
// room under the file-size ratchet. Pure — no I/O, no mutation.

import { getCI, getPath, isObject, normalizeTime, str } from "./siemImport.js";
import { toUtcIso } from "./timeUtc.js";

type Row = Record<string, unknown>;

// autorunsc -t (which Windows.Sysinternals.Autoruns passes) prints Time as "normalized UTC" in a
// compact YYYYMMDD-hhmmss form. It is not ISO, so it used to pass through unchanged and the raw string
// became the event time (#1618).
const COMPACT_UTC_RE = /^(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})(\d{2})$/;

// ISO for a compact UTC time; "" when the digits are not a real calendar time (month 13, Feb 29 of a
// common year, hour 24). Null when not that shape.
function compactUtcTime(s: string): string | null {
  const m = COMPACT_UTC_RE.exec(s.trim());
  if (!m) return null;
  return canonicalOrEmpty(`${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}Z`);
}

// A canonical UTC ISO time with its parts: YYYY-MM-DDTHH:MM:SS, an optional fraction of any length, Z.
const CANONICAL_RE = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d+)?Z$/;
// Go's time.String form, which Velociraptor prints for some nested times: "2025-12-05 02:41:36 +0000 UTC".
const GO_TIME_RE = /^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}(?:\.\d+)?) ([+-]\d{4})(?: [A-Za-z]{1,6})?$/;
const DATE_ONLY_RE = /^\d{4}-\d{2}-\d{2}$/;
// The leading date and clock of an ISO-like string, checked BEFORE an offset conversion: Date rolls
// "2024-02-30T10:00:00+02:00" over to March 1 instead of rejecting it.
const LEADING_PARTS_RE = /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})/;
// Epoch digits as a string (a CSV export): 10 digits are seconds, 13 are milliseconds.
const EPOCH_S_RE = /^\d{10}(?:\.\d+)?$/;
const EPOCH_MS_RE = /^\d{13}$/;
// Amcache InventoryApplication InstallDate: MM/DD/YYYY hh:mm:ss (US order, no zone).
const US_DATE_TIME_RE = /^(\d{2})\/(\d{2})\/(\d{4}) (\d{2}):(\d{2}):(\d{2})$/;

// True when the parts name a real calendar time. Date.UTC rolls Feb 30 over to Mar 1 and hour 24 over
// to the next day, so every part must read back unchanged. setUTCFullYear, because Date.UTC reads a
// year below 100 as 19xx — and Go's zero time "0001-01-01T00:00:00Z" must read back as year 1.
function realTime([y, mo, d, h, mi, s]: readonly number[]): boolean {
  const t = new Date(0);
  t.setUTCFullYear(y, mo - 1, d);
  t.setUTCHours(h, mi, s);
  return (
    t.getUTCFullYear() === y &&
    t.getUTCMonth() === mo - 1 &&
    t.getUTCDate() === d &&
    t.getUTCHours() === h &&
    t.getUTCMinutes() === mi &&
    t.getUTCSeconds() === s
  );
}

// The string itself when it is a canonical UTC ISO time on a real calendar day, else "". The fraction
// is kept as written, so Velociraptor's 7-digit precision survives.
function canonicalOrEmpty(s: string): string {
  const m = CANONICAL_RE.exec(s);
  if (!m) return "";
  return realTime(m.slice(1, 7).map(Number)) ? s : "";
}

function epochIso(ms: number): string {
  const d = new Date(ms);
  return Number.isNaN(d.getTime()) ? "" : d.toISOString();
}

// ISO for Amcache's US MM/DD/YYYY hh:mm:ss, read as UTC (the naive-is-UTC convention); "" otherwise.
// Kept out of vrTime: DD/MM and MM/DD are indistinguishable in general, and only this column is known.
export function usDateTime(v: unknown): string {
  const m = US_DATE_TIME_RE.exec(str(v).trim());
  if (!m) return "";
  const [mo, d, y, h, mi, s] = m.slice(1, 7).map(Number);
  if (!realTime([y, mo, d, h, mi, s])) return "";
  return `${m[3]}-${m[1]}-${m[2]}T${m[4]}:${m[5]}:${m[6]}Z`;
}

// A time string as canonical UTC ISO, or "" when it is not a readable time (#1631). An unreadable
// value such as "unknown" or "N/A" used to pass through unchanged and become the event time.
function stringTime(raw: string): string {
  const s = raw.trim();
  if (!s) return "";
  const compact = compactUtcTime(s);
  if (compact !== null) return compact;
  if (EPOCH_S_RE.test(s)) return epochIso(Number(s) * 1000);
  if (EPOCH_MS_RE.test(s)) return epochIso(Number(s));
  const lead = LEADING_PARTS_RE.exec(s);
  if (lead && !realTime(lead.slice(1, 7).map(Number))) return "";
  const go = GO_TIME_RE.exec(s);
  if (go) return canonicalOrEmpty(toUtcIso(`${go[1]}T${go[2]}${go[3]}`));
  if (DATE_ONLY_RE.test(s)) return canonicalOrEmpty(`${s}T00:00:00Z`);
  return canonicalOrEmpty(normalizeTime(s));
}

// Velociraptor times arrive as RFC3339 strings, epoch numbers (`_ts` is collection-time
// epoch seconds), `{ SystemTime }` objects, or the Autoruns compact form. Normalize any of them to UTC
// ISO; "" for anything that is not a readable time.
export function vrTime(v: unknown): string {
  if (v == null) return "";
  if (typeof v === "number") {
    if (!Number.isFinite(v) || v <= 0) return "";
    return epochIso(v > 1e12 ? v : v * 1000); // >1e12 ⇒ already ms
  }
  if (isObject(v)) {
    const st = getCI(v, "SystemTime") ?? getPath(v, "#attributes.SystemTime");
    return st != null ? vrTime(st) : "";
  }
  return stringTime(str(v));
}

// A time column that holds a value vrTime cannot read — not blank, not an all-zero "unset" sentinel.
// Such a row must not fall back to the collection time: that reads as incident activity (#1618, #1631).
function unreadableTime(v: unknown, read: (v: unknown) => string): boolean {
  if (typeof v !== "string") return false;
  const s = v.trim();
  return s !== "" && !/^0+(?:\.0+)?$/.test(s) && !read(v);
}

// The artifact's OWN time first; `_ts` (collection time) only as a last resort. Includes a few
// nested forensic containers (MFT $SI/$FN, file-info, hit-context) and registry/app keys so the
// detection artifacts that bury their time one level down still get a real timestamp.
const TIME_KEYS = [
  "System.TimeCreated.SystemTime",
  "System.TimeCreated",
  "EventTime",
  "EventTimestamp",
  "Mtime",
  "Btime",
  "Ctime",
  "Created",
  "CreationTime",
  "LastWriteTime",
  "KeyLastWriteTimestamp",
  "KeyMTime",
  "TimeGenerated",
  "Timestamp",
  "timestamp",
  "time",
  "StartTime",
  // Nested NTFS $FILE_NAME / $STANDARD_INFO containers (DetectRaptor.Windows.Detection.MFT and newer
  // Windows.NTFS.MFT). Same order as the bare columns below — $FN Created, $SI Created, then the
  // modified / record-change times — because a COPIED file keeps the source's $SI LastModified while
  // every Created stamp records the copy. Dating from LastModified0x10 put each attacker decoy (a copy
  // of cmd.exe) at cmd.exe's build date, months before the drop, and the AI read that as a staging
  // wave with a 264-day dwell (#1415).
  "FNTimestamps.Created0x30",
  "SITimestamps.Created0x10",
  "SITimestamps.LastModified0x10",
  "SITimestamps.LastRecordChange0x10",
  // Bare NTFS $FILE_NAME / $STANDARD_INFO timestamps: Windows.NTFS.MFT (and USN) emit these as TOP-LEVEL
  // columns on many server versions (not nested under SITimestamps/FNTimestamps), so an MFT row would
  // otherwise land with NO time. Prefer $FN Created (0x30 — harder to timestomp) per analyst preference,
  // then $SI Created, then last-modified / record-change / access.
  "Created0x30",
  "Created0x10",
  "LastModified0x10",
  "LastModified0x30",
  "LastRecordChange0x10",
  "LastAccess0x10",
  // Windows.Forensics.Lnk buries the target's birth time under OSPath (the stat object), so the shortcut
  // lands dated at its target's creation. Browser-history (visit) + registry (UserAssist/Shellbags) time
  // columns whose exact names vary by version.
  "OSPath.Btime",
  "visit_time",
  "last_visit_time",
  "LastVisited",
  "LastExecution",
  "LastExecutionTime",
  "last_run",
  // Nested file-stat blocks: FileInfo.* (DetectRaptor PSReadline), Stat.* (the Generic PSReadline /
  // QuickWins shape), so history-line + Amcache/LolDrivers (KeyMTime) rows land dated, not at epoch 0.
  "FileInfo.Mtime",
  "FileInfo.Ctime",
  "FileInfo.Btime",
  "Stat.Mtime",
  "Stat.Ctime",
  "Stat.Btime",
  "HitContext.Mtime",
  "@timestamp", // Elasticsearch-indexed rows (Kibana push) carry the event time here
];

// A column whose NAME denotes an event time — used by the fallback scan when no explicit TIME_KEY matched.
const TIME_NAME_RE =
  /(?:time|date|created|modif|written|changed|access|visit|execut|last.?run|last.?used|btime|mtime|ctime|atime|\bborn\b)/i;
// Plausibility window for the fallback: skip FILETIME (1601) / Unix (1970) / epoch-0 "unset" sentinels
// and absurd far-future values, so a blank timestamp field can't date an event to the year 1601.
export const MIN_TIME_MS = Date.parse("2000-01-01T00:00:00Z");
export const MAX_TIME_MS = Date.parse("2100-01-01T00:00:00Z");

// A file whose Mtime predates its Btime by more than this is dated by Btime (#1603). The margin keeps
// rounding and sub-second jitter between the two stamps from switching the time column.
const COPIED_FILE_MARGIN_MS = 1000;
// The same path columns mapYara reads, so every row it treats as a file hit qualifies.
const FILE_PATH_KEYS = ["OSPath", "FullPath", "_FullPath", "File", "FilePath", "Path"];

export interface CopiedFileTimes {
  created: string; // Btime — when this file was created on the scanned volume
  modified: string; // Mtime — the modified time, inherited from the source file on a copy
}

// A file observation (a top-level path plus the Mtime/Btime pair from one stat of that file) whose
// modified time predates its creation time. A file cannot be modified before it exists, so the
// Mtime came with the content — a copy or an extraction keeps the source's modified time and gets a
// fresh Btime. Btime is when the file appeared on this volume; Mtime says nothing about this host.
// Null for a normal edit (Btime at or before Mtime), a row with no path, or a missing stamp.
export function copiedFileTimes(row: Row): CopiedFileTimes | null {
  if (!FILE_PATH_KEYS.some((k) => str(getCI(row, k)).trim())) return null;
  const modified = vrTime(getCI(row, "Mtime"));
  const created = vrTime(getCI(row, "Btime"));
  if (!modified || !created) return null;
  const m = Date.parse(modified);
  const c = Date.parse(created);
  if (Number.isNaN(m) || Number.isNaN(c) || c - m <= COPIED_FILE_MARGIN_MS) return null;
  return { created, modified };
}

// A YARA hit carries the RULE's metadata beside the match. Its date / modified fields are when the
// rule was written, never when anything happened on the host — the fallback scan dated a
// process-memory hit to its rule's 2014 authoring date (#1603). Skipped only on a YARA-shaped row.
const RULE_META_RE = /^meta(?:data)?$/i;

// `preferred` columns (an artifact's own time names; dotted paths allowed, an array reads its first
// element) are tried before TIME_KEYS, through `readPreferred` when the artifact has its own format.
export function pickTime(
  row: Row,
  preferred: readonly string[] = [],
  readPreferred: (v: unknown) => string = vrTime,
): string {
  let unreadable = false;
  for (const k of preferred) {
    const raw = k.includes(".") ? getPath(row, k) : getCI(row, k);
    const v = Array.isArray(raw) ? raw[0] : raw;
    const t = readPreferred(v);
    if (t) return t;
    if (unreadableTime(v, readPreferred)) unreadable = true;
  }
  for (const k of TIME_KEYS) {
    const v = k.includes(".") ? getPath(row, k) : getCI(row, k);
    const t = vrTime(v);
    // An unreadable time column: keep looking for another artifact time, but never fall back to the
    // collection time below.
    if (!t) {
      if (unreadableTime(v, vrTime)) unreadable = true;
      continue;
    }
    if (k === "Mtime") return copiedFileTimes(row)?.created ?? t;
    return t;
  }
  const yaraRow = getCI(row, "Rule") != null;
  // Fallback: no known column matched (browser history, shellbags, userassist, and other raw artifacts
  // whose time column varies by Velociraptor version). Scan every time-NAMED column (incl. one nesting
  // level) for the EARLIEST plausible timestamp — a real artifact time beats the `_ts` collection time
  // below, and a blank/sentinel field can't win.
  let best = "",
    bestMs = Infinity;
  const scan = (obj: Row, prefix: string, depth: number): void => {
    for (const [k, v] of Object.entries(obj)) {
      if (v == null) continue;
      if (isObject(v)) {
        if (yaraRow && depth === 0 && RULE_META_RE.test(k)) continue;
        if (depth < 1) scan(v, `${prefix}${k}.`, depth + 1);
        continue;
      }
      if (Array.isArray(v)) continue;
      if (!TIME_NAME_RE.test(prefix + k)) continue;
      const t = vrTime(v);
      if (!t) continue;
      const ms = Date.parse(t);
      if (ms >= MIN_TIME_MS && ms <= MAX_TIME_MS && ms < bestMs) {
        bestMs = ms;
        best = t;
      }
    }
  };
  scan(row, "", 0);
  if (best) return best;
  if (unreadable) return ""; // undated beats dated at the collection time (#1618, #1631)
  return vrTime(getCI(row, "_ts")); // collection time — absolute last resort, only when nothing else dated the row
}
