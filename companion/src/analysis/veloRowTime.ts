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

type Row = Record<string, unknown>;

// Velociraptor times arrive as RFC3339 strings, epoch numbers (`_ts` is collection-time
// epoch seconds), or `{ SystemTime }` objects. Normalize any of them to UTC ISO.
export function vrTime(v: unknown): string {
  if (v == null) return "";
  if (typeof v === "number") {
    if (!Number.isFinite(v) || v <= 0) return "";
    const d = new Date(v > 1e12 ? v : v * 1000); // >1e12 ⇒ already ms
    return Number.isNaN(d.getTime()) ? "" : d.toISOString();
  }
  if (isObject(v)) {
    const st = getCI(v, "SystemTime") ?? getPath(v, "#attributes.SystemTime");
    return st != null ? vrTime(st) : "";
  }
  return normalizeTime(str(v));
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
  "SITimestamps.LastModified0x10",
  "SITimestamps.LastRecordChange0x10",
  "SITimestamps.Created0x10",
  "FNTimestamps.Created0x30",
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

export function pickTime(row: Row): string {
  for (const k of TIME_KEYS) {
    const v = k.includes(".") ? getPath(row, k) : getCI(row, k);
    const t = vrTime(v);
    if (t) return t;
  }
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
  return vrTime(getCI(row, "_ts")); // collection time — absolute last resort, only when nothing else dated the row
}
