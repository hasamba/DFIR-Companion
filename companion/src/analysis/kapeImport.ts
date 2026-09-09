// Deterministic importer for KAPE / Eric Zimmerman (EZ) Tools CSV output — the host-forensics
// counterpart to the EDR/network connectors. The seventh deterministic ingest path; no AI call.
//
// EZ tools each emit a CSV with the artifact's own columns and time field(s). A KAPE collection
// is a folder of these; the analyst uploads one CSV per import. This module DETECTS which tool
// produced the CSV from its header, then maps each row to a forensic event reading the
// artifact's OWN time (program last-run, file MAC time, deletion time…) and pulling file/hash/
// process IOCs. These are EVIDENCE rows (no maliciousness verdict), so severity is Info — their
// value is the super-timeline + cross-source correlation; synthesis + the high-severity backfill
// still escalate anything that lines up with a real detection.
//
// Supported artifacts (header-detected): Prefetch (PECmd), Amcache (AmcacheParser), AppCompatCache/
// ShimCache (AppCompatCacheParser), LNK (LECmd), JumpLists (JLECmd), UsnJrnl $J + $MFT (MFTECmd),
// SRUM network usage (SrumECmd), Recycle Bin (RBCmd), Shellbags (SBECmd).

import type { Severity } from "./stateTypes.js";
import { parseCsv } from "./csvImport.js";
import {
  aggregateEvents,
  addIoc,
  firstStr,
  baseName,
  oneLine,
  str,
  getCI,
  normalizeTime,
  type MappedEvent,
  type SiemEvent,
  type SiemIoc,
  maxEventsDefault,
} from "./siemImport.js";
import { detectTimestomp } from "./timestompDetect.js";
import { parseReasons, pairRenames, summarizeLifecycle, type UsnRecord } from "./usnLifecycle.js";
import { prefetchSignal } from "./prefetchExecution.js";
import { readSrumRow, totalSrum, srumSignal, type SrumRow } from "./srumNetwork.js";

type Row = Record<string, unknown>;

export interface KapeImportOptions {
  aggregate?: boolean;
  minSeverity?: Severity;
  maxEvents?: number;
  maxIocs?: number;
}

export interface KapeParseResult {
  events: SiemEvent[];
  iocs: SiemIoc[];
  total: number; // data rows in the CSV
  kept: number; // events emitted (after aggregation + cap)
  dropped: number; // rows not represented (no usable time/path / capped)
  groups: number; // distinct event groups before the cap
  artifact: string; // detected EZ artifact ("Prefetch", "Amcache", …) or "unknown"
  format: string; // = artifact, for parity with the other importers
}

// ───────────────────────────── helpers ─────────────────────────────

// MFTECmd $J columns → the identity-bearing shape the lifecycle module works on. The volume comes
// from SourceFile when the export records it: entry 12345 on C: and on D: are different files, and
// one collection can contain both journals.
function toUsnRecords(rows: readonly Row[]): UsnRecord[] {
  return rows.map((row) => ({
    name: firstStr(row, ["Name"]),
    entry: firstStr(row, ["EntryNumber", "FileReferenceNumber"]),
    sequence: firstStr(row, ["SequenceNumber"]),
    parentEntry: firstStr(row, ["ParentEntryNumber", "ParentFileReferenceNumber"]),
    parentSequence: firstStr(row, ["ParentSequenceNumber"]),
    usn: firstStr(row, ["UpdateSequenceNumber", "Usn"]),
    timestamp: ezTime(getCI(row, "UpdateTimestamp")),
    reasons: parseReasons(firstStr(row, ["UpdateReasons"])),
    parentPath: firstStr(row, ["ParentPath"]),
    // SourceFile names the file the parser READ, which in a KAPE collection is the staging path
    // (E:\KAPE\Collection\C\$Extend\$J) — its drive letter is the collector's, not the host's.
    // So a real volume column is preferred, and SourceFile is used only when it is not a staging
    // path. An empty volume is honest; a wrong one silently merges two volumes' files.
    volume: usnVolume(firstStr(row, ["Volume", "VolumeName"]), firstStr(row, ["SourceFile"])),
  }));
}

// The volume a journal record belongs to, or "" when the export does not reliably say.
function usnVolume(explicit: string, sourceFile: string): string {
  const v = explicit.trim();
  if (/^[A-Za-z]:?$/.test(v)) return `${v[0].toUpperCase()}:`;
  const src = sourceFile.trim();
  // A staging path has the journal nested under a collection directory; its leading drive letter is
  // the collector's. Only a path that IS the journal at a volume root is trusted.
  if (/^[A-Za-z]:\\\$Extend\\\$(?:J|UsnJrnl)/i.test(src)) return `${src[0].toUpperCase()}:`;
  return "";
}

// EZ timestamps are UTC "yyyy-MM-dd HH:mm:ss(.fffffff)" (no zone). Truncate the 7-digit
// fraction to ms, drop the .NET min-date sentinel, then normalize (treats naive as UTC).
function ezTime(v: unknown): string {
  let t = str(v).trim();
  if (!t || t.startsWith("0001-01-01") || t.startsWith("1601-01-01")) return "";
  t = t.replace(/(\.\d{3})\d+/, "$1");
  return normalizeTime(t);
}

// How many journal rows lifecycle reconstruction will hold at once. Renames are adjacent in the
// journal, so a prefix reconstructs the same pairs a whole file would for everything inside it.
const MAX_LIFECYCLE_ROWS = 200_000;

const HASH40 = /[a-f0-9]{40}/i;
function addHash(sink: Map<string, SiemIoc>, raw: string): void {
  const m = HASH40.exec(raw.trim()); // Amcache SHA1 sometimes carries a leading "0000" prefix
  if (m) addIoc(sink, "hash", m[0].toLowerCase());
  else {
    const h = raw.trim().toLowerCase();
    if (/^[a-f0-9]{32}$|^[a-f0-9]{64}$/.test(h)) addIoc(sink, "hash", h);
  }
}
function addFile(sink: Map<string, SiemIoc>, p: string): void {
  const v = p.trim();
  if (v && v !== "-" && /[\\/]/.test(v)) addIoc(sink, "file", v.slice(0, 300));
}
function addProc(sink: Map<string, SiemIoc>, name: string): string | undefined {
  const bn = baseName(name.trim());
  if (bn && /\.\w{2,4}$/.test(bn)) {
    addIoc(sink, "process", bn);
    return bn;
  }
  return undefined;
}
function truthy(v: unknown): boolean {
  return /^(yes|true|1)$/i.test(str(v).trim());
}

// ───────────────────────────── artifact profiles ─────────────────────────────

interface Profile {
  name: string;
  match: (h: Set<string>) => boolean;
  map: (row: Row, sink: Map<string, SiemIoc>) => MappedEvent | null;
}

const has = (h: Set<string>, ...keys: string[]): boolean => keys.every((k) => h.has(k.toLowerCase()));

const PROFILES: Profile[] = [
  {
    name: "Prefetch",
    match: (h) => has(h, "ExecutableName", "RunCount") && (h.has("lastrun") || h.has("sourcefilename")),
    map: (row, sink) => {
      const exe = firstStr(row, ["ExecutableName"]);
      if (!exe) return null;
      const runCount = firstStr(row, ["RunCount"]);
      const proc = addProc(sink, exe);
      const time = ezTime(getCI(row, "LastRun")) || ezTime(getCI(row, "SourceModified"));
      // Prefetch carries no command line, so the binary's NAME is all there is to grade — and ungraded it
      // stays Info, below the forensic floor, where synthesis never reads it. PECmd exports no executable
      // path column, so the location-dependent rules stay silent. See prefetchExecution.ts.
      const signal = prefetchSignal(exe);
      return {
        timestamp: time,
        description: `Prefetch: ${exe} executed${runCount ? ` (run ${runCount}×)` : ""}`.slice(0, 600),
        severity: signal?.severity ?? "Info",
        mitre: signal ? signal.mitre : [],
        aggKey: `pf|${exe.toLowerCase()}`,
        sources: ["Prefetch"],
        ...(proc ? { processName: proc } : {}),
      };
    },
  },
  {
    name: "Amcache",
    match: (h) => has(h, "FullPath", "SHA1") || has(h, "FullPath", "FileKeyLastWriteTimestamp"),
    map: (row, sink) => {
      const path = firstStr(row, ["FullPath"]);
      if (!path) return null;
      const sha1 = firstStr(row, ["SHA1"]);
      if (sha1) addHash(sink, sha1);
      addFile(sink, path);
      const proc = addProc(sink, path);
      return {
        timestamp: ezTime(getCI(row, "FileKeyLastWriteTimestamp")),
        description: `Amcache: ${path}${sha1 ? ` (SHA1 ${sha1.replace(/^0+/, "").slice(0, 40)})` : ""}`.slice(
          0,
          600,
        ),
        severity: "Info",
        mitre: [],
        aggKey: `amcache|${path.toLowerCase()}`,
        sources: ["Amcache"],
        path,
        ...(proc ? { processName: proc } : {}),
      };
    },
  },
  {
    name: "ShimCache",
    match: (h) => has(h, "Path", "LastModifiedTimeUTC") && (h.has("executed") || h.has("cacheentryposition")),
    map: (row, sink) => {
      const path = firstStr(row, ["Path"]);
      if (!path) return null;
      addFile(sink, path);
      const proc = addProc(sink, path);
      const executed = truthy(getCI(row, "Executed"));
      return {
        timestamp: ezTime(getCI(row, "LastModifiedTimeUTC")),
        description: `ShimCache: ${path}${executed ? " (Executed)" : ""}`.slice(0, 600),
        severity: "Info",
        mitre: [],
        aggKey: `shim|${path.toLowerCase()}`,
        sources: ["ShimCache"],
        path,
        // ShimCache keeps its copy of the modification time in the REGISTRY, which a tool that
        // rewrites the MFT does not necessarily touch. That independence is the whole point.
        ...(ezTime(getCI(row, "LastModifiedTimeUTC"))
          ? { fileModified: ezTime(getCI(row, "LastModifiedTimeUTC")) }
          : {}),
        ...(proc ? { processName: proc } : {}),
      };
    },
  },
  {
    name: "LNK",
    match: (h) => has(h, "TargetCreated", "Arguments") && (h.has("localpath") || h.has("relativepath")),
    map: (row, sink) => {
      const target = firstStr(row, ["LocalPath", "RelativePath"]);
      const src = firstStr(row, ["SourceFile"]);
      const args = firstStr(row, ["Arguments"]);
      if (!target && !src) return null;
      if (target) addFile(sink, target);
      return {
        timestamp:
          ezTime(getCI(row, "TargetModified")) ||
          ezTime(getCI(row, "TargetCreated")) ||
          ezTime(getCI(row, "SourceModified")),
        description:
          `LNK: ${baseName(src) || "shortcut"} → ${target || "?"}${args ? ` ${oneLine(args).slice(0, 120)}` : ""}`.slice(
            0,
            600,
          ),
        severity: "Info",
        mitre: [],
        aggKey: `lnk|${(src || target).toLowerCase()}`,
        sources: ["LNK"],
        ...(target ? { path: target } : {}),
      };
    },
  },
  {
    name: "JumpLists",
    match: (h) => has(h, "AppId", "Path") && h.has("targetcreated"),
    map: (row, sink) => {
      const path = firstStr(row, ["Path"]);
      const app = firstStr(row, ["AppIdDescription", "AppId"]);
      if (!path) return null;
      addFile(sink, path);
      return {
        timestamp: ezTime(getCI(row, "TargetModified")) || ezTime(getCI(row, "TargetCreated")),
        description: `JumpList: ${app || "?"} → ${path}`.slice(0, 600),
        severity: "Info",
        mitre: [],
        aggKey: `jl|${app.toLowerCase()}|${path.toLowerCase()}`,
        sources: ["JumpLists"],
        path,
      };
    },
  },
  {
    name: "UsnJrnl",
    match: (h) => has(h, "UpdateReasons", "UpdateTimestamp"),
    map: (row, sink) => {
      const name = firstStr(row, ["Name"]);
      const reasons = firstStr(row, ["UpdateReasons"]);
      if (!name) return null;
      // The file reference — entry AND sequence — is what identifies the file across renames
      // (#909 item 7). Keeping only the name meant a rename could not be reconstructed at all.
      const entry = firstStr(row, ["EntryNumber", "FileReferenceNumber"]);
      const seq = firstStr(row, ["SequenceNumber"]);
      // A bare filename is not identity, so cross-artifact comparison refuses it. Where the export
      // recorded the directory, the event carries the full path instead — otherwise the journal
      // could never be matched against an MFT record for the same file.
      const parent = firstStr(row, ["ParentPath"]);
      const full = parent ? `${parent.replace(/[\\/]+$/, "")}\\${name}` : name;
      addFile(sink, full);
      return {
        timestamp: ezTime(getCI(row, "UpdateTimestamp")),
        description: `UsnJrnl: ${name} — ${reasons}${entry ? ` [file ${entry}-${seq || "?"}]` : ""}`.slice(
          0,
          600,
        ),
        severity: "Info",
        mitre: [],
        // Identity in the key, so two files that happened to share a name stay apart.
        aggKey: `usn|${entry}-${seq}|${name.toLowerCase()}|${reasons.toLowerCase()}`,
        sources: ["UsnJrnl"],
        path: full,
      };
    },
  },
  {
    name: "MFT",
    match: (h) => has(h, "ParentPath", "FileName") && (h.has("created0x10") || h.has("lastmodified0x10")),
    map: (row, sink) => {
      if (truthy(getCI(row, "IsDirectory"))) return null; // files only — directories are noise
      const parent = firstStr(row, ["ParentPath"]);
      const fileName = firstStr(row, ["FileName"]);
      if (!fileName) return null;
      const path = (parent ? `${parent.replace(/[\\/]+$/, "")}\\` : "") + fileName;
      addFile(sink, path);
      const proc = addProc(sink, fileName);
      const size = firstStr(row, ["FileSize"]);
      // Timestomp check: MFTECmd emits $SI (Created0x10) and $FN (Created0x30) creation on the same
      // row. Pass the RAW strings (not ezTime, which drops the sub-second the truncation signal needs).
      const ts = detectTimestomp(str(getCI(row, "Created0x10")), str(getCI(row, "Created0x30")));
      let description = `MFT: ${path}${size ? ` (${size} bytes)` : ""}`;
      if (ts) description = `${description} — ${ts.note}`;
      return {
        timestamp: ezTime(getCI(row, "Created0x10")) || ezTime(getCI(row, "LastModified0x10")),
        description: description.slice(0, 600),
        severity: ts ? ts.severity : "Info",
        mitre: ts ? ts.mitre : [],
        aggKey: `mft|${path.toLowerCase()}`,
        sources: ["MFT"],
        path,
        // The MFT's own record of when the file was modified, kept structured so it can be
        // compared against ShimCache's independent copy (#909 item 8).
        ...(ezTime(getCI(row, "LastModified0x10"))
          ? { fileModified: ezTime(getCI(row, "LastModified0x10")) }
          : {}),
        ...(proc ? { processName: proc } : {}),
      };
    },
  },
  {
    name: "SRUM",
    // BytesRecvd is SrumECmd's spelling. Requiring BytesReceived meant a real export was never
    // recognised as SRUM at all (#909 item 9).
    match: (h) => h.has("bytessent") && (h.has("bytesrecvd") || h.has("bytesreceived")),
    map: (row, sink) => {
      const exe = firstStr(row, ["ExeInfo", "AppId", "Application"]);
      if (!exe) return null;
      const proc = addProc(sink, exe);
      const sent = firstStr(row, ["BytesSent"]);
      const recv = firstStr(row, ["BytesRecvd", "BytesReceived"]);
      const user = firstStr(row, ["UserName", "User"]) || firstStr(row, ["Sid", "UserId"]);
      return {
        timestamp: ezTime(getCI(row, "Timestamp")),
        // The per-row event keeps the ATTRIBUTION, not just the numbers: which user, which
        // interface. A total without them cannot be defended.
        description:
          `SRUM network: ${baseName(exe)}${user ? ` as ${user}` : ""} sent ${sent || "?"} / recv ${recv || "?"} bytes`.slice(
            0,
            600,
          ),
        severity: "Info",
        mitre: [],
        // Identity in the key: two users of one application are two facts, and one key merged them.
        aggKey: `srum|${exe.toLowerCase()}|${user.toLowerCase()}|${firstStr(row, ["InterfaceLuid", "L2ProfileId"])}`,
        sources: ["SRUM"],
        ...(proc ? { processName: proc } : {}),
      };
    },
  },
  {
    name: "RecycleBin",
    match: (h) => has(h, "DeletedOn", "FileName") && h.has("filesize"),
    map: (row, sink) => {
      const file = firstStr(row, ["FileName"]);
      if (!file) return null;
      addFile(sink, file);
      return {
        timestamp: ezTime(getCI(row, "DeletedOn")),
        description: `RecycleBin: deleted ${file}`.slice(0, 600),
        severity: "Info",
        mitre: [],
        aggKey: `rb|${file.toLowerCase()}`,
        sources: ["RecycleBin"],
        path: file,
      };
    },
  },
  {
    name: "Shellbags",
    match: (h) => has(h, "AbsolutePath") && (h.has("lastinteracted") || h.has("firstinteracted")),
    map: (row, sink) => {
      const path = firstStr(row, ["AbsolutePath"]);
      if (!path) return null;
      addFile(sink, path);
      return {
        timestamp: ezTime(getCI(row, "LastInteracted")) || ezTime(getCI(row, "FirstInteracted")),
        description: `Shellbag: ${path}`.slice(0, 600),
        severity: "Info",
        mitre: [],
        aggKey: `sb|${path.toLowerCase()}`,
        sources: ["Shellbags"],
        path,
      };
    },
  },
];

function detectProfile(headers: string[]): Profile | null {
  const set = new Set(headers.map((h) => h.trim().toLowerCase()));
  for (const p of PROFILES) if (p.match(set)) return p;
  return null;
}

// ───────────────────────────── top-level parse ─────────────────────────────

export function parseKapeCsv(text: string, opts: KapeImportOptions = {}): KapeParseResult {
  const maxIocs = opts.maxIocs ?? 5000;
  const { headers, rows } = parseCsv(text);
  const profile = headers.length ? detectProfile(headers) : null;
  if (!profile) {
    return {
      events: [],
      iocs: [],
      total: rows.length,
      kept: 0,
      dropped: rows.length,
      groups: 0,
      artifact: "unknown",
      format: "unknown",
    };
  }

  const iocSink = new Map<string, SiemIoc>();
  const mapped: MappedEvent[] = [];
  const usnRows: Row[] = [];
  const srumRows: SrumRow[] = [];
  for (const cols of rows) {
    const row: Row = {};
    headers.forEach((h, i) => {
      row[h.trim()] = cols[i] ?? "";
    });
    const m = profile.map(row, iocSink);
    if (m) mapped.push(m);
    // Bounded. A real $J export runs to millions of rows, and lifecycle reconstruction holds every
    // one it is given, sorts a copy, and allocates a record per row — all BEFORE maxEvents applies.
    // Unbounded, that exhausts the process before any capped result is produced.
    if (profile.name === "UsnJrnl" && usnRows.length < MAX_LIFECYCLE_ROWS) usnRows.push(row);
    if (profile.name === "SRUM") {
      const r = readSrumRow((k) => getCI(row, k));
      if (r) srumRows.push({ ...r, timestamp: ezTime(r.timestamp) || r.timestamp });
    }
  }

  // Lifecycle reconstruction needs every record at once: a rename is TWO records, and which names a
  // file was known under is a property of the whole journal, not of any single row (#909 item 7).
  // Totals per application AND user AND interface, over deduplicated rows (#909 item 9). One row
  // per hour says nothing; the total is the evidence, and it is only defensible with the
  // attribution and the interval attached.
  for (const t of totalSrum(srumRows)) {
    const signal = srumSignal(t);
    if (!signal) continue;
    mapped.push({
      timestamp: t.last || t.first,
      description: `SRUM total: ${signal.note}`.slice(0, 900),
      severity: signal.severity,
      mitre: signal.mitre,
      aggKey: `srum|total|${t.app.toLowerCase()}|${(t.sid || t.user).toLowerCase()}|${t.interfaceId}`,
      sources: ["SRUM"],
      ...(t.app ? { processName: baseName(t.app) } : {}),
    });
  }

  const usnRecords = toUsnRecords(usnRows);
  // Files the journal shows being DELETED, and files it knew under several names. This is where the
  // deleted-Prefetch case surfaces: a .pf record carrying FILE_DELETE is an execution artifact
  // removed, which is anti-forensics rather than housekeeping.
  for (const life of summarizeLifecycle(usnRecords)) {
    const prefetchDeleted = life.deletedSeen && life.names.some((n) => /\.pf$/i.test(n));
    const multiName = life.names.length > 1;
    if (!prefetchDeleted && !multiName) continue;
    mapped.push({
      timestamp: life.last || life.first,
      description:
        `UsnJrnl lifecycle: ${life.note}` +
        (prefetchDeleted
          ? " A Prefetch file being deleted removes execution evidence; Windows does not routinely delete them individually."
          : ""),
      severity: prefetchDeleted ? "Medium" : "Info",
      mitre: prefetchDeleted ? ["T1070.004"] : [],
      aggKey: `usn|life|${life.reference}`,
      sources: ["UsnJrnl"],
      path: life.names[life.names.length - 1],
    });
  }

  for (const pair of pairRenames(usnRecords)) {
    mapped.push({
      timestamp: pair.timestamp,
      description: `UsnJrnl: ${pair.newName} — ${pair.note}`.slice(0, 600),
      severity: pair.severity,
      mitre: [],
      aggKey: `usn|${pair.kind}|${pair.reference}|${pair.oldName.toLowerCase()}|${pair.newName.toLowerCase()}|${pair.oldParent}|${pair.newParent}`,
      sources: ["UsnJrnl"],
      path: pair.newName,
    });
  }

  const { events, groups } = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: opts.minSeverity,
    maxEvents: opts.maxEvents ?? maxEventsDefault(),
  });

  const represented = events.reduce((n, e) => n + (e.count ?? 1), 0);
  return {
    events,
    iocs: [...iocSink.values()].slice(0, maxIocs),
    total: rows.length,
    kept: events.length,
    dropped: Math.max(0, rows.length - represented),
    groups,
    artifact: profile.name,
    format: profile.name,
  };
}
