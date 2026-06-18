// Deterministic importer for Plaso / log2timeline super-timelines exported by `psort` to CSV.
// The eleventh deterministic ingest path; no AI call.
//
// Plaso unifies dozens of artifact parsers into one timeline, so — like KAPE — these are
// EVIDENCE rows with no maliciousness verdict (severity Info). Their value is the merged
// super-timeline read at each event's OWN time, plus IOCs scraped from the message (hashes,
// URLs, IPs) and the source file path; cross-source correlation + the high-severity backfill
// escalate anything that lines up with a real detection from the other connectors.
//
// Two psort CSV flavours are header-detected:
//   • dynamic (psort default) — `datetime,timestamp_desc,source,source_long,message,parser,
//     display_name,tag` (datetime is ISO8601 with offset).
//   • l2tcsv (legacy `-o l2tcsv`) — `date,time,timezone,MACB,source,sourcetype,type,user,host,
//     short,desc,version,filename,inode,notes,format,extra` (date MM/DD/YYYY + time + timezone).

import type { Severity } from "./stateTypes.js";
import { parseCsvRecords, parseCsvRecordsFromLines } from "./csvImport.js";
import {
  aggregateEvents,
  createEventAggregator,
  cleanIp,
  addIoc,
  firstStr,
  oneLine,
  normalizeTime,
  type MappedEvent,
  type SiemEvent,
  type SiemIoc,
} from "./siemImport.js";

type Row = Record<string, unknown>;

export interface PlasoImportOptions {
  aggregate?: boolean;
  minSeverity?: Severity;
  maxEvents?: number;
  maxIocs?: number;
}

export interface PlasoParseResult {
  events: SiemEvent[];
  iocs: SiemIoc[];
  total: number;
  kept: number;
  dropped: number;
  groups: number;
  format: string; // "dynamic" | "l2tcsv" | "unknown"
}

const RE_HASH = /\b[a-f0-9]{64}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{32}\b/gi;
const RE_URL = /\bhttps?:\/\/[^\s"'<>)\]]+/gi;
const RE_IPV4 = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;

// Scrape IOCs out of a free-text Plaso message (bounded by the IOC cap downstream).
function textIocs(msg: string, sink: Map<string, SiemIoc>): void {
  if (!msg) return;
  for (const m of msg.matchAll(RE_HASH)) addIoc(sink, "hash", m[0].toLowerCase());
  for (const m of msg.matchAll(RE_URL)) addIoc(sink, "url", m[0].slice(0, 300));
  for (const m of msg.matchAll(RE_IPV4)) { const ip = cleanIp(m[0]); if (ip) addIoc(sink, "ip", ip); }
}

// Plaso `display_name`/`filename` carries a "TYPE:path" prefix (TSK:/OS:/GZIP:…); strip it and
// keep the path as a file IOC + the event's path. URLs are handled by textIocs instead.
function pathFrom(display: string): string {
  let p = display.trim();
  if (!p || /^https?:\/\//i.test(p)) return "";
  const m = /^[A-Z0-9]{2,6}:(.+)$/.exec(p); // "TSK:/Windows/..." → "/Windows/..."
  if (m) p = m[1];
  return /[\\/]/.test(p) ? p.slice(0, 300) : "";
}

// l2tcsv "MM/DD/YYYY" + "HH:MM:SS" + timezone → UTC ISO. (psort is normally run in UTC; a
// non-UTC/odd zone falls back to treating the wall-clock as UTC — documented behaviour.)
function l2tTime(date: string, time: string, tz: string): string {
  const m = /^(\d{1,2})\/(\d{1,2})\/(\d{4})$/.exec(date.trim());
  if (!m) return "";
  const [, mm, dd, yyyy] = m;
  const iso = `${yyyy}-${mm.padStart(2, "0")}-${dd.padStart(2, "0")}T${time.trim()}`;
  const z = /^[+-]\d{2}:?\d{2}$/.test(tz.trim()) ? tz.trim() : "Z";
  return normalizeTime(iso + z);
}

// dynamic `datetime` ISO (often 6-digit microseconds) → truncate to ms, then normalize.
function dynTime(v: string): string {
  return normalizeTime(v.trim().replace(/(\.\d{3})\d+/, "$1"));
}

interface Flavor {
  name: "dynamic" | "l2tcsv";
  map: (row: Row, sink: Map<string, SiemIoc>) => MappedEvent | null;
}

function detectFlavor(headers: Set<string>): Flavor | null {
  if (headers.has("datetime") && headers.has("message")) {
    return {
      name: "dynamic",
      map: (row, sink) => {
        const message = firstStr(row, ["message"]);
        const source = firstStr(row, ["source_long", "source"]);
        const tdesc = firstStr(row, ["timestamp_desc"]);
        const display = firstStr(row, ["display_name"]);
        if (!message) return null;
        textIocs(message, sink);
        const path = pathFrom(display);
        if (path) addIoc(sink, "file", path);
        let description = `Plaso${source ? ` [${source}]` : ""}: ${oneLine(message)}`;
        if (tdesc) description += ` (${tdesc})`;
        description = description.slice(0, 600);
        return {
          timestamp: dynTime(firstStr(row, ["datetime"])),
          description, severity: "Info", mitre: [],
          aggKey: aggKey(source, message), sources: ["Plaso"],
          ...(path ? { path } : {}),
        };
      },
    };
  }
  if (headers.has("date") && headers.has("time") && (headers.has("desc") || headers.has("short"))) {
    return {
      name: "l2tcsv",
      map: (row, sink) => {
        const message = firstStr(row, ["desc", "short"]);
        const source = firstStr(row, ["sourcetype", "source"]);
        const type = firstStr(row, ["type"]);
        const host = firstStr(row, ["host"]);
        const display = firstStr(row, ["filename"]);
        if (!message) return null;
        textIocs(message, sink);
        const path = pathFrom(display);
        if (path) addIoc(sink, "file", path);
        let description = `Plaso${source ? ` [${source}]` : ""}: ${oneLine(message)}`;
        if (type) description += ` (${type})`;
        if (host && host !== "-") description += ` @ ${host}`;
        description = description.slice(0, 600);
        return {
          timestamp: l2tTime(firstStr(row, ["date"]), firstStr(row, ["time"]), firstStr(row, ["timezone"])),
          description, severity: "Info", mitre: [],
          aggKey: aggKey(source, message), sources: ["Plaso"],
          ...(path ? { path } : {}),
          ...(host && host !== "-" ? { asset: host } : {}),
        };
      },
    };
  }
  return null;
}

// Collapse repetitive rows: drop long digit runs (timestamps/sizes/inodes/offsets) from the key.
function aggKey(source: string, message: string): string {
  return `plaso|${source}|${message}`
    .toLowerCase()
    .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/g, "<guid>")
    .replace(/\d{3,}/g, "#")
    .slice(0, 400);
}

// Per-import mapping context shared by the in-memory and streaming entry points: a bounded IOC
// sink + a row→MappedEvent mapper. Once the sink hits maxIocs it stops growing (a swap to a no-op
// sink), so a file with millions of distinct indicators can't balloon memory.
function makePlasoMapper(headers: string[], flavor: Flavor, maxIocs: number): {
  iocSink: Map<string, SiemIoc>;
  mapRow: (cols: string[]) => MappedEvent | null;
} {
  const iocSink = new Map<string, SiemIoc>();
  const noopSink = new Map<string, SiemIoc>();
  const trimmedHeaders = headers.map((h) => h.trim());
  return {
    iocSink,
    mapRow(cols: string[]): MappedEvent | null {
      const row: Row = {};
      trimmedHeaders.forEach((h, i) => { row[h] = cols[i] ?? ""; });
      return flavor.map(row, iocSink.size >= maxIocs ? noopSink : iocSink);
    },
  };
}

function detectFlavorFromHeaders(headers: string[]): Flavor | null {
  return headers.length ? detectFlavor(new Set(headers.map((h) => h.trim().toLowerCase()))) : null;
}

export function parsePlasoCsv(text: string, opts: PlasoImportOptions = {}): PlasoParseResult {
  const maxIocs = opts.maxIocs ?? 5000;

  // STREAMING: a Plaso super-timeline can be 100s of MB (millions of rows). Parsing it into a
  // full 2D array + a full mapped[] array OOMs the server. Instead we stream records one at a
  // time through map→aggregate, so memory stays bounded by the distinct aggKey set (thousands)
  // + the capped IOC sink — never the row count. (For files too big to hold as a string at all,
  // use parsePlasoFromLines, which streams from disk line-by-line.)
  const iter = parseCsvRecords(text);
  const first = iter.next();
  const headers = first.done ? [] : first.value;
  const flavor = detectFlavorFromHeaders(headers);

  let total = 0;
  if (!flavor) {
    for (const _ of iter) total++; // drain to count rows for the "unknown format" report
    return { events: [], iocs: [], total, kept: 0, dropped: total, groups: 0, format: "unknown" };
  }

  const { iocSink, mapRow } = makePlasoMapper(headers, flavor, maxIocs);
  function* mappedGen(): Generator<MappedEvent> {
    for (const cols of iter) { total++; const m = mapRow(cols); if (m) yield m; }
  }

  const { events, groups } = aggregateEvents(mappedGen(), {
    aggregate: opts.aggregate,
    minSeverity: opts.minSeverity,
    maxEvents: opts.maxEvents ?? 2000,
  });

  const represented = events.reduce((n, e) => n + (e.count ?? 1), 0);
  return {
    events,
    iocs: [...iocSink.values()].slice(0, maxIocs),
    total,
    kept: events.length,
    dropped: Math.max(0, total - represented),
    groups,
    format: flavor.name,
  };
}

// Streaming-from-disk variant: parse a Plaso super-timeline from a LINE source (node:readline over
// a file read stream) so a file too large to ever hold as one JS string — a 555 MB super-timeline
// EXCEEDS V8's ~512 MB max string length, so readFile(utf8) throws "Invalid string length" — is
// processed with bounded memory (header + one logical record at a time; aggregation collapses the
// rest into the capped distinct-key set). Same result shape + caps as parsePlasoCsv.
export async function parsePlasoFromLines(
  lines: AsyncIterable<string>,
  opts: PlasoImportOptions = {},
): Promise<PlasoParseResult> {
  const maxIocs = opts.maxIocs ?? 5000;
  const records = parseCsvRecordsFromLines(lines);

  const firstRes = await records.next();
  const headers = firstRes.done ? [] : firstRes.value;
  const flavor = detectFlavorFromHeaders(headers);

  let total = 0;
  if (!flavor) {
    for await (const _ of records) total++; // drain to count rows
    return { events: [], iocs: [], total, kept: 0, dropped: total, groups: 0, format: "unknown" };
  }

  const { iocSink, mapRow } = makePlasoMapper(headers, flavor, maxIocs);
  const agg = createEventAggregator({
    aggregate: opts.aggregate,
    minSeverity: opts.minSeverity,
    maxEvents: opts.maxEvents ?? 2000,
  });
  for await (const cols of records) {
    total++;
    const m = mapRow(cols);
    if (m) agg.add(m);
  }
  const { events, groups } = agg.finish();

  const represented = events.reduce((n, e) => n + (e.count ?? 1), 0);
  return {
    events,
    iocs: [...iocSink.values()].slice(0, maxIocs),
    total,
    kept: events.length,
    dropped: Math.max(0, total - represented),
    groups,
    format: flavor.name,
  };
}
