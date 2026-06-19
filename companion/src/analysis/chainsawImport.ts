// Deterministic importer for Chainsaw (WithSecure) hunt output and raw EVTX-as-JSON.
// The third JSON ingest path besides THOR and the generic SIEM/EDR import, and the most
// useful one for Windows IR: it carries the *artifact's own* Windows event PLUS, for
// Chainsaw, the Sigma/built-in rule verdict that matched it.
//
// Two related inputs are handled, auto-detected per record:
//
//   1. CHAINSAW HUNT JSON (`chainsaw hunt -r rules/ --json|--jsonl evtx/`) — an array (or
//      NDJSON) of detections. Each detection embeds the raw EVTX event(s) it fired on
//      (`document.data.Event` / `documents[].data.Event`) and the rule that matched
//      (`rule.name`/`name`, `rule.level`/`level`, `rule.tags`/`tags` with `attack.tXXXX`
//      MITRE tags). The Sigma LEVEL is a real maliciousness verdict (unlike a bare Windows
//      log), so it drives severity; the rule name leads the description and the attack tags
//      become MITRE techniques — on top of the structured IOC/asset/process extraction.
//   2. RAW EVTX JSON (`evtx_dump -o json|jsonl`) — an array (or NDJSON) of bare
//      `{ "Event": { "System": {...}, "EventData": {...} } }` records with no verdict.
//      These fall back to the same per-EID severity/MITRE derivation as the SIEM importer.
//
// The valuable per-EID Windows mapping, IOC/hash extraction, aggregation, sort and cap all
// come from `siemImport.ts` (shared, unit-tested) — this module only NORMALIZES the nested
// EVTX `Event` document into the flat record that mapper expects and OVERLAYS the Sigma
// verdict. No AI call; the artifact's own time is used; events are tagged Chainsaw / EVTX.

import type { Severity } from "./stateTypes.js";
import {
  extractRecords,
  mapWindows,
  aggregateEvents,
  worst,
  isObject,
  str,
  getCI,
  getPath,
  normalizeTime,
  type MappedEvent,
  type SiemEvent,
  type SiemIoc,
} from "./siemImport.js";

type Row = Record<string, unknown>;

export interface ChainsawImportOptions {
  // Collapse repetitive identical events into one counted row. Default true.
  aggregate?: boolean;
  // Drop events below this severity floor. Default undefined = keep everything.
  minSeverity?: Severity;
  // Safety cap on emitted events (most-severe first). Default 2000.
  maxEvents?: number;
  // Safety cap on emitted IOCs. Default 5000.
  maxIocs?: number;
}

export interface ChainsawParseResult {
  events: SiemEvent[];
  iocs: SiemIoc[];
  total: number;       // records found in the container
  kept: number;        // events emitted (after aggregation + cap)
  dropped: number;     // records not represented (below floor / capped / unparseable)
  groups: number;      // distinct event groups before the cap
  detections: number;  // Chainsaw rule detections seen (0 ⇒ a pure raw-EVTX dump)
  format: string;      // "chainsaw" | "evtx" | "mixed" | "empty"
  hostname: string;    // best-effort dominant host
}

// Sigma severity vocabulary → our Severity. Chainsaw passes the rule's level straight
// through, so this is the authoritative maliciousness signal for a matched detection.
const SIGMA_LEVEL: Record<string, Severity> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  informational: "Info",
  info: "Info",
};

// Pull MITRE technique ids (T1059, T1003.001) out of Sigma `attack.tXXXX` tags.
function mitreFromTags(tags: unknown): string[] {
  const out = new Set<string>();
  const push = (s: string): void => {
    for (const m of s.matchAll(/\bt\d{4}(?:\.\d{3})?\b/gi)) out.add(m[0].toUpperCase());
  };
  if (Array.isArray(tags)) for (const t of tags) push(str(t));
  else push(str(tags));
  return [...out];
}

// ───────────────────────────── embedded EVTX extraction ─────────────────────────────

// Find the EVTX `Event` object(s) a record carries. Handles a Chainsaw detection's
// `document.data.Event`, an aggregate detection's `documents[].data.Event`, a bare
// `data.Event`, and a raw `{ Event: {...} }` dump. Returns [] when none is present.
function eventDocs(rec: Row): Row[] {
  const out: Row[] = [];
  const docs = getCI(rec, "documents");
  if (Array.isArray(docs)) for (const d of docs) { const e = pickEvent(d); if (e) out.push(e); }
  const doc = getCI(rec, "document");
  if (isObject(doc)) { const e = pickEvent(doc); if (e) out.push(e); }
  if (out.length === 0) { const e = pickEvent(rec); if (e) out.push(e); }
  return out;
}

function pickEvent(d: unknown): Row | null {
  if (!isObject(d)) return null;
  const viaData = getPath(d, "data.Event");
  if (isObject(viaData)) return viaData;
  const direct = getCI(d, "Event");
  if (isObject(direct)) return direct;
  // Some shapes put the Event fields directly under `data` (it has a System block).
  const data = getCI(d, "data");
  if (isObject(data) && isObject(getCI(data, "System"))) return data;
  return null;
}

// EVTX EventData renders either as a flat name→value object (the common `evtx` crate /
// Chainsaw form) or as `{ Data: [ { "@Name": "Image", "#text": "..." }, ... ] }`. Normalize
// both to the flat object `mapWindows` reads.
function normalizeEventData(ed: unknown): Row {
  if (!isObject(ed)) return {};
  const data = getCI(ed, "Data");
  if (Array.isArray(data)) {
    const out: Row = {};
    for (const item of data) {
      if (!isObject(item)) continue;
      const name = str(getCI(item, "@Name") ?? getCI(item, "Name")).trim();
      const val = getCI(item, "#text") ?? getCI(item, "text") ?? getCI(item, "value") ?? "";
      if (name) out[name] = val;
    }
    for (const [k, v] of Object.entries(ed)) if (k.toLowerCase() !== "data") out[k] = v;
    return out;
  }
  return ed;
}

function providerName(sys: Row): string {
  return str(getPath(sys, "Provider.#attributes.Name"))
    || str(getPath(sys, "Provider.Name"))
    || str(getPath(sys, "Provider_attributes.Name"));
}

function systemTime(sys: Row): string {
  return str(getPath(sys, "TimeCreated.#attributes.SystemTime"))
    || str(getPath(sys, "TimeCreated.SystemTime"))
    || str(getCI(sys, "TimeCreated"));
}

// Normalize an EVTX `Event` document into the flat record `mapWindows` consumes
// (`event_id` / `channel` / `event_data` / `@timestamp`) plus the host (System.Computer).
function toFlatRecord(event: Row): { rec: Row; host: string } {
  const sys = isObject(getCI(event, "System")) ? (getCI(event, "System") as Row) : {};
  const channel = str(getCI(sys, "Channel")) || providerName(sys);
  const host = str(getCI(sys, "Computer")).trim();
  const rec: Row = {
    event_id: getCI(sys, "EventID"),                 // mapWindows unwraps a {#text} form
    channel,
    event_data: normalizeEventData(getCI(event, "EventData")),
    "@timestamp": systemTime(sys),
    message: str(getPath(event, "RenderingInfo.Message")),
  };
  return { rec, host };
}

// ───────────────────────────── per-record mapping ─────────────────────────────

interface SigmaMeta {
  group: string;
  ruleName: string;
  level: string;
  tags: unknown;
  ts: string;
}

function readSigmaMeta(rec: Row): SigmaMeta {
  const rule = isObject(getCI(rec, "rule")) ? (getCI(rec, "rule") as Row) : undefined;
  const pick = (key: string): unknown => (rule ? getCI(rule, key) : undefined) ?? getCI(rec, key);
  return {
    group: str(getCI(rec, "group")),
    ruleName: str(pick("name")) || str(getCI(rec, "title")) || "detection",
    level: str(pick("level")),
    tags: pick("tags") ?? getCI(rec, "tags"),
    ts: str(getCI(rec, "timestamp")),
  };
}

// Overlay a Chainsaw rule verdict onto a Windows-mapped event in place: raise severity to
// the Sigma level, union the attack-tag MITRE, lead the description with the rule name, and
// key the aggregate by rule (so two different rules on the same event stay distinct).
function applySigma(mapped: MappedEvent, meta: SigmaMeta): MappedEvent {
  const sev = SIGMA_LEVEL[meta.level.toLowerCase()];
  if (sev) mapped.severity = worst(mapped.severity, sev);
  for (const m of mitreFromTags(meta.tags)) if (!mapped.mitre.includes(m)) mapped.mitre.push(m);
  const head = `Chainsaw${meta.group ? `/${meta.group}` : ""}: ${meta.ruleName}`;
  mapped.description = `${head} - ${mapped.description}`.slice(0, 600);
  mapped.aggKey = `chainsaw|${meta.ruleName.toLowerCase()}|${mapped.aggKey}`;
  mapped.sources = ["Chainsaw"];
  if (!mapped.timestamp && meta.ts) mapped.timestamp = normalizeTime(meta.ts);
  return mapped;
}

// A Chainsaw detection that carries no embedded EVTX event (e.g. a non-evtx source) still
// becomes one event from its rule metadata alone, so the verdict is never lost.
function genericDetection(meta: SigmaMeta): MappedEvent {
  const head = `Chainsaw${meta.group ? `/${meta.group}` : ""}: ${meta.ruleName}`;
  return {
    timestamp: meta.ts ? normalizeTime(meta.ts) : "",
    description: head.slice(0, 600),
    severity: SIGMA_LEVEL[meta.level.toLowerCase()] ?? "Medium",
    mitre: mitreFromTags(meta.tags),
    aggKey: `chainsaw|${meta.ruleName.toLowerCase()}|${meta.ts}`.toLowerCase(),
    sources: ["Chainsaw"],
  };
}

// True when a record looks like a Chainsaw detection (vs a bare EVTX dump record).
function isDetection(rec: Row): boolean {
  return !!(getCI(rec, "document") || getCI(rec, "documents") || getCI(rec, "rule")
    || (getCI(rec, "group") && getCI(rec, "kind")));
}

// ───────────────────────────── top-level parse ─────────────────────────────

export function parseChainsawReport(text: string, opts: ChainsawImportOptions = {}): ChainsawParseResult {
  const maxIocs = opts.maxIocs ?? 5000;

  const { records } = extractRecords(text);
  const total = records.length;
  if (total === 0) {
    return { events: [], iocs: [], total: 0, kept: 0, dropped: 0, groups: 0, detections: 0, format: "empty", hostname: "" };
  }

  const iocSink = new Map<string, SiemIoc>();
  const hostTally = new Map<string, number>();
  const mapped: MappedEvent[] = [];
  let detections = 0;
  let sawEvtx = false;

  for (const rec of records) {
    const detection = isDetection(rec);
    if (detection) detections++;
    const docs = eventDocs(rec);
    if (docs.length === 0) {
      // A detection with no embedded event → keep the verdict; a non-Windows/empty raw
      // record → nothing to map, counts toward `dropped`.
      if (detection) mapped.push(genericDetection(readSigmaMeta(rec)));
      continue;
    }
    const meta = detection ? readSigmaMeta(rec) : null;
    for (const event of docs) {
      const { rec: flat, host } = toFlatRecord(event);
      if (host) hostTally.set(host, (hostTally.get(host) ?? 0) + 1);
      const win = mapWindows(flat, host, iocSink);
      if (!win) { if (meta) mapped.push(genericDetection(meta)); continue; }
      sawEvtx = true;
      if (meta) mapped.push(applySigma(win, meta));
      else { win.sources = ["EVTX"]; mapped.push(win); }
    }
  }

  const { events, groups } = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: opts.minSeverity,
    maxEvents: opts.maxEvents ?? 2000,
  });

  const represented = events.reduce((n, e) => n + (e.count ?? 1), 0);
  const hostname = [...hostTally.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] ?? "";
  // A file with any rule detection is reported as Chainsaw hunt output; otherwise, if we
  // mapped bare EVTX records, it's a raw evtx_dump.
  const format = detections > 0 ? "chainsaw" : sawEvtx ? "evtx" : "empty";

  return {
    events,
    iocs: [...iocSink.values()].slice(0, maxIocs),
    total,
    kept: events.length,
    dropped: Math.max(0, total - represented),
    groups,
    detections,
    format,
    hostname,
  };
}
