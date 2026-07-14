// Deterministic importer for Wazuh SIEM/EDR alert exports — no AI call.
//
// Wazuh is one of the most widely deployed open-source SIEM/EDR platforms. Analysts
// export alerts as JSON for offline analysis. Two formats are handled, auto-detected:
//
//   1. alerts.json / wazuh-alerts-*.json — array or NDJSON of alert objects.
//   2. Wazuh API export — objects from GET /security/events, wrapped in
//      { data: { affected_items: [...] } }.
//
// Severity is DERIVED from rule.level (the Wazuh rule severity scale 0-15):
//   ≥13 → Critical, ≥10 → High, ≥7 → Medium, else Info.
//   Alerts with rule.level < 3 are noise and dropped by default (override via minLevel).
//
// Reuses siemImport's extractRecords, aggregateEvents, addIoc, cleanIp.

import type { Severity } from "./stateTypes.js";
import {
  extractRecords,
  aggregateEvents,
  addIoc,
  cleanIp,
  str,
  isObject,
  getCI,
  getPath,
  normalizeTime,
  oneLine,
  type MappedEvent,
  type SiemEvent,
  type SiemIoc,
  maxEventsDefault,
} from "./siemImport.js";

type Row = Record<string, unknown>;

export interface WazuhImportOptions {
  // Collapse repetitive identical events into one counted row. Default true.
  aggregate?: boolean;
  // Drop events below this severity floor. Default undefined = keep everything except noise.
  minSeverity?: Severity;
  // Drop alerts whose rule.level is below this value. Default 3 (suppress pure noise).
  minLevel?: number;
  // Safety cap on emitted events. Default 2000 (overridable via DFIR_MAX_EVENTS).
  maxEvents?: number;
  // Safety cap on emitted IOCs. Default 5000.
  maxIocs?: number;
}

export interface WazuhParseResult {
  events: SiemEvent[];
  iocs: SiemIoc[];
  total: number;    // alert records found in the input
  kept: number;     // events emitted (after aggregation + cap)
  dropped: number;  // records not represented (below floor / capped / noise)
  groups: number;   // distinct event groups before the cap
  format: string;   // "array" | "ndjson" | "api-export" | "empty"
  hostname: string; // best-effort dominant agent host
}

// Map a Wazuh rule.level (0-15) to a Companion severity.
function wazuhLevelToSeverity(level: number): Severity {
  if (level >= 13) return "Critical";
  if (level >= 10) return "High";
  if (level >= 7) return "Medium";
  return "Info";
}

// Extract MITRE technique IDs from rule.mitre.technique (string | string[]).
function mitreFromWazuh(mitre: unknown): string[] {
  if (!mitre) return [];
  const items = Array.isArray(mitre) ? mitre : [mitre];
  const out: string[] = [];
  for (const item of items) {
    const s = str(item).trim().toUpperCase();
    if (/^T\d{4}(\.\d{3})?$/.test(s)) out.push(s);
  }
  return out;
}

// Wazuh alert timestamp: "2024-01-15T10:30:00.123+0000", ISO variants, or numeric ms.
function wazuhTime(raw: unknown): string {
  if (raw == null) return "";
  if (typeof raw === "number") return new Date(raw).toISOString();
  return normalizeTime(str(raw));
}

function mapAlert(rec: Row, iocSink: Map<string, SiemIoc>): MappedEvent | null {
  const rule = getCI(rec, "rule");
  if (!isObject(rule)) return null;

  const levelRaw = getCI(rule, "level");
  const level = typeof levelRaw === "number" ? levelRaw : Number(levelRaw);
  if (!Number.isFinite(level)) return null;

  const description = oneLine(str(getCI(rule, "description"))).slice(0, 400);
  if (!description) return null;

  const severity = wazuhLevelToSeverity(level);
  const mitre = mitreFromWazuh(getPath(rule, "mitre.technique"));

  // Asset: agent.name is the endpoint the alert fired on.
  const agentName = str(getPath(rec, "agent.name")).trim();

  // Timestamp from the alert's own timestamp field — never capture time.
  const timestamp = wazuhTime(getCI(rec, "timestamp") ?? getPath(rec, "@timestamp"));

  // Build description including rule id and groups for context.
  const ruleId = str(getCI(rule, "id")).trim();
  const groups: string[] = [];
  const rawGroups = getCI(rule, "groups");
  if (Array.isArray(rawGroups)) for (const g of rawGroups) { const s = str(g).trim(); if (s) groups.push(s); }
  else if (rawGroups) { const s = str(rawGroups).trim(); if (s) groups.push(s); }

  let desc = description;
  if (ruleId) desc += ` [rule ${ruleId}]`;
  if (agentName) desc += ` @ ${agentName}`;
  desc = desc.slice(0, 600);

  // IOC extraction from Wazuh data fields.
  const data = getCI(rec, "data");
  if (isObject(data)) {
    // Network IOCs.
    for (const k of ["srcip", "src_ip", "dstip", "dst_ip"]) {
      const ip = cleanIp(str(getCI(data, k)));
      if (ip) addIoc(iocSink, "ip", ip);
    }
    // Hash IOCs.
    const md5 = str(getCI(data, "md5")).trim().toLowerCase();
    if (/^[a-f0-9]{32}$/.test(md5)) addIoc(iocSink, "hash", md5);
    const sha256 = str(getCI(data, "sha256")).trim().toLowerCase();
    if (/^[a-f0-9]{64}$/.test(sha256)) addIoc(iocSink, "hash", sha256);
    // URL IOC.
    const url = str(getCI(data, "url")).trim();
    if (url && /^https?:\/\//i.test(url)) addIoc(iocSink, "url", url.slice(0, 300));
    // Command line for process context.
    const winData = getCI(data, "win");
    if (isObject(winData)) {
      const eventData = getCI(winData, "eventdata");
      if (isObject(eventData)) {
        const cmdLine = str(getCI(eventData, "commandLine") ?? getCI(eventData, "commandline")).trim();
        if (cmdLine) addIoc(iocSink, "process", cmdLine.slice(0, 200));
      }
    }
  }

  // Also extract network.srcIp / dstIp from top-level network object.
  const network = getCI(rec, "network");
  if (isObject(network)) {
    const srcIp = cleanIp(str(getPath(network, "srcIp") ?? getPath(network, "src_ip") ?? ""));
    if (srcIp) addIoc(iocSink, "ip", srcIp);
    const dstIp = cleanIp(str(getPath(network, "destIp") ?? getPath(network, "dst_ip") ?? ""));
    if (dstIp) addIoc(iocSink, "ip", dstIp);
  }

  // Deduplicate aggregate key: rule id + agent + groups (stable, no volatile fields).
  const aggKey = `wazuh|${ruleId}|${agentName}|${groups.join(",")}`.toLowerCase().slice(0, 400);

  return {
    timestamp,
    description: desc,
    severity,
    mitre,
    aggKey,
    ...(agentName ? { asset: agentName } : {}),
    sources: ["Wazuh"],
  };
}

// Unwrap the Wazuh API export envelope: { data: { affected_items: [...] } }.
function unwrapApiExport(text: string): { records: Row[]; format: string } | null {
  let root: unknown;
  try { root = JSON.parse(text.trim()); } catch { return null; }
  if (!isObject(root)) return null;
  const data = getCI(root, "data");
  if (!isObject(data)) return null;
  const items = getCI(data, "affected_items");
  if (!Array.isArray(items)) return null;
  const records = items.filter((el): el is Row => isObject(el));
  return { records, format: "api-export" };
}

export function parseWazuhAlerts(text: string, opts: WazuhImportOptions = {}): WazuhParseResult {
  const minLevel = opts.minLevel ?? 3;
  const maxIocs = opts.maxIocs ?? 5000;

  const trimmed = text.trim();
  if (!trimmed) {
    return { events: [], iocs: [], total: 0, kept: 0, dropped: 0, groups: 0, format: "empty", hostname: "" };
  }

  // Try API export envelope first ({ data: { affected_items: [...] } }).
  let records: Row[];
  let format: string;
  const apiResult = unwrapApiExport(trimmed);
  if (apiResult) {
    records = apiResult.records;
    format = apiResult.format;
  } else {
    const extracted = extractRecords(trimmed);
    records = extracted.records;
    format = extracted.format;
  }

  const total = records.length;
  if (total === 0) {
    return { events: [], iocs: [], total: 0, kept: 0, dropped: 0, groups: 0, format, hostname: "" };
  }

  const iocSink = new Map<string, SiemIoc>();
  const mapped: MappedEvent[] = [];
  let noise = 0;

  for (const rec of records) {
    // Drop low-level noise before mapping.
    const rule = getCI(rec, "rule");
    if (isObject(rule)) {
      const levelRaw = getCI(rule, "level");
      const level = typeof levelRaw === "number" ? levelRaw : Number(levelRaw);
      if (Number.isFinite(level) && level < minLevel) { noise++; continue; }
    }
    const m = mapAlert(rec, iocSink);
    if (m) mapped.push(m);
    else noise++;
  }

  if (mapped.length === 0) {
    return { events: [], iocs: [], total, kept: 0, dropped: total, groups: 0, format, hostname: "" };
  }

  const { events, groups } = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: opts.minSeverity,
    maxEvents: opts.maxEvents ?? maxEventsDefault(),
  });

  // Best-effort dominant host: most-common agent.name across ALL mapped events.
  const hostCount = new Map<string, number>();
  for (const m of mapped) {
    if (m.asset) hostCount.set(m.asset, (hostCount.get(m.asset) ?? 0) + 1);
  }
  let hostname = "";
  let best = 0;
  for (const [h, n] of hostCount) { if (n > best) { best = n; hostname = h; } }

  const represented = events.reduce((n, e) => n + (e.count ?? 1), 0);
  return {
    events,
    iocs: [...iocSink.values()].slice(0, maxIocs),
    total,
    kept: events.length,
    dropped: Math.max(0, total - noise - represented),
    groups,
    format,
    hostname,
  };
}
