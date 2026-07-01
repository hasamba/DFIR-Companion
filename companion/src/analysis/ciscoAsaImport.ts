// Deterministic importer for Cisco ASA firewall syslog — the classic BSD-syslog-framed
// `%ASA-<level>-<msgid>` message format:
//
//   <166>May 14 19:00:02 fw01 %ASA-6-302013: Built outbound TCP connection 1182983 for
//     inside:10.30.20.30/42449 (45.62.114.1/34951) to outside:13.107.6.157/443 (13.107.6.157/443)
//   <164>May 14 19:02:58 fw01 %ASA-4-106023: Deny tcp src inside:10.30.10.27/60228
//     dst outside:42.5.45.223/23 by access-group "inside_access_in" [0xa9d4, 0xa8e5]
//
// A firewall's Built/Teardown log is telemetry, not a detection feed (mirrors Zeek conn.json /
// the ECAR FLOW/CONNECT events) — so severity is Info by default. The one message ASA itself
// grades as noteworthy, an explicit Deny, is bumped to Low: a block is prevention, not confirmed
// compromise, but still worth surfacing — see the branch-office benchmark, where blanket-demoting
// denies would have hidden a real lateral port-scan that manifested AS denied connections.
// Dynamic-NAT-translation messages (305011/305012) carry NO destination IP — only the NAT
// mapping — so they're dropped as pure noise; their paired Built/Teardown already carries the
// same source AND the real destination.
//
// Like Snort, the ASA timestamp carries NO YEAR (`MMM DD HH:MM:SS`); an assumed year is stamped
// and the `mergeDelta` year-clamp re-anchors it once dated evidence lands (see the branch-office
// benchmark's ASA-no-year gotcha). PUBLIC destination IPs become IOCs (RFC1918/loopback/CGNAT
// skipped, like the Snort/ECAR importers, to keep the list tight). Pure, no AI. Reuses
// siemImport's aggregation + IOC sink.

import type { Severity } from "./stateTypes.js";
import { aggregateEvents, addIoc, cleanIp, oneLine, type MappedEvent, type SiemIoc, type SiemParseResult } from "./siemImport.js";

export interface CiscoAsaImportOptions {
  aggregate?: boolean;
  minSeverity?: Severity;
  maxEvents?: number;
  maxIocs?: number;
  assumeYear?: number; // year stamped onto the year-less timestamps (default: current UTC year)
}

export type CiscoAsaParseResult = SiemParseResult;

export const CISCO_ASA_SOURCE = "Cisco ASA";

// "<PRI>MMM DD HH:MM:SS host %ASA-LEVEL-MSGID: message" — the PRI/host are optional-ish in
// practice (a raw `logging host` export may omit the `<PRI>` framing), but the "%ASA-#-######:"
// tag is unique enough on its own to anchor the line.
const ASA_LINE = /%ASA-\d-\d{6}:/;

// Is this text a Cisco ASA syslog export? True when a meaningful share of the first non-blank
// lines carry the `%ASA-#-######:` tag.
export function looksLikeCiscoAsa(text: string): boolean {
  const lines = text.split(/\r?\n/).map((l) => l.trim()).filter(Boolean).slice(0, 50);
  if (!lines.length) return false;
  const hits = lines.filter((l) => ASA_LINE.test(l)).length;
  return hits >= 1 && hits >= lines.length * 0.5;
}

function isPrivateIp(ip: string): boolean {
  const m = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  if (a === 10 || a === 127 || a === 0) return true;
  if (a === 192 && b === 168) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 169 && b === 254) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  return false;
}

const MONTHS: Record<string, string> = {
  Jan: "01", Feb: "02", Mar: "03", Apr: "04", May: "05", Jun: "06",
  Jul: "07", Aug: "08", Sep: "09", Oct: "10", Nov: "11", Dec: "12",
};

// Parse the year-less "MMM DD HH:MM:SS" timestamp into an ISO string at `year`. "" if unparseable.
function parseAsaTime(ts: string, year: number): string {
  const m = ts.trim().match(/^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})$/);
  if (!m) return "";
  const [, mon, dd, hh, mi, ss] = m;
  const month = MONTHS[mon];
  if (!month) return "";
  const t = Date.parse(`${year}-${month}-${dd.padStart(2, "0")}T${hh}:${mi}:${ss}Z`);
  return Number.isNaN(t) ? "" : new Date(t).toISOString();
}

// Full line shape: optional `<PRI>` framing, the year-less timestamp, hostname, then the ASA tag
// and message body.
const LINE_RE = /^(?:<\d+>)?\s*([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+%ASA-(\d)-(\d{6}):\s*(.*)$/;

// Any `<zone>:<ip>/<port>` token — the shared shape across "for inside:X/Y to outside:A/B",
// "src inside:X/Y dst outside:A/B", regardless of the exact phrasing per message id. The FIRST
// match is the source (always logged first by ASA), the SECOND is the destination.
const ZONE_IP_PORT = /\b[a-zA-Z][\w-]*:(\d{1,3}(?:\.\d{1,3}){3})\/(\d+)\b/g;

const DURATION_BYTES = /duration\s+(\d+:\d+:\d+)(?:\s+bytes\s+(\d+))?/i;
const PROTO_RE = /\b(TCP|UDP|ICMP)\b/i;

interface Flow { srcIp: string; srcPort?: number; dstIp: string; dstPort?: number; }

function extractFlow(body: string): Flow | null {
  const matches = [...body.matchAll(ZONE_IP_PORT)];
  if (matches.length < 2) return null;
  const [src, dst] = matches;
  const srcIp = cleanIp(src[1]);
  const dstIp = cleanIp(dst[1]);
  if (!srcIp || !dstIp) return null;
  return {
    srcIp, srcPort: Number(src[2]) || undefined,
    dstIp, dstPort: Number(dst[2]) || undefined,
  };
}

type Action = "built" | "teardown" | "deny" | "other";

function classifyAction(body: string): Action {
  if (/^Built\b/i.test(body)) return "built";
  if (/^Teardown\b/i.test(body)) return "teardown";
  if (/^Deny\b/i.test(body)) return "deny";
  return "other";
}

// Map one ASA syslog line to a forensic event (collecting IOCs), or null if it isn't an ASA line,
// or is pure NAT-translation noise with no destination IP.
export function mapCiscoAsaLine(line: string, year: number, sink: Map<string, SiemIoc>): MappedEvent | null {
  const m = LINE_RE.exec(line.trim());
  if (!m) return null;
  const [, tsRaw, host, , msgId, body] = m;

  // Dynamic NAT translation (305011/305012 and friends) carries only the NAT mapping, never the
  // real remote destination — its paired Built/Teardown message already has both. Pure noise.
  if (/dynamic\s+(?:TCP|UDP)\s+translation/i.test(body)) return null;

  const action = classifyAction(body);
  const flow = extractFlow(body);
  const proto = PROTO_RE.exec(body)?.[1]?.toUpperCase() ?? "";
  const durMatch = DURATION_BYTES.exec(body);

  if (flow?.dstIp && !isPrivateIp(flow.dstIp)) addIoc(sink, "ip", flow.dstIp);

  const flowStr = flow
    ? ` ${flow.srcIp}${flow.srcPort ? `:${flow.srcPort}` : ""} → ${flow.dstIp}${flow.dstPort ? `:${flow.dstPort}` : ""}`
    : "";
  const verb = action === "built" ? "Built" : action === "teardown" ? "Teardown" : action === "deny" ? "Denied" : oneLine(body).slice(0, 60);
  const detail = durMatch ? ` (duration ${durMatch[1]}${durMatch[2] ? `, ${durMatch[2]}b` : ""})` : "";
  const description = `ASA: ${verb}${proto ? ` ${proto}` : ""} connection${flowStr}${detail} @ ${host}`.slice(0, 600);

  const timestamp = parseAsaTime(tsRaw, year);
  const port = flow?.dstPort && flow.dstPort > 0 && flow.dstPort <= 65535 ? flow.dstPort : undefined;

  return {
    timestamp,
    description,
    severity: action === "deny" ? "Low" : "Info",
    mitre: [],
    aggKey: `asa|${msgId}|${flow?.srcIp ?? ""}|${flow?.dstIp ?? ""}|${port ?? ""}`.toLowerCase(),
    sources: [CISCO_ASA_SOURCE],
    ...(flow?.srcIp ? { srcIp: flow.srcIp } : {}),
    ...(flow?.dstIp ? { dstIp: flow.dstIp } : {}),
    ...(port ? { port } : {}),
  };
}

// Parse a Cisco ASA syslog export into the shared SIEM result shape (aggregated + capped). Pure.
export function parseCiscoAsaLog(text: string, opts: CiscoAsaImportOptions = {}): CiscoAsaParseResult {
  const year = opts.assumeYear ?? new Date().getUTCFullYear();
  const maxIocs = opts.maxIocs ?? 5000;
  const sink = new Map<string, SiemIoc>();
  const mapped: MappedEvent[] = [];
  let total = 0;

  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) continue;
    if (!ASA_LINE.test(line)) continue;
    total++;
    const m = mapCiscoAsaLine(line, year, sink);
    if (m) mapped.push(m);
  }

  const { events, groups } = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: opts.minSeverity,
    maxEvents: opts.maxEvents ?? 2000,
  });
  const represented = events.reduce((n, e) => n + (e.count ?? 1), 0);

  return {
    events,
    iocs: [...sink.values()].slice(0, maxIocs),
    total,
    kept: events.length,
    dropped: Math.max(0, total - represented),
    groups,
    format: "cisco-asa",
    hostname: "",
  };
}
