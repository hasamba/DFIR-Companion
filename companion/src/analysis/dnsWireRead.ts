// What one sensor-side DNS record and one connection record SAY — read, validated, bounded, and
// nothing joined yet (#996, the second half of #933 item 2). Zeek `dns.log` and `conn.log`,
// Suricata `dns` (v1 / v2 answer, v3 response) and `flow` / `netflow`. The join is dnsConnJoin.ts;
// the rows are dnsWireRows.ts.
//
// A DNS record establishes: which client address asked which server for a name (and a type), what
// the server's response code was, and the VALUES the response carried. Zeek keeps the answer
// section's rdata with no owner name, so — exactly like the Windows records (dnsRecord.ts) — the
// values are `returned`, never "resolves to". Suricata keeps `rrname` per answer: an owner the
// record states, still not a resolution the sensor verified. A connection record establishes that
// the sensor saw a flow start from one address to another, and — through Zeek's `conn_state` or
// Suricata's packet counts — whether the peer ever answered. A record with a lone SYN is not a
// connection, and the join never words it as one.
//
// Every list is bounded at read time: DNS_RETURNED_MAX values are kept per record, the rest are
// counted, and the identity digest still covers every value parsed (the #1009 rule).

import { isIP } from "node:net";
import type { DnsReply } from "./canonicalDns.js";
import { asciiName, isValidQueryName } from "./dnsRecord.js";
import { keyDigest, showToken } from "./recordIdentity.js";
import { getCI, isObject, normalizeTime, str } from "./siemImport.js";
import { sensorOf, type SensorRef } from "./webChainRead.js";

type Row = Record<string, unknown>;

/** Returned values read from one record; the rest are counted (and digested) only. */
export const DNS_RETURNED_MAX = 32;
/** RFC 2181: a TTL is an unsigned 31-bit integer; anything else is not a TTL. */
const TTL_MAX = 2 ** 31 - 1;
/** A query round trip past this is not a round trip the join can place an answer by. */
const RTT_MAX_S = 60;
const VALUE_KEPT_MAX = 512;
const DNS_PORT = 53;

export type DnsSource = "zeek-dns" | "suricata-dns";
export type ConnSource = "zeek-conn" | "suricata-flow" | "suricata-netflow";

/** RR type names the words use; every other type is `type N`. */
const TYPE_BY_NAME: Record<string, number> = {
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  PTR: 12,
  MX: 15,
  TXT: 16,
  AAAA: 28,
  SRV: 33,
  HTTPS: 65,
  ANY: 255,
};
const NAME_TYPES = new Set([2, 5, 6, 12, 15, 33, 39]);
const V4_MAPPED = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i;

export interface ReturnedWire {
  type?: number;
  typeName?: string;
  /** Canonical: an address as isIP reads it, a name in lowercase A-label form, other text whole. */
  value: string;
  kind: "address" | "name" | "other";
  /** Seconds, validated; absent when the record carries none or an invalid one. */
  ttl?: number;
  owner?: string;
}

export interface DnsObservation {
  source: DnsSource;
  locator: string;
  observer?: SensorRef;
  /** The record's own time as epoch milliseconds, and as ISO. */
  ts: number;
  timestamp: string;
  /** What that time IS: a Zeek `ts` is the query; a Suricata answer event's timestamp is the answer. */
  anchor: "query" | "answer";
  /** Zeek `rtt` in seconds, validated; the answer arrived at ts + rtt. */
  rtt?: number;
  /** The asking address, when it is one the join can use (isJoinableClient). */
  client?: string;
  /** The two ends as recorded, for the words — present even when `client` is not joinable. */
  ends?: { a: string; b: string; direction: "client → server" | "not in this record" };
  server?: string;
  serverPort?: number;
  /** The raw field the query came from, for provenance (`query`, `dns.rrname`, `dns.queries[0].rrname`). */
  queryField: string;
  /** The query name exactly as recorded (shown neutralised); `queryAscii` is its wire form or "". */
  query: string;
  queryAscii: string;
  queryValid: boolean;
  queryType?: number;
  queryTypeName?: string;
  /** The response code name, uppercase, bounded — or absent when the record has none. */
  rcode?: string;
  aa?: boolean;
  ra?: boolean;
  rejected?: boolean;
  returned: ReturnedWire[];
  returnedTotal: number;
  /** Digest over EVERY parsed value (type, owner, value), sorted — the identity, not the kept list. */
  returnedIdentity: string;
  ownership: "not in this record" | "stated in the record";
  /** The record's own connection identifier (`uid` / `flow_id`) — excluded from the join. */
  recordId?: string;
}

export interface ConnObservation {
  source: ConnSource;
  locator: string;
  sensor: string;
  /** First-packet time, epoch ms; `end` when the record says when the flow ended. */
  start: number;
  end?: number;
  src: string;
  dst: string;
  reply: DnsReply;
  recordId?: string;
}

// ───────────────────────────── field readers ─────────────────────────────

const text = (v: unknown): string | undefined =>
  v === undefined || v === null ? undefined : typeof v === "string" ? v : String(v);

const bool = (v: unknown): boolean | undefined =>
  typeof v === "boolean"
    ? v
    : v === "true" || v === "T"
      ? true
      : v === "false" || v === "F"
        ? false
        : undefined;

// Lowercase so an IPv6 written in two cases keys and joins as one address.
// Any well-formed address the record wrote, lowercase (an IPv6 in two cases is one address) —
// loopback and link-local included, so the words can show the end the record names.
const address = (v: unknown): string | undefined => {
  const raw = str(v).trim();
  const mapped = V4_MAPPED.exec(raw);
  const a = (mapped ? mapped[1] : raw).toLowerCase();
  return a && isIP(a) ? a : undefined;
};

// A client the join can use: a unicast address that is not loopback or link-local — a stub
// resolver on the host (`127.0.0.1`), LLMNR/mDNS (`fe80::…` → `ff02::…`) name nothing the
// sensor's connection records can be matched to.
const NOT_JOINABLE =
  /^(?:127\.|0\.0\.0\.0$|::1$|::$|fe[89ab][0-9a-f]:|ff[0-9a-f]{2}:|169\.254\.|224\.|2(?:2[5-9]|3\d)\.)/i;
export const isJoinableClient = (a: string): boolean => !NOT_JOINABLE.test(a);

const portOf = (v: unknown): number | undefined => {
  const n = typeof v === "number" ? v : Number(text(v)?.trim());
  return Number.isInteger(n) && n > 0 && n <= 65535 ? n : undefined;
};

/** Seconds as the record wrote them, or undefined when not a finite non-negative number. */
const seconds = (v: unknown): number | undefined => {
  if (v === undefined || v === null || v === "") return undefined;
  const n = typeof v === "number" ? v : typeof v === "string" ? Number(v.trim()) : NaN;
  return Number.isFinite(n) && n >= 0 ? n : undefined;
};

export const ttlOf = (v: unknown): number | undefined => {
  const n = seconds(v);
  return n !== undefined && Number.isInteger(n) && n <= TTL_MAX ? n : undefined;
};

export const rttOf = (v: unknown): number | undefined => {
  const n = seconds(v);
  return n !== undefined && n <= RTT_MAX_S ? n : undefined;
};

function epochMs(v: unknown): number | undefined {
  const n =
    typeof v === "number" ? v : typeof v === "string" && /^\d+(\.\d+)?$/.test(v.trim()) ? Number(v) : NaN;
  if (Number.isFinite(n) && n > 1e9) return Math.round(n > 1e12 ? n : n * 1000);
  const iso = normalizeTime(str(v));
  const ms = iso ? Date.parse(iso) : NaN;
  return Number.isFinite(ms) ? ms : undefined;
}

const isoOf = (ms: number | undefined): string => (ms === undefined ? "" : new Date(ms).toISOString());

// A `-` is the Zeek placeholder for "unset" (a TSV-converted export), never a value.
const upperToken = (v: unknown, max = 24): string | undefined => {
  const t = text(v)?.trim();
  return t && t !== "-" ? showToken(t).toUpperCase().slice(0, max) : undefined;
};
// An RR type name is a bare token; anything else reaches no words (it would be free text).
const TYPE_TOKEN = /^[A-Z0-9]{1,16}$/;

const queryTypeOf = (name: unknown, num: unknown): Pick<DnsObservation, "queryType" | "queryTypeName"> => {
  const t = typeOf(name, num);
  return {
    ...(t.type !== undefined ? { queryType: t.type } : {}),
    ...(t.typeName ? { queryTypeName: t.typeName } : {}),
  };
};

function typeOf(name: unknown, num: unknown): { type?: number; typeName?: string } {
  const token = upperToken(name, 16);
  const typeName = token && TYPE_TOKEN.test(token) ? token : undefined;
  const fromName = typeName ? TYPE_BY_NAME[typeName] : undefined;
  const n = typeof num === "number" ? num : Number(text(num)?.trim());
  const type = fromName ?? (Number.isInteger(n) && n >= 0 && n <= 65535 ? n : undefined);
  return { ...(type !== undefined ? { type } : {}), ...(typeName ? { typeName } : {}) };
}

// The sensor: the shipper's fields (sensorOf), else the bare `host` / `hostname` a Suricata
// eve.json carries — on a dns or conn record neither is a client-written header.
function sensorRef(row: Row): SensorRef | undefined {
  const shipped = sensorOf(row);
  if (shipped) return shipped;
  for (const field of ["host", "hostname"]) {
    const v = getCI(row, field);
    const name = typeof v === "string" ? v.trim() : "";
    if (name) return { name, sourceField: field };
  }
  return undefined;
}

/** Query types whose answer section can carry an address the client would then contact. */
const ADDRESS_QUERY_TYPES = new Set([1, 28, 64, 65, 255]);

/**
 * One returned value, classified the way dnsRecord.ts classifies a Windows result. An untyped
 * value (Zeek keeps no RR type per answer) is an address only when the QUERY could return one:
 * a TXT answer that spells an address is data, never a lead.
 */
export function classifyReturned(
  raw: string,
  type: number | undefined,
  queryType?: number,
): Pick<ReturnedWire, "value" | "kind"> {
  const mapped = V4_MAPPED.exec(raw.trim());
  const candidate = mapped ? mapped[1] : raw.trim();
  const addressType =
    type !== undefined
      ? type === 1 || type === 28
      : queryType === undefined || ADDRESS_QUERY_TYPES.has(queryType);
  if (isIP(candidate))
    return addressType
      ? { value: candidate.toLowerCase(), kind: "address" }
      : { value: raw.slice(0, VALUE_KEPT_MAX), kind: "other" };
  if ((type === undefined || NAME_TYPES.has(type)) && isValidQueryName(raw))
    return { value: asciiName(raw).toLowerCase(), kind: "name" };
  return { value: raw.slice(0, VALUE_KEPT_MAX), kind: "other" };
}

interface RawAnswer {
  value: string;
  type?: number;
  typeName?: string;
  ttl?: number;
  owner?: string;
}

/** Bound and digest a parsed answer list; the digest covers every entry. */
function boundReturned(
  all: RawAnswer[],
  queryType: number | undefined,
): Pick<DnsObservation, "returned" | "returnedTotal" | "returnedIdentity"> {
  const classified: ReturnedWire[] = all.map((a) => ({
    ...(a.type !== undefined ? { type: a.type } : {}),
    ...(a.typeName ? { typeName: a.typeName } : {}),
    ...classifyReturned(a.value, a.type, queryType),
    ...(a.ttl !== undefined ? { ttl: a.ttl } : {}),
    ...(a.owner ? { owner: a.owner } : {}),
  }));
  const identity = keyDigest(
    classified
      .map((v) => `${v.type ?? "-"}:${v.owner ?? "-"}:${v.value.length}:${v.value}`)
      .sort()
      .join("\n"),
  );
  return {
    returned: classified.slice(0, DNS_RETURNED_MAX),
    returnedTotal: classified.length,
    returnedIdentity: identity,
  };
}

const flags = (
  aa?: boolean,
  ra?: boolean,
  rejected?: boolean,
): Pick<DnsObservation, "aa" | "ra" | "rejected"> => ({
  ...(aa !== undefined ? { aa } : {}),
  ...(ra !== undefined ? { ra } : {}),
  ...(rejected !== undefined ? { rejected } : {}),
});

function queryFields(raw: unknown): Pick<DnsObservation, "query" | "queryAscii" | "queryValid"> {
  const query = text(raw) ?? "";
  const valid = isValidQueryName(query);
  return { query, queryAscii: valid ? asciiName(query).toLowerCase() : "", queryValid: valid };
}

// ───────────────────────────── Zeek dns.log ─────────────────────────────

export function readZeekDns(row: Row, recordIndex: number): DnsObservation | undefined {
  const ts = epochMs(getCI(row, "ts"));
  if (ts === undefined) return undefined;
  const answersRaw = getCI(row, "answers");
  const ttlsRaw = getCI(row, "TTLs") ?? getCI(row, "ttls");
  const answers = Array.isArray(answersRaw)
    ? answersRaw
    : answersRaw != null && answersRaw !== "-"
      ? [answersRaw]
      : [];
  const ttls = Array.isArray(ttlsRaw) ? ttlsRaw : [];
  // TTLs align with answers by index; a mismatched list leaves the unmatched answers without one.
  const all: RawAnswer[] = answers.map((a, i) => {
    const ttl = i < ttls.length && ttls.length === answers.length ? ttlOf(ttls[i]) : undefined;
    return { value: str(a), ...(ttl !== undefined ? { ttl } : {}) };
  });
  const rcode = upperToken(getCI(row, "rcode_name"));
  const rtt = rttOf(getCI(row, "rtt"));
  const uid = text(getCI(row, "uid"))?.trim();
  const orig = address(getCI(row, "id.orig_h")),
    resp = address(getCI(row, "id.resp_h"));
  const type = queryTypeOf(getCI(row, "qtype_name"), getCI(row, "qtype"));
  return {
    source: "zeek-dns",
    locator: `record:${recordIndex}`,
    observer: sensorRef(row),
    ts,
    timestamp: isoOf(ts),
    anchor: "query",
    ...(rtt !== undefined ? { rtt } : {}),
    ...(orig && isJoinableClient(orig) ? { client: orig } : {}),
    ...(orig && resp ? { ends: { a: orig, b: resp, direction: "client → server" } } : {}),
    ...(resp ? { server: resp } : {}),
    ...(portOf(getCI(row, "id.resp_p")) !== undefined ? { serverPort: portOf(getCI(row, "id.resp_p")) } : {}),
    queryField: "query",
    ...queryFields(getCI(row, "query")),
    ...type,
    ...(rcode ? { rcode } : {}),
    ...flags(bool(getCI(row, "AA")), bool(getCI(row, "RA")), bool(getCI(row, "rejected"))),
    ...boundReturned(all, type.queryType),
    ownership: "not in this record",
    ...(uid ? { recordId: uid } : {}),
  };
}

// ───────────────────────────── Suricata dns ─────────────────────────────

// The client is the side whose port is not 53: packet-direction outputs put the answering server
// in `src_ip` on an answer event, flow-direction outputs put the client there. When the ports do
// not decide (both 53, neither recorded) the record does not say which end asked, and no client
// is asserted.
function suricataEnds(row: Row): Pick<DnsObservation, "client" | "ends" | "server" | "serverPort"> {
  const src = address(getCI(row, "src_ip")),
    dst = address(getCI(row, "dest_ip"));
  const sp = portOf(getCI(row, "src_port")),
    dp = portOf(getCI(row, "dest_port"));
  if (!src || !dst) return {};
  const decided =
    sp === DNS_PORT && dp !== DNS_PORT
      ? [dst, src, sp]
      : dp === DNS_PORT && sp !== DNS_PORT
        ? [src, dst, dp]
        : undefined;
  if (!decided) return { ends: { a: src, b: dst, direction: "not in this record" } };
  const [client, server, serverPort] = decided as [string, string, number];
  return {
    ...(isJoinableClient(client) ? { client } : {}),
    ends: { a: client, b: server, direction: "client → server" },
    server,
    serverPort,
  };
}

function suricataAnswer(a: unknown): RawAnswer | undefined {
  if (!isObject(a)) return undefined;
  const value = text(getCI(a, "rdata"));
  if (value === undefined) return undefined;
  const ttl = ttlOf(getCI(a, "ttl"));
  const ownerRaw = text(getCI(a, "rrname"));
  const owner = ownerRaw && isValidQueryName(ownerRaw) ? asciiName(ownerRaw).toLowerCase() : undefined;
  return {
    value,
    ...typeOf(getCI(a, "rrtype"), undefined),
    ...(ttl !== undefined ? { ttl } : {}),
    ...(owner ? { owner } : {}),
  };
}

/** Suricata `dns.type` is `answer` (v1/v2) or `response` (v3); a `query` / `request` establishes no answer. */
export function isSuricataDnsAnswer(dns: Row): boolean {
  const t = text(getCI(dns, "type"))?.trim().toLowerCase();
  return t === "answer" || t === "response";
}

/** A v1 answer event is one RR per event: its `rrname` is that RR's owner, not the question. */
export const isSuricataV1Answer = (dns: Row): boolean =>
  isSuricataDnsAnswer(dns) &&
  !Array.isArray(getCI(dns, "answers")) &&
  text(getCI(dns, "rdata")) !== undefined;

/** The query name(s) a Suricata dns event carries: `rrname` (v2) or `queries[].rrname` (v3). */
export function suricataQueryNames(dns: Row): string[] {
  const names: string[] = [];
  const top = isSuricataV1Answer(dns) ? undefined : text(getCI(dns, "rrname"));
  if (top) names.push(top);
  const queries = getCI(dns, "queries");
  if (Array.isArray(queries))
    for (const q of queries)
      if (isObject(q)) {
        const n = text(getCI(q, "rrname"));
        if (n) names.push(n);
      }
  return names;
}

export function readSuricataDns(row: Row, recordIndex: number): DnsObservation | undefined {
  const dns = getCI(row, "dns");
  if (!isObject(dns) || !isSuricataDnsAnswer(dns)) return undefined;
  const ts = epochMs(getCI(row, "timestamp"));
  if (ts === undefined) return undefined;
  const queries = getCI(dns, "queries");
  const q0 = Array.isArray(queries) && isObject(queries[0]) ? queries[0] : undefined;
  const v1 = isSuricataV1Answer(dns);
  // v1 wrote one answer RR per event with `rrname` as the RR's OWNER; the question is not in the
  // record. v2 carries the question as `rrname`; v3 keeps it in `queries[]`.
  const queryName = v1
    ? undefined
    : (text(getCI(dns, "rrname")) ?? (q0 ? text(getCI(q0, "rrname")) : undefined));
  const queryField = v1
    ? ""
    : text(getCI(dns, "rrname")) !== undefined
      ? "dns.rrname"
      : "dns.queries[0].rrname";
  const qtype = v1 ? undefined : (getCI(dns, "rrtype") ?? (q0 ? getCI(q0, "rrtype") : undefined));
  const answersRaw = getCI(dns, "answers");
  let all: RawAnswer[] = Array.isArray(answersRaw)
    ? answersRaw.map(suricataAnswer).filter((a): a is RawAnswer => !!a)
    : [];
  if (v1) {
    const one = suricataAnswer(dns);
    if (one) all = [one];
  }
  const grouped = getCI(dns, "grouped");
  if (!all.length && !v1 && isObject(grouped))
    for (const [typeName, values] of Object.entries(grouped))
      if (Array.isArray(values))
        for (const v of values) all.push({ value: str(v), ...typeOf(typeName, undefined) });
  const rcode = upperToken(getCI(dns, "rcode"));
  const flowId = text(getCI(row, "flow_id"))?.trim();
  const type = queryTypeOf(qtype, undefined);
  return {
    source: "suricata-dns",
    locator: `record:${recordIndex}`,
    observer: sensorRef(row),
    ts,
    timestamp: isoOf(ts),
    anchor: "answer",
    ...suricataEnds(row),
    queryField,
    ...queryFields(queryName),
    ...type,
    ...(rcode ? { rcode } : {}),
    ...flags(bool(getCI(dns, "aa")), bool(getCI(dns, "ra")), undefined),
    ...boundReturned(all, type.queryType),
    ownership: all.some((a) => a.owner) ? "stated in the record" : "not in this record",
    ...(flowId ? { recordId: flowId } : {}),
  };
}

// ───────────────────────────── connections ─────────────────────────────

// Zeek's conn_state, read for the one fact the join words: did the peer ever answer.
const PEER_ANSWERED = new Set(["SF", "S1", "S2", "S3", "RSTO", "RSTR", "RSTRH", "SHR", "OTH"]);
const PEER_SILENT = new Set(["S0", "REJ", "RSTOS0", "SH"]);

export function replyOfConnState(state: string | undefined): DnsReply {
  const s = state?.trim().toUpperCase();
  if (!s) return "reply not in this record";
  if (PEER_ANSWERED.has(s)) return "answered by the peer";
  if (PEER_SILENT.has(s)) return "no reply from the peer";
  return "reply not in this record";
}

export function readZeekConn(row: Row, recordIndex: number): ConnObservation | undefined {
  const start = epochMs(getCI(row, "ts"));
  const src = address(getCI(row, "id.orig_h")),
    dst = address(getCI(row, "id.resp_h"));
  if (start === undefined || !src || !dst) return undefined;
  const duration = seconds(getCI(row, "duration"));
  const uid = text(getCI(row, "uid"))?.trim();
  return {
    source: "zeek-conn",
    locator: `record:${recordIndex}`,
    sensor: sensorRef(row)?.name ?? "",
    start,
    ...(duration !== undefined ? { end: start + Math.round(duration * 1000) } : {}),
    src,
    dst,
    reply: replyOfConnState(text(getCI(row, "conn_state"))),
    ...(uid ? { recordId: uid } : {}),
  };
}

function suricataReply(flow: Row): DnsReply {
  const toClient = getCI(flow, "pkts_toclient");
  const n = typeof toClient === "number" ? toClient : Number(text(toClient)?.trim());
  if (Number.isFinite(n)) return n > 0 ? "answered by the peer" : "no reply from the peer";
  const state = text(getCI(flow, "state"))?.trim().toLowerCase();
  if (state === "established" || state === "closed") return "answered by the peer";
  if (state === "new") return "no reply from the peer";
  return "reply not in this record";
}

/** A Suricata `flow` (bidirectional) or `netflow` (one direction; no reply fact) event. */
export function readSuricataFlow(
  row: Row,
  etype: "flow" | "netflow",
  recordIndex: number,
): ConnObservation | "unplaced" | undefined {
  const block = getCI(row, etype);
  const src = address(getCI(row, "src_ip")),
    dst = address(getCI(row, "dest_ip"));
  if (!src || !dst) return undefined;
  // A flow with both ends but no `start` cannot be placed in time: counted, so the row never
  // says the upload had no connection records.
  const start = isObject(block) ? epochMs(getCI(block, "start")) : undefined;
  if (start === undefined) return "unplaced";
  const end = isObject(block) ? epochMs(getCI(block, "end")) : undefined;
  const flowId = text(getCI(row, "flow_id"))?.trim();
  return {
    source: etype === "flow" ? "suricata-flow" : "suricata-netflow",
    locator: `record:${recordIndex}`,
    sensor: sensorRef(row)?.name ?? "",
    start,
    ...(end !== undefined && end >= start ? { end } : {}),
    src,
    dst,
    reply: etype === "flow" && isObject(block) ? suricataReply(block) : "reply not in this record",
    ...(flowId ? { recordId: flowId } : {}),
  };
}
