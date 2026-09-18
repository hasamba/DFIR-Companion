// The join inside one upload: a DNS answer against the connection records the SAME sensor saw
// from the SAME client to a returned address (#996). Nothing else joins — not a name, not a
// resolver's guess about who asked, not another upload's clock.
//
// The window is the answer's own TTL, opened when the answer ARRIVED (a Zeek `ts` is the query;
// its `rtt` moves the arrival later) and closed TTL + DNS_WINDOW_SLACK_S later. A record with no
// TTL gets a fixed window, worded as fixed. The window bounds candidates; it confirms nothing —
// TTL is cache guidance, a client may hold an answer past it, and the same address may have been
// returned for another name. Every lead state names what the records establish and no more:
// order and address, never cause.
//
// Bounds: DNS observations past DNS_OBSERVATIONS_MAX are counted per source and never read;
// connection records past CONN_INDEX_MAX disable the join for every lead (no partial index ever
// computes a "first connection"); each pair's list is sorted once, every lookup is a binary
// search or a prefix read, and nothing scans a pair's list per lead.

import { DNS_FIXED_WINDOW_S, DNS_WINDOW_SLACK_S, gapBand } from "./canonicalDns.js";
import type { DnsGapBand, DnsLeadState, DnsReply } from "./canonicalDns.js";
import type { ConnObservation, DnsObservation, DnsSource, SuricataQueryCandidate } from "./dnsWireRead.js";

// Re-exported unchanged for this file's own existing importers (siemDnsConnJoin.ts,
// dnsWireWords.ts, dnsWireRows.ts, quarantineJoin.ts) — the real definitions moved to
// canonicalDns.ts (#996) so analysis/timeline's cross-upload join can reach them without
// importing analysis/ingest. See canonicalDns.ts's own comment there for why.
export { DNS_FIXED_WINDOW_S, DNS_WINDOW_SLACK_S, gapBand };

/** DNS observations retained per upload; records past it are counted per source, never read. */
export const DNS_OBSERVATIONS_MAX = 65_536;
/** Connection records indexed per upload; past it no lead is computed at all. */
export const CONN_INDEX_MAX = 1_048_576;
/** Other-name answers scanned per lead when checking whether the address was shared. */
const SHARED_SCAN_MAX = 64;

export type JoinState =
  | "joined"
  | "no connection records in this upload"
  | "answered with no address"
  | "client not joinable"
  | "connection records exceed the index"
  | "connection records not placeable";

/** A fact the records also establish beside the in-window lead: the client did not wait for it. */
export type AlsoBefore = "began before this answer arrived" | "open at the time of this answer";

export interface Lead {
  address: string;
  state: DnsLeadState;
  band?: DnsGapBand;
  reply?: DnsReply;
  window: { basis: "ttl" | "fixed"; seconds: number };
  sharedWithOtherNames?: boolean;
  /** With an in-window / after-window state: an earlier record also began before, or was open at, the arrival. */
  alsoBefore?: AlsoBefore;
  /** The connection record the state names, when one does. */
  connection?: ConnObservation;
}

export interface DnsChain {
  dns: DnsObservation;
  joinState: JoinState;
  leads: Lead[];
}

export interface DnsObservations {
  dns: DnsObservation[];
  dnsOverflow: Map<DnsSource, { count: number; firstTs: string }>;
  conns: ConnObservation[];
  connOverflow: number;
  /** Connection records with both ends but no start time — never placed, never "absent". */
  connUnplaced: number;
  /** Suricata query-type events, held only to pair against a v1 answer's missing question (#996). */
  suricataQueries: SuricataQueryCandidate[];
}

export function emptyDnsObservations(): DnsObservations {
  return {
    dns: [],
    dnsOverflow: new Map(),
    conns: [],
    connOverflow: 0,
    connUnplaced: 0,
    suricataQueries: [],
  };
}

export function addDns(sink: DnsObservations, o: DnsObservation): void {
  if (sink.dns.length < DNS_OBSERVATIONS_MAX) {
    sink.dns.push(o);
    return;
  }
  const over = sink.dnsOverflow.get(o.source);
  if (over) {
    over.count += 1;
    if (o.timestamp && (!over.firstTs || o.timestamp < over.firstTs)) over.firstTs = o.timestamp;
  } else sink.dnsOverflow.set(o.source, { count: 1, firstTs: o.timestamp });
}

export function addConn(sink: DnsObservations, o: ConnObservation | "unplaced"): void {
  if (o === "unplaced") sink.connUnplaced += 1;
  else if (sink.conns.length >= CONN_INDEX_MAX) sink.connOverflow += 1;
  else sink.conns.push(o);
}

/** Bounded like addDns above (#996) — a query-only-heavy upload must not grow this without limit. */
export function addSuricataQuery(sink: DnsObservations, c: SuricataQueryCandidate): void {
  if (sink.suricataQueries.length < DNS_OBSERVATIONS_MAX) sink.suricataQueries.push(c);
}

// ───────────────────────────── time ─────────────────────────────

const S = 1000;

/** When the answer arrived: the record's time, plus the round trip when the time is the query's. */
export const arrivalOf = (dns: DnsObservation): number =>
  dns.anchor === "query" ? dns.ts + Math.round((dns.rtt ?? 0) * S) : dns.ts;

function windowOf(ttl: number | undefined): Lead["window"] {
  return ttl === undefined ? { basis: "fixed", seconds: DNS_FIXED_WINDOW_S } : { basis: "ttl", seconds: ttl };
}

// ───────────────────────────── indexes ─────────────────────────────

interface PairList {
  conns: ConnObservation[];
  /** prefixMaxEnd[i] = the latest `end` among conns[0..i], and which record carries it. */
  prefixMaxEnd: number[];
  prefixMaxEndIdx: number[];
}

interface AnswerList {
  arrivals: number[];
  queries: string[];
}

interface Indexes {
  /** sensor|client|dst → that pair's connections, sorted by start. */
  pairs: Map<string, PairList>;
  /** sensor|dst → every connection to that address, any client, sorted by start. */
  byDst: Map<string, ConnObservation[]>;
  /** sensor|address → addresses observed as a queried server (a client that is one forwards). */
  servers: Set<string>;
  /** sensor|client|address → the answers that returned it, sorted by arrival. */
  answers: Map<string, AnswerList>;
}

const sensorOfDns = (d: DnsObservation): string => d.observer?.name ?? "";
const pairKey = (sensor: string, client: string, dst: string): string => `${sensor}|${client}|${dst}`;

function pairList(conns: ConnObservation[]): PairList {
  const prefixMaxEnd: number[] = [];
  const prefixMaxEndIdx: number[] = [];
  let max = -Infinity,
    at = -1;
  conns.forEach((c, i) => {
    const end = c.end ?? c.start;
    if (end > max) {
      max = end;
      at = i;
    }
    prefixMaxEnd.push(max);
    prefixMaxEndIdx.push(at);
  });
  return { conns, prefixMaxEnd, prefixMaxEndIdx };
}

function buildIndexes(obs: DnsObservations): Indexes {
  const pairs = new Map<string, ConnObservation[]>();
  const byDst = new Map<string, ConnObservation[]>();
  for (const c of obs.conns) {
    const pk = pairKey(c.sensor, c.src, c.dst);
    (pairs.get(pk) ?? pairs.set(pk, []).get(pk)!).push(c);
    const dk = `${c.sensor}|${c.dst}`;
    (byDst.get(dk) ?? byDst.set(dk, []).get(dk)!).push(c);
  }
  const sorted = new Map<string, PairList>();
  for (const [k, list] of pairs) sorted.set(k, pairList(list.sort((a, b) => a.start - b.start)));
  for (const list of byDst.values()) list.sort((a, b) => a.start - b.start);
  const servers = new Set<string>();
  const raw = new Map<string, { arrival: number; query: string }[]>();
  for (const d of obs.dns) {
    const sensor = sensorOfDns(d);
    if (d.server) servers.add(`${sensor}|${d.server}`);
    if (!d.client) continue;
    const arrival = arrivalOf(d);
    for (const address of addressesOf(d)) {
      const k = pairKey(sensor, d.client, address);
      (raw.get(k) ?? raw.set(k, []).get(k)!).push({ arrival, query: d.queryAscii });
    }
  }
  const answers = new Map<string, AnswerList>();
  for (const [k, list] of raw) {
    list.sort((a, b) => a.arrival - b.arrival);
    answers.set(k, { arrivals: list.map((a) => a.arrival), queries: list.map((a) => a.query) });
  }
  return { pairs: sorted, byDst, servers, answers };
}

/** The distinct addresses a record returned, in record order. */
export function addressesOf(d: DnsObservation): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const v of d.returned)
    if (v.kind === "address" && !seen.has(v.value)) {
      seen.add(v.value);
      out.push(v.value);
    }
  return out;
}

/** The smallest TTL among the values carrying this address; undefined when none carries one. */
function ttlFor(d: DnsObservation, address: string): number | undefined {
  let ttl: number | undefined;
  for (const v of d.returned)
    if (v.kind === "address" && v.value === address && v.ttl !== undefined)
      ttl = ttl === undefined ? v.ttl : Math.min(ttl, v.ttl);
  return ttl;
}

// First index whose key is >= t, over a sorted list read through `key`.
function lowerBound<T>(list: readonly T[], t: number, key: (x: T) => number): number {
  let lo = 0,
    hi = list.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (key(list[mid]) < t) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}
const startOf = (c: ConnObservation): number => c.start;
const self = (n: number): number => n;

// The DNS exchange's own connection (a shared `uid` / `flow_id`) is never the lead. It can only
// sit in this pair when a returned address is the server asked, so the rebuild is rare and the
// per-lead cost is otherwise nothing.
function withoutOwn(pair: PairList | undefined, d: DnsObservation, address: string): PairList {
  if (!pair) return { conns: [], prefixMaxEnd: [], prefixMaxEndIdx: [] };
  const own = d.recordId;
  if (!own || address !== d.server) return pair;
  return pair.conns.some((c) => c.recordId === own)
    ? pairList(pair.conns.filter((c) => c.recordId !== own))
    : pair;
}

// ───────────────────────────── one lead ─────────────────────────────

function leadOf(d: DnsObservation, address: string, ix: Indexes): Lead {
  const sensor = sensorOfDns(d);
  const client = d.client!;
  const arrival = arrivalOf(d);
  const window = windowOf(ttlFor(d, address));
  const windowEnd = arrival + (window.seconds + DNS_WINDOW_SLACK_S) * S;
  const base = { address, window, ...sharedWithOtherNames(d, address, arrival, windowEnd, ix) };
  const { conns, prefixMaxEnd, prefixMaxEndIdx } = withoutOwn(
    ix.pairs.get(pairKey(sensor, client, address)),
    d,
    address,
  );

  const i = lowerBound(conns, arrival, startOf);
  // Before the answer: a flow that began between the query and the arrival did not wait for this
  // answer; one that began earlier and was still open at the arrival did not need it. Either is
  // said beside an in-window lead, never instead of it.
  const before: { alsoBefore: AlsoBefore; connection: ConnObservation } | undefined =
    i > 0 && d.anchor === "query" && conns[i - 1].start >= d.ts
      ? { alsoBefore: "began before this answer arrived", connection: conns[i - 1] }
      : i > 0 && prefixMaxEnd[i - 1] >= arrival
        ? { alsoBefore: "open at the time of this answer", connection: conns[prefixMaxEndIdx[i - 1]] }
        : undefined;
  if (i < conns.length) {
    const c = conns[i];
    const state: DnsLeadState =
      c.start <= windowEnd ? "connected inside the window" : "first connection after the window";
    return {
      ...base,
      state,
      band: gapBand(c.start - arrival),
      reply: c.reply,
      connection: c,
      ...(before ? { alsoBefore: before.alsoBefore } : {}),
    };
  }
  if (before)
    return {
      ...base,
      state: before.alsoBefore,
      reply: before.connection.reply,
      connection: before.connection,
    };
  if (conns.length) return { ...base, state: "earlier connections only" };
  if (ix.servers.has(`${sensor}|${client}`)) {
    const all = ix.byDst.get(`${sensor}|${address}`) ?? [];
    const j = lowerBound(all, arrival, startOf);
    // The exchange's own record is never "another client's connection".
    for (let k = j; k < all.length && all[k].start <= windowEnd && k < j + SHARED_SCAN_MAX; k++)
      if (all[k].recordId !== d.recordId)
        return { ...base, state: "other clients connected inside the window" };
  }
  return { ...base, state: "no connection in this upload" };
}

// Another name's answer to the same client carried this address with its arrival inside this
// lead's window (a bounded scan); the mirror case is caught on the other row.
function sharedWithOtherNames(
  d: DnsObservation,
  address: string,
  arrival: number,
  windowEnd: number,
  ix: Indexes,
): { sharedWithOtherNames?: boolean } {
  const list = ix.answers.get(pairKey(sensorOfDns(d), d.client!, address));
  if (!list) return {};
  const from = lowerBound(list.arrivals, arrival, self);
  for (let k = from; k < list.arrivals.length && k < from + SHARED_SCAN_MAX; k++) {
    if (list.arrivals[k] > windowEnd) break;
    if (list.queries[k] !== d.queryAscii) return { sharedWithOtherNames: true };
  }
  return {};
}

/** Every lead the upload establishes, for every retained DNS observation. */
export function joinDnsLeads(obs: DnsObservations): DnsChain[] {
  const ix = buildIndexes(obs);
  const exceeded = obs.connOverflow > 0;
  const none = obs.conns.length === 0;
  return obs.dns.map((dns) => {
    const addresses = addressesOf(dns);
    if (!addresses.length) return { dns, joinState: "answered with no address", leads: [] };
    if (!dns.client) return { dns, joinState: "client not joinable", leads: [] };
    if (exceeded) return { dns, joinState: "connection records exceed the index", leads: [] };
    if (none)
      return {
        dns,
        joinState: obs.connUnplaced
          ? "connection records not placeable"
          : "no connection records in this upload",
        leads: [],
      };
    return { dns, joinState: "joined", leads: addresses.map((a) => leadOf(dns, a, ix)) };
  });
}
