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
// computes a "first connection"); each pair's list is sorted once, so a lookup is a binary search.

import type { DnsGapBand, DnsLeadState, DnsReply } from "./canonicalDns.js";
import type { ConnObservation, DnsObservation, DnsSource } from "./dnsWireRead.js";

/** DNS observations retained per upload; records past it are counted per source, never read. */
export const DNS_OBSERVATIONS_MAX = 65_536;
/** Connection records indexed per upload; past it no lead is computed at all. */
export const CONN_INDEX_MAX = 1_048_576;
/** Seconds added to every window for the client's resolve-to-connect latency. */
export const DNS_WINDOW_SLACK_S = 1;
/** The window when the record carries no TTL — worded as fixed, never as a TTL. */
export const DNS_FIXED_WINDOW_S = 300;
/** Other-name answers scanned per lead when checking whether the address was shared. */
const SHARED_SCAN_MAX = 64;

export type JoinState =
  | "joined"
  | "no connection records in this upload"
  | "answered with no address"
  | "connection records exceed the index";

export interface Lead {
  address: string;
  state: DnsLeadState;
  band?: DnsGapBand;
  reply?: DnsReply;
  window: { basis: "ttl" | "fixed"; seconds: number };
  sharedWithOtherNames?: boolean;
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
  dnsOverflow: Map<DnsSource, number>;
  conns: ConnObservation[];
  connOverflow: number;
}

export function emptyDnsObservations(): DnsObservations {
  return { dns: [], dnsOverflow: new Map(), conns: [], connOverflow: 0 };
}

export function addDns(sink: DnsObservations, o: DnsObservation): void {
  if (sink.dns.length >= DNS_OBSERVATIONS_MAX)
    sink.dnsOverflow.set(o.source, (sink.dnsOverflow.get(o.source) ?? 0) + 1);
  else sink.dns.push(o);
}

export function addConn(sink: DnsObservations, o: ConnObservation): void {
  if (sink.conns.length >= CONN_INDEX_MAX) sink.connOverflow += 1;
  else sink.conns.push(o);
}

// ───────────────────────────── time ─────────────────────────────

const S = 1000;

export function gapBand(gapMs: number): DnsGapBand {
  if (gapMs <= 1 * S) return "≤1 s";
  if (gapMs <= 10 * S) return "≤10 s";
  if (gapMs <= 60 * S) return "≤60 s";
  if (gapMs <= 600 * S) return "≤10 min";
  if (gapMs <= 3600 * S) return "≤1 h";
  if (gapMs <= 86_400 * S) return "≤24 h";
  return ">24 h";
}

/** When the answer arrived: the record's time, plus the round trip when the time is the query's. */
export const arrivalOf = (dns: DnsObservation): number =>
  dns.anchor === "query" ? dns.ts + Math.round((dns.rtt ?? 0) * S) : dns.ts;

function windowOf(ttl: number | undefined): Lead["window"] {
  return ttl === undefined ? { basis: "fixed", seconds: DNS_FIXED_WINDOW_S } : { basis: "ttl", seconds: ttl };
}

// ───────────────────────────── indexes ─────────────────────────────

interface PairList {
  conns: ConnObservation[];
  /** prefixMaxEnd[i] = the latest `end` among conns[0..i] — "was any earlier flow still open". */
  prefixMaxEnd: number[];
}

interface Answered {
  arrival: number;
  queryAscii: string;
}

interface Indexes {
  /** sensor|client|dst → that pair's connections, sorted by start. */
  pairs: Map<string, PairList>;
  /** sensor|dst → every start to that address, any client, sorted. */
  byDst: Map<string, number[]>;
  /** sensor|address → addresses observed as a queried server (a client that is one forwards). */
  servers: Set<string>;
  /** sensor|client|address → the answers that returned it, sorted by arrival. */
  answers: Map<string, Answered[]>;
}

const sensorOfDns = (d: DnsObservation): string => d.observer?.name ?? "";
const pairKey = (sensor: string, client: string, dst: string): string => `${sensor}|${client}|${dst}`;

function buildIndexes(obs: DnsObservations): Indexes {
  const pairs = new Map<string, ConnObservation[]>();
  const byDst = new Map<string, number[]>();
  for (const c of obs.conns) {
    const pk = pairKey(c.sensor, c.src, c.dst);
    (pairs.get(pk) ?? pairs.set(pk, []).get(pk)!).push(c);
    const dk = `${c.sensor}|${c.dst}`;
    (byDst.get(dk) ?? byDst.set(dk, []).get(dk)!).push(c.start);
  }
  const sorted = new Map<string, PairList>();
  for (const [k, list] of pairs) sorted.set(k, pairList(list.sort((a, b) => a.start - b.start)));
  for (const list of byDst.values()) list.sort((a, b) => a - b);
  const servers = new Set<string>();
  const answers = new Map<string, Answered[]>();
  for (const d of obs.dns) {
    const sensor = sensorOfDns(d);
    if (d.server) servers.add(`${sensor}|${d.server}`);
    if (!d.client) continue;
    const arrival = arrivalOf(d);
    for (const address of addressesOf(d)) {
      const k = pairKey(sensor, d.client, address);
      (answers.get(k) ?? answers.set(k, []).get(k)!).push({ arrival, queryAscii: d.queryAscii });
    }
  }
  for (const list of answers.values()) list.sort((a, b) => a.arrival - b.arrival);
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

// First index whose start is >= t.
function lowerBound(list: readonly { start: number }[] | readonly number[], t: number): number {
  let lo = 0,
    hi = list.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    const v = list[mid];
    if ((typeof v === "number" ? v : v.start) < t) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

function pairList(conns: ConnObservation[]): PairList {
  const prefixMaxEnd: number[] = [];
  let max = -Infinity;
  for (const c of conns) {
    max = Math.max(max, c.end ?? c.start);
    prefixMaxEnd.push(max);
  }
  return { conns, prefixMaxEnd };
}

// The DNS exchange's own connection (a shared `uid` / `flow_id`) is never the lead. It can only
// sit in this pair when a returned address is the server asked, so the rebuild is rare.
function withoutOwn(pair: PairList | undefined, own: string | undefined): PairList {
  if (!pair) return { conns: [], prefixMaxEnd: [] };
  if (!own || !pair.conns.some((c) => c.recordId === own)) return pair;
  return pairList(pair.conns.filter((c) => c.recordId !== own));
}

// ───────────────────────────── one lead ─────────────────────────────

function leadOf(d: DnsObservation, address: string, ix: Indexes): Lead {
  const sensor = sensorOfDns(d);
  const client = d.client!;
  const arrival = arrivalOf(d);
  const window = windowOf(ttlFor(d, address));
  const windowEnd = arrival + (window.seconds + DNS_WINDOW_SLACK_S) * S;
  const base = { address, window };
  const shared = sharedWithOtherNames(d, address, arrival, windowEnd, ix);
  const { conns, prefixMaxEnd } = withoutOwn(ix.pairs.get(pairKey(sensor, client, address)), d.recordId);

  const i = lowerBound(conns, arrival);
  // Before the answer: a flow that began between the query and the arrival did not wait for this
  // answer; one that began earlier and was still open at the arrival did not need it.
  if (i > 0 && conns[i - 1].start >= d.ts && d.anchor === "query")
    return {
      ...base,
      ...shared,
      state: "began before this answer arrived",
      reply: conns[i - 1].reply,
      connection: conns[i - 1],
    };
  if (i > 0 && prefixMaxEnd[i - 1] >= arrival) {
    // The open flow is the latest-ending one before the arrival; find it for the locator.
    let open = conns[i - 1];
    for (let j = i - 1; j >= 0 && j >= i - SHARED_SCAN_MAX; j--)
      if ((conns[j].end ?? conns[j].start) >= arrival) {
        open = conns[j];
        break;
      }
    return {
      ...base,
      ...shared,
      state: "open at the time of this answer",
      reply: open.reply,
      connection: open,
    };
  }
  if (i < conns.length) {
    const c = conns[i];
    const gap = c.start - arrival;
    const state: DnsLeadState =
      c.start <= windowEnd ? "connected inside the window" : "first connection after the window";
    return { ...base, ...shared, state, band: gapBand(gap), reply: c.reply, connection: c };
  }
  if (conns.length) return { ...base, ...shared, state: "earlier connections only" };
  if (ix.servers.has(`${sensor}|${client}`)) {
    const starts = ix.byDst.get(`${sensor}|${address}`) ?? [];
    const j = lowerBound(starts, arrival);
    if (j < starts.length && starts[j] <= windowEnd)
      return { ...base, ...shared, state: "other clients connected inside the window" };
  }
  return { ...base, ...shared, state: "no connection in this upload" };
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
  const list = ix.answers.get(pairKey(sensorOfDns(d), d.client!, address)) ?? [];
  const from = lowerBound(
    list.map((a) => ({ start: a.arrival })),
    arrival,
  );
  for (let k = from; k < list.length && k < from + SHARED_SCAN_MAX; k++) {
    if (list[k].arrival > windowEnd) break;
    if (list[k].queryAscii !== d.queryAscii) return { sharedWithOtherNames: true };
  }
  return {};
}

/** Every lead the upload establishes, for every retained DNS observation. */
export function joinDnsLeads(obs: DnsObservations): DnsChain[] {
  const ix = buildIndexes(obs);
  const exceeded = obs.connOverflow > 0;
  const none = obs.conns.length === 0 && !exceeded;
  return obs.dns.map((dns) => {
    const addresses = dns.client ? addressesOf(dns) : [];
    if (!addresses.length) return { dns, joinState: "answered with no address", leads: [] };
    if (exceeded) return { dns, joinState: "connection records exceed the index", leads: [] };
    if (none) return { dns, joinState: "no connection records in this upload", leads: [] };
    return { dns, joinState: "joined", leads: addresses.map((a) => leadOf(dns, a, ix)) };
  });
}
