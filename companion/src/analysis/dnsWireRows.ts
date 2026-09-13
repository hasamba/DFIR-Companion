// Sensor-side DNS rows: identity, bound, envelope, indicators (#996). One row per shape — every
// fact the words and the envelope show: the exchange's ends, the query, the response code, the
// returned values (every one, by digest), and per address what the upload's connection records
// establish (state, gap band, reply, window basis). TTL VALUES are not identity: a cached answer
// counts its TTL down on every re-query, and each would be its own row; the row carries the range
// across the folded observations as an aggregate, like its count. Locators (`uid`, `flow_id`,
// record indexes) are never keyed.
//
// Rows are Info with no technique — every web visit is exactly this shape. A row whose lead names
// an observed contact inside the window ranks first under the import's event budget (a stronger
// basis, not a higher grade), then rows answered with an address, then the rest.

import type { DnsBlock, DnsLead } from "./canonicalDns.js";
import { createCanonicalEvent, type CanonicalEventEnvelope } from "./canonicalEvent.js";
import { isIndicatorName } from "./dnsRecord.js";
import { DNS_WINDOW_SLACK_S, type DnsChain, type DnsObservations, type Lead } from "./dnsConnJoin.js";
import type { DnsObservation, DnsSource } from "./dnsWireRead.js";
import { dnsHead, dnsTags, outcomeState } from "./dnsWireWords.js";
import { identityMark, keyDigest, packTags } from "./recordIdentity.js";
import {
  foldOverflow,
  foldShape,
  newShapeSink,
  rankedRows,
  type ShapeRow,
  type ShapeSink,
} from "./shapeSink.js";
import { addIoc, mergeRowIocs, type MappedEvent, type SiemIoc } from "./siemImport.js";

/** Distinct row shapes one import keeps; every later new shape folds into an overflow row. */
export const DNS_SHAPES_MAX = 8192;
const DESCRIPTION_MAX = 600;
const RETURNED_ENVELOPE_MAX = 32;

export interface DnsTallyRow {
  chain: DnsChain;
  /** The TTL range across the folded observations' returned values; absent when none carried one. */
  ttl?: { min: number; max: number };
}

const OVERFLOW_KEY = (source: string): string => `dns|${source}|overflow`;

// ───────────────────────────── identity ─────────────────────────────

const leadFacts = (l: Lead): string =>
  [
    l.address,
    l.state,
    l.band ?? "-",
    l.reply ?? "-",
    l.window.basis,
    l.sharedWithOtherNames ? "shared" : "-",
  ].join(":");

export function dnsKey(c: DnsChain): string {
  const d = c.dns;
  return [
    "dns",
    d.source,
    d.observer ? `t:${keyDigest(d.observer.name)}` : "-",
    d.client ?? "-",
    d.server ?? "-",
    d.serverPort ?? "-",
    // A valid name keys on its wire form (one row per name, not per capitalisation); an invalid
    // string is its own exact identity — the #1009 rule.
    `q${keyDigest(d.queryValid ? d.queryAscii : d.query)}`,
    d.queryValid ? "v" : "x",
    `t${d.queryType ?? d.queryTypeName ?? "-"}`,
    `r${d.rejected ? "rejected" : (d.rcode ?? "-")}`,
    `${d.aa ? "aa" : "-"}${d.ra ? "ra" : "-"}`,
    `o${d.ownership === "stated in the record" ? "s" : "-"}`,
    `a${d.returnedIdentity}`,
    `n${d.returnedTotal}`,
    `j${c.joinState}`,
    `l${keyDigest(c.leads.map(leadFacts).sort().join("\n"))}`,
  ].join("|");
}

// ───────────────────────────── rank ─────────────────────────────

const rankOf = (c: DnsChain): number =>
  c.leads.some((l) => l.state === "connected inside the window") ? 2 : c.joinState === "joined" ? 1 : 0;

// ───────────────────────────── tally ─────────────────────────────

function ttlRange(d: DnsObservation): { min: number; max: number } | undefined {
  let range: { min: number; max: number } | undefined;
  for (const v of d.returned)
    if (v.ttl !== undefined)
      range = range
        ? { min: Math.min(range.min, v.ttl), max: Math.max(range.max, v.ttl) }
        : { min: v.ttl, max: v.ttl };
  return range;
}

/**
 * Fold every joined chain into row shapes, minting the query indicator against its row key so
 * the domain IOC's provenance names the row. Records past the retained bound join their source's
 * overflow row: counted, never read.
 */
export function tallyDnsChains(
  obs: DnsObservations,
  chains: DnsChain[],
  iocSink: Map<string, SiemIoc>,
): ShapeSink<DnsTallyRow> {
  const sink = newShapeSink<DnsTallyRow>(DNS_SHAPES_MAX, 3, OVERFLOW_KEY);
  for (const chain of chains) {
    const key = dnsKey(chain);
    const rowIocs = new Map<string, SiemIoc>();
    if (isIndicatorName(chain.dns.query)) addIoc(rowIocs, "domain", chain.dns.queryAscii);
    mergeRowIocs(iocSink, rowIocs, key);
    const ttl = ttlRange(chain.dns);
    const existing = sink.rows.get(key);
    foldShape(sink, {
      key,
      source: chain.dns.source,
      ts: chain.dns.timestamp,
      first: { chain, ...(ttl ? { ttl } : {}) },
      rank: rankOf(chain),
    });
    // The TTL range is an aggregate over the folded observations, widened on every fold.
    const row = sink.rows.get(key);
    if (existing && row?.first && ttl)
      row.first = {
        ...row.first,
        ttl: row.first.ttl
          ? { min: Math.min(row.first.ttl.min, ttl.min), max: Math.max(row.first.ttl.max, ttl.max) }
          : ttl,
      };
  }
  for (const [source, n] of obs.dnsOverflow) foldOverflow(sink, source, "", n);
  return sink;
}

// ───────────────────────────── envelope ─────────────────────────────

const leadBlock = (l: Lead): DnsLead => ({
  address: l.address,
  state: l.state,
  ...(l.band ? { band: l.band } : {}),
  ...(l.reply ? { reply: l.reply } : {}),
  window: { basis: l.window.basis, slackSeconds: DNS_WINDOW_SLACK_S },
  ...(l.sharedWithOtherNames ? { sharedWithOtherNames: true } : {}),
});

function dnsBlock(row: DnsTallyRow, count: number): DnsBlock {
  const { chain, ttl } = row;
  const d = chain.dns;
  return {
    query: d.queryAscii || d.query.slice(0, 253),
    queryValid: d.queryValid,
    indicator: isIndicatorName(d.query),
    ...(d.queryType !== undefined ? { queryType: d.queryType } : {}),
    state: outcomeState(d),
    returned: d.returned.slice(0, RETURNED_ENVELOPE_MAX).map((v) => ({
      ...(v.type !== undefined ? { type: v.type } : {}),
      value: v.value,
      kind: v.kind,
      ...(v.owner ? { owner: v.owner } : {}),
    })),
    ownership: d.ownership,
    vantage: "sensor",
    ...(d.client ? { client: d.client } : {}),
    ...(d.server ? { server: d.server } : {}),
    ...(d.rcode ? { rcode: d.rcode } : {}),
    flags: {
      ...(d.aa !== undefined ? { aa: d.aa } : {}),
      ...(d.ra !== undefined ? { ra: d.ra } : {}),
      ...(d.rejected !== undefined ? { rejected: d.rejected } : {}),
    },
    anchor: d.anchor,
    ...(ttl ? { ttl } : {}),
    returnedTotal: d.returnedTotal,
    joinState: chain.joinState,
    leads: chain.leads.map(leadBlock),
    records: count,
  };
}

function envelopeOf(t: ShapeRow<DnsTallyRow>): CanonicalEventEnvelope {
  const ts = t.firstTs;
  if (t.overflow || !t.first) {
    return createCanonicalEvent({
      event: { category: "network", type: "dns" },
      dns: {
        query: "",
        queryValid: false,
        indicator: false,
        state: "folded",
        returned: [],
        ownership: "not in this record",
        vantage: "sensor",
        folded: true,
        records: t.count,
      },
      time: { observed: ts, normalized: ts },
      evidence: { rawRecords: [{ source: t.source, locator: t.key }] },
      producer: { importer: "network", parserVersion: "1", mappingVersion: "dns-wire-v1" },
    });
  }
  const { chain } = t.first;
  const d = chain.dns;
  const rawRecords = [
    { source: d.source, locator: d.locator, ...(d.recordId ? { recordId: d.recordId } : {}) },
    ...chain.leads.flatMap((l) =>
      l.connection
        ? [
            {
              source: l.connection.source,
              locator: l.connection.locator,
              ...(l.connection.recordId ? { recordId: l.connection.recordId } : {}),
            },
          ]
        : [],
    ),
  ];
  const locatorMap: Record<string, string> = {};
  chain.leads.forEach((l, i) => {
    if (l.connection) locatorMap[`dns.leads.${i}`] = l.connection.locator;
  });
  const seen = new Set<string>();
  return createCanonicalEvent({
    event: {
      category: "network",
      type: "dns",
      ...(d.queryTypeName ? { action: d.queryTypeName.toLowerCase() } : {}),
      ...(d.rcode ? { outcome: d.rcode } : {}),
    },
    ...(d.client ? { actor: { kind: "network", address: d.client } } : {}),
    ...(d.server
      ? { target: { kind: "network", address: d.server, ...(d.serverPort ? { port: d.serverPort } : {}) } }
      : {}),
    network: {
      ...(d.client ? { source: { address: d.client } } : {}),
      ...(d.server
        ? { destination: { address: d.server, ...(d.serverPort ? { port: d.serverPort } : {}) } }
        : {}),
      protocol: "dns",
    },
    dns: dnsBlock(t.first, t.count),
    time: { observed: ts, normalized: ts },
    evidence: {
      rawRecords: rawRecords.filter((r) => (seen.has(r.locator) ? false : (seen.add(r.locator), true))),
    },
    producer: { importer: "network", parserVersion: "1", mappingVersion: "dns-wire-v1" },
    rawFieldMap: {
      "dns.query": [d.source === "zeek-dns" ? "query" : "dns.rrname"],
      "time.observed": [d.source === "zeek-dns" ? "ts" : "timestamp"],
    },
    locatorMap,
  });
}

// ───────────────────────────── rows ─────────────────────────────

const sourcesOf = (source: DnsSource | string): string[] => [source.startsWith("zeek") ? "Zeek" : "Suricata"];

function mapRow(t: ShapeRow<DnsTallyRow>): MappedEvent {
  const mark = identityMark(t.key);
  const n = t.count;
  const tail = ` — ${n} record${n === 1 ? "" : "s"}`;
  if (t.overflow || !t.first)
    return {
      timestamp: t.firstTs,
      description: `[overflow: ${n} DNS record${n === 1 ? "" : "s"} beyond the retained bounds folded; none shown]${mark}`,
      severity: "Info",
      mitre: [],
      canonical: envelopeOf(t),
      aggKey: t.key,
      sources: sourcesOf(t.source),
      origin: "wire",
    };
  const { chain, ttl } = t.first;
  const d = chain.dns;
  const head = dnsHead(d);
  const room = DESCRIPTION_MAX - mark.length - head.length - tail.length;
  return {
    timestamp: t.firstTs,
    description: `${head}${packTags(dnsTags(chain, ttl), Math.max(0, room))}${tail}${mark}`,
    severity: "Info",
    mitre: [],
    canonical: envelopeOf(t),
    aggKey: t.key,
    sources: sourcesOf(d.source),
    origin: "wire",
    ...(d.client ? { srcIp: d.client } : {}),
    ...(d.server ? { dstIp: d.server } : {}),
    ...(d.serverPort ? { port: d.serverPort } : {}),
  };
}

/** Rows with an in-window contact first, then answered rows, then the most seen — up to `budget`. */
export function mapDnsRows(sink: ShapeSink<DnsTallyRow>, budget: number): MappedEvent[] {
  return rankedRows(sink, budget).map(mapRow);
}
