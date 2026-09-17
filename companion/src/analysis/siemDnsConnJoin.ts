// The Windows half of #996's within-upload join: Sysmon 22 / DNS-Client 3006/3008/3020 returned
// addresses against Sysmon 3 ("Network connection detected") records from the SAME host, in the
// SAME upload. Reuses dnsConnJoin.ts's JoinState/Lead types and dnsWireWords.ts's lead/join
// wording verbatim (canonicalDns.ts's header: "Two vantages share it") — this file only adds the
// host-keyed candidate collection and matching, the part genuinely new for the endpoint vantage.
//
// Windows DNS records carry no client IP (dnsRecord.ts: "the vantage is the endpoint's own stub
// resolver") and no TTL, so the join key here is the log's own asserted host identity
// (siemImport.ts's pickHost/Computer), and every window is fixed (DNS_FIXED_WINDOW_S), never TTL.
// A Sysmon 3 record is a single instant, not a start/end range, so this file only ever emits the
// subset of JoinState/Lead a point observation can support: never "began before this answer
// arrived", "open at the time of this answer", "other clients connected inside the window", or
// "connection records not placeable" (Sysmon 3 always carries UtcTime).
//
// Disclosed limitation: a candidate is any Sysmon 3 "network" row with a destination address —
// Sysmon 3's own `Initiated` field (true = this host originated the connection, false = it merely
// received one) is NOT read here, so an inbound connection whose peer's address happens to equal
// a returned DNS address would also show as "connected". Accepted for this pass: siemImport.ts
// and canonicalEvent.ts are both already at their file-size ledger's ceiling (#384/#385), and the
// row's own wording never claims causation regardless — "order and address, never cause" holds
// either way. A follow-up can thread `Initiated` through once either file has room again.

import {
  CONN_INDEX_MAX,
  DNS_FIXED_WINDOW_S,
  DNS_OBSERVATIONS_MAX,
  DNS_WINDOW_SLACK_S,
  gapBand,
} from "./dnsConnJoin.js";
import type { JoinState, Lead } from "./dnsConnJoin.js";
import { DESCRIPTION_MAX, rewriteAggKeySink } from "./dnsRecord.js";
import { leadBlock } from "./dnsWireRows.js";
import { joinTag, leadTag, windowTag } from "./dnsWireWords.js";
import { identityMark, packTags } from "./recordIdentity.js";

const S = 1000;
const WINDOW_MS = (DNS_FIXED_WINDOW_S + DNS_WINDOW_SLACK_S) * S;
/** DNS transactions run over port 53; a connection this close to the query is that exchange itself. */
const OWN_EXCHANGE_PORT = 53;

export interface SiemDnsCandidate {
  /** Index into buildSiemResult's `mapped` array — the row this candidate's join result rewrites. */
  mappedIndex: number;
  host: string;
  ts: number;
  addresses: string[];
}

export interface SiemConnCandidate {
  host: string;
  ts: number;
  destinationIp: string;
  destinationPort?: number;
}

export interface DnsConnSink {
  dns: SiemDnsCandidate[];
  conns: SiemConnCandidate[];
}

/** The already-mapped row's own fields carry everything a join candidate needs — see #0 in the plan. */
export interface DnsConnMappedRow {
  timestamp: string;
  canonical?: {
    dns?: { returned?: { kind: string; value: string }[] };
    target?: { kind: string; name?: string };
    network?: { destination?: { address?: string; port?: number } };
  };
}

function collectWindowsDnsConnCandidate(sink: DnsConnSink, mappedIndex: number, row: DnsConnMappedRow): void {
  const ts = Date.parse(row.timestamp);
  const host = row.canonical?.target?.kind === "host" ? row.canonical.target.name : undefined;
  if (!Number.isFinite(ts) || !host) return;
  const returned = row.canonical?.dns?.returned;
  if (returned) {
    const seen = new Set<string>();
    sink.dns.push({
      mappedIndex,
      host,
      ts,
      addresses: returned
        .filter((v) => v.kind === "address")
        .map((v) => v.value)
        .filter((a) => (seen.has(a) ? false : (seen.add(a), true))),
    });
  }
  const dst = row.canonical?.network?.destination;
  if (dst?.address)
    sink.conns.push({
      host,
      ts,
      destinationIp: dst.address,
      ...(dst.port ? { destinationPort: dst.port } : {}),
    });
}

/**
 * IPv6 keyed case- and zero-compression-insensitively (one record may render an address expanded,
 * another compressed) so both still land on the same index key. IPv4 needs no normalization here —
 * siemImport.ts's `cleanIp` already normalizes it before either candidate is built.
 */
export function normalizeAddress(address: string): string {
  if (!address.includes(":")) return address;
  const lower = address.toLowerCase();
  const [headPart, tailPart] = lower.includes("::") ? lower.split("::") : [lower, undefined];
  const head = headPart ? headPart.split(":") : [];
  const tail = tailPart !== undefined ? tailPart.split(":").filter(Boolean) : [];
  const missing = tailPart !== undefined ? Math.max(8 - head.length - tail.length, 0) : 0;
  const hextets = tailPart !== undefined ? [...head, ...Array(missing).fill("0"), ...tail] : head;
  return hextets.map((h) => h.replace(/^0+(?=.)/, "") || "0").join(":");
}

const indexKey = (host: string, address: string): string => `${host}|${normalizeAddress(address)}`;

function leadFor(d: SiemDnsCandidate, address: string, conns: readonly SiemConnCandidate[]): Lead {
  const window = { basis: "fixed" as const, seconds: DNS_FIXED_WINDOW_S };
  const usable = conns
    .filter(
      (c) => !(c.destinationPort === OWN_EXCHANGE_PORT && Math.abs(c.ts - d.ts) <= DNS_WINDOW_SLACK_S * S),
    )
    .slice()
    .sort((a, b) => a.ts - b.ts);
  const after = usable.find((c) => c.ts >= d.ts);
  if (after) {
    const gapMs = after.ts - d.ts;
    const state: Lead["state"] =
      gapMs <= WINDOW_MS ? "connected inside the window" : "first connection after the window";
    return { address, state, band: gapBand(gapMs), window };
  }
  if (usable.some((c) => c.ts < d.ts)) return { address, state: "earlier connections only", window };
  return { address, state: "no connection in this upload", window };
}

/** Every lead the upload establishes for the Windows DNS candidates, keyed by their mappedIndex. */
export function joinWindowsDnsConn(
  dnsCandidates: readonly SiemDnsCandidate[],
  connCandidates: readonly SiemConnCandidate[],
): Map<number, { joinState: JoinState; leads: Lead[] }> {
  const result = new Map<number, { joinState: JoinState; leads: Lead[] }>();
  // Candidates past the bound get no join annotation at all — the row keeps its plain,
  // already-rendered DNS overlay text, same as the Zeek path silently drops overflowed DNS
  // observations from its own join rather than emitting a partial result for them.
  const dns = dnsCandidates.slice(0, DNS_OBSERVATIONS_MAX);
  const exceeded = connCandidates.length > CONN_INDEX_MAX;

  const byHostAddress = new Map<string, SiemConnCandidate[]>();
  const hostsWithConns = new Set<string>();
  if (!exceeded)
    for (const c of connCandidates) {
      hostsWithConns.add(c.host);
      const k = indexKey(c.host, c.destinationIp);
      (byHostAddress.get(k) ?? byHostAddress.set(k, []).get(k)!).push(c);
    }

  for (const d of dns) {
    if (!d.host) {
      result.set(d.mappedIndex, { joinState: "client not joinable", leads: [] });
      continue;
    }
    if (!d.addresses.length) {
      result.set(d.mappedIndex, { joinState: "answered with no address", leads: [] });
      continue;
    }
    if (exceeded) {
      result.set(d.mappedIndex, { joinState: "connection records exceed the index", leads: [] });
      continue;
    }
    if (!hostsWithConns.has(d.host)) {
      result.set(d.mappedIndex, { joinState: "no connection records in this upload", leads: [] });
      continue;
    }
    const leads = d.addresses.map((a) => leadFor(d, a, byHostAddress.get(indexKey(d.host, a)) ?? []));
    result.set(d.mappedIndex, { joinState: "joined", leads });
  }
  return result;
}

const MARK_TAG = / #[A-Za-z0-9_-]{22}$/;

/**
 * Runs the join and mutates the already-mapped rows in place: appends the reused lead/join
 * wording (dnsWireWords.ts) to `description`, folds the outcome into `aggKey` (so two occurrences
 * of an identical query with DIFFERENT connection follow-ups split into separate aggregated rows
 * instead of one row claiming a single outcome — the "un-aggregated observations" requirement:
 * the join itself already ran per individual record, before this folds the RESULT into the key
 * `aggregateEvents` groups by), and sets `canonical.dns.joinState`/`.leads` — the same fields
 * `dnsBlockSchema` already accepts for the sensor vantage (canonicalDns.ts, "Two vantages share
 * it"). Called AFTER `boundDnsVariants` (its own `aggKey` suffix regex must see the row
 * untouched) and BEFORE `aggregateEvents`. A row `boundDnsVariants` already folded
 * (`canonical.dns.folded`) is skipped — its original returned addresses are no longer knowable.
 */
interface JoinableRow {
  aggKey: string;
  description: string;
  canonical?: {
    dns?: Record<string, unknown>;
    evidence?: { rawRecords?: { locator?: string }[] };
    fieldProvenance?: Record<string, unknown>;
  };
}

const JOIN_DERIVATION = "siemDnsConnJoin.ts: Sysmon 22/DNS-Client to Sysmon 3 join within one upload (#996)";

function applyWindowsDnsConnJoin(
  mapped: JoinableRow[],
  dnsCandidates: readonly SiemDnsCandidate[],
  connCandidates: readonly SiemConnCandidate[],
  sink: Map<string, { sourceAggKeys?: string[] }>,
): void {
  if (!dnsCandidates.length) return;
  const results = joinWindowsDnsConn(dnsCandidates, connCandidates);
  const rewritten = new Map<string, string>();
  for (const d of dnsCandidates) {
    const outcome = results.get(d.mappedIndex);
    const row = mapped[d.mappedIndex];
    if (!outcome || !row?.canonical?.dns || row.canonical.dns.folded) continue;
    const locator = row.canonical.evidence?.rawRecords?.[0]?.locator;
    if (!locator) continue; // createCanonicalEvent guarantees this on every row it built; defensive only
    const { joinState, leads } = outcome;
    const chainLike = { joinState, leads };
    const inWindow = leads
      .filter((l) => l.state === "connected inside the window")
      .map((l) => leadTag(l, d.host));
    const rest = leads
      .filter((l) => l.state !== "connected inside the window")
      .map((l) => leadTag(l, d.host));
    const tags = [...inWindow, ...rest, windowTag(chainLike, undefined), joinTag(chainLike)].filter(
      (t): t is string => Boolean(t),
    );
    if (!tags.length) continue;
    const oldAggKey = row.aggKey;
    const outcomeDigest = leads.length ? `:${leads.map((l) => `${l.address}=${l.state}`).join(",")}` : "";
    const newAggKey = `${oldAggKey}|conn:${joinState}${outcomeDigest}`;
    row.aggKey = newAggKey;
    rewritten.set(oldAggKey, newAggKey);
    const bare = row.description.replace(MARK_TAG, "");
    const mark = identityMark(newAggKey);
    row.description = `${bare}${packTags(tags, DESCRIPTION_MAX - bare.length - mark.length)}${mark}`;
    row.canonical.dns = { ...row.canonical.dns, joinState, leads: leads.map(leadBlock) };
    // These two fields did not exist when createCanonicalEvent computed field provenance (that ran
    // before this join even started) — added by hand here, same shape it would have produced, so
    // canonicalConformanceIssues still sees every leaf field accounted for.
    const provenance = {
      origin: "derived" as const,
      confidence: "high" as const,
      derivation: JOIN_DERIVATION,
      recordLocators: [locator],
    };
    row.canonical.fieldProvenance = {
      ...row.canonical.fieldProvenance,
      "dns.joinState": provenance,
      ...(leads.length ? { "dns.leads": provenance } : {}),
    };
  }
  rewriteAggKeySink(sink, rewritten);
}

/**
 * The single entry point `buildSiemResult` calls (siemImport.ts is a ledgered, zero-headroom
 * file — this keeps its footprint to one call): collects every row's join candidate, then runs
 * and applies the join. Call AFTER `boundDnsVariants`, before `aggregateEvents`.
 */
export function runWindowsDnsConnJoin(
  mapped: (JoinableRow & DnsConnMappedRow)[],
  sink: Map<string, { sourceAggKeys?: string[] }>,
): void {
  const dnsConnSink: DnsConnSink = { dns: [], conns: [] };
  mapped.forEach((row, i) => collectWindowsDnsConnCandidate(dnsConnSink, i, row));
  applyWindowsDnsConnJoin(mapped, dnsConnSink.dns, dnsConnSink.conns, sink);
}
