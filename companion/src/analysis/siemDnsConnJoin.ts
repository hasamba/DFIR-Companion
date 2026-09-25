// The Windows half of #996's within-upload join: Sysmon 22 / DNS-Client 3006/3008/3020 returned
// addresses against Sysmon 3 ("Network connection detected") records from the SAME host, in the
// SAME upload. Reuses dnsConnJoin.ts's JoinState/Lead types and dnsWireWords.ts's lead/join
// wording verbatim (canonicalDns.ts's header: "Three vantages share it") — this file only adds the
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
//
// The SAME gap exists on the WFP 5156 vantage, at the same root cause: `Direction` (%%14592
// inbound / %%14593 outbound) is not decoded anywhere in the import path, so an inbound 5156 whose
// peer address matches a returned DNS address shows as "connected" too (#1212). Fix both
// `Initiated` and `Direction` together, not separately — they are the same limitation on two
// sources, and threading only one through would leave the join inconsistent between vantages.

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

/** The already-mapped row's own fields carry everything a join candidate needs — see #0 in the plan. */
export interface DnsConnMappedRow {
  timestamp: string;
  canonical?: {
    dns?: { returned?: { kind: string; value: string }[] };
    target?: { kind: string; name?: string };
    network?: { destination?: { address?: string; port?: number } };
  };
}

function rowHostAndTime(row: DnsConnMappedRow): { host: string; ts: number } | undefined {
  const ts = Date.parse(row.timestamp);
  const host = row.canonical?.target?.kind === "host" ? row.canonical.target.name : undefined;
  return Number.isFinite(ts) && host ? { host, ts } : undefined;
}

function collectWindowsDnsCandidate(
  sink: SiemDnsCandidate[],
  mappedIndex: number,
  row: DnsConnMappedRow,
): void {
  const at = rowHostAndTime(row);
  const returned = row.canonical?.dns?.returned;
  if (!at || !returned) return;
  const seen = new Set<string>();
  sink.push({
    mappedIndex,
    ...at,
    addresses: returned
      .filter((v) => v.kind === "address")
      .map((v) => v.value)
      .filter((a) => (seen.has(a) ? false : (seen.add(a), true))),
  });
}

/**
 * The connection side of one row, if it has one. Exported so a builder that streams rows (the
 * Windows Event XML import, siemBuildProgress.ts, #1636) can keep only these small candidates
 * instead of every connection row. Stops storing past CONN_INDEX_MAX + 1: the join then already
 * answers "connection records exceed the index", which needs only the count to pass the bound.
 */
export function collectWindowsConnCandidate(sink: SiemConnCandidate[], row: DnsConnMappedRow): void {
  const at = rowHostAndTime(row);
  const dst = row.canonical?.network?.destination;
  if (!at || !dst?.address || sink.length > CONN_INDEX_MAX) return;
  sink.push({ ...at, destinationIp: dst.address, ...(dst.port ? { destinationPort: dst.port } : {}) });
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

const isOwnExchange = (c: SiemConnCandidate, d: SiemDnsCandidate): boolean =>
  c.destinationPort === OWN_EXCHANGE_PORT && Math.abs(c.ts - d.ts) <= DNS_WINDOW_SLACK_S * S;

/** First index in a ts-sorted bucket whose ts is at or after `ts`. */
function firstAtOrAfter(conns: readonly SiemConnCandidate[], ts: number): number {
  let [lo, hi] = [0, conns.length];
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (conns[mid].ts < ts) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

/**
 * `conns` is one host/address bucket, sorted by time once per upload (#1636: re-sorting it per DNS
 * record made a dense upload superlinear). Only the DNS exchange's own port-53 connections are
 * skipped, and those sit within the slack of the query, so each walk below stays short.
 */
function leadFor(d: SiemDnsCandidate, address: string, conns: readonly SiemConnCandidate[]): Lead {
  const window = { basis: "fixed" as const, seconds: DNS_FIXED_WINDOW_S };
  const start = firstAtOrAfter(conns, d.ts);
  let i = start;
  while (i < conns.length && isOwnExchange(conns[i], d)) i++;
  const after = conns[i];
  if (after) {
    const gapMs = after.ts - d.ts;
    const state: Lead["state"] =
      gapMs <= WINDOW_MS ? "connected inside the window" : "first connection after the window";
    return { address, state, band: gapBand(gapMs), window };
  }
  let j = start - 1;
  while (j >= 0 && isOwnExchange(conns[j], d)) j--;
  if (j >= 0) return { address, state: "earlier connections only", window };
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
  for (const bucket of byHostAddress.values()) bucket.sort((a, b) => a.ts - b.ts);

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
 * `dnsBlockSchema` already accepts for the sensor vantage (canonicalDns.ts, "Three vantages share
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
 *
 * `conns`, when given, is the upload's WHOLE connection side, already collected row by row with
 * `collectWindowsConnCandidate` (the streaming Windows-event builder holds only its DNS rows, #1636);
 * `mapped` then supplies only the DNS side, so no row's connection is counted twice.
 */
export function runWindowsDnsConnJoin(
  mapped: (JoinableRow & DnsConnMappedRow)[],
  sink: Map<string, { sourceAggKeys?: string[] }>,
  conns?: readonly SiemConnCandidate[],
): void {
  const dns: SiemDnsCandidate[] = [];
  const collected: SiemConnCandidate[] = [];
  mapped.forEach((row, i) => {
    collectWindowsDnsCandidate(dns, i, row);
    if (!conns) collectWindowsConnCandidate(collected, row);
  });
  applyWindowsDnsConnJoin(mapped, dns, conns ?? collected, sink);
}
