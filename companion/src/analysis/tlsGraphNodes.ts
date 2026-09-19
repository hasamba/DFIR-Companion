// The nodes one upload establishes over its retained TLS sessions (#997): per sensor, a server
// certificate identity, a name (SNI), a client certificate identity, a JA3 hash — each with the
// distinct values the sessions showed beside it, the observation range, and the leads a cluster
// suggests. One linear pass; every distinct set is tracked to TLS_DISTINCT_TRACK_MAX and said as
// "at least" past it; every derived claim (a name not listed by the certificate, an issuer string
// shared, the same DNS names on a renewal) is made only when the records it needs are complete
// and agree, and otherwise says why it was not made. Retention is order-independent: nodes are
// built completely, sorted, and the first TLS_NODES_MAX per kind are kept.

import type { TlsGraphLead, TlsGraphNodeKind } from "./canonicalTls.js";
import { asciiName, isValidQueryName } from "./dnsRecord.js";
import { keyDigest } from "./recordIdentity.js";
import { sensorKeyOf, type TlsObservations } from "./tlsGraphJoin.js";
import { isTlsHostname, NAMES_KEPT_MAX, type CertRef, type TlsObservation } from "./tlsSession.js";
import { show } from "./tlsSessionWords.js";

/** Nodes retained per kind; the rest fold into the kind's overflow row. */
export const TLS_NODES_MAX = 8192;
/** Distinct values tracked per edge; past it the count is "at least". */
export const TLS_DISTINCT_TRACK_MAX = 256;
/** A certificate presented under this many names is a lead — with the alternatives named beside it. */
export const TLS_MANY_NAMES_LEAD = 8;
/** A JA3 with this many sessions to at most TLS_JA3_FEW_DESTINATIONS server addresses is a lead. */
export const TLS_JA3_CONCENTRATED_MIN_SESSIONS = 20;
export const TLS_JA3_FEW_DESTINATIONS = 3;
/** Locators kept per node for the envelope. */
const LOCATORS_MAX = 8;
/** Identities per name checked pairwise for alternation. */
const ALTERNATION_PAIRS_MAX = 64;

export const CLUSTER_CAVEAT =
  "a cluster proves nothing on its own — strengthen it with a process that made the connection or a payload";

// ───────────────────────────── bounded sets ─────────────────────────────

export interface Distinct {
  /** Sorted; at most TLS_DISTINCT_TRACK_MAX — the lexicographically smallest values seen, so the set is the same in any upload order. */
  values: string[];
  count: number;
  atLeast: boolean;
  seen: Set<string>;
}

const distinct = (): Distinct => ({ values: [], count: 0, atLeast: false, seen: new Set() });

/** Binary-search insert position in a sorted array. */
function slot(values: readonly string[], v: string): number {
  let lo = 0;
  let hi = values.length;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (values[mid] < v) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

function add(d: Distinct, v: string): void {
  if (d.seen.has(v)) return;
  if (d.seen.size >= TLS_DISTINCT_TRACK_MAX) {
    d.atLeast = true;
    // Past the bound the tracked set is the smallest values: a smaller newcomer displaces the largest.
    const largest = d.values[d.values.length - 1];
    if (v >= largest) return;
    d.seen.delete(largest);
    d.values.pop();
  } else d.count += 1;
  d.seen.add(v);
  d.values.splice(slot(d.values, v), 0, v);
}

// ───────────────────────────── nodes ─────────────────────────────

export interface CertSpan {
  ref: CertRef;
  first?: number;
  last?: number;
  sessions: number;
}

export interface CertRecordFacts {
  records: number;
  subject?: string;
  issuer?: string;
  notBefore?: string;
  notAfter?: string;
  /** Canonical DNS names when the retained record lists them completely (≤ NAMES_KEPT_MAX). */
  dnsNames?: string[];
  dnsNamesTotal?: number;
  disagree: string[];
  locators: string[];
}

export type NotListed = { count: number; listed: string[] } | { state: "not compared"; reason: string };

export interface TlsNode {
  kind: TlsGraphNodeKind;
  /** `kind:value` of the identity, the canonical name, or the JA3 hash. */
  id: string;
  ref?: CertRef;
  /** The name as first written, for the words (name node). */
  shown?: string;
  sensor: string;
  sources: Set<TlsObservation["source"]>;
  sessions: number;
  names: Distinct;
  servers: Distinct;
  clientAddresses: Distinct;
  certificates?: Map<string, CertSpan>;
  noSni: number;
  chainChecks: Distinct;
  sniMismatches: number;
  identityUnavailable: number;
  first?: number;
  last?: number;
  untimed: number;
  locators: string[];
  certificate?: CertRecordFacts;
  notListed?: NotListed;
  issuerString?: number;
  /** What the identities' ranges establish about their order (name node with ≥2 identities). */
  order?: "sequence" | "not established";
  /** In sequence (no alternation) and both records list the same DNS names. */
  sameNames?: boolean;
  leads: TlsGraphLead[];
  rank: number;
}

export interface TlsGraphOverflow {
  kind: TlsGraphNodeKind;
  sensor: string;
  sources: string[];
  count: number;
  firstTs: string;
}

export interface TlsGraph {
  nodes: TlsNode[];
  /** Nodes past TLS_NODES_MAX, counted per kind, sensor and source set — `kind|sensor|sources` → row. */
  overflow: Map<string, TlsGraphOverflow>;
  coverage: {
    sessionsRead: number;
    sessionsTotal: number;
    certificatesRead: number;
    certificatesTotal: number;
  };
}

const refId = (r: CertRef): string => `${r.kind}:${r.value}`;

function newNode(kind: TlsGraphNodeKind, id: string, sensor: string): TlsNode {
  return {
    kind,
    id,
    sensor,
    sources: new Set(),
    sessions: 0,
    names: distinct(),
    servers: distinct(),
    clientAddresses: distinct(),
    ...(kind === "name" ? { certificates: new Map<string, CertSpan>() } : {}),
    noSni: 0,
    chainChecks: distinct(),
    sniMismatches: 0,
    identityUnavailable: 0,
    untimed: 0,
    locators: [],
    leads: [],
    rank: 0,
  };
}

/** A name's canonical form for identity: its wire form lowercased when valid, else the exact string. */
export const canonicalName = (raw: string): string =>
  isValidQueryName(raw) ? asciiName(raw).toLowerCase() : raw;

const timeOf = (o: TlsObservation): number | undefined => {
  const t = Date.parse(o.timestamp);
  return Number.isFinite(t) ? t : undefined;
};

function touch(n: TlsNode, o: TlsObservation, t: number | undefined): void {
  n.sessions += 1;
  n.sources.add(o.source);
  if (t === undefined) n.untimed += 1;
  else {
    if (n.first === undefined || t < n.first) n.first = t;
    if (n.last === undefined || t > n.last) n.last = t;
  }
  if (o.uid && n.locators.length < LOCATORS_MAX && !n.locators.includes(o.uid)) n.locators.push(o.uid);
  if (o.src) add(n.clientAddresses, o.src);
  if (o.dst) add(n.servers, o.port ? `${o.dst}:${o.port}` : o.dst);
}

// ───────────────────────────── certificate facts ─────────────────────────────

const namesDigest = (names: string[]): string => keyDigest([...names].sort().join("\n"));

/**
 * The certificate facts per (sensor, identity): from the certificate records, and from the
 * sessions that carry the certificate's own fields inline (a Suricata `tls` record) — the same
 * record's facts under the same identity. `records` counts certificate records only.
 */
function factsOf(store: TlsObservations, sessions: TlsObservation[]): Map<string, CertRecordFacts> {
  const out = new Map<string, CertRecordFacts>();
  const inline = sessions.filter((o) => o.cert && o.certificate && Object.keys(o.certificate).length);
  for (const c of [...store.certs, ...inline]) {
    if (!c.cert || c.role === "client") continue;
    const key = `${sensorKeyOf(c)}|${refId(c.cert)}`;
    const f = c.certificate ?? {};
    const dns = f.dnsNames?.map(canonicalName);
    const record = c.kind === "certificate" ? 1 : 0;
    const existing = out.get(key);
    if (!existing) {
      out.set(key, {
        records: record,
        ...(f.subject !== undefined ? { subject: f.subject } : {}),
        ...(f.issuer !== undefined ? { issuer: f.issuer } : {}),
        ...(f.notBefore ? { notBefore: f.notBefore } : {}),
        ...(f.notAfter ? { notAfter: f.notAfter } : {}),
        ...(dns ? { dnsNames: dns, dnsNamesTotal: f.dnsNamesTotal ?? dns.length } : {}),
        disagree: [],
        locators: record && c.locatorId ? [c.locatorId] : record && c.uid ? [c.uid] : [],
      });
      continue;
    }
    existing.records += record;
    const loc = record ? (c.locatorId ?? c.uid) : undefined;
    if (loc && existing.locators.length < LOCATORS_MAX && !existing.locators.includes(loc))
      existing.locators.push(loc);
    // Only two PRESENT values can disagree: a chain member carries no facts, and that is not a
    // dispute — an absent fact is filled from a later record instead.
    const differs = (field: string, a: string | undefined, b: string | undefined) =>
      a !== undefined && b !== undefined && a !== b && !existing.disagree.includes(field);
    if (differs("subject", existing.subject, f.subject)) existing.disagree.push("subject");
    else if (existing.subject === undefined && f.subject !== undefined) existing.subject = f.subject;
    if (differs("issuer", existing.issuer, f.issuer)) existing.disagree.push("issuer");
    else if (existing.issuer === undefined && f.issuer !== undefined) existing.issuer = f.issuer;
    const validity = (x: CertRecordFacts | typeof f) => `${x.notBefore ?? ""}|${x.notAfter ?? ""}`;
    if ((f.notBefore || f.notAfter) && (existing.notBefore || existing.notAfter)) {
      if (validity(existing) !== validity(f) && !existing.disagree.includes("validity"))
        existing.disagree.push("validity");
    } else if (f.notBefore || f.notAfter) {
      if (f.notBefore) existing.notBefore = f.notBefore;
      if (f.notAfter) existing.notAfter = f.notAfter;
    }
    if (dns && existing.dnsNames) {
      if (namesDigest(dns) !== namesDigest(existing.dnsNames) && !existing.disagree.includes("names"))
        existing.disagree.push("names");
    } else if (dns) {
      existing.dnsNames = dns;
      existing.dnsNamesTotal = f.dnsNamesTotal ?? dns.length;
    }
  }
  return out;
}

/** issuer string → distinct server-certificate identities carrying it, per sensor. */
function issuerCounts(store: TlsObservations, sessions: TlsObservation[]): Map<string, Set<string>> {
  const out = new Map<string, Set<string>>();
  const note = (sensor: string, issuer: string | undefined, ref: CertRef | undefined) => {
    if (issuer === undefined || !ref) return;
    const key = `${sensor}|${issuer.trim()}`;
    (out.get(key) ?? out.set(key, new Set()).get(key)!).add(refId(ref));
  };
  for (const c of store.certs)
    if (c.role !== "client") note(sensorKeyOf(c), c.certificate?.issuer ?? c.issuer, c.cert);
  for (const o of sessions) note(sensorKeyOf(o), o.issuer, o.cert);
  return out;
}

// ───────────────────────────── covered names ─────────────────────────────

/** Exact, or a `*.` entry covering exactly one more label (RFC 6125 §6.4.3, the one-label form). */
export function listedBy(canonicalSni: string, dnsNames: readonly string[]): boolean {
  for (const n of dnsNames) {
    if (n === canonicalSni) return true;
    if (n.startsWith("*.")) {
      const dot = canonicalSni.indexOf(".");
      if (dot > 0 && canonicalSni.slice(dot + 1) === n.slice(2)) return true;
    }
  }
  return false;
}

function notListedOf(n: TlsNode, certsComplete: boolean): NotListed | undefined {
  const f = n.certificate;
  if (!f) return undefined;
  if (!certsComplete)
    return { state: "not compared", reason: "certificate records beyond the retained bound" };
  if (f.disagree.length)
    return { state: "not compared", reason: "certificate records for this identity disagree" };
  if (!f.dnsNames) return { state: "not compared", reason: "the certificate record lists no DNS names" };
  if ((f.dnsNamesTotal ?? 0) > NAMES_KEPT_MAX)
    return {
      state: "not compared",
      reason: `the certificate's DNS-name list was truncated at ${NAMES_KEPT_MAX}`,
    };
  if (n.names.atLeast)
    return { state: "not compared", reason: `more names than the graph tracks (${TLS_DISTINCT_TRACK_MAX})` };
  const listed: string[] = [];
  let count = 0;
  for (const raw of n.names.values) {
    // Only a hostname is compared — an IP literal, a wildcard or an invalid name can neither be
    // listed by a dNSName SAN nor be a coverage lead.
    if (!isTlsHostname(raw, "sni")) continue;
    if (listedBy(canonicalName(raw), f.dnsNames)) continue;
    count += 1;
    if (listed.length < 3) listed.push(raw);
  }
  return { count, listed };
}

// ───────────────────────────── leads ─────────────────────────────

const fmt = (n: number): string => n.toLocaleString("en-US");
const plural = (n: number, one: string, many = `${one}s`): string => `${fmt(n)} ${n === 1 ? one : many}`;

function certificateLeads(n: TlsNode): TlsGraphLead[] {
  const leads: TlsGraphLead[] = [];
  const names = n.names.atLeast ? `${TLS_DISTINCT_TRACK_MAX}+` : fmt(n.names.count);
  if (n.names.atLeast || n.names.count >= TLS_MANY_NAMES_LEAD)
    leads.push({
      kind: "many-names",
      words: `one certificate presented under ${names} names — shared hosting, a CDN or an inspection proxy present one certificate for many names; the records do not say which; ${CLUSTER_CAVEAT}`,
    });
  const nl = n.notListed;
  if (nl && "count" in nl && nl.count > 0)
    leads.push({
      kind: "name-not-listed",
      words: `presented under ${plural(nl.count, "name")} not among the ${plural(n.certificate?.dnsNames?.length ?? 0, "DNS name")} listed by the retained certificate record: ${nl.listed.map(show).join(", ")}${nl.count > nl.listed.length ? ` (+${nl.count - nl.listed.length} more)` : ""}; ${CLUSTER_CAVEAT}`,
    });
  return leads;
}

/** Two identities alternate when an observation of one falls strictly inside the other's range. */
export function alternates(a: CertSpan, b: CertSpan): boolean {
  if (a.first === undefined || a.last === undefined || b.first === undefined || b.last === undefined)
    return false;
  return (a.first < b.first && b.first < a.last) || (b.first < a.first && a.first < b.last);
}

/** The alternation lead, or what the ranges establish about the identities' order when there is none. */
function nameOrder(n: TlsNode): { leads: TlsGraphLead[]; order?: TlsNode["order"] } {
  const all = [...(n.certificates?.values() ?? [])];
  if (all.length < 2) return { leads: [] };
  const spans = all.slice(0, ALTERNATION_PAIRS_MAX);
  for (let i = 0; i < spans.length; i++)
    for (let j = i + 1; j < spans.length; j++)
      if (alternates(spans[i], spans[j]))
        return {
          leads: [
            {
              kind: "certificates-alternate",
              words: `served with ${plural(all.length, "certificate")} in alternation — observation ranges overlap; the records do not say both were served at one instant; ${CLUSTER_CAVEAT}`,
            },
          ],
        };
  // A sequence is established only when every identity has a range and every pair was compared.
  const established = all.length <= ALTERNATION_PAIRS_MAX && all.every((s) => s.first !== undefined);
  return { leads: [], order: established ? "sequence" : "not established" };
}

function ja3Leads(n: TlsNode): TlsGraphLead[] {
  if (
    n.sessions >= TLS_JA3_CONCENTRATED_MIN_SESSIONS &&
    !n.servers.atLeast &&
    n.servers.count <= TLS_JA3_FEW_DESTINATIONS
  )
    return [
      {
        kind: "ja3-concentrated",
        words: `${plural(n.sessions, "session")} from ${plural(n.clientAddresses.count, "client address", "client addresses")} to only ${plural(n.servers.count, "server address", "server addresses")} — concentrated; ${CLUSTER_CAVEAT}`,
      },
    ];
  return [];
}

// ───────────────────────────── build ─────────────────────────────

const multiEdge = (n: TlsNode): boolean =>
  n.names.count >= 2 ||
  n.servers.count >= 2 ||
  n.clientAddresses.count >= 2 ||
  (n.certificates?.size ?? 0) >= 2;

const emitted = (n: TlsNode): boolean => {
  if (n.kind === "name") return (n.certificates?.size ?? 0) >= 2 || n.servers.count >= 2;
  if (n.kind === "ja3" || n.kind === "ja3s") return n.sessions >= 2;
  return true;
};

/** Same DNS names on the earliest and latest identity of a name in sequence, when both records are complete and agree. */
function sameNamesOf(
  n: TlsNode,
  facts: Map<string, CertRecordFacts>,
  certsComplete: boolean,
): boolean | undefined {
  const spans = [...(n.certificates?.values() ?? [])].filter((s) => s.first !== undefined);
  if (!certsComplete || spans.length < 2) return undefined;
  spans.sort((a, b) => a.first! - b.first!);
  const a = facts.get(`${n.sensor}|${refId(spans[0].ref)}`);
  const b = facts.get(`${n.sensor}|${refId(spans[spans.length - 1].ref)}`);
  if (!a?.dnsNames || !b?.dnsNames || a.disagree.length || b.disagree.length) return undefined;
  if ((a.dnsNamesTotal ?? 0) > NAMES_KEPT_MAX || (b.dnsNamesTotal ?? 0) > NAMES_KEPT_MAX) return undefined;
  return namesDigest(a.dnsNames) === namesDigest(b.dnsNames);
}

export function buildTlsGraph(store: TlsObservations, sessions: TlsObservation[]): TlsGraph {
  const nodes = new Map<string, TlsNode>();
  const get = (kind: TlsGraphNodeKind, id: string, sensor: string): TlsNode => {
    const key = `${kind}|${sensor}|${id}`;
    return nodes.get(key) ?? nodes.set(key, newNode(kind, id, sensor)).get(key)!;
  };
  for (const o of sessions) {
    const sensor = sensorKeyOf(o);
    const t = timeOf(o);
    const name = o.sni !== undefined ? canonicalName(o.sni) : undefined;
    if (o.cert) {
      const c = get("certificate", refId(o.cert), sensor);
      c.ref = o.cert;
      touch(c, o, t);
      if (o.sni !== undefined) add(c.names, o.sni);
      else c.noSni += 1;
      if (o.validation !== undefined) add(c.chainChecks, o.validation);
      if (o.sniMatchesCert === false) c.sniMismatches += 1;
    }
    if (name !== undefined) {
      const n = get("name", name, sensor);
      n.shown ??= name;
      touch(n, o, t);
      if (o.cert) {
        const id = refId(o.cert);
        const span = n.certificates!.get(id);
        if (span) {
          span.sessions += 1;
          if (t !== undefined) {
            if (span.first === undefined || t < span.first) span.first = t;
            if (span.last === undefined || t > span.last) span.last = t;
          }
        } else if (n.certificates!.size < TLS_DISTINCT_TRACK_MAX)
          n.certificates!.set(id, {
            ref: o.cert,
            sessions: 1,
            ...(t !== undefined ? { first: t, last: t } : {}),
          });
      } else n.identityUnavailable += 1;
    }
    if (o.clientCert?.ref) {
      const cc = get("client-certificate", refId(o.clientCert.ref), sensor);
      cc.ref = o.clientCert.ref;
      touch(cc, o, t);
      if (o.sni !== undefined) add(cc.names, o.sni);
    }
    if (o.ja3 !== undefined) {
      const j = get("ja3", o.ja3, sensor);
      touch(j, o, t);
      if (o.sni !== undefined) add(j.names, o.sni);
    }
    // The server's own signature (#997): the addresses that presented it, under which names, to
    // which clients. No lead of its own — a server stack concentrated on few addresses is the
    // ordinary case, and a signature shared across a fleet says only that the stack is shared.
    if (o.ja3s !== undefined) {
      const j = get("ja3s", o.ja3s, sensor);
      touch(j, o, t);
      if (o.sni !== undefined) add(j.names, o.sni);
    }
  }

  const coverage = {
    sessionsRead: store.sessions.length,
    sessionsTotal: store.sessionsTotal,
    certificatesRead: store.certs.length,
    certificatesTotal: store.certsTotal,
  };
  const certsComplete = coverage.certificatesRead === coverage.certificatesTotal;
  const facts = factsOf(store, sessions);
  const issuers = issuerCounts(store, sessions);
  const built: TlsNode[] = [];
  for (const n of nodes.values()) {
    if (!emitted(n)) continue;
    if (n.kind === "certificate") {
      const f = facts.get(`${n.sensor}|${n.id}`);
      if (f) n.certificate = f;
      n.notListed = notListedOf(n, certsComplete);
      const issuer = f && !f.disagree.includes("issuer") ? f.issuer : undefined;
      if (issuer !== undefined && certsComplete)
        n.issuerString = issuers.get(`${n.sensor}|${issuer.trim()}`)?.size;
      n.leads = f?.disagree.length ? [] : certificateLeads(n);
    } else if (n.kind === "name") {
      const { leads, order } = nameOrder(n);
      n.leads = leads;
      if (order) n.order = order;
      if (order === "sequence") {
        const same = sameNamesOf(n, facts, certsComplete);
        if (same !== undefined) n.sameNames = same;
      }
    } else if (n.kind === "ja3") n.leads = ja3Leads(n);
    n.rank = n.leads.length ? 2 : multiEdge(n) ? 1 : 0;
    built.push(n);
  }
  // Order-independent retention: the whole set sorted, the first TLS_NODES_MAX per kind kept.
  built.sort(
    (a, b) =>
      b.rank - a.rank ||
      b.sessions - a.sessions ||
      (a.first ?? Number.MAX_SAFE_INTEGER) - (b.first ?? Number.MAX_SAFE_INTEGER) ||
      (a.id < b.id ? -1 : a.id > b.id ? 1 : 0),
  );
  const kept: TlsNode[] = [];
  const perKind = new Map<TlsGraphNodeKind, number>();
  const overflow: TlsGraph["overflow"] = new Map();
  for (const n of built) {
    const k = perKind.get(n.kind) ?? 0;
    if (k < TLS_NODES_MAX) {
      perKind.set(n.kind, k + 1);
      kept.push(n);
      continue;
    }
    const ts = n.first !== undefined ? new Date(n.first).toISOString() : "";
    const sources = [...n.sources].sort();
    const key = `${n.kind}|${n.sensor}|${sources.join(",")}`;
    const over = overflow.get(key);
    if (over) {
      over.count += 1;
      if (ts && (!over.firstTs || ts < over.firstTs)) over.firstTs = ts;
    } else overflow.set(key, { kind: n.kind, sensor: n.sensor, sources, count: 1, firstTs: ts });
  }
  return { nodes: kept, overflow, coverage };
}
