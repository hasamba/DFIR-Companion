// TLS relationship rows: identity, envelope, words (#997). One Info row per retained node; every
// fact the words and the envelope show is the row's identity (a re-import of the same upload folds;
// another upload's edges are another row), while session and certificate record counts and the
// coverage statement are aggregates outside it. Locators are never keyed. A node row carries no
// srcIp / dstIp — it names many — so it never unions with an endpoint event on its own.

import { createCanonicalEvent, type CanonicalEventEnvelope } from "./canonicalEvent.js";
import type { TlsGraphBlock, TlsGraphEdge, TlsGraphNodeKind } from "./canonicalTls.js";
import { identityMark, keyDigest, packTags } from "./recordIdentity.js";
import type { MappedEvent } from "./siemImport.js";
import { joinSessionsToCertificates, type TlsObservations } from "./tlsGraphJoin.js";
import {
  buildTlsGraph,
  TLS_DISTINCT_TRACK_MAX,
  type Distinct,
  type TlsGraph,
  type TlsNode,
} from "./tlsGraphNodes.js";
import { mapTlsRows, tallyTls } from "./tlsSession.js";
import { ends, refWords, show } from "./tlsSessionWords.js";

const DESCRIPTION_MAX = 600;
const LISTED_ENVELOPE_MAX = 8;
const LISTED_WORDS_MAX = 3;
const BASIS = "records in this upload only; no contact with any observed infrastructure" as const;
const KIND_WORDS: Record<TlsGraphNodeKind, string> = {
  certificate: "certificate",
  name: "name",
  "client-certificate": "client certificate",
  ja3: "ja3",
};

const fmt = (n: number): string => n.toLocaleString("en-US");
const plural = (n: number, one: string, many = `${one}s`): string => `${fmt(n)} ${n === 1 ? one : many}`;
const countWords = (d: Distinct): string => (d.atLeast ? `${TLS_DISTINCT_TRACK_MAX}+` : fmt(d.count));
const minute = (ms: number): string => new Date(ms).toISOString().slice(0, 16).replace("T", " ");
const day = (iso: string): string => iso.slice(0, 10);

// ───────────────────────────── identity ─────────────────────────────

const edgeBlock = (d: Distinct): TlsGraphEdge => ({
  count: d.count,
  listed: d.values.slice(0, LISTED_ENVELOPE_MAX),
  ...(d.atLeast ? { atLeast: true } : {}),
});

function block(n: TlsNode, g: TlsGraph): TlsGraphBlock {
  const f = n.certificate;
  return {
    node: { kind: n.kind, id: n.ref ? n.ref.value : n.id, ...(n.ref?.alg ? { alg: n.ref.alg } : {}) },
    sensor: n.sensor ? { name: n.sensor } : { state: "not named" },
    ...(n.kind !== "name" ? { names: edgeBlock(n.names) } : {}),
    servers: edgeBlock(n.servers),
    clientAddresses: edgeBlock(n.clientAddresses),
    ...(n.certificates
      ? {
          certificates: {
            count: n.certificates.size,
            listed: [...n.certificates.values()].slice(0, LISTED_ENVELOPE_MAX).map((s) => s.ref.value),
            ...(n.certificates.size >= TLS_DISTINCT_TRACK_MAX ? { atLeast: true } : {}),
          },
          spans: [...n.certificates.values()].slice(0, LISTED_ENVELOPE_MAX).map((s) => ({
            identity: s.ref.value,
            ...(s.ref.alg ? { alg: s.ref.alg } : {}),
            ...(s.first !== undefined ? { first: new Date(s.first).toISOString() } : {}),
            ...(s.last !== undefined ? { last: new Date(s.last).toISOString() } : {}),
            sessions: s.sessions,
          })),
        }
      : {}),
    ...(n.kind === "certificate" ? { noSni: n.noSni, sniMismatches: n.sniMismatches } : {}),
    ...(n.chainChecks.count ? { chainChecks: n.chainChecks.values.slice(0, LISTED_ENVELOPE_MAX) } : {}),
    ...(n.kind === "name" ? { identityUnavailable: n.identityUnavailable } : {}),
    ...(f
      ? {
          certificate: {
            records: f.records,
            ...(f.subject !== undefined ? { subject: f.subject } : {}),
            ...(f.issuer !== undefined ? { issuer: f.issuer } : {}),
            ...(f.notBefore ? { notBefore: f.notBefore } : {}),
            ...(f.notAfter ? { notAfter: f.notAfter } : {}),
            ...(f.dnsNames
              ? { dnsNamesListed: f.dnsNames.length, dnsNamesTotal: f.dnsNamesTotal ?? f.dnsNames.length }
              : {}),
            ...(f.disagree.length ? { disagree: f.disagree } : {}),
          },
        }
      : {}),
    ...(n.notListed ? { notListed: n.notListed } : {}),
    ...(n.issuerString !== undefined ? { issuerString: n.issuerString } : {}),
    ...(n.first !== undefined ? { first: new Date(n.first).toISOString() } : {}),
    ...(n.last !== undefined ? { last: new Date(n.last).toISOString() } : {}),
    ...(n.untimed ? { untimed: n.untimed } : {}),
    sessions: n.sessions,
    leads: n.leads,
    coverage: g.coverage,
    basis: BASIS,
  };
}

/** Everything shown, less the aggregates (record counts, coverage) — the row's identity. */
export function tlsGraphKey(n: TlsNode, b: TlsGraphBlock): string {
  const { sessions: _s, coverage: _c, ...shown } = b;
  return `tlsg|${n.kind}|${n.sensor ? `t:${keyDigest(n.sensor)}` : "-"}|${keyDigest(JSON.stringify(shown))}`;
}

const OVERFLOW_KEY = (kind: TlsGraphNodeKind): string => `tlsg|${kind}|overflow`;

// ───────────────────────────── words ─────────────────────────────

const idWords = (n: TlsNode): string => (n.ref ? refWords(n.ref) : n.kind === "ja3" ? ends(n.id) : "");

/** `<count> — a, b, c (+n more)`: the first LISTED_WORDS_MAX values, neutralised. */
function countList(d: Distinct): string {
  const shown = d.values.slice(0, LISTED_WORDS_MAX).map(show).join(", ");
  const more = d.atLeast
    ? " (and more)"
    : d.count > LISTED_WORDS_MAX
      ? ` (+${fmt(d.count - LISTED_WORDS_MAX)} more)`
      : "";
  return `${countWords(d)} — ${shown}${more}`;
}
const listWords = (d: Distinct, one: string, many = `${one}s`): string =>
  countList(d).replace(" — ", ` ${d.count === 1 && !d.atLeast ? one : many} — `);

const spanWords = (first?: number, last?: number): string =>
  first === undefined || last === undefined ? "" : `${minute(first)} → ${minute(last)}`;

// The relationships first — they are what the row exists for — then the certificate record's own
// facts, so a packed description keeps the edges before the attributes.
function certificateTags(n: TlsNode): string[] {
  const f = n.certificate;
  const tags: string[] = [`presented under: ${listWords(n.names, "name")}`];
  if (n.noSni) tags.push(`no SNI in ${plural(n.noSni, "session")}`);
  tags.push(`at server addresses: ${countList(n.servers)}`);
  tags.push(`client addresses: ${countWords(n.clientAddresses)}`);
  if (n.chainChecks.count) tags.push(`chain check: ${n.chainChecks.values.slice(0, 4).map(show).join(", ")}`);
  if (n.sniMismatches)
    tags.push(`SNI does not match the certificate in ${plural(n.sniMismatches, "session")}`);
  if (f) {
    if (f.disagree.length)
      tags.push(`certificate records for this identity disagree: ${f.disagree.join(", ")}`);
    if (f.subject !== undefined) tags.push(`subject: ${show(f.subject)}`);
    if (f.issuer !== undefined) tags.push(`issuer: ${show(f.issuer)}`);
    if (f.notBefore || f.notAfter)
      tags.push(`valid: ${f.notBefore ? day(f.notBefore) : "?"} – ${f.notAfter ? day(f.notAfter) : "?"}`);
    if (f.dnsNames) tags.push(`lists ${plural(f.dnsNamesTotal ?? f.dnsNames.length, "DNS name")}`);
  }
  const nl = n.notListed;
  if (nl && "state" in nl) tags.push(`covered-name comparison not made: ${nl.reason}`);
  if (n.issuerString !== undefined && n.issuerString > 1)
    tags.push(
      `issuer string shared by ${plural(n.issuerString, "certificate identity", "certificate identities")} in this upload`,
    );
  return tags;
}

function nameTags(n: TlsNode): string[] {
  const tags: string[] = [`name: ${show(n.shown ?? n.id)}`];
  const spans = [...(n.certificates?.values() ?? [])];
  if (spans.length && !n.leads.length) {
    const listed = spans
      .slice(0, LISTED_WORDS_MAX)
      .map((s) => `${refWords(s.ref)}${s.first !== undefined ? ` (${spanWords(s.first, s.last)})` : ""}`)
      .join(", ");
    const more = spans.length > LISTED_WORDS_MAX ? ` (+${spans.length - LISTED_WORDS_MAX} more)` : "";
    const how =
      spans.length >= 2
        ? ` in sequence — a renewal or a replacement; the records do not say which${n.sameNames ? "; the later certificate lists the same DNS names" : ""}`
        : "";
    tags.push(`served with: ${plural(spans.length, "certificate")}${how} — ${listed}${more}`);
  }
  if (n.identityUnavailable)
    tags.push(`certificate identity unavailable in ${plural(n.identityUnavailable, "session")}`);
  tags.push(`at server addresses: ${countList(n.servers)}`);
  tags.push(`client addresses: ${countWords(n.clientAddresses)}`);
  return tags;
}

function clientCertificateTags(n: TlsNode): string[] {
  return [
    `presented by: ${listWords(n.clientAddresses, "client address", "client addresses")}`,
    `presented to: ${listWords(n.servers, "server")}`,
    ...(n.names.count ? [`under: ${listWords(n.names, "name")}`] : []),
  ];
}

function ja3Tags(n: TlsNode): string[] {
  return [
    `client addresses: ${countWords(n.clientAddresses)}`,
    `to server addresses: ${countList(n.servers)}`,
    ...(n.names.count ? [`under: ${listWords(n.names, "name")}`] : []),
    "a TLS library signature — every client with the same stack shares it; never an identity",
  ];
}

function tagsOf(n: TlsNode, g: TlsGraph): string[] {
  const body =
    n.kind === "certificate"
      ? certificateTags(n)
      : n.kind === "name"
        ? nameTags(n)
        : n.kind === "client-certificate"
          ? clientCertificateTags(n)
          : ja3Tags(n);
  const leads = n.leads.map((l) => `lead: ${l.words}`);
  // The name node's span leads with the name, then the leads; every other kind leads with its leads.
  const ordered = n.kind === "name" ? [body[0], ...leads, ...body.slice(1)] : [...leads, ...body];
  const tail: string[] = [];
  const span = spanWords(n.first, n.last);
  if (span) tail.push(`observed ${span}`);
  if (n.untimed) tail.push(`${plural(n.untimed, "session")} with no readable time excluded from the range`);
  const c = g.coverage;
  if (c.sessionsRead < c.sessionsTotal)
    tail.push(`graph over ${fmt(c.sessionsRead)} of ${fmt(c.sessionsTotal)} session records`);
  if (c.certificatesRead < c.certificatesTotal)
    tail.push(`certificate records: ${fmt(c.certificatesRead)} of ${fmt(c.certificatesTotal)} read`);
  if (!n.sensor) tail.push("sensor not named in the records");
  return [...ordered, ...tail];
}

// ───────────────────────────── rows ─────────────────────────────

const sourcesOf = (n: TlsNode): string[] => {
  const out: string[] = [];
  if ([...n.sources].some((s) => s.startsWith("zeek"))) out.push("Zeek");
  if (n.sources.has("suricata-tls")) out.push("Suricata");
  return out;
};

function envelopeOf(n: TlsNode, b: TlsGraphBlock, ts: string, key: string): CanonicalEventEnvelope {
  const sources = [...n.sources];
  const rawRecords = [
    ...n.locators.map((locator) => ({ source: sources[0] ?? "zeek-ssl", locator })),
    ...(n.certificate?.locators ?? []).map((locator) => ({ source: "zeek-x509", locator })),
  ];
  return createCanonicalEvent({
    event: { category: "network", type: "tls-graph" },
    tlsGraph: b,
    time: { observed: ts, normalized: ts },
    evidence: {
      rawRecords: rawRecords.length ? rawRecords : [{ source: sources[0] ?? "zeek-ssl", locator: key }],
    },
    producer: { importer: "network", parserVersion: "1", mappingVersion: "tls-graph-v1" },
  });
}

function mapNode(n: TlsNode, g: TlsGraph): MappedEvent {
  const b = block(n, g);
  const key = tlsGraphKey(n, b);
  const mark = identityMark(key);
  const ts = n.first !== undefined ? new Date(n.first).toISOString() : "";
  const id = idWords(n);
  const head = `TLS-graph ${KIND_WORDS[n.kind]}${id ? ` ${id}` : ""}`;
  const sensor = n.sensor ? ` @ ${show(n.sensor)}` : "";
  const records = n.certificate?.records;
  const tail = ` — ${plural(n.sessions, "session record")}${records ? `, ${plural(records, "certificate record")}` : ""}`;
  const room = DESCRIPTION_MAX - mark.length - head.length - sensor.length - tail.length;
  return {
    timestamp: ts,
    description: `${head}${packTags(tagsOf(n, g), Math.max(0, room))}${sensor}${tail}${mark}`,
    severity: "Info",
    mitre: [],
    canonical: envelopeOf(n, b, ts, key),
    aggKey: key,
    sources: sourcesOf(n),
    origin: "wire",
  };
}

function mapOverflow(kind: TlsGraphNodeKind, count: number, firstTs: string, g: TlsGraph): MappedEvent {
  const key = OVERFLOW_KEY(kind);
  return {
    timestamp: firstTs,
    description: `[overflow: ${plural(count, `${KIND_WORDS[kind]} node`)} beyond the retained bound folded; none shown]${identityMark(key)}`,
    severity: "Info",
    mitre: [],
    canonical: createCanonicalEvent({
      event: { category: "network", type: "tls-graph" },
      tlsGraph: {
        node: { kind, id: "" },
        sensor: { state: "not named" },
        sessions: 0,
        leads: [],
        coverage: g.coverage,
        basis: BASIS,
        folded: true,
        records: count,
      },
      time: { observed: firstTs, normalized: firstTs },
      evidence: { rawRecords: [{ source: "zeek-ssl", locator: key }] },
      producer: { importer: "network", parserVersion: "1", mappingVersion: "tls-graph-v1" },
    }),
    aggKey: key,
    sources: ["Zeek"],
    origin: "wire",
  };
}

/** Leads first, then the most sessions, then the earliest — up to `budget`; overflow rows after. */
export function mapTlsGraphRows(g: TlsGraph, budget: number): MappedEvent[] {
  return [
    ...g.nodes.slice(0, budget).map((n) => mapNode(n, g)),
    ...[...g.overflow.entries()].map(([kind, o]) => mapOverflow(kind, o.count, o.firstTs, g)),
  ];
}

/**
 * The two TLS families of one upload: session and certificate rows (the retained sessions joined
 * to their x509 records, then folded into the shape tally beside the rest), and the graph rows.
 */
export function tlsFamilies(store: TlsObservations, budget: number): [MappedEvent[], MappedEvent[]] {
  const joined = joinSessionsToCertificates(store);
  for (const o of joined) tallyTls(o, store.tally);
  return [mapTlsRows(store.tally, budget), mapTlsGraphRows(buildTlsGraph(store, joined), budget)];
}
