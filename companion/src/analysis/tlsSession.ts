// A TLS record, read for what it establishes (#933 item 6, prerequisite phase).
//
// Zeek `ssl.log`, Zeek `x509.log` and Suricata `tls` records used to be IOC-only telemetry: the SNI
// became a domain indicator, every certificate SAN became a domain indicator, and nothing else was
// read — so a self-signed certificate on a raw address with no SNI and a valid CA-issued one on a
// CDN read identically. Now each record shape is ONE row, folded the way `conn` folds into flows:
// a session row per (sensor, client, server, port, SNI, version, cipher, established, resumed,
// chain check, JA3, JA3S, certificate) and a certificate row per certificate identity.
//
// What one record establishes: that a client at an address asked a server at an address for a name
// (the SNI — the client's claim), which protocol facts the sensor saw, what certificate the SERVER
// presented, and what the sensor's own chain check said. It does not establish that a certificate
// name was contacted (a certificate covering a name is not a contact — SAN names are not
// indicators), that two sessions sharing a certificate share an operator, that "ok" means benign,
// or that a JA3 hash is an identity (it is a library signature). A fingerprint is never a `hash`
// indicator — that type means a file — and is never shown as a bare hex run, or the merge would
// read it as one. The graph over these facts is a spec; every fact it needs is in the envelope.

import { createHash } from "node:crypto";
import { createCanonicalEvent, type CanonicalEventEnvelope } from "./canonicalEvent.js";
import { breakHashRuns, identityMark, keyDigest, showToken } from "./recordIdentity.js";
import { cleanIp, getCI, getPath, isObject, normalizeTime, str, type MappedEvent } from "./siemImport.js";

type Row = Record<string, unknown>;

export interface CertRef {
  kind: "fingerprint" | "identity";
  value: string;
  alg?: "sha1" | "sha256";
}

export interface CertificateFacts {
  subject?: string;
  issuer?: string;
  serial?: string;
  names?: string[];
  notBefore?: string;
  notAfter?: string;
  ca?: boolean;
}

export interface TlsObservation {
  source: "zeek-ssl" | "zeek-x509" | "suricata-tls";
  kind: "session" | "certificate";
  timestamp: string;
  uid?: string;
  /** The x509 observation id (a FUID) — a locator, never an identity. */
  locatorId?: string;
  /** Zeek x509 `client_cert` / `host_cert`: which side presented it — a keyed fact of the row. */
  role?: "client" | "server";
  certChainFuids?: string[];
  observer?: { name: string; sourceField: string };
  /** Zeek `ssl_history` `^`: the TLS client was the connection responder; src/dst already swapped. */
  directionFlipped?: boolean;
  src?: string;
  dst?: string;
  port?: number;
  sni?: string;
  /** Zeek's own check that the SNI matches the certificate (`sni_matches_cert`). */
  sniMatchesCert?: boolean;
  version?: string;
  cipher?: string;
  established?: boolean;
  resumed?: boolean;
  validation?: string;
  subject?: string;
  issuer?: string;
  ja3?: string;
  ja3s?: string;
  cert?: CertRef;
  certificate?: CertificateFacts;
  /** The CLIENT's certificate, when the record carries one (Zeek `client_*`): keyed and shown apart. */
  clientCert?: {
    subject?: string;
    issuer?: string;
    ref?: CertRef;
    chainFuids?: string[];
    facts?: CertificateFacts;
  };
}

const NAMES_KEPT_MAX = 64;
const NAMES_SHOWN_MAX = 3;
const TEXT_SHOWN_MAX = 80;
const DESCRIPTION_MAX = 600;
const CERT_ID_VERSION = "certid-v1";
const CHAIN_MAX = 16;

// ───────────────────────────── shared readers ─────────────────────────────

const text = (v: unknown): string | undefined =>
  v == null ? undefined : typeof v === "string" ? v : typeof v === "object" ? undefined : String(v);
const bool = (v: unknown): boolean | undefined =>
  typeof v === "boolean"
    ? v
    : v === "true" || v === "T"
      ? true
      : v === "false" || v === "F"
        ? false
        : undefined;
const list = (v: unknown): string[] | undefined => {
  if (v == null) return undefined;
  const arr = Array.isArray(v) ? v : [v];
  return arr.map(text).filter((s): s is string => typeof s === "string" && s.length > 0);
};

function time(v: unknown): string {
  if (typeof v === "number") {
    if (!Number.isFinite(v) || v <= 0) return "";
    const d = new Date(v > 1e12 ? v : v * 1000);
    return Number.isNaN(d.getTime()) ? "" : d.toISOString();
  }
  return normalizeTime(str(v));
}

/** A validity bound only when it PARSES as a time — normalizeTime hands unparseable text back verbatim. */
function validity(v: unknown): string | undefined {
  if (v == null) return undefined;
  const t = time(v);
  return t && !Number.isNaN(Date.parse(t)) ? t : undefined;
}

// A hex identifier in its documented grammar (hex, optionally colon- or space-separated) — or
// nothing. Deleting stray characters would let `aa:zz:bb` and `aa:bb` mint one identity.
const HEX_GRAMMAR = /^[0-9a-f]+(?:[:\s][0-9a-f]{2})*$/i;
const hexOf = (v: string): string | undefined => {
  const t = v.trim();
  return HEX_GRAMMAR.test(t) ? t.replace(/[:\s]/g, "").toLowerCase() : undefined;
};
// Only the digests a source writes as a certificate fingerprint: SHA-1 (Suricata, Zeek) and SHA-256.
const FINGERPRINT_LENGTHS = new Set([40, 64]);

// Canonical base64 only: Node's decoder is permissive, so `!!!!` would decode to zero bytes and
// every malformed value would share the empty input's sha256 — one forged identity for them all.
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

/** The sha256 of DER bytes the record carries as base64 — a real fingerprint, or nothing. */
function derFingerprint(b64: string | undefined): CertRef | undefined {
  const v = b64?.replace(/\s+/g, "");
  if (!v || !BASE64.test(v)) return undefined;
  const bytes = Buffer.from(v, "base64");
  return bytes.length
    ? { kind: "fingerprint", value: createHash("sha256").update(bytes).digest("hex"), alg: "sha256" }
    : undefined;
}

/** A source-given fingerprint: colons stripped, lowercase; the algorithm by its length. */
function fingerprint(v: unknown, allowed: ReadonlySet<number> = FINGERPRINT_LENGTHS): CertRef | undefined {
  const raw = text(v)?.trim();
  if (!raw) return undefined;
  const hex = hexOf(raw);
  // A fingerprint is exactly the digest its SOURCE writes: Suricata's `fingerprint` field is SHA-1
  // and only SHA-1 — a 64-hex value there is not a SHA-256 and must never key with one derived
  // from DER bytes; Zeek's fields may carry either.
  if (!hex || !allowed.has(hex.length)) return undefined;
  return { kind: "fingerprint", value: hex, alg: hex.length === 64 ? "sha256" : "sha1" };
}
const SURICATA_FINGERPRINT = new Set([40]);

/**
 * The identity of a certificate that carries no fingerprint: the canonical issuer and serial only —
 * the pair that names one certificate under one CA — so a record that omits an optional attribute
 * still keys the same certificate. Versioned, because it is a key.
 */
export function certIdentity(issuer: string, serial: string): string | undefined {
  const hex = hexOf(serial);
  if (!hex) return undefined;
  const canonicalSerial = hex.replace(/^0+/, "") || "0";
  return `${CERT_ID_VERSION}:${keyDigest(`${issuer.trim()}|${canonicalSerial}`)}`;
}

/** issuer + serial → a cert identity reference, or nothing when the serial is not hex. */
function identityRef(issuer: string | undefined, serial: string | undefined): CertRef | undefined {
  const value = issuer && serial ? certIdentity(issuer, serial) : undefined;
  return value ? { kind: "identity", value } : undefined;
}

/** ECS sensors name themselves in `observer.*`; `host.name` names the shipper and is a fallback. */
function observerOf(row: Row): TlsObservation["observer"] {
  for (const path of ["observer.name", "observer.hostname", "host.name", "agent.hostname"]) {
    const v = text(getCI(row, path) ?? getPath(row, path))?.trim();
    if (v) return { name: v, sourceField: path };
  }
  return undefined;
}

// ───────────────────────────── Zeek ssl.log ─────────────────────────────

export function readZeekSsl(row: Row, fallbackTs: string): TlsObservation {
  const fps = list(getCI(row, "cert_chain_fps"));
  const clientCert = clientCertOf(row);
  // Zeek marks a session whose TLS client is the connection RESPONDER with `^` in ssl_history:
  // the TLS client and server are then the reverse of originator and responder.
  const flipped = /\^/.test(text(getCI(row, "ssl_history")) ?? "");
  const clientKey = flipped ? "id.resp_h" : "id.orig_h";
  const serverKey = flipped ? "id.orig_h" : "id.resp_h";
  const port = Number(getCI(row, flipped ? "id.orig_p" : "id.resp_p"));
  return {
    source: "zeek-ssl",
    kind: "session",
    timestamp: time(getCI(row, "ts")) || fallbackTs,
    uid: text(getCI(row, "uid")),
    certChainFuids: list(getCI(row, "cert_chain_fuids")),
    observer: observerOf(row),
    src: cleanIp(str(getCI(row, clientKey))) || undefined,
    dst: cleanIp(str(getCI(row, serverKey))) || undefined,
    ...(Number.isInteger(port) && port > 0 ? { port } : {}),
    ...(flipped ? { directionFlipped: true } : {}),
    sni: text(getCI(row, "server_name")),
    sniMatchesCert: bool(getCI(row, "sni_matches_cert")),
    version: text(getCI(row, "version")),
    cipher: text(getCI(row, "cipher")),
    established: bool(getCI(row, "established")),
    resumed: bool(getCI(row, "resumed")),
    validation: text(getCI(row, "validation_status")),
    subject: text(getCI(row, "subject")),
    issuer: text(getCI(row, "issuer")),
    ja3: text(getCI(row, "ja3")),
    ja3s: text(getCI(row, "ja3s")),
    // Zeek 6 writes the chain's fingerprints; a standard ssl row carries no serial, so without them
    // the certificate has NO identity here — subject and issuer are session attributes.
    cert: fps?.length ? fingerprint(fps[0]) : undefined,
    ...(clientCert ? { clientCert } : {}),
  };
}

/** The client's certificate fields, when the record carries any. */
function clientCertOf(row: Row): TlsObservation["clientCert"] {
  const fps = list(getCI(row, "client_cert_chain_fps"));
  const out = {
    ...(text(getCI(row, "client_subject")) !== undefined
      ? { subject: text(getCI(row, "client_subject")) }
      : {}),
    ...(text(getCI(row, "client_issuer")) !== undefined ? { issuer: text(getCI(row, "client_issuer")) } : {}),
    ...(fps?.length && fingerprint(fps[0]) ? { ref: fingerprint(fps[0]) } : {}),
    ...(list(getCI(row, "client_cert_chain_fuids"))?.length
      ? { chainFuids: list(getCI(row, "client_cert_chain_fuids")) }
      : {}),
  };
  return Object.keys(out).length ? out : undefined;
}

// ───────────────────────────── Zeek x509.log ─────────────────────────────

export function readZeekX509(row: Row, fallbackTs: string): TlsObservation {
  const cert = (k: string) => getCI(row, `certificate.${k}`) ?? getPath(row, `certificate.${k}`);
  const san = (k: string) => list(getCI(row, `san.${k}`) ?? getPath(row, `san.${k}`)) ?? [];
  const issuer = text(cert("issuer"));
  const serial = text(cert("serial"));
  const fp = fingerprint(getCI(row, "fingerprint"));
  const ca = bool(getCI(row, "basic_constraints.ca") ?? getPath(row, "basic_constraints.ca"));
  return {
    source: "zeek-x509",
    kind: "certificate",
    timestamp: time(getCI(row, "ts")) || fallbackTs,
    locatorId: text(getCI(row, "id")),
    observer: observerOf(row),
    // Zeek says which side sent the certificate; a client's certificate is not "the server's".
    // `client_cert: false` alone establishes nothing (a chain member, a certificate met outside
    // TLS); "server" needs the positive pair host_cert:true + client_cert:false.
    ...(bool(getCI(row, "client_cert")) === true
      ? { role: "client" as const }
      : bool(getCI(row, "host_cert")) === true && bool(getCI(row, "client_cert")) === false
        ? { role: "server" as const }
        : {}),
    subject: text(cert("subject")),
    issuer,
    cert: fp ?? identityRef(issuer, serial),
    certificate: {
      ...(text(cert("subject")) !== undefined ? { subject: text(cert("subject")) } : {}),
      ...(issuer !== undefined ? { issuer } : {}),
      ...(serial !== undefined && hexOf(serial) ? { serial: hexOf(serial) } : {}),
      names: [...san("dns"), ...san("uri"), ...san("email"), ...san("ip")].slice(0, NAMES_KEPT_MAX),
      ...(validity(cert("not_valid_before")) ? { notBefore: validity(cert("not_valid_before")) } : {}),
      ...(validity(cert("not_valid_after")) ? { notAfter: validity(cert("not_valid_after")) } : {}),
      ...(ca !== undefined ? { ca } : {}),
    },
  };
}

// ───────────────────────────── Suricata tls ─────────────────────────────

export function readSuricataTls(row: Row, fallbackTs: string): TlsObservation {
  const tls = getCI(row, "tls");
  const t: Row = isObject(tls) ? tls : {};
  const hashOf = (v: unknown): string | undefined => (isObject(v) ? text(getCI(v, "hash")) : text(v));
  const issuer = text(getCI(t, "issuerdn")) ?? text(getCI(t, "issuer"));
  const serial = text(getCI(t, "serial"));
  // The leaf's DER bytes, when the output carries them, give a REAL sha256 — computed here. The
  // leaf is the explicit `certificate`, else the first chain entry (the same rule the certificate
  // rows follow), so a chain-only session still keys and shows the certificate it presented.
  const derFp = derFingerprint(text(getCI(t, "certificate")) ?? list(getCI(t, "chain"))?.[0]);
  const port = Number(getCI(row, "dest_port"));
  const names = list(getCI(t, "subjectaltname"));
  // A certificate object only when the record carries a certificate field: a resumed session with
  // none must not put a certificate — even an "unavailable" one — into the envelope.
  const facts: CertificateFacts = {
    ...(text(getCI(t, "subject")) !== undefined ? { subject: text(getCI(t, "subject")) } : {}),
    ...(issuer !== undefined ? { issuer } : {}),
    ...(serial !== undefined && hexOf(serial) ? { serial: hexOf(serial) } : {}),
    ...(names ? { names: names.slice(0, NAMES_KEPT_MAX) } : {}),
    ...(validity(getCI(t, "notbefore")) ? { notBefore: validity(getCI(t, "notbefore")) } : {}),
    ...(validity(getCI(t, "notafter")) ? { notAfter: validity(getCI(t, "notafter")) } : {}),
  };
  return {
    source: "suricata-tls",
    kind: "session",
    timestamp: time(getCI(row, "timestamp")) || fallbackTs,
    uid: text(getCI(row, "flow_id")),
    observer: observerOf(row),
    src: cleanIp(str(getCI(row, "src_ip"))) || undefined,
    dst: cleanIp(str(getCI(row, "dest_ip"))) || undefined,
    ...(Number.isInteger(port) && port > 0 ? { port } : {}),
    sni: text(getCI(t, "sni")),
    version: text(getCI(t, "version")),
    resumed: bool(getCI(t, "session_resumed")),
    subject: text(getCI(t, "subject")),
    issuer,
    ja3: hashOf(getCI(t, "ja3")),
    ja3s: hashOf(getCI(t, "ja3s")),
    ...(suricataClientCert(t) ? { clientCert: suricataClientCert(t) } : {}),
    cert: fingerprint(getCI(t, "fingerprint"), SURICATA_FINGERPRINT) ?? derFp ?? identityRef(issuer, serial),
    ...(Object.keys(facts).length ? { certificate: facts } : {}),
  };
}

/** The certificates a Suricata record carries as DER (`tls.certificate`, `tls.chain`) — one observation each. */
export function readSuricataCertificates(row: Row, fallbackTs: string): TlsObservation[] {
  const tls = getCI(row, "tls");
  const t: Row = isObject(tls) ? tls : {};
  // The server's certificates live under `tls`; Suricata 8 records the CLIENT's under `tls.client`
  // — its own certificate, chain and names, kept apart by role.
  const client = getCI(t, "client");
  return [
    ...derCertificates(row, t, "server", fallbackTs),
    ...(isObject(client) ? derCertificates(row, client, "client", fallbackTs) : []),
  ];
}

function derCertificates(row: Row, t: Row, role: "server" | "client", fallbackTs: string): TlsObservation[] {
  const explicit = list(getCI(t, "certificate")) ?? [];
  const chain = list(getCI(t, "chain")) ?? [];
  // The leaf is the explicit `certificate`, else chain index 0 — by ORIGIN, not by which entry
  // happened to decode: a malformed leaf must not hand its subject to the next valid entry.
  const ders = [
    ...explicit.map((d) => ({ der: d, leaf: true })),
    ...chain.map((d, i) => ({ der: d, leaf: !explicit.length && i === 0 })),
  ];
  const seen = new Set<string>();
  const out: TlsObservation[] = [];
  for (const { der, leaf } of ders.slice(0, CHAIN_MAX)) {
    const fp = derFingerprint(der)?.value;
    if (!fp || seen.has(fp)) continue;
    seen.add(fp);
    // The leaf's subject/issuer/serial are the record's own fields; a chain entry's are not
    // decoded here (no ASN.1 parser), so it carries its sha256 and nothing else. The leaf is the
    // explicit `certificate`, else the FIRST chain entry (Suricata writes the chain leaf-first).
    out.push({
      source: "suricata-tls",
      kind: "certificate",
      role,
      timestamp: time(getCI(row, "timestamp")) || fallbackTs,
      uid: text(getCI(row, "flow_id")),
      observer: observerOf(row),
      cert: { kind: "fingerprint", value: fp, alg: "sha256" },
      certificate: leaf ? suricataFacts(t) : {},
    });
  }
  return out;
}

/** Suricata 8's `tls.client`: the client's certificate, when the record carries one. */
function suricataClientCert(t: Row): TlsObservation["clientCert"] {
  const c = getCI(t, "client");
  if (!isObject(c)) return undefined;
  const fp =
    fingerprint(getCI(c, "fingerprint"), SURICATA_FINGERPRINT) ??
    derFingerprint(text(getCI(c, "certificate")) ?? list(getCI(c, "chain"))?.[0]) ??
    identityRef(text(getCI(c, "issuerdn")) ?? text(getCI(c, "issuer")), text(getCI(c, "serial")));
  // Every client fact the record carries (serial, SANs, validity) is evidence, with or without an
  // identity: a filtered record with only a serial is not a record with no client certificate.
  const facts = suricataFacts(c);
  const out = {
    ...(facts.subject !== undefined ? { subject: facts.subject } : {}),
    ...(facts.issuer !== undefined ? { issuer: facts.issuer } : {}),
    ...(fp ? { ref: fp } : {}),
    ...(Object.keys(facts).length ? { facts } : {}),
  };
  return Object.keys(out).length ? out : undefined;
}

/** The certificate facts a Suricata `tls` (or `tls.client`) object carries. */
function suricataFacts(t: Row): CertificateFacts {
  const issuer = text(getCI(t, "issuerdn")) ?? text(getCI(t, "issuer"));
  const serial = text(getCI(t, "serial"));
  const names = list(getCI(t, "subjectaltname"));
  return {
    ...(text(getCI(t, "subject")) !== undefined ? { subject: text(getCI(t, "subject")) } : {}),
    ...(issuer !== undefined ? { issuer } : {}),
    ...(serial !== undefined && hexOf(serial) ? { serial: hexOf(serial) } : {}),
    ...(names ? { names: names.slice(0, NAMES_KEPT_MAX) } : {}),
    ...(validity(getCI(t, "notbefore")) ? { notBefore: validity(getCI(t, "notbefore")) } : {}),
    ...(validity(getCI(t, "notafter")) ? { notAfter: validity(getCI(t, "notafter")) } : {}),
  };
}

// ───────────────────────────── folding ─────────────────────────────

export interface TlsTally {
  first: TlsObservation;
  count: number;
  firstTs: string;
  /** The overflow row: shapes beyond TLS_SHAPES_MAX folded here; `first` carries no facts. */
  overflow?: boolean;
}

// Every keyed fact, absent as `-`, an empty string as `e:` (its own value), free text as a digest of
// the whole text: an SNI or a subject that differs only past the shown width is another row.
const seg = (v: string | number | boolean | undefined): string =>
  v === undefined ? "-" : v === "" ? "e:" : typeof v === "string" ? `t:${keyDigest(v)}` : String(v);
const short = (v: string | number | boolean | undefined): string =>
  v === undefined ? "-" : v === "" ? "e:" : String(v);

export function tlsKey(o: TlsObservation): string {
  const sensor = o.observer ? `t:${keyDigest(o.observer.name)}` : "-";
  const cert = o.cert ? `${o.cert.kind}:${o.cert.value}` : "-";
  // The source kind is a keyed fact: a Zeek row and a Suricata row of one shape are two
  // observations by two tools, each with its own provenance.
  if (o.kind === "certificate") return `cert|${o.source}|${sensor}|${short(o.role)}|${cert}`;
  return [
    "tls",
    o.source,
    sensor,
    short(o.src),
    short(o.dst),
    short(o.port),
    seg(o.sni),
    seg(o.version),
    seg(o.cipher),
    short(o.established),
    short(o.resumed),
    seg(o.validation),
    seg(o.ja3),
    seg(o.ja3s),
    seg(o.subject),
    seg(o.issuer),
    short(o.sniMatchesCert),
    short(o.directionFlipped),
    cert,
    o.clientCert ? `c:${keyDigest(JSON.stringify(o.clientCert))}` : "-",
    // Certificate FACTS with no identity (a SAN list, a serial, validity) are evidence too: a
    // record carrying them and one without are two rows.
    o.certificate && Object.keys(o.certificate).length
      ? `f:${keyDigest(JSON.stringify(o.certificate))}`
      : "-",
  ].join("|");
}

/** Distinct row shapes one import keeps; every later NEW shape folds into one overflow row per kind. */
export const TLS_SHAPES_MAX = 8192;
// Partitioned by kind AND source: the overflow row's provenance names the tool that produced it.
const OVERFLOW_KEY = (o: Pick<TlsObservation, "kind" | "source">) =>
  `${o.kind === "session" ? "tls" : "cert"}|${o.source}|overflow`;

export function tallyTls(o: TlsObservation, sink: Map<string, TlsTally>): void {
  // A certificate record with no identity yields no certificate row: its facts are on the session.
  if (o.kind === "certificate" && !o.cert) return;
  const key = tlsKey(o);
  const existing = sink.get(key);
  if (existing) {
    existing.count += 1;
    if (o.timestamp && (!existing.firstTs || o.timestamp < existing.firstTs)) existing.firstTs = o.timestamp;
    return;
  }
  // The shapes are attacker-controlled (a server can present a new subject per session), so the
  // map is bounded DURING ingestion, not after: past the cap a new shape joins one overflow row
  // that shows no shape as representative.
  if (sink.size >= TLS_SHAPES_MAX) {
    const ok = OVERFLOW_KEY(o);
    const over = sink.get(ok);
    if (over) {
      over.count += 1;
      if (o.timestamp && o.timestamp < over.firstTs) over.firstTs = o.timestamp;
    } else
      sink.set(ok, {
        first: { source: o.source, kind: o.kind, timestamp: o.timestamp },
        count: 1,
        firstTs: o.timestamp,
        overflow: true,
      });
    return;
  }
  sink.set(key, { first: o, count: 1, firstTs: o.timestamp });
}

// ───────────────────────────── words ─────────────────────────────

const show = (v: string): string => {
  const shown = breakHashRuns(showToken(v));
  return shown.length > TEXT_SHOWN_MAX ? `${shown.slice(0, TEXT_SHOWN_MAX - 1)}…` : shown;
};
const ends = (hex: string): string => (hex.length > 12 ? `${hex.slice(0, 8)}…${hex.slice(-4)}` : hex);

/** A certificate reference as words: a fingerprint by its ends, a cert identity by its ends. */
const refWords = (r: CertRef): string =>
  r.kind === "identity"
    ? `cert identity ${breakHashRuns(r.value)}`
    : `${r.alg === "sha256" ? "sha256" : "fp"} ${ends(r.value)}`;

function certWords(o: TlsObservation): string {
  const ref = !o.cert ? "identity unavailable" : refWords(o.cert);
  return [
    o.subject !== undefined ? `subject ${show(o.subject)}` : "",
    o.issuer !== undefined ? `issuer ${show(o.issuer)}` : "",
    ref,
  ]
    .filter(Boolean)
    .join("; ");
}

function sessionTags(o: TlsObservation): string[] {
  const tags: string[] = [];
  tags.push(o.sni !== undefined ? `sni: ${show(o.sni)}` : "no SNI");
  const proto = [
    o.version !== undefined ? show(o.version) : "",
    o.cipher !== undefined ? `cipher ${show(o.cipher)}` : "",
  ]
    .filter(Boolean)
    .join(", ");
  if (proto) tags.push(proto);
  // A chain FUID is Zeek saying it saw a certificate, even when the export kept no other field.
  const hasCert =
    o.subject !== undefined ||
    o.issuer !== undefined ||
    o.cert !== undefined ||
    (o.certChainFuids?.length ?? 0) > 0 ||
    Object.keys(o.certificate ?? {}).length > 0;
  tags.push(hasCert ? `cert: ${certWords(o)}` : "no server certificate observed in this record");
  if (o.clientCert) {
    const cc = o.clientCert;
    const ref = cc.ref ? refWords(cc.ref) : cc.chainFuids?.length ? "identity unavailable" : "";
    tags.push(
      `client cert: ${[cc.subject !== undefined ? `subject ${show(cc.subject)}` : "", cc.issuer !== undefined ? `issuer ${show(cc.issuer)}` : "", ref].filter(Boolean).join("; ")}`,
    );
  }
  if (o.directionFlipped) tags.push("TLS client was the connection responder");
  if (o.validation !== undefined) tags.push(`chain check: ${show(o.validation)}`);
  if (o.sniMatchesCert !== undefined)
    tags.push(o.sniMatchesCert ? "SNI matches the certificate" : "SNI does not match the certificate");
  if (o.established === false) tags.push("not established");
  if (o.resumed === true) tags.push("session resumed");
  if (o.ja3 !== undefined) tags.push(`ja3 ${ends(hexOf(o.ja3) ?? show(o.ja3))}`);
  if (o.ja3s !== undefined) tags.push(`ja3s ${ends(hexOf(o.ja3s) ?? show(o.ja3s))}`);
  return tags;
}

function certificateTag(o: TlsObservation): string {
  const c = o.certificate ?? {};
  const names = c.names ?? [];
  const shownNames = names.slice(0, NAMES_SHOWN_MAX).map(show).join(", ");
  const more = names.length > NAMES_SHOWN_MAX ? ` (+${names.length - NAMES_SHOWN_MAX} more)` : "";
  return [
    `certificate: ${o.role ? `${o.role}-presented; ` : ""}${certWords({ ...o, subject: undefined, issuer: undefined })}`,
    c.subject !== undefined ? `subject ${show(c.subject)}` : "",
    c.issuer !== undefined ? `issuer ${show(c.issuer)}` : "",
    c.notBefore || c.notAfter ? `valid ${show(c.notBefore ?? "?")}–${show(c.notAfter ?? "?")}` : "",
    names.length ? `covers ${names.length} name${names.length === 1 ? "" : "s"}: ${shownNames}${more}` : "",
  ]
    .filter(Boolean)
    .join("; ");
}

/** One bracketed tag, clipped inside its brackets so it can never end half-open. */
function clipTag(tag: string, room: number): string {
  const inner = tag.length + 2 <= room ? tag : `${tag.slice(0, Math.max(0, room - 3))}…`;
  return `[${inner}]`;
}

// ───────────────────────────── rows ─────────────────────────────

function envelopeOf(o: TlsObservation, count: number): CanonicalEventEnvelope {
  const locator = {
    ...(o.uid ? { uid: o.uid } : {}),
    ...(o.locatorId ? { id: o.locatorId } : {}),
    ...(o.certChainFuids?.length ? { certChainFuids: o.certChainFuids } : {}),
  };
  return createCanonicalEvent({
    event: { category: "network", type: o.kind === "session" ? "tls" : "certificate" },
    ...(o.src ? { actor: { kind: "network", address: o.src } } : {}),
    ...(o.dst ? { target: { kind: "network", address: o.dst, ...(o.port ? { port: o.port } : {}) } } : {}),
    ...(o.src || o.dst
      ? {
          network: {
            ...(o.src ? { source: { address: o.src } } : {}),
            ...(o.dst ? { destination: { address: o.dst, ...(o.port ? { port: o.port } : {}) } } : {}),
            protocol: "tls",
          },
        }
      : {}),
    tls: {
      ...(o.sni !== undefined ? { sni: o.sni } : {}),
      ...(o.version !== undefined ? { version: o.version } : {}),
      ...(o.cipher !== undefined ? { cipher: o.cipher } : {}),
      ...(o.established !== undefined ? { established: o.established } : {}),
      ...(o.resumed !== undefined ? { resumed: o.resumed } : {}),
      ...(o.validation !== undefined ? { validation: o.validation } : {}),
      ...(o.sniMatchesCert !== undefined ? { sniMatchesCert: o.sniMatchesCert } : {}),
      ...(o.directionFlipped ? { directionFlipped: true } : {}),
      ...(o.ja3 !== undefined ? { ja3: o.ja3 } : {}),
      ...(o.ja3s !== undefined ? { ja3s: o.ja3s } : {}),
      ...(o.role ? { certificateRole: o.role } : {}),
      ...(o.subject !== undefined || o.issuer !== undefined || o.cert || o.certificate
        ? {
            certificate: {
              ...(o.cert?.kind === "fingerprint"
                ? { fingerprint: o.cert.value, fingerprintAlg: o.cert.alg }
                : {}),
              identity: o.cert?.kind === "identity" ? o.cert.value : o.cert ? o.cert.value : "unavailable",
              ...(o.subject !== undefined ? { subject: o.subject } : {}),
              ...(o.issuer !== undefined ? { issuer: o.issuer } : {}),
              ...o.certificate,
            },
          }
        : {}),
      ...(o.clientCert
        ? {
            clientCertificate: {
              ...(o.clientCert.subject !== undefined ? { subject: o.clientCert.subject } : {}),
              ...(o.clientCert.issuer !== undefined ? { issuer: o.clientCert.issuer } : {}),
              ...(o.clientCert.ref?.kind === "fingerprint"
                ? { fingerprint: o.clientCert.ref.value, fingerprintAlg: o.clientCert.ref.alg }
                : {}),
              ...(o.clientCert.ref?.kind === "identity" ? { identity: o.clientCert.ref.value } : {}),
              ...(o.clientCert.facts?.serial !== undefined ? { serial: o.clientCert.facts.serial } : {}),
              ...(o.clientCert.facts?.names ? { names: o.clientCert.facts.names } : {}),
              ...(o.clientCert.facts?.notBefore ? { notBefore: o.clientCert.facts.notBefore } : {}),
              ...(o.clientCert.facts?.notAfter ? { notAfter: o.clientCert.facts.notAfter } : {}),
              ...(o.clientCert.chainFuids ? { chainFuids: o.clientCert.chainFuids } : {}),
            },
          }
        : {}),
      ...(o.observer ? { observer: o.observer } : {}),
      ...(Object.keys(locator).length ? { locator } : {}),
      records: count,
    },
    time: { observed: o.timestamp, normalized: o.timestamp },
    evidence: { rawRecords: [{ source: o.source, locator: o.uid ?? o.locatorId ?? tlsKey(o) }] },
    producer: { importer: "network", parserVersion: "1", mappingVersion: "tls-v1" },
    rawFieldMap: {
      "time.observed": [o.source === "suricata-tls" ? "timestamp" : "ts"],
      ...(o.sni !== undefined
        ? { "tls.sni": [o.source === "suricata-tls" ? "tls.sni" : "server_name"] }
        : {}),
    },
  });
}

function mapTlsRow(t: TlsTally): MappedEvent {
  const o = t.first;
  const key = t.overflow ? OVERFLOW_KEY(o) : tlsKey(o);
  const mark = identityMark(key);
  let description: string;
  let lossy: boolean;
  if (t.overflow) {
    const what = o.kind === "session" ? "TLS" : "certificate";
    description = `[overflow: ${t.count} ${what} record${t.count === 1 ? "" : "s"} in shapes beyond ${TLS_SHAPES_MAX} distinct ones folded; none shown]`;
    lossy = true;
  } else if (o.kind === "certificate") {
    // Attributes are the FIRST observation's; the row is lossy by definition.
    const tag = certificateTag(o);
    const tail = ` — ${t.count} certificate record${t.count === 1 ? "" : "s"}`;
    description = `${clipTag(tag, DESCRIPTION_MAX - tail.length - mark.length)}${tail}`;
    lossy = true;
  } else {
    const head = `TLS ${o.src ?? "?"} → ${o.dst ?? "?"}${o.port ? `:${o.port}` : ""}`;
    const tail = ` — ${t.count} TLS record${t.count === 1 ? "" : "s"}`;
    const tags = sessionTags(o);
    // Every session row carries the mark: the key holds facts the words never show verbatim (the
    // observer, `established: true`, `resumed: false`, a hash's middle), and two rows that differ
    // only there would read alike after import.
    lossy = true;
    let body = `${head} ${tags.map((x) => `[${x}]`).join(" ")}${tail}`;
    if (body.length > DESCRIPTION_MAX - mark.length) {
      // Pack whole tags into what is left; a half-open tag would hide the fact it names.
      const kept: string[] = [];
      let room = DESCRIPTION_MAX - mark.length - head.length - tail.length;
      for (const x of tags) {
        if (x.length + 3 > room) continue;
        kept.push(`[${x}]`);
        room -= x.length + 3;
      }
      body = `${head} ${kept.join(" ")}${tail}`;
      lossy = true;
    }
    description = body;
  }
  return {
    timestamp: t.firstTs,
    description: lossy ? `${description}${mark}` : description,
    severity: "Info",
    mitre: [],
    canonical: envelopeOf(o, t.count),
    aggKey: key,
    sources: [o.source.startsWith("zeek") ? "Zeek" : "Suricata"],
    ...(o.src ? { srcIp: o.src } : {}),
    ...(o.dst ? { dstIp: o.dst } : {}),
    ...(o.port ? { port: o.port } : {}),
  };
}

/** The most-seen relationships first, up to `budget` — a scanner's one-off SNIs cannot push out the persistent ones. */
export function mapTlsRows(sink: Map<string, TlsTally>, budget: number): MappedEvent[] {
  return [...sink.values()]
    .sort((a, b) => b.count - a.count || a.firstTs.localeCompare(b.firstTs))
    .slice(0, budget)
    .map(mapTlsRow);
}
