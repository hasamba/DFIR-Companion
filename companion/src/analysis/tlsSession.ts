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
  certChainFuids?: string[];
  observer?: { name: string; sourceField: string };
  src?: string;
  dst?: string;
  port?: number;
  sni?: string;
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
}

const NAMES_KEPT_MAX = 64;
const NAMES_SHOWN_MAX = 3;
const TEXT_SHOWN_MAX = 80;
const DESCRIPTION_MAX = 600;
const CERT_ID_VERSION = "certid-v1";

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

const hexOf = (v: string): string => v.replace(/[^0-9a-f]/gi, "").toLowerCase();

/** A source-given fingerprint: colons stripped, lowercase; the algorithm by its length. */
function fingerprint(v: unknown): CertRef | undefined {
  const raw = text(v)?.trim();
  if (!raw) return undefined;
  const hex = hexOf(raw);
  return hex ? { kind: "fingerprint", value: hex, alg: hex.length === 64 ? "sha256" : "sha1" } : undefined;
}

/**
 * The identity of a certificate that carries no fingerprint: the canonical issuer and serial only —
 * the pair that names one certificate under one CA — so a record that omits an optional attribute
 * still keys the same certificate. Versioned, because it is a key.
 */
export function certIdentity(issuer: string, serial: string): string {
  const canonicalSerial = hexOf(serial).replace(/^0+/, "") || "0";
  return `${CERT_ID_VERSION}:${keyDigest(`${issuer.trim()}|${canonicalSerial}`)}`;
}

/** ECS sensors name themselves in `observer.*`; `host.name` names the shipper and is a fallback. */
function observerOf(row: Row): TlsObservation["observer"] {
  for (const path of ["observer.name", "observer.hostname", "host.name", "agent.hostname"]) {
    const v = text(getPath(row, path))?.trim();
    if (v) return { name: v, sourceField: path };
  }
  return undefined;
}

// ───────────────────────────── Zeek ssl.log ─────────────────────────────

export function readZeekSsl(row: Row, fallbackTs: string): TlsObservation {
  const fps = list(getCI(row, "cert_chain_fps"));
  const port = Number(getCI(row, "id.resp_p"));
  return {
    source: "zeek-ssl",
    kind: "session",
    timestamp: time(getCI(row, "ts")) || fallbackTs,
    uid: text(getCI(row, "uid")),
    certChainFuids: list(getCI(row, "cert_chain_fuids")),
    observer: observerOf(row),
    src: cleanIp(str(getCI(row, "id.orig_h"))) || undefined,
    dst: cleanIp(str(getCI(row, "id.resp_h"))) || undefined,
    ...(Number.isInteger(port) && port > 0 ? { port } : {}),
    sni: text(getCI(row, "server_name")),
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
  };
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
    subject: text(cert("subject")),
    issuer,
    cert: fp ?? (issuer && serial ? { kind: "identity", value: certIdentity(issuer, serial) } : undefined),
    certificate: {
      ...(text(cert("subject")) !== undefined ? { subject: text(cert("subject")) } : {}),
      ...(issuer !== undefined ? { issuer } : {}),
      ...(serial !== undefined ? { serial: hexOf(serial) } : {}),
      names: [...san("dns"), ...san("uri"), ...san("email"), ...san("ip")].slice(0, NAMES_KEPT_MAX),
      ...(cert("not_valid_before") != null ? { notBefore: time(cert("not_valid_before")) } : {}),
      ...(cert("not_valid_after") != null ? { notAfter: time(cert("not_valid_after")) } : {}),
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
  const der = text(getCI(t, "certificate"));
  // The leaf's DER bytes, when the output carries them, give a REAL sha256 — computed here.
  const derFp = der
    ? {
        kind: "fingerprint" as const,
        value: createHash("sha256").update(Buffer.from(der, "base64")).digest("hex"),
        alg: "sha256" as const,
      }
    : undefined;
  const port = Number(getCI(row, "dest_port"));
  const names = list(getCI(t, "subjectaltname"));
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
    cert:
      fingerprint(getCI(t, "fingerprint")) ??
      derFp ??
      (issuer && serial ? { kind: "identity", value: certIdentity(issuer, serial) } : undefined),
    certificate: {
      ...(text(getCI(t, "subject")) !== undefined ? { subject: text(getCI(t, "subject")) } : {}),
      ...(issuer !== undefined ? { issuer } : {}),
      ...(serial !== undefined ? { serial: hexOf(serial) } : {}),
      ...(names ? { names: names.slice(0, NAMES_KEPT_MAX) } : {}),
      ...(getCI(t, "notbefore") != null ? { notBefore: time(getCI(t, "notbefore")) } : {}),
      ...(getCI(t, "notafter") != null ? { notAfter: time(getCI(t, "notafter")) } : {}),
    },
  };
}

// ───────────────────────────── folding ─────────────────────────────

export interface TlsTally {
  first: TlsObservation;
  count: number;
  firstTs: string;
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
  if (o.kind === "certificate") return `cert|${sensor}|${cert}`;
  return [
    "tls",
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
    cert,
  ].join("|");
}

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
  sink.set(key, { first: o, count: 1, firstTs: o.timestamp });
}

// ───────────────────────────── words ─────────────────────────────

const show = (v: string): string => {
  const shown = breakHashRuns(showToken(v));
  return shown.length > TEXT_SHOWN_MAX ? `${shown.slice(0, TEXT_SHOWN_MAX - 1)}…` : shown;
};
const isLossy = (v: string | undefined): boolean => v !== undefined && show(v) !== v;
const ends = (hex: string): string => (hex.length > 12 ? `${hex.slice(0, 8)}…${hex.slice(-4)}` : hex);

function certWords(o: TlsObservation): string {
  const ref = !o.cert
    ? "identity unavailable"
    : o.cert.kind === "identity"
      ? `cert identity ${o.cert.value}`
      : `${o.cert.alg === "sha256" ? "sha256" : "fp"} ${ends(o.cert.value)}`;
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
  const hasCert = o.subject !== undefined || o.issuer !== undefined || o.cert !== undefined;
  tags.push(hasCert ? `cert: ${certWords(o)}` : "no certificate observed in this record");
  if (o.validation !== undefined) tags.push(`chain check: ${show(o.validation)}`);
  if (o.established === false) tags.push("not established");
  if (o.resumed === true) tags.push("session resumed");
  if (o.ja3 !== undefined) tags.push(`ja3 ${ends(hexOf(o.ja3) || show(o.ja3))}`);
  if (o.ja3s !== undefined) tags.push(`ja3s ${ends(hexOf(o.ja3s) || show(o.ja3s))}`);
  return tags;
}

function certificateTag(o: TlsObservation): string {
  const c = o.certificate ?? {};
  const names = c.names ?? [];
  const shownNames = names.slice(0, NAMES_SHOWN_MAX).map(show).join(", ");
  const more = names.length > NAMES_SHOWN_MAX ? ` (+${names.length - NAMES_SHOWN_MAX} more)` : "";
  return [
    `certificate: ${certWords({ ...o, subject: undefined, issuer: undefined })}`,
    c.subject !== undefined ? `subject ${show(c.subject)}` : "",
    c.issuer !== undefined ? `issuer ${show(c.issuer)}` : "",
    c.notBefore || c.notAfter ? `valid ${c.notBefore ?? "?"}–${c.notAfter ?? "?"}` : "",
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
      ...(o.ja3 !== undefined ? { ja3: o.ja3 } : {}),
      ...(o.ja3s !== undefined ? { ja3s: o.ja3s } : {}),
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
  const key = tlsKey(o);
  const mark = identityMark(key);
  let description: string;
  let lossy: boolean;
  if (o.kind === "certificate") {
    // Attributes are the FIRST observation's; the row is lossy by definition.
    const tag = certificateTag(o);
    const tail = ` — ${t.count} certificate record${t.count === 1 ? "" : "s"}`;
    description = `${clipTag(tag, DESCRIPTION_MAX - tail.length - mark.length)}${tail}`;
    lossy = true;
  } else {
    const head = `TLS ${o.src ?? "?"} → ${o.dst ?? "?"}${o.port ? `:${o.port}` : ""}`;
    const tail = ` — ${t.count} TLS record${t.count === 1 ? "" : "s"}`;
    const tags = sessionTags(o);
    lossy =
      [o.sni, o.version, o.cipher, o.validation, o.subject, o.issuer].some(isLossy) ||
      o.ja3 !== undefined ||
      o.ja3s !== undefined ||
      o.cert !== undefined;
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
