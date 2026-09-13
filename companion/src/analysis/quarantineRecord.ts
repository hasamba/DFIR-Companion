// A macOS quarantine record, read for what it establishes (#933 item 7, prerequisite phase).
//
// Two artifacts carry the mark-of-the-web: the LSQuarantineEventsV2 database (one row per download
// event: which agent fetched which resource, from which referring page, when, and an event UUID)
// and the `com.apple.quarantine` extended attribute on the file itself (flags, a Unix-epoch time,
// the agent, and the same UUID). The row used to show the URL's last path segment as "the file",
// key on `agent|host` while showing the full URLs (two downloads from one host folded), and hand
// the database's Cocoa-epoch timestamp to a Unix-epoch parser.
//
// One record establishes: that an agent recorded a download event of a RESOURCE (a URL) from a
// referring ORIGIN, of a KIND (web download, email attachment, …), at a time whose representation
// is the record's own. It does not establish which local file that was (the database keeps no
// path; the xattr on the file carries the UUID that joins them), that the file ran, or that it was
// malicious. Every time value is decoded by its DECLARED representation — the native column is
// Cocoa seconds, the xattr's field is Unix hex seconds, an ISO string is ISO, and a number under a
// generic header establishes no epoch unless the import declares one — never by its magnitude.

import { isIP } from "node:net";
import { breakHashRuns, identityMark, keyDigest, packTags, showToken } from "./recordIdentity.js";
import { addIoc, getCI, normalizeTime, type MappedEvent, type SiemIoc } from "./siemImport.js";
import { createCanonicalEvent } from "./canonicalEvent.js";

type Row = Record<string, unknown>;

export interface QuarantineTime {
  iso: string;
  encoding: "cocoa-seconds" | "iso" | "unix-seconds" | "unix-ms" | "unreadable";
}

/** Seconds between the Unix epoch and Apple's Core Data / Cocoa epoch (2001-01-01T00:00:00Z). */
const COCOA_EPOCH_OFFSET = 978307200;
const NATIVE_TIME_HEADER = /^lsquarantinetimestamp$/i;
// A converted dump declares its epoch in the column name; `timestamp`/`time` declare nothing.
const UNIX_SECONDS_HEADER = /^(?:unix_?time|unix_?seconds|epoch|epoch_?seconds)$/i;
const UNIX_MS_HEADER = /^(?:unix_?ms|unix_?millis|epoch_?ms|epoch_?millis)$/i;
const EPOCH_WORDS = {
  cocoa: "Cocoa seconds expected",
  "unix-seconds": "Unix seconds expected",
  "unix-ms": "Unix milliseconds expected",
  none: "the column names no epoch (a converted dump names it: unix_time or unix_ms)",
};
// Every column readQuarantineTime can decode, native first, then each epoch spelling declaredEpoch names.
const TIME_HEADERS = [
  "LSQuarantineTimeStamp",
  "timestamp",
  "time",
  "unix_time",
  "unixtime",
  "unix_seconds",
  "epoch",
  "epoch_seconds",
  "unix_ms",
  "unixms",
  "unix_millis",
  "epoch_ms",
  "epoch_millis",
];
const NUMERIC = /^-?\d+(?:\.\d+)?$/;
const ISO_8601 = /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2})(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})$/;
const DESCRIPTION_MAX = 600;
const URL_SHOWN_MAX = 200;
const TEXT_SHOWN_MAX = 80;
/** A URL indicator is the record's whole URL or nothing — a prefix would be a URL the record never held. */
const URL_IOC_MAX = 500;

function isoOf(ms: number): string {
  const d = new Date(ms);
  return Number.isNaN(d.getTime()) ? "" : d.toISOString();
}

/** The epoch a column name declares, or none: `timestamp`/`time` may alias the native column. */
export function declaredEpoch(header: string): "cocoa" | "unix-seconds" | "unix-ms" | undefined {
  const h = header.trim();
  if (NATIVE_TIME_HEADER.test(h)) return "cocoa";
  if (UNIX_SECONDS_HEADER.test(h)) return "unix-seconds";
  if (UNIX_MS_HEADER.test(h)) return "unix-ms";
  return undefined;
}

/**
 * The record's time by its declared representation. `header` is the column the value came from:
 * the native `LSQuarantineTimeStamp` holds Cocoa seconds; a converted dump names its epoch in the
 * column (`unix_time`, `unix_ms`); a generic header (`timestamp`, `time`) may be an aliased native
 * column or a converted one, and establishes no epoch on its own.
 */
export function readQuarantineTime(raw: string, header: string): QuarantineTime {
  const text = raw.trim();
  if (!text) return { iso: "", encoding: "unreadable" };
  if (!NUMERIC.test(text)) {
    // ISO-8601 with an explicit offset or Z, and nothing else: "May 7, 2026 @ 16:31" carries no
    // zone and no declared representation, so it establishes no instant.
    const m = ISO_8601.exec(text);
    if (!m) return { iso: "", encoding: "unreadable" };
    // A real calendar date: Date.parse rolls "04-31" into May and accepts "02-29" in a common year.
    const [y, mo, d, hh, mi, ss] = [m[1], m[2], m[3], m[4], m[5], m[6] ?? "0"].map(Number);
    const probe = new Date(Date.UTC(y, mo - 1, d, hh, mi, ss));
    if (probe.getUTCMonth() !== mo - 1 || probe.getUTCDate() !== d || hh > 23 || mi > 59 || ss > 60)
      return { iso: "", encoding: "unreadable" };
    const iso = normalizeTime(text);
    return iso && !Number.isNaN(Date.parse(iso))
      ? { iso, encoding: "iso" }
      : { iso: "", encoding: "unreadable" };
  }
  const n = Number(text);
  const encoding = declaredEpoch(header);
  if (!encoding || !Number.isFinite(n) || n < 0) return { iso: "", encoding: "unreadable" };
  // A value the epoch cannot express (out of Date's range) is unreadable, never a readable blank.
  const iso =
    encoding === "cocoa"
      ? isoOf((n + COCOA_EPOCH_OFFSET) * 1000)
      : encoding === "unix-ms"
        ? isoOf(n)
        : isoOf(n * 1000);
  if (!iso) return { iso: "", encoding: "unreadable" };
  return { iso, encoding: encoding === "cocoa" ? "cocoa-seconds" : encoding };
}

/** Apple's LSQuarantineType, and nothing else. */
const QUARANTINE_TYPES: Record<number, string> = {
  0: "web download",
  1: "other download",
  2: "email attachment",
  3: "message attachment",
  4: "calendar attachment",
  5: "other attachment",
};

export function readQuarantineType(raw: string): { typeNumber?: number; kind: string; typeRaw?: string } {
  const text = raw.trim();
  if (!text) return { kind: "kind not in this record" };
  // A value that is not a type number is evidence of its own: kept raw, never folded into a phrase.
  if (!/^\d{1,4}$/.test(text)) return { kind: "kind not readable", typeRaw: text };
  const typeNumber = Number(text);
  return { typeNumber, kind: QUARANTINE_TYPES[typeNumber] ?? `type ${typeNumber} (not in the table)` };
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** The one UUID grammar, lowercased — or nothing: an invalid id is never a join handle. */
export function canonicalUuid(raw: string): string | undefined {
  const t = raw.trim();
  return UUID_RE.test(t) ? t.toLowerCase() : undefined;
}

// The xattr's flag bits, from Apple's QuarantineSPI.h. Every other bit is shown as hex, named nothing.
const XATTR_FLAGS: Array<[number, string]> = [
  [0x0001, "download"],
  [0x0002, "sandbox"],
  [0x0004, "hard"],
  [0x0040, "user-approved"],
];

export interface QuarantineXattr {
  flags: { raw: number; named: string[]; unnamed?: string };
  time: { iso: string; encoding: "unix-hex-seconds" };
  agent: string;
  /** The canonical UUID, or undefined when the 4th field is not one. */
  eventId?: string;
  words: string;
}

/** `<flags hex>;<unix hex seconds>;<agent>;<uuid>` — decoded per its documented form, or null. */
export function readQuarantineXattr(raw: string): QuarantineXattr | null {
  const parts = raw.trim().split(";");
  if (parts.length < 4) return null;
  const [flagsHex, timeHex, agentRaw, idRaw] = parts;
  if (!/^[0-9a-f]{1,8}$/i.test(flagsHex) || !/^[0-9a-f]{1,16}$/i.test(timeHex)) return null;
  const flagsRaw = parseInt(flagsHex, 16);
  const named = XATTR_FLAGS.filter(([bit]) => flagsRaw & bit).map(([, name]) => name);
  // Unsigned: a 32-bit flag word's high bit must never read as a negative mask.
  const unnamedBits = XATTR_FLAGS.reduce((rest, [bit]) => (rest & ~bit) >>> 0, flagsRaw >>> 0);
  const unnamed = unnamedBits ? `0x${unnamedBits.toString(16).padStart(4, "0")}` : undefined;
  const iso = isoOf(parseInt(timeHex, 16) * 1000);
  const agent = breakHashRuns(showToken(agentRaw)).slice(0, TEXT_SHOWN_MAX);
  const eventId = canonicalUuid(idRaw);
  const flagWords = `${named.join(", ") || "no named flag"}${unnamed ? ` (+${unnamed})` : ""}`;
  const idWords = eventId ?? `not decodable: ${breakHashRuns(showToken(idRaw)).slice(0, TEXT_SHOWN_MAX)}`;
  return {
    flags: { raw: flagsRaw, named, ...(unnamed ? { unnamed } : {}) },
    time: { iso, encoding: "unix-hex-seconds" },
    agent,
    ...(eventId ? { eventId } : {}),
    words: `quarantine mark: ${flagWords}; agent ${agent}; marked ${iso || "(time not readable)"} (Unix hex); event ${idWords}`,
  };
}

// ───────────────────────────── the database row ─────────────────────────────

export interface QuarantineEnvelope {
  kind: string;
  typeNumber?: number;
  /** A type value that is not a type number, as recorded. */
  typeRaw?: string;
  agent?: string;
  bundleId?: string;
  dataUrl?: string;
  originUrl?: string;
  originTitle?: string;
  senderName?: string;
  senderAddress?: string;
  eventId?: string;
  eventIdRaw?: string;
  timeEncoding: QuarantineTime["encoding"];
  timeRaw?: string;
  /** Why a URL minted no `url` indicator (its host still does). */
  urlIndicator?: string;
  localFile: "not in this record";
  /** An overflow row: records with this identifier beyond the variant budget folded; nothing shown. */
  folded?: boolean;
}

export interface QuarantineRow extends MappedEvent {
  envelope: QuarantineEnvelope;
  /** The canonical UUID and the digest of every shown fact — for boundQuarantineVariants. */
  eventId?: string;
  factsDigest: string;
  /** This row's own indicators — merged into the file sink only for rows that survive the bound. */
  iocs: SiemIoc[];
}

const text = (v: unknown): string => (typeof v === "string" ? v : v == null ? "" : String(v));
const first = (rec: Row, keys: readonly string[]): { value: string; header: string } => {
  for (const k of keys) {
    const v = getCI(rec, k);
    if (v != null && text(v).trim() !== "") return { value: text(v).trim(), header: k };
  }
  return { value: "", header: "" };
};
const show = (v: string, max = TEXT_SHOWN_MAX): string => {
  const shown = breakHashRuns(showToken(v));
  return shown.length > max ? `${shown.slice(0, max - 1)}…` : shown;
};

/**
 * The URL and its host as indicators: an address is `ip`, a name is `domain`; http(s)/ftp only. A
 * URL past URL_IOC_MAX mints no `url` indicator (the host still does) and says so.
 */
function mintUrl(sink: Map<string, SiemIoc>, url: string, schemes: RegExp): "minted" | "omitted" | undefined {
  if (!schemes.test(url)) return undefined;
  let host = "";
  try {
    host = new URL(url).hostname;
  } catch {
    return undefined;
  }
  const urlIoc = url.length <= URL_IOC_MAX;
  if (urlIoc) addIoc(sink, "url", url);
  const bare = host.startsWith("[") ? host.slice(1, -1) : host;
  if (bare) {
    if (isIP(bare)) addIoc(sink, "ip", bare);
    else addIoc(sink, "domain", bare.toLowerCase());
  }
  return urlIoc ? "minted" : "omitted";
}

/** One LSQuarantineEventsV2 record → a row that says what the record establishes. */
export function quarantineOverlay(
  rec: Row,
  fileSink: Map<string, SiemIoc>,
  opts: { deferIocs?: boolean } = {},
): QuarantineRow {
  // Indicators go to the row first; the importer merges them after the per-UUID bound, so a flood
  // of variants under one identifier cannot fill the file's indicator budget either.
  const sink = opts.deferIocs ? new Map<string, SiemIoc>() : fileSink;
  const time = first(rec, TIME_HEADERS);
  const when = readQuarantineTime(time.value, time.header);
  const type = readQuarantineType(first(rec, ["LSQuarantineTypeNumber", "type"]).value);
  const agent = first(rec, ["LSQuarantineAgentName", "agent"]).value;
  const bundleId = first(rec, ["LSQuarantineAgentBundleIdentifier", "bundle_id"]).value;
  const dataUrl = first(rec, ["LSQuarantineDataURLString", "data_url", "url"]).value;
  const originUrl = first(rec, ["LSQuarantineOriginURLString", "origin_url", "referrer"]).value;
  const originTitle = first(rec, ["LSQuarantineOriginTitle", "origin_title"]).value;
  const senderName = first(rec, ["LSQuarantineSenderName", "sender"]).value;
  const senderAddress = first(rec, ["LSQuarantineSenderAddress", "sender_address"]).value;
  // Only the native column and the declared alias: a generic `id` is export metadata, not an event.
  const idRaw = first(rec, ["LSQuarantineEventIdentifier", "event_id"]).value;
  const eventId = canonicalUuid(idRaw);

  // Indicators: the resource the agent fetched, and a lure page — only under a fetchable scheme.
  const urlIndicators = [
    mintUrl(sink, dataUrl, /^(?:https?|ftp):\/\//i),
    mintUrl(sink, originUrl, /^https?:\/\//i),
  ];
  const urlOmitted = urlIndicators.includes("omitted");

  const tags: string[] = [`kind: ${type.kind}${type.typeRaw ? ` (${show(type.typeRaw)})` : ""}`];
  if (agent || bundleId)
    tags.push(`agent: ${[show(agent), bundleId ? `(${show(bundleId)})` : ""].filter(Boolean).join(" ")}`);
  if (dataUrl) tags.push(`data url: ${show(dataUrl, URL_SHOWN_MAX)}`);
  if (originUrl || originTitle)
    tags.push(
      `origin: ${[show(originUrl, URL_SHOWN_MAX), originTitle ? `("${show(originTitle)}")` : ""].filter(Boolean).join(" ")}`,
    );
  if (senderName || senderAddress)
    tags.push(
      `sender: ${[show(senderName), senderAddress ? `<${show(senderAddress)}>` : ""].filter(Boolean).join(" ")}`,
    );
  tags.push(
    when.encoding === "unreadable"
      ? `time: not readable — ${EPOCH_WORDS[declaredEpoch(time.header) ?? "none"]}`
      : when.encoding === "cocoa-seconds"
        ? "time: Cocoa seconds"
        : when.encoding === "iso"
          ? "time: ISO"
          : `time: ${when.encoding === "unix-ms" ? "Unix milliseconds" : "Unix seconds"} (column ${time.header})`,
  );
  tags.push(
    eventId
      ? `event: ${eventId}`
      : idRaw
        ? `event identifier not decodable: ${show(idRaw)}`
        : "event identifier not in this record",
  );
  tags.push("local file: not in this record — joined by the event identifier");

  // Every shown fact, framed; the time as its ISO form or a digest of the raw text.
  const facts = [
    type.typeRaw ? `type?:${type.typeRaw}` : type.kind,
    agent,
    bundleId,
    dataUrl,
    originUrl,
    originTitle,
    senderName,
    senderAddress,
    // The instant AND its representation: a Cocoa row and an ISO row of one instant are two
    // records with different evidence, not one.
    `${when.encoding}:${when.iso || `t?:${time.value}`}`,
    eventId ? "" : idRaw,
  ]
    .map((f) => `${f.length}:${f}`)
    .join("|");
  const factsDigest = keyDigest(facts);
  const aggKey = eventId
    ? `macos-quarantine|event:${eventId}|${factsDigest}`
    : `macos-quarantine|facts:${factsDigest}`;

  // Lossy when anything shown is not the record's own text.
  const typeRaw = type.typeRaw ?? "";
  const shownAll = [
    agent,
    bundleId,
    dataUrl,
    originUrl,
    originTitle,
    senderName,
    senderAddress,
    idRaw,
    typeRaw,
  ];
  // …including an identifier clipped past the shown width and a time the row cannot show at all
  // (an unreadable `timeRaw` is identity the words do not carry).
  const lossy =
    shownAll.some((v) => v && breakHashRuns(showToken(v)) !== v) ||
    dataUrl.length > URL_SHOWN_MAX ||
    originUrl.length > URL_SHOWN_MAX ||
    [agent, bundleId, originTitle, senderName, senderAddress, idRaw, typeRaw].some(
      (v) => v.length > TEXT_SHOWN_MAX,
    ) ||
    (when.encoding === "unreadable" && time.value !== "");
  const mark = identityMark(aggKey);
  const head = "macOS quarantine";
  const full = `${head}${packTags(tags, Number.POSITIVE_INFINITY)}`;
  const fits = full.length <= DESCRIPTION_MAX;
  const description =
    !lossy && fits ? full : `${head}${packTags(tags, DESCRIPTION_MAX - mark.length - head.length)}${mark}`;

  const envelope: QuarantineEnvelope = {
    kind: type.kind,
    ...(type.typeNumber !== undefined ? { typeNumber: type.typeNumber } : {}),
    ...(type.typeRaw ? { typeRaw: type.typeRaw } : {}),
    ...(agent ? { agent } : {}),
    ...(bundleId ? { bundleId } : {}),
    ...(dataUrl ? { dataUrl } : {}),
    ...(originUrl ? { originUrl } : {}),
    ...(originTitle ? { originTitle } : {}),
    ...(senderName ? { senderName } : {}),
    ...(senderAddress ? { senderAddress } : {}),
    ...(eventId ? { eventId } : {}),
    ...(!eventId && idRaw ? { eventIdRaw: idRaw } : {}),
    timeEncoding: when.encoding,
    ...(when.encoding === "unreadable" && time.value ? { timeRaw: time.value } : {}),
    ...(urlOmitted
      ? { urlIndicator: `omitted: a URL longer than ${URL_IOC_MAX} characters; the host is the indicator` }
      : {}),
    localFile: "not in this record",
  };
  return {
    timestamp: when.iso,
    description,
    severity: "Info",
    mitre: [],
    aggKey,
    sources: ["macOS Quarantine"],
    canonical: createCanonicalEvent({
      event: { category: "file", type: "download-record" },
      ...(agent ? { actor: { kind: "process", name: agent } } : {}),
      quarantine: envelope,
      time: { observed: when.iso || time.value, normalized: when.iso },
      evidence: { rawRecords: [{ source: "macos-quarantine", locator: eventId ?? `facts:${factsDigest}` }] },
      producer: { importer: "macos", parserVersion: "1", mappingVersion: "quarantine-v1" },
      rawFieldMap: {
        ...(when.iso ? { "time.observed": [time.header] } : {}),
        ...(dataUrl ? { "quarantine.dataUrl": ["LSQuarantineDataURLString"] } : {}),
      },
    }),
    envelope,
    ...(eventId ? { eventId } : {}),
    factsDigest,
    iocs: opts.deferIocs ? [...sink.values()] : [],
  };
}

const SHARED_MARK = " [event identifier shared by records with different facts]";
/** Distinct fact sets one event identifier may keep as rows; the rest fold into one overflow row. */
export const QUARANTINE_VARIANTS_MAX = 16;

/**
 * A UUID names ONE download event. Two records that share a UUID but disagree on a fact are two
 * rows (their keys differ by the facts digest), and both say so — the join must refuse a UUID that
 * names more than one fact set. Past QUARANTINE_VARIANTS_MAX distinct fact sets the rest fold into
 * one overflow row per UUID that shows none of them, so a flood of variants under one identifier
 * cannot consume the import's event budget. Rewrites in place; a re-dump (same facts) is untouched.
 */
export function boundQuarantineVariants(rows: QuarantineRow[]): QuarantineRow[] {
  const byId = new Map<string, string[]>();
  for (const r of rows) {
    if (!r.eventId) continue;
    const seen = byId.get(r.eventId) ?? byId.set(r.eventId, []).get(r.eventId)!;
    if (!seen.includes(r.factsDigest) && seen.length < QUARANTINE_VARIANTS_MAX) seen.push(r.factsDigest);
  }
  for (const r of rows) {
    if (!r.eventId) continue;
    const seen = byId.get(r.eventId) ?? [];
    if (!seen.includes(r.factsDigest)) {
      r.aggKey = `macos-quarantine|event:${r.eventId}|overflow`;
      r.iocs = [];
      continue;
    }
    if (seen.length < 2 || r.description.includes(SHARED_MARK)) continue;
    const mark = / #[A-Za-z0-9_-]{22}$/.exec(r.description)?.[0] ?? "";
    const body = mark ? r.description.slice(0, -mark.length) : r.description;
    r.description = `${body.slice(0, DESCRIPTION_MAX - SHARED_MARK.length - mark.length)}${SHARED_MARK}${mark}`;
  }
  // The rows that remain: every kept variant, and ONE overflow row per UUID that says how many
  // records it stands for — so the bound holds whether or not the caller aggregates. The row's time
  // is the earliest folded record's; the description names the fold, never a folded fact.
  const out: QuarantineRow[] = [];
  const overflow = new Map<string, { row: QuarantineRow; folded: number }>();
  for (const r of rows) {
    if (!r.aggKey.endsWith("|overflow")) {
      out.push(r);
      continue;
    }
    const seen = overflow.get(r.aggKey);
    if (!seen) {
      overflow.set(r.aggKey, { row: r, folded: 1 });
      out.push(r);
      continue;
    }
    seen.folded += 1;
    if (r.timestamp && (!seen.row.timestamp || r.timestamp < seen.row.timestamp))
      seen.row.timestamp = r.timestamp;
  }
  for (const { row, folded } of overflow.values()) foldRow(row, folded);
  return out;
}

// The overflow row's words, envelope and canonical form — built once, from the row's final
// (earliest folded) time, so the record never carries two times.
function foldRow(row: QuarantineRow, folded: number): void {
  row.description = `macOS quarantine [event: ${row.eventId}] [overflow: ${folded} records with this event identifier and further differing facts beyond ${QUARANTINE_VARIANTS_MAX} sets folded; none shown]${identityMark(row.aggKey)}`;
  // The envelope shows no folded record as the row's: only the identifier and the fold.
  row.envelope = {
    kind: "folded",
    eventId: row.eventId,
    timeEncoding: "unreadable",
    localFile: "not in this record",
    folded: true,
  };
  row.canonical = createCanonicalEvent({
    event: { category: "file", type: "download-record" },
    quarantine: row.envelope,
    time: { observed: row.timestamp, normalized: row.timestamp },
    evidence: { rawRecords: [{ source: "macos-quarantine", locator: `overflow:${row.eventId}` }] },
    producer: { importer: "macos", parserVersion: "1", mappingVersion: "quarantine-v1" },
  });
}

/** The marking-only name the tests use; boundQuarantineVariants marks and bounds. */
export const markSharedIdentifiers = boundQuarantineVariants;
