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
const NATIVE_TIME_HEADER = "LSQuarantineTimeStamp";
// A converted dump declares its epoch in the column name; `timestamp`/`time` declare nothing. One
// list per epoch is both the grammar declaredEpoch reads and the columns the reader extracts.
const UNIX_SECONDS_HEADERS = [
  "unix_time",
  "unixtime",
  "unix_seconds",
  "unixseconds",
  "epoch",
  "epoch_seconds",
  "epochseconds",
];
const UNIX_MS_HEADERS = [
  "unix_ms",
  "unixms",
  "unix_millis",
  "unixmillis",
  "epoch_ms",
  "epochms",
  "epoch_millis",
  "epochmillis",
];
const GENERIC_TIME_HEADERS = ["timestamp", "time"];
const EPOCH_WORDS = {
  cocoa: "Cocoa seconds expected",
  "unix-seconds": "Unix seconds expected",
  "unix-ms": "Unix milliseconds expected",
  none: "the column names no epoch (a converted dump names it: unix_time or unix_ms)",
};
// Every column readQuarantineTime can decode: the native column, then each declared epoch, then the
// generic names — so a declaration is never shadowed by a generic alias beside it.
const TIME_HEADERS = [
  NATIVE_TIME_HEADER,
  ...UNIX_SECONDS_HEADERS,
  ...UNIX_MS_HEADERS,
  ...GENERIC_TIME_HEADERS,
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
  const h = header.trim().toLowerCase();
  if (h === NATIVE_TIME_HEADER.toLowerCase()) return "cocoa";
  if (UNIX_SECONDS_HEADERS.includes(h)) return "unix-seconds";
  if (UNIX_MS_HEADERS.includes(h)) return "unix-ms";
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
    // The reading is the platform's millisecond ISO form; the raw spelling stays identity.
    const iso = isoOf(Date.parse(normalizeTime(text) || text));
    return iso ? { iso, encoding: "iso" } : { iso: "", encoding: "unreadable" };
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
  /** Digest of the origin alias (bookmark data) the record carries — identity, never shown. */
  originAliasDigest?: string;
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

// A structured JSON value (an exporter's BLOB as `{type:"Buffer",data:[…]}`) keeps its shape as
// JSON text — never `[object Object]`, which would make every such value one value.
const text = (v: unknown): string =>
  typeof v === "string"
    ? v
    : v == null
      ? ""
      : isRepeatedColumn(v)
        ? frameOccurrences(v.values.map((value) => ({ header: "", value })))
        : typeof v === "object"
          ? JSON.stringify(v)
          : String(v);
const first = (rec: Row, keys: readonly string[]): { value: string; header: string } => {
  for (const k of keys) {
    const v = getCI(rec, k);
    if (v != null && text(v).trim() !== "") return { value: text(v).trim(), header: k };
  }
  return { value: "", header: "" };
};
/**
 * A header the CSV repeated: the projection wraps its values so a genuine JSON array (`[716403200.5]`)
 * is never mistaken for one — a JSON array stays a structured value with its own text.
 */
export class RepeatedColumn {
  constructor(readonly values: readonly string[]) {}
}
const isRepeatedColumn = (v: unknown): v is RepeatedColumn => v instanceof RepeatedColumn;
const TIME_HEADER_RANK = new Map(TIME_HEADERS.map((h, i) => [h.toLowerCase(), i]));
/**
 * Every time column the record actually carries — each key whose name is a time header by any case,
 * and each value of a header the source repeated (the CSV projection keeps repeats as an array) —
 * native first, then declared epochs, then generic names, source order within a rank.
 */
function timeOccurrences(rec: Row): { header: string; value: string }[] {
  const out: { header: string; value: string; rank: number }[] = [];
  for (const [k, v] of Object.entries(rec)) {
    const rank = TIME_HEADER_RANK.get(k.trim().toLowerCase());
    if (rank === undefined) continue;
    // A header the source repeated is that many columns, blank or not; a single blank key is none.
    if (isRepeatedColumn(v)) for (const one of v.values) out.push({ header: k.trim(), value: one, rank });
    else if (text(v).trim()) out.push({ header: k.trim(), value: text(v), rank });
  }
  return out.sort((a, b) => a.rank - b.rank).map(({ header, value }) => ({ header, value }));
}
/** Whether the ISO reading carries the raw text back exactly — else the words lost a digit. */
function timeRoundTrips(raw: string, when: QuarantineTime): boolean {
  // An ISO spelling the reading does not repeat verbatim (`+0200`, a space, an offset) is lost.
  if (when.encoding === "iso") return raw === when.iso;
  // Date keeps milliseconds: more fraction digits than the encoding's millisecond has are lost —
  // and so is any spelling that is not the number's canonical one (`.5000`, `+5`, `01.5`).
  const canonical = raw === String(Number(raw));
  const fraction = (raw.split(".")[1] ?? "").length;
  return canonical && fraction <= (when.encoding === "unix-ms" ? 0 : 3);
}
/** Length-framed `header=value` pairs: two different column sets never serialise alike. */
const frameOccurrences = (times: { header: string; value: string }[]): string =>
  times.map((t) => `${t.header.length}:${t.header}=${t.value.length}:${t.value}`).join("|");
const show = (v: string, max = TEXT_SHOWN_MAX): string => {
  const shown = breakHashRuns(showToken(v));
  return shown.length > max ? `${shown.slice(0, max - 1)}…` : shown;
};

/**
 * The URL and its host as indicators: an address is `ip`, a name is `domain`; http(s)/ftp only. A
 * URL past URL_IOC_MAX mints no `url` indicator (the host still does) and says so.
 */
function mintUrl(
  sink: Map<string, SiemIoc>,
  url: string,
  schemes: readonly string[],
): "minted" | "omitted" | undefined {
  const host = fetchableHost(url, schemes);
  if (host === undefined) return undefined;
  const urlIoc = url.length <= URL_IOC_MAX;
  if (urlIoc) addIoc(sink, "url", url);
  const bare = host.startsWith("[") ? host.slice(1, -1) : host;
  if (bare) {
    if (isIP(bare)) addIoc(sink, "ip", bare);
    else addIoc(sink, "domain", bare.toLowerCase());
  }
  return urlIoc ? "minted" : "omitted";
}

/**
 * The host of a URL under one of `schemes` (WHATWG grammar: `https:example.com/a` is absolute too),
 * or undefined when the value is not such a URL or names no host.
 */
export function fetchableHost(
  value: string,
  schemes: readonly string[] = DOWNLOAD_SCHEMES,
): string | undefined {
  let u: URL;
  try {
    u = new URL(value);
  } catch {
    return undefined;
  }
  return schemes.includes(u.protocol) && u.hostname !== "" ? u.hostname : undefined;
}
const DOWNLOAD_SCHEMES = ["http:", "https:", "ftp:"];
const PAGE_SCHEMES = ["http:", "https:"];

/** One LSQuarantineEventsV2 record → a row that says what the record establishes. */
export function quarantineOverlay(
  rec: Row,
  fileSink: Map<string, SiemIoc>,
  opts: { deferIocs?: boolean } = {},
): QuarantineRow {
  // Indicators go to the row first; the importer merges them after the per-UUID bound, so a flood
  // of variants under one identifier cannot fill the file's indicator budget either.
  const sink = opts.deferIocs ? new Map<string, SiemIoc>() : fileSink;
  // Two time columns in one record — by any spelling or case, or one header twice — name no
  // single instant: the row keeps every occurrence, decodes none.
  const times = timeOccurrences(rec);
  const time =
    times.length > 1
      ? { value: frameOccurrences(times), header: "" }
      : (times[0] ?? { value: "", header: "" });
  const when =
    times.length > 1
      ? { iso: "", encoding: "unreadable" as const }
      : readQuarantineTime(time.value, time.header);
  const type = readQuarantineType(first(rec, ["LSQuarantineTypeNumber", "type"]).value);
  const agent = first(rec, ["LSQuarantineAgentName", "agent"]).value;
  const bundleId = first(rec, ["LSQuarantineAgentBundleIdentifier", "bundle_id"]).value;
  const dataUrl = first(rec, ["LSQuarantineDataURLString", "data_url", "url"]).value;
  const originUrl = first(rec, ["LSQuarantineOriginURLString", "origin_url", "referrer"]).value;
  const originTitle = first(rec, ["LSQuarantineOriginTitle", "origin_title"]).value;
  const senderName = first(rec, ["LSQuarantineSenderName", "sender"]).value;
  const senderAddress = first(rec, ["LSQuarantineSenderAddress", "sender_address"]).value;
  // The origin alias is bookmark data — identity, never words: two dumps that differ only in it
  // are two records, and the row says the alias is present without showing it.
  const originAlias = first(rec, ["LSQuarantineOriginAlias", "origin_alias"]).value;
  // Only the native column and the declared alias: a generic `id` is export metadata, not an event.
  const idRaw = first(rec, ["LSQuarantineEventIdentifier", "event_id"]).value;
  const eventId = canonicalUuid(idRaw);

  // Indicators: the resource the agent fetched, and a lure page — only under a fetchable scheme.
  const urlIndicators = [mintUrl(sink, dataUrl, DOWNLOAD_SCHEMES), mintUrl(sink, originUrl, PAGE_SCHEMES)];
  const urlOmitted = urlIndicators.includes("omitted");

  const tags: string[] = [`kind: ${type.kind}${type.typeRaw ? ` (${show(type.typeRaw)})` : ""}`];
  if (agent || bundleId)
    tags.push(`agent: ${[show(agent), bundleId ? `(${show(bundleId)})` : ""].filter(Boolean).join(" ")}`);
  if (dataUrl) tags.push(`data url: ${show(dataUrl, URL_SHOWN_MAX)}`);
  if (originUrl || originTitle)
    tags.push(
      `origin: ${[show(originUrl, URL_SHOWN_MAX), originTitle ? `("${show(originTitle)}")` : ""].filter(Boolean).join(" ")}`,
    );
  if (originAlias) tags.push(`origin alias: present (${originAlias.length} characters, not shown)`);
  if (senderName || senderAddress)
    tags.push(
      `sender: ${[show(senderName), senderAddress ? `<${show(senderAddress)}>` : ""].filter(Boolean).join(" ")}`,
    );
  tags.push(
    when.encoding === "unreadable"
      ? `time: not readable — ${times.length > 1 ? `${times.length} time columns in this record (${times.map((t) => show(t.header, 40)).join(", ")})` : EPOCH_WORDS[declaredEpoch(time.header) ?? "none"]}`
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
    originAlias ? `alias:${keyDigest(originAlias)}` : "",
    // The instant AND its representation AND the raw text: a Cocoa row and an ISO row of one instant
    // are two records with different evidence, and so are two REAL values that round to one
    // millisecond (716403200.5001 vs .5002) — the raw text is the evidence, the ISO is a reading.
    `${when.encoding}:${when.iso}:${time.header}:${time.value}`,
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
    (when.encoding === "unreadable" && time.value !== "") ||
    // …and a time whose text the ISO reading does not carry back (sub-millisecond digits,
    // a non-canonical spelling): the words then show a reading, not the record's value.
    (when.iso !== "" && !timeRoundTrips(time.value, when)) ||
    originAlias !== "";
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
    ...(originAlias ? { originAliasDigest: keyDigest(originAlias) } : {}),
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
