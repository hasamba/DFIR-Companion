// A file's `com.apple.quarantine` attribute as a record of its own (#933 item 7, join half —
// #1037): a path and the raw attribute value, as `xattr -p com.apple.quarantine` over a directory,
// `ls -l@`, or a collector glob with `xattr()` emits them. One record establishes: that a file at a
// PATH carried a quarantine mark with these flags, this Unix-hex time, this agent name and this
// event identifier — the same identifier the LSQuarantineEventsV2 record carries, which is the
// only thing the two are joined through (quarantineJoin.ts). It does not establish the URL (the
// attribute keeps none), that the file ran, or — when the cell is empty — that the file has no
// attribute: a blank cell is "empty or not reported", never absence.
//
// The record is recognised by the unmistakable key alone: a column named exactly
// `com.apple.quarantine` (case-insensitive). `quarantine`, `xattr` and a path column are not a
// signature — a generic inventory or a Velociraptor export carries those too.

import { breakHashRuns, identityMark, keyDigest, packTags, showToken } from "./recordIdentity.js";
import type { MappedEvent } from "./siemImport.js";
import { createCanonicalEvent, type CreateCanonicalEventInput } from "./canonicalEvent.js";
import type { QuarantineAttributeBlock } from "./canonicalQuarantine.js";
import {
  HOST_COLUMNS,
  RepeatedColumn,
  readQuarantineXattr,
  type QuarantineXattr,
} from "./quarantineRecord.js";

type Row = Record<string, unknown>;

export const ATTRIBUTE_KEY = "com.apple.quarantine";
const PATH_COLUMNS = ["path", "file", "fullpath", "name", "filename", "ospath"];
const SHA256_COLUMNS = ["sha256", "hash"];
const MD5_COLUMNS = ["md5"];
const SIZE_COLUMNS = ["size", "filesize"];
/** Characters of path and of attribute value read; past them the value is clipped, marked and never joined. */
export const ATTRIBUTE_PATH_MAX = 4096;
export const ATTRIBUTE_VALUE_MAX = 1024;
const PATH_SHOWN_MAX = 200;
const TEXT_SHOWN_MAX = 80;
const DESCRIPTION_MAX = 600;

export type ValueState = "not in this record" | "2 values in this record" | "clipped";

export interface AttributeObservation {
  /** The record's position in the upload — a locator, never identity. */
  index: number;
  path?: string;
  pathState?: ValueState;
  /** The raw attribute value as written (clipped past ATTRIBUTE_VALUE_MAX). */
  raw: string;
  attributeState?: ValueState | "empty";
  mark?: QuarantineXattr;
  host?: string;
  hostState?: "2 values in this record";
  sha256?: string;
  md5?: string;
  size?: number;
}

const text = (v: unknown): string =>
  typeof v === "string" ? v : v == null ? "" : typeof v === "object" ? JSON.stringify(v) : String(v);

/** Every value under any of `keys` (case-insensitive, a repeated header expanded), non-empty, distinct. */
function occurrences(rec: Row, keys: readonly string[]): string[] {
  const out: string[] = [];
  for (const [h, v] of Object.entries(rec)) {
    if (!keys.includes(h.trim().toLowerCase())) continue;
    const values = v instanceof RepeatedColumn ? v.values : [text(v)];
    for (const value of values) {
      const t = value.trim();
      if (t && !out.includes(t)) out.push(t);
    }
  }
  return out;
}

export function isQuarantineAttributeRecord(rec: Row): boolean {
  return Object.keys(rec).some((h) => h.trim().toLowerCase() === ATTRIBUTE_KEY);
}

const hexOf = (v: string, len: number): string | undefined =>
  new RegExp(`^[0-9a-f]{${len}}$`, "i").test(v.trim()) ? v.trim().toLowerCase() : undefined;

export function readQuarantineAttributeRecord(rec: Row, index: number): AttributeObservation {
  const paths = occurrences(rec, PATH_COLUMNS);
  const attrs = occurrences(rec, [ATTRIBUTE_KEY]);
  const hosts = occurrences(rec, HOST_COLUMNS);
  const sha = occurrences(rec, SHA256_COLUMNS)
    .map((v) => hexOf(v, 64))
    .find(Boolean);
  const md5 = occurrences(rec, MD5_COLUMNS)
    .map((v) => hexOf(v, 32))
    .find(Boolean);
  const size = Number(occurrences(rec, SIZE_COLUMNS)[0]);
  const path = paths.length === 1 ? paths[0] : undefined;
  const pathState: ValueState | undefined =
    paths.length === 0
      ? "not in this record"
      : paths.length > 1
        ? "2 values in this record"
        : path!.length > ATTRIBUTE_PATH_MAX
          ? "clipped"
          : undefined;
  const raw = attrs.length === 1 ? attrs[0] : "";
  const attributeState: AttributeObservation["attributeState"] =
    attrs.length === 0
      ? "empty"
      : attrs.length > 1
        ? "2 values in this record"
        : raw.length > ATTRIBUTE_VALUE_MAX
          ? "clipped"
          : undefined;
  const mark = attributeState === undefined ? (readQuarantineXattr(raw) ?? undefined) : undefined;
  return {
    index,
    ...(path !== undefined ? { path: path.slice(0, ATTRIBUTE_PATH_MAX) } : {}),
    ...(pathState ? { pathState } : {}),
    raw: raw.slice(0, ATTRIBUTE_VALUE_MAX),
    ...(attributeState ? { attributeState } : {}),
    ...(mark ? { mark } : {}),
    ...(hosts.length === 1 ? { host: hosts[0] } : {}),
    ...(hosts.length > 1 ? { hostState: "2 values in this record" as const } : {}),
    ...(sha ? { sha256: sha } : {}),
    ...(md5 ? { md5 } : {}),
    ...(Number.isInteger(size) && size >= 0 ? { size } : {}),
  };
}

// ───────────────────────────── the row ─────────────────────────────

const show = (v: string, max = TEXT_SHOWN_MAX): string => {
  const shown = breakHashRuns(showToken(v));
  return shown.length > max ? `${shown.slice(0, max - 1)}…` : shown;
};

export type AttributeJoin = QuarantineAttributeBlock["join"];

export interface AttributeJoinFacts {
  join: AttributeJoin;
  download?: QuarantineAttributeBlock["download"];
  /** The database records consulted (one when joined; every variant when they disagree), for the provenance. */
  databaseLocators?: string[];
  /** The joined database records' words for the `download event` span. */
  downloadWords?: string;
}

export const attributeLocator = (a: AttributeObservation): string => `attribute:${a.index}`;

/** The words of what the join established, or why it did not. */
export function joinTags(join: AttributeJoin, downloadWords: string | undefined): string[] {
  const tags: string[] = [];
  switch (join.state) {
    case "joined":
      tags.push(`download event: ${downloadWords ?? ""} — the database record with this event identifier`);
      break;
    case "no database record in this upload":
      tags.push("download event: not among this upload's database records");
      break;
    case "database records disagree":
      tags.push("download event: the database records with this identifier disagree — not joined");
      break;
    case "two attribute values for one path":
      tags.push("download event: two attribute values for one path — not joined");
      break;
    case "path not established":
      tags.push("download event: the file's path is not established by this record — not joined");
      break;
    case "host not established":
      tags.push("download event: the host is not established by this record — not joined");
      break;
    case "no identifier":
      break;
  }
  if (join.agentAgreement === "agrees") tags.push("agent agrees");
  if (join.timeAgreement) tags.push(timeWords(join.timeAgreement));
  tags.push(...flagTags(join));
  return tags;
}

/** The download bit as the record has it; "sandbox mark only" only when the sandbox bit is the whole word. */
export function flagTags(join: Pick<AttributeJoin, "downloadFlag" | "sandboxOnly">): string[] {
  if (join.downloadFlag === true) return ["download flag set"];
  if (join.downloadFlag === false)
    return [join.sandboxOnly ? "download flag not set — sandbox mark only" : "download flag not set"];
  return [];
}

const ENCODING_WORDS: Record<string, string> = {
  "cocoa-seconds": "Cocoa seconds",
  iso: "ISO 8601",
  "unix-seconds": "Unix seconds",
  "unix-ms": "Unix milliseconds",
  unreadable: "not readable",
};

export function timeWords(t: NonNullable<AttributeJoin["timeAgreement"]>): string {
  if (t.state === "not compared") return `time not compared: ${t.reason}`;
  const encodings = `(attribute: Unix hex; database: ${ENCODING_WORDS[t.databaseEncoding]})`;
  if (t.state === "same second") return `marked and recorded in the same second ${encodings}`;
  return `marked ${t.band} ${t.state === "marked after the record" ? "after" : "before"} the record ${encodings}`;
}

export function mapAttributeRow(a: AttributeObservation, facts: AttributeJoinFacts): MappedEvent {
  const tags: string[] = [];
  if (a.path !== undefined && a.pathState !== "2 values in this record")
    tags.push(`file: ${show(a.path, PATH_SHOWN_MAX)}${a.pathState === "clipped" ? " (clipped)" : ""}`);
  else tags.push(`path: ${a.pathState ?? "not in this record"}`);
  if (a.mark) tags.push(a.mark.words);
  else if (a.attributeState === "empty")
    tags.push("attribute value empty or not reported — absence of the attribute not established");
  else if (a.attributeState === "2 values in this record")
    tags.push("quarantine mark: 2 values in this record");
  else if (a.attributeState === "clipped") tags.push("quarantine mark (not decodable): value clipped");
  else tags.push(`quarantine mark (not decodable): ${show(a.raw)}`);
  if (a.sha256) tags.push(`sha256 ${a.sha256.slice(0, 8)}…${a.sha256.slice(-4)}`);
  if (a.size !== undefined) tags.push(`size ${a.size}`);
  tags.push(...joinTags(facts.join, facts.downloadWords));
  if (a.host) tags.push(`host: ${show(a.host)}`);
  else if (a.hostState) tags.push("host: 2 values in this record");
  else tags.push("host not named in the records");

  const block: QuarantineAttributeBlock = {
    ...(a.path !== undefined ? { path: a.path } : {}),
    ...(a.pathState ? { pathState: a.pathState } : {}),
    mark: a.mark
      ? {
          flags: a.mark.flags.raw,
          named: a.mark.flags.named,
          ...(a.mark.flags.unnamed ? { unnamed: a.mark.flags.unnamed } : {}),
          time: a.mark.time.iso,
          encoding: "unix-hex-seconds",
          agent: a.mark.agent,
          ...(a.mark.eventId ? { eventId: a.mark.eventId } : {}),
        }
      : a.attributeState === "empty"
        ? { state: "empty or not reported" }
        : a.attributeState === "2 values in this record"
          ? { state: "2 values in this record" }
          : a.attributeState === "clipped"
            ? { state: "clipped" }
            : { state: "not decodable", raw: a.raw },
    host: a.host ? { name: a.host } : a.hostState ? { state: a.hostState } : { state: "not named" },
    ...(a.sha256 ? { sha256: a.sha256 } : {}),
    ...(a.md5 ? { md5: a.md5 } : {}),
    ...(a.size !== undefined ? { size: a.size } : {}),
    ...(facts.download ? { download: facts.download } : {}),
    join: facts.join,
  };
  // Every shown fact is identity: the host, the path, the raw value, the hashes, the size, the
  // join and its facts.
  const key = `macos-quarantine-attr|${a.host ? `h:${keyDigest(a.host)}` : a.hostState ? "h:2" : "-"}|${keyDigest(a.path ?? `?${a.pathState}`)}|${keyDigest(a.raw)}|${a.sha256 ?? "-"}|${a.md5 ?? "-"}|${a.size ?? "-"}|${keyDigest(JSON.stringify(facts.join))}|${keyDigest(JSON.stringify(facts.download ?? null))}`;
  const mark = identityMark(key);
  const head = "macOS quarantine attribute";
  const own = attributeLocator(a);
  const dbLocators = facts.databaseLocators ?? [];
  const rawRecords = [
    { source: "macos-quarantine-attribute", locator: own },
    ...dbLocators.map((locator) => ({
      source: "macos-quarantine",
      locator,
      ...(a.mark?.eventId ? { recordId: a.mark.eventId } : {}),
    })),
  ];
  const locatorMap: Record<string, string> = {};
  if (dbLocators.length) {
    locatorMap["quarantineAttribute.download"] = dbLocators[0];
    // The join state rests on every database record consulted; the agreement fields on both records.
    dbLocators.forEach(
      (locator, i) => (locatorMap[`quarantineAttribute.join.state.database.${i}`] = locator),
    );
    for (const leaf of ["agentAgreement", "timeAgreement", "downloadFlag"] as const)
      if (facts.join[leaf] !== undefined)
        locatorMap[`quarantineAttribute.join.${leaf}.database`] = dbLocators[0];
  }
  const input: CreateCanonicalEventInput = {
    event: { category: "file", type: "quarantine-attribute" },
    ...(a.path !== undefined && !a.pathState
      ? {
          file: { path: a.path, ...(a.sha256 ? { sha256: a.sha256 } : {}), ...(a.md5 ? { md5: a.md5 } : {}) },
        }
      : {}),
    quarantineAttribute: block,
    time: { observed: a.mark?.time.iso ?? "", normalized: a.mark?.time.iso ?? "" },
    evidence: { rawRecords },
    producer: { importer: "macos", parserVersion: "1", mappingVersion: "quarantine-attribute-v1" },
    rawFieldMap: {
      ...(a.path !== undefined ? { "quarantineAttribute.path": ["path"] } : {}),
      ...(a.mark ? { "quarantineAttribute.mark": [ATTRIBUTE_KEY] } : {}),
    },
    locatorMap,
  };
  return {
    timestamp: a.mark?.time.iso ?? "",
    description: `${head}${packTags(tags, DESCRIPTION_MAX - mark.length - head.length)}${mark}`,
    severity: "Info",
    mitre: [],
    aggKey: key,
    sources: ["macOS Quarantine"],
    canonical: createCanonicalEvent(input),
    // No `path` on the row: correlate.ts case-folds paths and APFS may not; the exact path is in the
    // envelope. A valid hash IS on the row: a hash names the bytes on any volume.
    ...(a.sha256 ? { sha256: a.sha256 } : {}),
    ...(a.md5 ? { md5: a.md5 } : {}),
  };
}

/** The overflow row: attribute records past the retained bound, counted, none shown. */
export function mapAttributeOverflow(count: number): MappedEvent {
  const key = "macos-quarantine-attr|overflow";
  return {
    timestamp: "",
    description: `macOS quarantine attribute [overflow: ${count} attribute record${count === 1 ? "" : "s"} beyond the retained bound folded; none shown]${identityMark(key)}`,
    severity: "Info",
    mitre: [],
    aggKey: key,
    sources: ["macOS Quarantine"],
    canonical: createCanonicalEvent({
      event: { category: "file", type: "quarantine-attribute" },
      quarantineAttribute: {
        host: { state: "not named" },
        join: { state: "no identifier" },
        folded: true,
        records: count,
      },
      time: { observed: "", normalized: "" },
      evidence: { rawRecords: [{ source: "macos-quarantine-attribute", locator: key }] },
      producer: { importer: "macos", parserVersion: "1", mappingVersion: "quarantine-attribute-v1" },
    }),
  };
}
