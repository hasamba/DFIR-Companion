// NTFS alternate data streams, read one record at a time (#932 item 3).
//
// Three surfaces name a stream: an MFTECmd $MFT row (`IsAds=True`, `FileName=file.exe:payload`,
// `HasAds`/`ZoneIdContents` on the host file's own row), a Velociraptor Windows.NTFS.MFT row (the
// stream in `OSPath`), and Sysmon Event 15 (`TargetFilename`, the stream's leading bytes in
// `Contents`, the HOST file's hash in `Hash`). Each used to read as a bare path with a colon in it,
// or — on Sysmon — as Medium + T1564.004 whatever the stream was, so a browser's Zone.Identifier
// mark and a 1 MB executable hidden behind `notes.txt:` read alike.
//
// One record establishes: that a stream exists, its name, its size, and — when the record carries
// them — its leading bytes, its magic or type. It does not establish that the stream ran, that the
// file was opened, or that a download was the user's intent. The reading is ordered EVIDENCE FIRST:
// code content decides before the name does (a stream called SmartScreen that starts with MZ is a
// payload), a Zone.Identifier is a download mark only when its contents have the mark's structure,
// the enumerated application streams are Info by name, and everything else is a named stream whose
// grade needs a positive signal — a code-like name, or a size worth a look. The name is attacker-
// chosen: it is the lead, never the proof, and the words say so.

import { createHash } from "node:crypto";
import { worstSeverity, type Severity } from "./stateTypes.js";
import { gradeMotwDownload, zoneText } from "./motwDownload.js";
import { STAGING_EXT } from "./stagingPaths.js";

export type StreamKind = "code" | "download-mark" | "application" | "named";

export interface StreamInput {
  /** The record's path, stream included when the record names one. */
  path: string;
  /** The record says so (MFTECmd `IsAds`); a stream in the path says so too. */
  isAds?: boolean;
  /** The host file's row says it carries streams (MFTECmd `HasAds`). */
  hasAds?: boolean;
  /** The stream's size in bytes (MFTECmd `FileSize` on the stream row). */
  size?: string;
  /** The stream's leading bytes or the Zone.Identifier text (`ZoneIdContents`, Sysmon `Contents`). */
  contents?: string;
  magic?: string;
  mime?: string;
  sha256?: string;
  md5?: string;
}

export interface StreamReading {
  kind: StreamKind;
  /** `alternate data stream "<name>" on <host file> (<n> bytes) — <what the kind establishes>`. */
  words: string;
  severity: Severity;
  mitre: string[];
  qualifiers: string[];
  hostPath: string;
  stream: string;
  /** The Zone.Identifier's zone id, "" when the stream is not a parsed download mark. */
  zone: string;
  url: string;
  referrer: string;
  sha256?: string;
  md5?: string;
  /** `|ads:<kind>|<zone>` — the stream itself is identity and already sits in the path. */
  keySegment: string;
}

export interface HostReading {
  /** `has alternate data streams`, `downloaded from the Internet zone (url)` — "" when nothing. */
  words: string;
  severity: Severity;
  mitre: string[];
  qualifiers: string[];
  zone: string;
  url: string;
  referrer: string;
}

const STREAM_NAME_MAX = 80;
const HOST_NAME_MAX = 120;
const URL_MAX = 300;
const MAGIC_MAX = 40;
const CONTENTS_MAX = 4096;
const ZONE_MARK_MAX_BYTES = 4096;
const LARGE_STREAM_BYTES = 65_536;
const TECHNIQUE_HIDE = "T1564.004";
export const PROVENANCE_NOTE = "download provenance, not execution";
export const CONTENT_NOTE = "stream content not in this record";
const ZONE_STREAM = "zone.identifier";

// Streams written by Windows itself and by common applications — a LITERAL list, matched
// case-insensitively, dated in the manual. A name here is Info by name; code content still wins.
export const APPLICATION_STREAMS: readonly string[] = [
  "SmartScreen",
  "OECustomProperty",
  "encryptable",
  "favicon",
  "Afp_AfpInfo",
  "Afp_Resource",
  "com.dropbox.attrs",
  "com.dropbox.attributes",
  "com.apple.quarantine",
  "com.apple.FinderInfo",
  "com.apple.ResourceFork",
  "WofCompressedData",
  "$TXF_DATA",
  "{4c8cc155-6c1e-11d1-8e41-00c04fb9386d}",
  "Win32App_1",
  "evernote.metadata",
  "Evernote.Base",
  "ms-properties",
];
const APPLICATION_SET = new Set(APPLICATION_STREAMS.map((s) => s.toLowerCase()));

const RUNNABLE_NAME = new RegExp(`\\.(?:${STAGING_EXT})$`, "i");
const CODE_MAGIC = /^(?:MZ|PE32|ELF|#!|PowerShell|Windows Script)/i;
const CODE_MIME =
  /^application\/(?:x-msdownload|x-dosexec|x-executable|x-msdos-program|javascript|x-powershell|x-sh|x-elf|vnd\.microsoft\.portable-executable)/i;
// The stream's leading bytes: a PE header, an ELF header (DEL E L F), a shebang, a script tag.
const CODE_CONTENTS = /^(?:MZ|\x7fELF|#!|<script|PowerShell)/i;
const HEX = /^[0-9a-f]+$/;
// A mark flattened onto one line (some exports drop the CRLFs) still splits at its field names.
const MARK_FIELDS =
  /\s+(?=(?:ZoneId|HostUrl|ReferrerUrl|HostIpAddress|LastWriterPackageFamilyName|AppZoneId)\s*=)/i;

const clip = (s: string, max: number): string => (s.length <= max ? s : `${s.slice(0, max - 1)}…`);
const flat = (s: string): string => zoneText(s).replace(/\s+/g, " ");

/** The truthy forms an MFTECmd boolean column takes. */
export const streamFlag = (v: unknown): boolean =>
  v === true || v === 1 || /^(?:true|yes|1)$/i.test(typeof v === "string" ? v.trim() : "");

/**
 * `<hostPath>:<stream>[:$<TYPE>]` — the stream is what follows the FIRST colon after the last path
 * separator (a drive letter's colon never is), a trailing `:$DATA`-style type is dropped, and a
 * stream name never contains a colon (NTFS forbids it). `stream` is "" when the path names none.
 */
export function splitStream(path: string): { hostPath: string; stream: string } {
  const sep = Math.max(path.lastIndexOf("\\"), path.lastIndexOf("/"));
  const name = path.slice(sep + 1);
  const colon = name.indexOf(":");
  if (colon < 0) return { hostPath: path, stream: "" };
  // `C:` at the start of a bare name is a drive, not a host file.
  if (sep < 0 && colon === 1 && /^[A-Za-z]$/.test(name[0])) return { hostPath: path, stream: "" };
  const rest = name.slice(colon + 1);
  const typeAt = rest.indexOf(":");
  const stream = typeAt >= 0 ? rest.slice(0, typeAt) : rest;
  const hostPath = path.slice(0, sep + 1) + name.slice(0, colon);
  return { hostPath, stream };
}

/** A hash counts only when it has its algorithm's length and is hex. */
export function validHash(v: string | undefined, length: 64 | 32): string {
  const h = (v ?? "").trim().toLowerCase();
  return h.length === length && HEX.test(h) ? h : "";
}

export interface ZoneMark {
  zone: string;
  url: string;
  referrer: string;
}

/** The `[ZoneTransfer]` text — `ZoneId=`, `HostUrl=`, `ReferrerUrl=` lines; null when not a mark. */
export function parseZoneMark(contents: string | undefined): ZoneMark | null {
  const raw = (contents ?? "").slice(0, CONTENTS_MAX).split(/\r\n|\r|\n/);
  const lines = (raw.length > 1 ? raw : raw[0].split(MARK_FIELDS)).map((l) => zoneText(l));
  if (!lines.some((l) => /^\[zonetransfer\]$/i.test(l))) return null;
  const field = (name: string): string => {
    const line = lines.find((l) => new RegExp(`^${name}\\s*=`, "i").test(l));
    return line ? line.slice(line.indexOf("=") + 1).trim() : "";
  };
  const zone = field("ZoneId");
  if (!/^\d+$/.test(zone)) return null;
  const url = (u: string): string => (/^https?:\/\//i.test(u) ? u.slice(0, URL_MAX) : "");
  return { zone, url: url(field("HostUrl")), referrer: url(field("ReferrerUrl")) };
}

const ZONE_WORDS: Record<string, string> = {
  "0": "the Local machine zone",
  "1": "the Local intranet zone",
  "2": "the Trusted sites zone",
  "3": "the Internet zone",
  "4": "the Restricted sites zone",
};

function markWords(mark: ZoneMark): string {
  const from = ZONE_WORDS[mark.zone] ?? `zone ${clip(mark.zone, 10)}`;
  const detail = [
    mark.url ? clip(mark.url, URL_MAX) : "",
    mark.referrer ? `referrer ${clip(mark.referrer, URL_MAX)}` : "",
  ]
    .filter(Boolean)
    .join(", ");
  return `downloaded from ${from}${detail ? ` (${detail})` : ""}`;
}

const baseName = (p: string): string => p.slice(Math.max(p.lastIndexOf("\\"), p.lastIndexOf("/")) + 1);
const sizeWords = (size: string | undefined): string =>
  size !== undefined && /^\d+$/.test(size.trim()) ? ` (${size.trim()} bytes)` : "";
const sizeNumber = (size: string | undefined): number | undefined =>
  size !== undefined && /^\d{1,15}$/.test(size.trim()) ? Number(size.trim()) : undefined;

/** The record's own content evidence that the stream holds code — "" when it carries none. */
function codeEvidence(input: StreamInput): string {
  const magic = flat(input.magic ?? "");
  if (magic && CODE_MAGIC.test(magic)) return `magic ${clip(magic, MAGIC_MAX)}`;
  const mime = flat(input.mime ?? "");
  if (mime && CODE_MIME.test(mime)) return `type ${clip(mime, MAGIC_MAX)}`;
  const contents = (input.contents ?? "").slice(0, 64);
  if (contents && CODE_CONTENTS.test(contents)) return `starts with ${clip(flat(contents.slice(0, 8)), 12)}`;
  return "";
}

/** Read one stream record. Null when the record names no stream — use `readHost` then. */
export function readStream(input: StreamInput): StreamReading | null {
  const { hostPath, stream } = splitStream(input.path);
  if (!stream && !input.isAds) return null;
  const hostName = clip(flat(baseName(hostPath)), HOST_NAME_MAX);
  const name = clip(flat(stream), STREAM_NAME_MAX) || "(unnamed)";
  const head = `alternate data stream "${name}" on ${hostName}${sizeWords(input.size)}`;
  const sha256 = validHash(input.sha256, 64);
  const md5 = validHash(input.md5, 32);
  const hashes = { ...(sha256 ? { sha256 } : {}), ...(md5 ? { md5 } : {}) };
  const done = (
    kind: StreamKind,
    tail: string,
    severity: Severity,
    mitre: string[],
    qualifiers: string[],
    mark: ZoneMark | null,
  ): StreamReading => ({
    kind,
    words: `${head} — ${tail}`,
    severity,
    mitre,
    qualifiers,
    hostPath,
    stream,
    zone: mark?.zone ?? "",
    url: mark?.url ?? "",
    referrer: mark?.referrer ?? "",
    ...hashes,
    keySegment: `|ads:${kind}|${mark?.zone ?? ""}`,
  });
  // a. Content evidence first — whatever the name says.
  const code = codeEvidence(input);
  if (code) return done("code", `executable content (${code})`, "Medium", [TECHNIQUE_HIDE], [], null);
  const size = sizeNumber(input.size);
  const lower = stream.toLowerCase();
  // b. A download mark: the name AND the structure (or no contents and a mark-sized stream).
  if (lower === ZONE_STREAM) {
    const mark = parseZoneMark(input.contents);
    if (mark) {
      const g = gradeMotwDownload(mark.zone, baseName(hostPath));
      return done("download-mark", markWords(mark), g.severity, [], [PROVENANCE_NOTE], mark);
    }
    const plausible = input.contents === undefined && (size === undefined || size <= ZONE_MARK_MAX_BYTES);
    if (plausible)
      return done("download-mark", "download mark (Zone.Identifier)", "Info", [], [PROVENANCE_NOTE], null);
    // A Zone.Identifier that is not a mark is a named stream wearing the name.
  }
  // c. An enumerated application or system stream.
  if (APPLICATION_SET.has(lower)) return done("application", "application stream", "Info", [], [], null);
  // d. A named stream — a positive signal grades it; the name is the lead, never the proof.
  if (size === 0) return done("named", "empty named stream", "Info", [], [], null);
  if (RUNNABLE_NAME.test(stream))
    return done(
      "named",
      "named stream with a code-like name",
      "Medium",
      [TECHNIQUE_HIDE],
      [CONTENT_NOTE],
      null,
    );
  if (size !== undefined && size >= LARGE_STREAM_BYTES)
    return done("named", "large named stream", "Low", [], [CONTENT_NOTE], null);
  return done("named", "named stream", "Info", [], [CONTENT_NOTE], null);
}

/** A host file's own row: whether it carries streams, and the Zone.Identifier text when supplied. */
export function readHost(input: StreamInput): HostReading {
  const mark = parseZoneMark(input.contents);
  const parts: string[] = [];
  if (input.hasAds) parts.push("has alternate data streams");
  let severity: Severity = "Info";
  if (mark) {
    parts.push(markWords(mark));
    severity = gradeMotwDownload(mark.zone, baseName(input.path)).severity;
  }
  return {
    words: parts.join("; "),
    severity,
    mitre: [],
    qualifiers: mark ? [PROVENANCE_NOTE] : [],
    zone: mark?.zone ?? "",
    url: mark?.url ?? "",
    referrer: mark?.referrer ?? "",
  };
}

/**
 * Sysmon Event 15 (FileCreateStreamHash) through the same reading, laid over the event's own
 * description and table severity. `field` reads one event-data key. The event's `Hash` is the hash
 * of the FILE the stream was added to (its unnamed stream), never the named stream's: it joins the
 * row's identity only, so the same stream re-created on a replaced host file is a second row, and
 * no hash is claimed for the stream itself.
 */
export function streamOverlay(
  field: (key: string) => string,
  description: string,
  severity: Severity,
): { description: string; severity: Severity; mitre: string[]; identity: string } | null {
  const path = field("TargetFilename");
  const contents = field("Contents");
  const r = readStream({ path, ...(contents ? { contents } : {}) });
  if (!r) return null;
  const digest = createHash("sha256").update(path.toLowerCase()).digest("hex").slice(0, 16);
  return {
    description: `${description} — ${[r.words, ...r.qualifiers].join(" — ")}`.slice(0, 600),
    severity: worstSeverity(severity, r.severity),
    mitre: r.mitre,
    identity: `|ads:${digest}|${field("Hash").trim().toLowerCase()}`,
  };
}
