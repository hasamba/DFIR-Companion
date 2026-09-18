// A bounded reader for the classic Alias Manager record — the pre-bookmark target format the
// pre-Sonoma `com.apple.loginitems.plist` stores under each item's `Alias` key (#933 item 8,
// #1301). Ported from dmgbuild/mac_alias's own `Alias._to_fd()` WRITER (@d0c076b) and cross-checked
// against strozfriedberg/plistutils's `ALIASV2`/`ALIASV3` NamedStructs (@3d00bf8, built from real
// samples, citing Apple's Aliases.h). mac_alias's v3 READER is buggy — it reads 46 bytes of a
// 50-byte block — so the writer and plistutils are the sources of truth for the v3 layout here.
//
// Structurally unrelated to a CFURL bookmark (no `book`/`alis` TOC; a fixed header plus TLV tags),
// so it is its own decoder, never an extension of cfurlBookmarkReader.ts. Every malformed case is
// an AliasRecordError, never a raw RangeError: the caller keeps the item and discloses the failure.
// Nothing is resolved against a live filesystem — these are the names, ids and dates the record
// stored when it was written.

export class AliasRecordError extends Error {}

/** A real record is a few hundred bytes; anything past this is not one. */
export const MAX_ALIAS_BYTES = 64 * 1024;
export const MAX_ALIAS_TAGS = 64;
export const MAX_CNID_PATH = 64;
/** mac_alias's own floor for `recsize`, which counts the whole record including its 8-byte header. */
const MIN_RECSIZE = 150;
const HEADER_BYTES = 8;
const V2_FIXED_BYTES = 142;
const V3_FIXED_BYTES = 50;
const TAG_TERMINATOR = -1;

const TAG_CARBON_FOLDER_NAME = 0;
const TAG_CNID_PATH = 1;
const TAG_CARBON_PATH = 2;
const TAG_UNICODE_FILENAME = 14;
const TAG_UNICODE_VOLUME_NAME = 15;
const TAG_HIGH_RES_VOLUME_CREATION_DATE = 16;
const TAG_HIGH_RES_CREATION_DATE = 17;
const TAG_POSIX_PATH = 18;
const TAG_POSIX_PATH_TO_MOUNTPOINT = 19;
const TAG_USER_HOME_LENGTH_PREFIX = 21;

const MAC_EPOCH_MS = Date.UTC(1904, 0, 1);

export interface AliasRecord {
  version: 2 | 3;
  /** The caller-set four-char code in bytes 0-3, as 4 ASCII chars when printable else hex. */
  appinfo: string;
  /** Declared record size (header included); trailing bytes past it are tolerated. */
  recsize: number;
  /** 0 = file, 1 = folder per mac_alias's ALIAS_KIND_FILE/ALIAS_KIND_FOLDER; anything else raw. */
  kind: number;
  volumeName?: string;
  volumeCreationDate?: string;
  fsType?: string;
  diskType?: number;
  folderCnid?: number;
  targetCnid?: number;
  /** The unicode (tag 14) filename when present, else the Pascal one with mac_alias's `/`→`:` transform. */
  targetFilename?: string;
  /** The v2 Pascal-string filename after mac_alias's `/`→`:` transform, kept separately for disclosure. */
  pascalFilename?: string;
  targetCreationDate?: string;
  creatorCode?: string;
  typeCode?: string;
  levelsFrom?: number;
  levelsTo?: number;
  volumeAttributes?: number;
  folderName?: string;
  cnidPath?: number[];
  carbonPath?: string;
  posixPath?: string;
  posixMountPoint?: string;
  userHomePrefixLen?: number;
  /** Every tag this reader does not interpret, by number only; tag 20 (a nested alias) is never recursed. */
  unknownTags: number[];
}

/**
 * The structural probe the loginitems collector dispatches on. NOT the first four bytes: those are
 * `appinfo`, a caller-set code mac_alias never validates, so `alis` there is legal and a magic-first
 * dispatch would send a real record to the bookmark decoder (#1301 design review finding 2). A CFURL
 * bookmark's bytes 4-7 are its little-endian u32 size, so bytes 6-7 read 0 for every bookmark under
 * 64 KiB — the probe cannot mistake a bookmark for an alias.
 */
export function looksLikeAliasRecord(bytes: Buffer): boolean {
  if (bytes.length < HEADER_BYTES) return false;
  const recsize = bytes.readInt16BE(4);
  const version = bytes.readInt16BE(6);
  return (version === 2 || version === 3) && recsize >= MIN_RECSIZE && recsize <= bytes.length;
}

function fail(msg: string): never {
  throw new AliasRecordError(msg);
}

/** A fixed-width code field (2 or 4 bytes): as ASCII when every byte is printable, else hex. */
function codeField(b: Buffer): string {
  const s = b.toString("latin1").replace(/\0+$/, "");
  return s.length > 0 && /^[\x20-\x7e]+$/.test(s) ? s : b.toString("hex");
}

/** A `p`-format Pascal string: one count byte, then at most `field - 1` bytes of text. */
function pascal(b: Buffer, off: number, field: number, what: string): string {
  const n = b[off];
  if (n > field - 1) fail(`${what} Pascal count ${n} exceeds its ${field - 1}-byte field`);
  // mac_alias: `.decode().replace("/", ":")` — HFS names use ':' as the separator.
  return b
    .subarray(off + 1, off + 1 + n)
    .toString("utf8")
    .replace(/\//g, ":");
}

function macDate(seconds: number, what: string): string | undefined {
  if (!Number.isFinite(seconds)) fail(`${what} not finite`);
  if (seconds === 0) return undefined; // the common "unset" value, never 1904-01-01
  const d = new Date(MAC_EPOCH_MS + seconds * 1000);
  if (Number.isNaN(d.getTime())) fail(`${what} out of representable range`);
  return d.toISOString();
}

/** A high-resolution date: a big-endian u64 of seconds × 65536 (top 48 bits seconds, low 16 fraction). */
function hiResDate(b: Buffer, what: string): string | undefined {
  const raw = b.readBigUInt64BE(0);
  return macDate(Number(raw) / 65536, what);
}

function utf16Tag(value: Buffer, what: string): string {
  // `>H count` then UTF-16BE; mac_alias reads `value[2:]` verbatim (no separator transform).
  if (value.length < 2 || (value.length - 2) % 2 !== 0) fail(`${what} not a valid UTF-16 tag`);
  return value.subarray(2).swap16().toString("utf16le");
}

export function parseAliasRecord(input: Buffer): AliasRecord {
  if (input.length > MAX_ALIAS_BYTES) fail("alias record exceeds the size budget");
  if (input.length < HEADER_BYTES) fail("shorter than the alias header");
  const appinfo = codeField(input.subarray(0, 4));
  const recsize = input.readInt16BE(4);
  const versionRaw = input.readInt16BE(6);
  if (versionRaw !== 2 && versionRaw !== 3) fail(`unsupported alias version ${versionRaw}`);
  if (recsize < MIN_RECSIZE) fail(`alias recsize ${recsize} below the ${MIN_RECSIZE}-byte floor`);
  if (recsize > input.length) fail(`alias recsize ${recsize} past the ${input.length}-byte buffer`);
  const version: 2 | 3 = versionRaw;
  const b = input;

  const fixedBytes = version === 2 ? V2_FIXED_BYTES : V3_FIXED_BYTES;
  if (HEADER_BYTES + fixedBytes > b.length) fail("alias fixed block truncated");

  const rec: AliasRecord = { version, appinfo, recsize, kind: 0, unknownTags: [] };
  let off = HEADER_BYTES;
  if (version === 2) {
    // >h 28p I 2s h I 64p I I 4s 4s h h I 2s 10s
    rec.kind = b.readInt16BE(off);
    rec.volumeName = pascal(b, off + 2, 28, "volume name");
    rec.volumeCreationDate = macDate(b.readUInt32BE(off + 30), "volume creation date");
    rec.fsType = codeField(b.subarray(off + 34, off + 36));
    rec.diskType = b.readInt16BE(off + 36);
    rec.folderCnid = b.readUInt32BE(off + 38);
    rec.pascalFilename = pascal(b, off + 42, 64, "filename");
    rec.targetFilename = rec.pascalFilename;
    rec.targetCnid = b.readUInt32BE(off + 106);
    rec.targetCreationDate = macDate(b.readUInt32BE(off + 110), "creation date");
    rec.creatorCode = codeField(b.subarray(off + 114, off + 118));
    rec.typeCode = codeField(b.subarray(off + 118, off + 122));
    rec.levelsFrom = b.readInt16BE(off + 122);
    rec.levelsTo = b.readInt16BE(off + 124);
    rec.volumeAttributes = b.readUInt32BE(off + 126);
  } else {
    // >h Q 4s h I I Q I 14s — 50 bytes (mac_alias's writer and plistutils agree; its reader does not)
    rec.kind = b.readInt16BE(off);
    rec.volumeCreationDate = hiResDate(b.subarray(off + 2, off + 10), "volume creation date");
    rec.fsType = codeField(b.subarray(off + 10, off + 14));
    rec.diskType = b.readInt16BE(off + 14);
    rec.folderCnid = b.readUInt32BE(off + 16);
    rec.targetCnid = b.readUInt32BE(off + 20);
    rec.targetCreationDate = hiResDate(b.subarray(off + 24, off + 32), "creation date");
    rec.volumeAttributes = b.readUInt32BE(off + 32);
  }
  off += fixedBytes;

  let tags = 0;
  for (;;) {
    if (off + 2 > b.length) fail("alias tag list has no terminator");
    const tag = b.readInt16BE(off);
    off += 2;
    if (tag === TAG_TERMINATOR) break;
    tags += 1;
    if (tags > MAX_ALIAS_TAGS) fail("alias tag budget exceeded");
    if (off + 2 > b.length) fail("alias tag length truncated");
    const length = b.readInt16BE(off);
    off += 2;
    if (length < 0) fail(`alias tag ${tag} has a negative length`);
    if (off + length > b.length) fail(`alias tag ${tag} value runs past the buffer`);
    const value = b.subarray(off, off + length);
    off += length + (length & 1);

    switch (tag) {
      case TAG_CARBON_FOLDER_NAME:
        rec.folderName = value.toString("utf8").replace(/\//g, ":");
        break;
      case TAG_CNID_PATH: {
        if (length < 4 || length % 4 !== 0) fail("alias CNID path length not a multiple of 4");
        const n = Math.min(length / 4, MAX_CNID_PATH);
        rec.cnidPath = Array.from({ length: n }, (_, i) => value.readUInt32BE(i * 4));
        break;
      }
      case TAG_CARBON_PATH:
        rec.carbonPath = value.toString("utf8");
        break;
      case TAG_UNICODE_FILENAME:
        rec.targetFilename = utf16Tag(value, "unicode filename");
        break;
      case TAG_UNICODE_VOLUME_NAME:
        rec.volumeName = utf16Tag(value, "unicode volume name");
        break;
      case TAG_HIGH_RES_VOLUME_CREATION_DATE:
        if (length !== 8) fail("alias high-res volume date not 8 bytes");
        rec.volumeCreationDate = hiResDate(value, "high-res volume creation date");
        break;
      case TAG_HIGH_RES_CREATION_DATE:
        if (length !== 8) fail("alias high-res creation date not 8 bytes");
        rec.targetCreationDate = hiResDate(value, "high-res creation date");
        break;
      case TAG_POSIX_PATH:
        rec.posixPath = value.toString("utf8");
        break;
      case TAG_POSIX_PATH_TO_MOUNTPOINT:
        rec.posixMountPoint = value.toString("utf8");
        break;
      case TAG_USER_HOME_LENGTH_PREFIX:
        if (length < 2) fail("alias user-home prefix length truncated");
        rec.userHomePrefixLen = value.readInt16BE(0);
        break;
      default:
        // Includes tag 20 (a nested alias of a disk image) — disclosed, never recursed into.
        rec.unknownTags.push(tag);
    }
  }
  return rec;
}
