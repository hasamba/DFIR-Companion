// A bounded reader for Apple's CFURL "bookmark" format (the `book`/`alis`-magic binary blob a
// login item's own configured target is stored as). Ported — not re-derived — from
// michaeldiazlutz/mac_alias's own `Bookmark._get_item()`/`Bookmark.from_bytes()` (fetched live from
// PyPI, actively maintained, used by `dmgbuild`; complete and bidirectional, so its byte-level
// structure is trustworthy in both directions). #933 item 8 (importer half, #1013). See
// RECOMMENDATION-12.md for the full research trail. This reads the modern CFURL bookmark format
// only — the older, structurally different classic Alias-record format (used by pre-Sonoma
// `com.apple.loginitems.plist`) is explicitly out of scope, never conflated with this one.

export class CfurlBookmarkError extends Error {}

export const MAX_BOOKMARK_BYTES = 2 * 1024 * 1024;
export const MAX_TOC_COUNT = 256;
export const MAX_TOC_ENTRIES = 4096;
export const MAX_ARRAY_ITEMS = 4096;
export const MAX_DICT_ENTRIES = 4096;
export const MAX_STRING_BYTES = 65536;

const BMK_DATA_TYPE_MASK = 0xffffff00;
const BMK_DATA_SUBTYPE_MASK = 0x000000ff;

const BMK_STRING = 0x0100;
const BMK_DATA = 0x0200;
const BMK_NUMBER = 0x0300;
const BMK_DATE = 0x0400;
const BMK_BOOLEAN = 0x0500;
const BMK_ARRAY = 0x0600;
const BMK_DICT = 0x0700;
const BMK_UUID = 0x0800;
const BMK_URL = 0x0900;
const BMK_NULL = 0x0a00;

const CF_NUMBER_SINT8 = 1;
const CF_NUMBER_SINT16 = 2;
const CF_NUMBER_SINT32 = 3;
const CF_NUMBER_SINT64 = 4;
const CF_NUMBER_FLOAT32 = 5;
const CF_NUMBER_FLOAT64 = 6;

const BMK_URL_ST_ABSOLUTE = 0x0001;
const BMK_URL_ST_RELATIVE = 0x0002;
const BMK_BOOLEAN_ST_TRUE = 0x0001;

export const kBookmarkPath = 0x1004;
export const kBookmarkCNIDPath = 0x1005;
export const kBookmarkFileCreationDate = 0x1040;
export const kBookmarkVolumePath = 0x2002;
export const kBookmarkVolumeName = 0x2010;
export const kBookmarkVolumeUUID = 0x2011;
export const kBookmarkVolumeIsRoot = 0x2030;
export const kBookmarkWasFileReference = 0xd001;
export const kBookmarkDisplayName = 0xf017;

export type BookmarkItem =
  | null
  | boolean
  | string
  | number
  | bigint
  | Date
  | Buffer
  | { absolute: string }
  | { base: BookmarkItem; relative: BookmarkItem }
  | BookmarkItem[]
  | Map<number | string, BookmarkItem>;

class Budget {
  entries = 0;
  bump(max: number, what: string): void {
    this.entries += 1;
    if (this.entries > max) throw new CfurlBookmarkError(`${what} budget exceeded`);
  }
}

function u32le(buf: Buffer, off: number): number {
  if (off < 0 || off + 4 > buf.length) throw new CfurlBookmarkError("u32 out of range");
  return buf.readUInt32LE(off);
}

function getItem(data: Buffer, hdrsize: number, offset: number, budget: Budget, depth: number): BookmarkItem {
  if (depth > 32) throw new CfurlBookmarkError("bookmark item nesting too deep");
  const actual = hdrsize + offset;
  if (actual < 0 || actual + 8 > data.length) throw new CfurlBookmarkError("item offset out of range");
  const length = u32le(data, actual);
  const typecode = u32le(data, actual + 4);
  if (length > data.length || actual + 8 + length > data.length) {
    throw new CfurlBookmarkError("item data truncated");
  }
  const bytes = data.subarray(actual + 8, actual + 8 + length);
  const dtype = typecode & BMK_DATA_TYPE_MASK;
  const dsubtype = typecode & BMK_DATA_SUBTYPE_MASK;

  if (dtype === BMK_STRING) {
    if (length > MAX_STRING_BYTES) throw new CfurlBookmarkError("string too long");
    return bytes.toString("utf8");
  }
  if (dtype === BMK_DATA) {
    if (length > MAX_STRING_BYTES) throw new CfurlBookmarkError("data item too long");
    return Buffer.from(bytes);
  }
  if (dtype === BMK_NUMBER) {
    if (dsubtype === CF_NUMBER_SINT8) return bytes.readInt8(0);
    if (dsubtype === CF_NUMBER_SINT16) return bytes.readInt16LE(0);
    if (dsubtype === CF_NUMBER_SINT32) return bytes.readInt32LE(0);
    if (dsubtype === CF_NUMBER_SINT64) return bytes.readBigInt64LE(0);
    if (dsubtype === CF_NUMBER_FLOAT32) return bytes.readFloatLE(0);
    if (dsubtype === CF_NUMBER_FLOAT64) return bytes.readDoubleLE(0);
    return null;
  }
  if (dtype === BMK_DATE) {
    // Dates are stored as *big-endian* doubles, unlike everything else in this format.
    const secs = bytes.readDoubleBE(0);
    if (!Number.isFinite(secs)) throw new CfurlBookmarkError("date value not finite");
    const date = new Date(Date.UTC(2001, 0, 1) + secs * 1000);
    // A finite secs value can still produce an out-of-range, Invalid Date — reject it here rather
    // than let it masquerade as a decoded value (#1190).
    if (Number.isNaN(date.getTime())) throw new CfurlBookmarkError("date value out of representable range");
    return date;
  }
  if (dtype === BMK_BOOLEAN) return dsubtype === BMK_BOOLEAN_ST_TRUE;
  if (dtype === BMK_UUID) {
    if (length !== 16) throw new CfurlBookmarkError("uuid item wrong length");
    return Buffer.from(bytes);
  }
  if (dtype === BMK_URL) {
    if (dsubtype === BMK_URL_ST_ABSOLUTE) return { absolute: bytes.toString("utf8") };
    if (dsubtype === BMK_URL_ST_RELATIVE) {
      if (length < 8) throw new CfurlBookmarkError("relative url item too short");
      const baseoff = bytes.readUInt32LE(0);
      const reloff = bytes.readUInt32LE(4);
      const base = getItem(data, hdrsize, baseoff, budget, depth + 1);
      const relative = getItem(data, hdrsize, reloff, budget, depth + 1);
      return { base, relative };
    }
    return null;
  }
  if (dtype === BMK_ARRAY) {
    const count = length / 4;
    if (!Number.isInteger(count)) throw new CfurlBookmarkError("array item length not a multiple of 4");
    if (count > MAX_ARRAY_ITEMS) throw new CfurlBookmarkError("array item count budget exceeded");
    const result: BookmarkItem[] = [];
    for (let i = 0; i < count; i++) {
      budget.bump(MAX_ARRAY_ITEMS * 16, "array elements");
      const eltoff = bytes.readUInt32LE(i * 4);
      result.push(getItem(data, hdrsize, eltoff, budget, depth + 1));
    }
    return result;
  }
  if (dtype === BMK_DICT) {
    const count = length / 8;
    if (!Number.isInteger(count)) throw new CfurlBookmarkError("dict item length not a multiple of 8");
    if (count > MAX_DICT_ENTRIES) throw new CfurlBookmarkError("dict item entry budget exceeded");
    const result = new Map<number | string, BookmarkItem>();
    for (let i = 0; i < count; i++) {
      budget.bump(MAX_DICT_ENTRIES * 16, "dict entries");
      const keyoff = bytes.readUInt32LE(i * 8);
      const valoff = bytes.readUInt32LE(i * 8 + 4);
      const key = getItem(data, hdrsize, keyoff, budget, depth + 1);
      const val = getItem(data, hdrsize, valoff, budget, depth + 1);
      if (typeof key === "string" || typeof key === "number") result.set(key, val);
    }
    return result;
  }
  if (dtype === BMK_NULL) return null;

  throw new CfurlBookmarkError(`unknown bookmark item type 0x${typecode.toString(16)}`);
}

export interface Bookmark {
  tocs: Map<number, Map<number | string, BookmarkItem>>;
  resolvedFromFormat: "book" | "alis";
  /** True when the TOC chain ended because a non-zero `nextToc` pointed at a block whose own magic
   * did not match 0xFFFFFFFE — real `mac_alias` treats this the same as a clean end of chain (a
   * `nextToc` of 0), but a mismatch after at least one real TOC was already read is at least as
   * consistent with truncation/corruption as with a deliberate terminator, so it is disclosed here
   * rather than silently folded into the same "clean" case (Ollama code review finding). */
  tocChainTruncated: boolean;
}

export function parseBookmark(data: Buffer): Bookmark {
  if (data.length > MAX_BOOKMARK_BYTES) throw new CfurlBookmarkError("bookmark exceeds the size budget");
  if (data.length < 16) throw new CfurlBookmarkError("not a bookmark (too short)");
  const magicBytes = data.toString("ascii", 0, 4);
  if (magicBytes !== "book" && magicBytes !== "alis") throw new CfurlBookmarkError("bad bookmark magic");
  const size = u32le(data, 4);
  const hdrsize = u32le(data, 12);
  if (hdrsize < 16 || hdrsize > size || size !== data.length) {
    throw new CfurlBookmarkError("inconsistent bookmark header");
  }

  const budget = new Budget();
  const tocs = new Map<number, Map<number | string, BookmarkItem>>();
  const visitedTocOffsets = new Set<number>();
  let tocOffset = u32le(data, hdrsize);
  let tocChainTruncated = false;

  while (tocOffset !== 0) {
    if (visitedTocOffsets.has(tocOffset)) throw new CfurlBookmarkError("TOC chain cycle");
    visitedTocOffsets.add(tocOffset);
    budget.bump(MAX_TOC_COUNT, "TOC count");

    const tocBase = hdrsize + tocOffset;
    if (tocOffset > size - hdrsize || size - tocBase < 20)
      throw new CfurlBookmarkError("TOC offset out of range");
    const tocMagic = u32le(data, tocBase + 4);
    if (tocMagic !== 0xfffffffe) {
      // Matches real mac_alias behavior: a mismatched magic ends the chain rather than throwing.
      // Disclosed, not silently folded into a clean end (a non-zero nextToc that fails this check
      // is at least as consistent with truncation/corruption as with a deliberate terminator).
      tocChainTruncated = true;
      break;
    }
    const tocId = u32le(data, tocBase + 8);
    const nextToc = u32le(data, tocBase + 12);
    const tocCount = u32le(data, tocBase + 16);
    if (tocCount > MAX_TOC_ENTRIES) throw new CfurlBookmarkError("TOC entry budget exceeded");

    const toc = new Map<number | string, BookmarkItem>();
    for (let n = 0; n < tocCount; n++) {
      budget.bump(MAX_TOC_ENTRIES * MAX_TOC_COUNT, "TOC entries");
      const eBase = tocBase + 20 + 12 * n;
      if (eBase + 12 > data.length) throw new CfurlBookmarkError("TOC entry out of range");
      let eid: number | BookmarkItem = u32le(data, eBase);
      const eOffset = u32le(data, eBase + 4);
      if (eid & 0x80000000) {
        eid = getItem(data, hdrsize, eid & 0x7fffffff, budget, 0);
      }
      const value = getItem(data, hdrsize, eOffset, budget, 0);
      if (typeof eid === "string" || typeof eid === "number") toc.set(eid, value);
    }
    tocs.set(tocId, toc);
    tocOffset = nextToc;
  }

  return { tocs, resolvedFromFormat: magicBytes, tocChainTruncated };
}

export function bookmarkGet(bookmark: Bookmark, key: number | string): BookmarkItem | undefined {
  for (const toc of bookmark.tocs.values()) {
    if (toc.has(key)) return toc.get(key);
  }
  return undefined;
}
