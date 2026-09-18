// A bounded reader for Apple's binary property-list format (bplist00). Schema verified live
// against cclgroupltd/ccl-bplist's own __decode_object()/load() (a well-established, actively
// referenced DFIR tool) — the type-byte encoding (null/bool/int/float/date/data/ASCII string/
// UTF-16 string/UID/array/set/dict), the 32-byte trailer (offsetIntSize, objectRefSize, numObjects,
// topObject, offsetTableOffset, all big-endian), and the offset table it points to. #933 item 8
// (importer half, #1013). See RECOMMENDATION-12.md for the full research trail, including the
// design-review rejection that caught this format's own hostile-input surface.
//
// Every wire-format integer used for navigation (offsets, sizes, counts) is read and checked as a
// bigint BEFORE any conversion to a JS number, and only ever converted once it is both a safe
// integer and within the buffer's own bounds — never a raw cast (Codex design review finding).

export class BplistUid {
  constructor(public readonly value: number) {}
}

export type BplistValue =
  | null
  | boolean
  | bigint
  | number
  | Date
  | Buffer
  | string
  | BplistUid
  | BplistValue[]
  | Map<BplistValue, BplistValue>;

export const MAX_INPUT_BYTES = 32 * 1024 * 1024;
export const MAX_OBJECTS = 100_000;
export const MAX_CONTAINER_ENTRIES = 50_000;
export const MAX_DECODED_BYTES = 16 * 1024 * 1024;
export const MAX_DEPTH = 64;

export class BplistError extends Error {}

const EPOCH_2001 = Date.UTC(2001, 0, 1);

function checkedOffset(value: bigint, bufLen: number, what: string): number {
  if (value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER) || value > BigInt(bufLen)) {
    throw new BplistError(`${what} out of range: ${value}`);
  }
  return Number(value);
}

class Budget {
  objects = 0;
  decodedBytes = 0;
  bumpObjects(): void {
    this.objects += 1;
    if (this.objects > MAX_OBJECTS) throw new BplistError("object count budget exceeded");
  }
  bumpBytes(n: number): void {
    this.decodedBytes += n;
    if (this.decodedBytes > MAX_DECODED_BYTES) throw new BplistError("decoded-bytes budget exceeded");
  }
}

function readMultibyteUint(buf: Buffer, off: number, len: number): bigint {
  if (off < 0 || off + len > buf.length) throw new BplistError("multibyte int out of range");
  switch (len) {
    case 1:
      return BigInt(buf.readUInt8(off));
    case 2:
      return BigInt(buf.readUInt16BE(off));
    case 4:
      return BigInt(buf.readUInt32BE(off));
    case 8:
      return buf.readBigUInt64BE(off);
    default:
      throw new BplistError(`unsupported unsigned int length ${len}`);
  }
}

function readMultibyteInt(buf: Buffer, off: number, len: number): bigint {
  if (off < 0 || off + len > buf.length) throw new BplistError("multibyte int out of range");
  switch (len) {
    case 1:
      return BigInt(buf.readUInt8(off)); // always unsigned per the real format
    case 2:
      return BigInt(buf.readInt16BE(off));
    case 4:
      return BigInt(buf.readInt32BE(off));
    case 8:
      return buf.readBigInt64BE(off);
    default:
      throw new BplistError(`unsupported signed int length ${len}`);
  }
}

// A length nibble of 0xF means "read an int object next, its decoded value is the real length" —
// used by data/ASCII/UTF-16/array/set/dict records alike.
function readExtendedLength(buf: Buffer, off: number, budget: Budget): { length: bigint; next: number } {
  const lowNibble = off < buf.length ? buf[off] & 0x0f : -1;
  if ((buf[off] & 0xf0) !== 0x10) throw new BplistError("extended length not followed by an int object");
  void lowNibble;
  const intLen = 2 ** (buf[off] & 0x0f);
  const length = readMultibyteUint(buf, off + 1, intLen);
  budget.bumpObjects();
  return { length, next: off + 1 + intLen };
}

function decodeObject(
  buf: Buffer,
  offset: number,
  objectRefSize: number,
  offsetTable: number[],
  budget: Budget,
  depth: number,
): BplistValue {
  if (depth > MAX_DEPTH) throw new BplistError("depth budget exceeded");
  if (offset < 0 || offset >= buf.length) throw new BplistError("object offset out of range");
  budget.bumpObjects();

  const typeByte = buf[offset];
  if (typeByte === 0x00) return null;
  if (typeByte === 0x08) return false;
  if (typeByte === 0x09) return true;
  if (typeByte === 0x0f) throw new BplistError("fill type not supported");

  if ((typeByte & 0xf0) === 0x10) {
    const len = 2 ** (typeByte & 0x0f);
    return readMultibyteInt(buf, offset + 1, len);
  }
  if ((typeByte & 0xf0) === 0x20) {
    // The real format defines exactly two float widths — nibble 2 (32-bit) and nibble 3 (64-bit).
    // Any other nibble is not a valid float record and must be rejected, never read as an
    // arbitrarily-sized region (Ollama code review finding).
    const nibble = typeByte & 0x0f;
    if (nibble !== 2 && nibble !== 3) throw new BplistError(`invalid float nibble ${nibble}`);
    const len = nibble === 2 ? 4 : 8;
    if (offset + 1 + len > buf.length) throw new BplistError("float out of range");
    return len === 4 ? buf.readFloatBE(offset + 1) : buf.readDoubleBE(offset + 1);
  }
  if (typeByte === 0x33) {
    if (offset + 9 > buf.length) throw new BplistError("date out of range");
    const secs = buf.readDoubleBE(offset + 1);
    if (!Number.isFinite(secs)) throw new BplistError("date value not finite");
    const date = new Date(EPOCH_2001 + secs * 1000);
    // A finite secs value (e.g. 1e300) can still produce an out-of-range, Invalid Date — reject it
    // here rather than let it masquerade as a decoded value (#1190).
    if (Number.isNaN(date.getTime())) throw new BplistError("date value out of representable range");
    return date;
  }
  if ((typeByte & 0xf0) === 0x40) {
    let dataLen: bigint;
    let dataStart: number;
    if ((typeByte & 0x0f) !== 0x0f) {
      dataLen = BigInt(typeByte & 0x0f);
      dataStart = offset + 1;
    } else {
      const ext = readExtendedLength(buf, offset + 1, budget);
      dataLen = ext.length;
      dataStart = ext.next;
    }
    const len = checkedOffset(dataLen, buf.length, "data length");
    if (dataStart + len > buf.length) throw new BplistError("data out of range");
    budget.bumpBytes(len);
    return Buffer.from(buf.subarray(dataStart, dataStart + len));
  }
  if ((typeByte & 0xf0) === 0x50) {
    let strLen: bigint;
    let strStart: number;
    if ((typeByte & 0x0f) !== 0x0f) {
      strLen = BigInt(typeByte & 0x0f);
      strStart = offset + 1;
    } else {
      const ext = readExtendedLength(buf, offset + 1, budget);
      strLen = ext.length;
      strStart = ext.next;
    }
    const len = checkedOffset(strLen, buf.length, "ascii length");
    if (strStart + len > buf.length) throw new BplistError("ascii string out of range");
    budget.bumpBytes(len);
    return buf.toString("ascii", strStart, strStart + len);
  }
  if ((typeByte & 0xf0) === 0x60) {
    let charLen: bigint;
    let strStart: number;
    if ((typeByte & 0x0f) !== 0x0f) {
      charLen = BigInt(typeByte & 0x0f);
      strStart = offset + 1;
    } else {
      const ext = readExtendedLength(buf, offset + 1, budget);
      charLen = ext.length;
      strStart = ext.next;
    }
    const chars = checkedOffset(charLen, buf.length, "utf16 length");
    const byteLen = chars * 2;
    if (strStart + byteLen > buf.length) throw new BplistError("utf16 string out of range");
    budget.bumpBytes(byteLen);
    // Big-endian UTF-16: swap byte pairs before decoding as UTF-16LE (Node has no native BE decoder).
    const be = buf.subarray(strStart, strStart + byteLen);
    const swapped = Buffer.from(be);
    swapped.swap16();
    return swapped.toString("utf16le");
  }
  if ((typeByte & 0xf0) === 0x80) {
    const len = (typeByte & 0x0f) + 1;
    const uid = readMultibyteUint(buf, offset + 1, len);
    // A UID is meaningful only as an index into the object table -- reject one that can't
    // possibly resolve, at this layer, rather than deferring the check to a caller that may not
    // apply it uniformly (Ollama code review finding).
    const idx = checkedOffset(uid, offsetTable.length, "uid");
    if (idx >= offsetTable.length) throw new BplistError(`uid ${idx} out of range`);
    return new BplistUid(idx);
  }
  if ((typeByte & 0xf0) === 0xa0 || (typeByte & 0xf0) === 0xc0) {
    let count: bigint;
    let refsStart: number;
    if ((typeByte & 0x0f) !== 0x0f) {
      count = BigInt(typeByte & 0x0f);
      refsStart = offset + 1;
    } else {
      const ext = readExtendedLength(buf, offset + 1, budget);
      count = ext.length;
      refsStart = ext.next;
    }
    const n = checkedOffset(count, MAX_CONTAINER_ENTRIES, "array/set count");
    if (n > MAX_CONTAINER_ENTRIES) throw new BplistError("container entry budget exceeded");
    const result: BplistValue[] = [];
    for (let i = 0; i < n; i++) {
      const refOff = refsStart + i * objectRefSize;
      const ref = checkedOffset(
        readMultibyteUint(buf, refOff, objectRefSize),
        offsetTable.length,
        "array ref",
      );
      if (ref >= offsetTable.length) throw new BplistError("array element ref out of range");
      result.push(decodeObject(buf, offsetTable[ref], objectRefSize, offsetTable, budget, depth + 1));
    }
    return result;
  }
  if ((typeByte & 0xf0) === 0xd0) {
    let count: bigint;
    let refsStart: number;
    if ((typeByte & 0x0f) !== 0x0f) {
      count = BigInt(typeByte & 0x0f);
      refsStart = offset + 1;
    } else {
      const ext = readExtendedLength(buf, offset + 1, budget);
      count = ext.length;
      refsStart = ext.next;
    }
    const n = checkedOffset(count, MAX_CONTAINER_ENTRIES, "dict count");
    if (n > MAX_CONTAINER_ENTRIES) throw new BplistError("container entry budget exceeded");
    const keyRefs: number[] = [];
    for (let i = 0; i < n; i++) {
      keyRefs.push(
        checkedOffset(
          readMultibyteUint(buf, refsStart + i * objectRefSize, objectRefSize),
          offsetTable.length,
          "dict key ref",
        ),
      );
    }
    const valRefsStart = refsStart + n * objectRefSize;
    const result = new Map<BplistValue, BplistValue>();
    for (let i = 0; i < n; i++) {
      const valRef = checkedOffset(
        readMultibyteUint(buf, valRefsStart + i * objectRefSize, objectRefSize),
        offsetTable.length,
        "dict value ref",
      );
      const kRef = keyRefs[i];
      if (kRef >= offsetTable.length || valRef >= offsetTable.length) {
        throw new BplistError("dict entry ref out of range");
      }
      const key = decodeObject(buf, offsetTable[kRef], objectRefSize, offsetTable, budget, depth + 1);
      const val = decodeObject(buf, offsetTable[valRef], objectRefSize, offsetTable, budget, depth + 1);
      result.set(key, val);
    }
    return result;
  }

  throw new BplistError(`unknown type byte 0x${typeByte.toString(16)}`);
}

export function parseBplist(buf: Buffer): BplistValue {
  if (buf.length > MAX_INPUT_BYTES) throw new BplistError("input exceeds the size budget");
  if (buf.length < 40 || buf.toString("ascii", 0, 8) !== "bplist00") {
    throw new BplistError("not a bplist00 file");
  }
  const trailer = buf.subarray(buf.length - 32);
  // 6 unused bytes, 1 sort-version byte (unused here), offsetIntSize:1, objectRefSize:1, then three
  // big-endian uint64s: numObjects, topObject, offsetTableOffset.
  const offsetIntSize = trailer.readUInt8(6);
  const objectRefSize = trailer.readUInt8(7);
  const numObjects = trailer.readBigUInt64BE(8);
  const topObject = trailer.readBigUInt64BE(16);
  const offsetTableOffset = trailer.readBigUInt64BE(24);

  if (offsetIntSize < 1 || offsetIntSize > 8 || objectRefSize < 1 || objectRefSize > 8) {
    throw new BplistError("invalid offset/ref size in trailer");
  }
  const objectCount = checkedOffset(numObjects, MAX_OBJECTS, "numObjects");
  if (objectCount > MAX_OBJECTS) throw new BplistError("object count budget exceeded");
  const topIndex = checkedOffset(topObject, objectCount, "topObject");
  if (topIndex >= objectCount) throw new BplistError("topObject out of range");
  const tableOffset = checkedOffset(offsetTableOffset, buf.length, "offsetTableOffset");

  const offsetTable: number[] = [];
  for (let i = 0; i < objectCount; i++) {
    const entryOff = tableOffset + i * offsetIntSize;
    const off = checkedOffset(
      readMultibyteUint(buf, entryOff, offsetIntSize),
      buf.length,
      "offset table entry",
    );
    // Every real object lives strictly BEFORE the offset table itself (the table and the 32-byte
    // trailer both follow the object stream) -- an entry that doesn't is either corrupt or crafted
    // to make an object decode from the trailer/table's own structural bytes instead of real
    // object data (Ollama code review finding).
    if (off >= tableOffset) throw new BplistError("offset table entry points outside the object stream");
    offsetTable.push(off);
  }

  const budget = new Budget();
  return decodeObject(buf, offsetTable[topIndex], objectRefSize, offsetTable, budget, 0);
}
