import { deflateRawSync, inflateRawSync } from "node:zlib";

// A tiny, dependency-free ZIP writer/reader. The redacted case export (#54) bundles the
// anonymized report + screenshots into one shareable archive; rather than pull in a native
// archiver, we emit a standard ZIP (DEFLATE method) with node:zlib so the logic stays pure and
// unit-testable (createZip → readZip round-trips). Output is deterministic — a fixed DOS
// timestamp is used so the same inputs always produce the same bytes.

export interface ZipEntry {
  /** POSIX-style path within the archive (forward slashes, no leading slash). */
  path: string;
  data: Buffer;
}

// CRC-32 (IEEE 802.3) lookup table — the checksum every ZIP entry carries.
const CRC_TABLE: Uint32Array = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

export function crc32(buf: Buffer): number {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = (CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8)) >>> 0;
  return (c ^ 0xffffffff) >>> 0;
}

const SIG_LOCAL = 0x04034b50;
const SIG_CENTRAL = 0x02014b50;
const SIG_EOCD = 0x06054b50;
const METHOD_DEFLATE = 8;
const VERSION = 20; // 2.0 — the minimum that supports DEFLATE
const FLAG_UTF8 = 0x0800; // general-purpose bit 11: filenames are UTF-8
// Fixed DOS time/date (1980-01-01 00:00:00) → reproducible archives, no Date dependency.
const DOS_TIME = 0;
const DOS_DATE = 0x0021; // (1980-1980)<<9 | 1<<5 | 1

interface PreparedEntry {
  nameBytes: Buffer;
  compressed: Buffer;
  crc: number;
  uncompressedSize: number;
  localOffset: number;
}

/** Build a ZIP archive (DEFLATE-compressed) from the given entries. Pure — never touches disk. */
export function createZip(entries: ZipEntry[]): Buffer {
  const localParts: Buffer[] = [];
  const prepared: PreparedEntry[] = [];
  let offset = 0;

  for (const entry of entries) {
    const nameBytes = Buffer.from(entry.path, "utf8");
    const compressed = deflateRawSync(entry.data);
    const crc = crc32(entry.data);

    const header = Buffer.alloc(30);
    header.writeUInt32LE(SIG_LOCAL, 0);
    header.writeUInt16LE(VERSION, 4);
    header.writeUInt16LE(FLAG_UTF8, 6);
    header.writeUInt16LE(METHOD_DEFLATE, 8);
    header.writeUInt16LE(DOS_TIME, 10);
    header.writeUInt16LE(DOS_DATE, 12);
    header.writeUInt32LE(crc, 14);
    header.writeUInt32LE(compressed.length, 18);
    header.writeUInt32LE(entry.data.length, 22);
    header.writeUInt16LE(nameBytes.length, 26);
    header.writeUInt16LE(0, 28); // extra field length

    prepared.push({ nameBytes, compressed, crc, uncompressedSize: entry.data.length, localOffset: offset });
    localParts.push(header, nameBytes, compressed);
    offset += header.length + nameBytes.length + compressed.length;
    // ZIP32 stores sizes/offsets as 32-bit. Fail loudly rather than silently emit a corrupt archive
    // (this is not a ZIP64 writer). 4 GB is far beyond any realistic redacted-case package.
    if (offset > 0xffffffff || entry.data.length > 0xffffffff) {
      throw new Error("archive too large for ZIP32 (over 4 GB) — exclude screenshots or split the case");
    }
  }

  const centralParts: Buffer[] = [];
  let centralSize = 0;
  for (const p of prepared) {
    const header = Buffer.alloc(46);
    header.writeUInt32LE(SIG_CENTRAL, 0);
    header.writeUInt16LE(VERSION, 4); // version made by
    header.writeUInt16LE(VERSION, 6); // version needed
    header.writeUInt16LE(FLAG_UTF8, 8);
    header.writeUInt16LE(METHOD_DEFLATE, 10);
    header.writeUInt16LE(DOS_TIME, 12);
    header.writeUInt16LE(DOS_DATE, 14);
    header.writeUInt32LE(p.crc, 16);
    header.writeUInt32LE(p.compressed.length, 20);
    header.writeUInt32LE(p.uncompressedSize, 24);
    header.writeUInt16LE(p.nameBytes.length, 28);
    header.writeUInt16LE(0, 30); // extra field length
    header.writeUInt16LE(0, 32); // comment length
    header.writeUInt16LE(0, 34); // disk number start
    header.writeUInt16LE(0, 36); // internal attributes
    header.writeUInt32LE(0, 38); // external attributes
    header.writeUInt32LE(p.localOffset, 42);

    centralParts.push(header, p.nameBytes);
    centralSize += header.length + p.nameBytes.length;
  }

  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(SIG_EOCD, 0);
  eocd.writeUInt16LE(0, 4); // this disk number
  eocd.writeUInt16LE(0, 6); // disk with central directory
  eocd.writeUInt16LE(prepared.length, 8); // entries on this disk
  eocd.writeUInt16LE(prepared.length, 10); // total entries
  eocd.writeUInt32LE(centralSize, 12);
  eocd.writeUInt32LE(offset, 16); // central directory offset
  eocd.writeUInt16LE(0, 20); // comment length

  return Buffer.concat([...localParts, ...centralParts, eocd]);
}

/**
 * Read back the entries of an archive produced by {@link createZip} (DEFLATE or stored). Walks the
 * central directory, inflates each entry, and verifies its CRC-32. Used by tests and any consumer
 * that needs to inspect a built package; not a general-purpose unzip (no ZIP64 / encryption).
 */
export function readZip(archive: Buffer): ZipEntry[] {
  // Locate the End Of Central Directory record (scan back from the end; no trailing comment).
  let eocd = -1;
  for (let i = archive.length - 22; i >= 0; i--) {
    if (archive.readUInt32LE(i) === SIG_EOCD) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new Error("not a ZIP archive: EOCD not found");

  const total = archive.readUInt16LE(eocd + 10);
  let ptr = archive.readUInt32LE(eocd + 16); // central directory offset
  const entries: ZipEntry[] = [];

  for (let i = 0; i < total; i++) {
    if (archive.readUInt32LE(ptr) !== SIG_CENTRAL) throw new Error("corrupt ZIP: bad central header");
    const method = archive.readUInt16LE(ptr + 10);
    const crc = archive.readUInt32LE(ptr + 16);
    const compSize = archive.readUInt32LE(ptr + 20);
    const nameLen = archive.readUInt16LE(ptr + 28);
    const extraLen = archive.readUInt16LE(ptr + 30);
    const commentLen = archive.readUInt16LE(ptr + 32);
    const localOffset = archive.readUInt32LE(ptr + 42);
    const name = archive.toString("utf8", ptr + 46, ptr + 46 + nameLen);

    // Jump to the local header to find the actual data start (its name/extra lengths may differ).
    const localNameLen = archive.readUInt16LE(localOffset + 26);
    const localExtraLen = archive.readUInt16LE(localOffset + 28);
    const dataStart = localOffset + 30 + localNameLen + localExtraLen;
    const compressed = archive.subarray(dataStart, dataStart + compSize);
    const data = method === METHOD_DEFLATE ? inflateRawSync(compressed) : Buffer.from(compressed);

    if (crc32(data) !== crc) throw new Error(`corrupt ZIP: CRC mismatch for ${name}`);
    entries.push({ path: name, data });
    ptr += 46 + nameLen + extraLen + commentLen;
  }
  return entries;
}
