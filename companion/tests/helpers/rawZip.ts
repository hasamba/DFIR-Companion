import { createDeflateRaw, crc32, deflateRawSync } from "node:zlib";

/**
 * A hand-rolled ZIP builder for tests that need archives a normal writer refuses to produce: lying
 * sizes, stored entries, overlapping entries, bombs (#1828).
 */

export interface RawZipEntry {
  name: string;
  /** Compressed (or stored) bytes as they go into the archive. */
  body: Buffer;
  method: 0 | 8;
  crc: number;
  /** The inflated size the headers declare — may lie. */
  size: number;
  flags?: number;
  /** Put this entry's data at another entry's local header (overlap tests). */
  shareLocalWith?: number;
}

export function deflatedEntry(name: string, data: Buffer): RawZipEntry {
  return { name, body: deflateRawSync(data), method: 8, crc: crc32(data), size: data.length };
}

export function storedEntry(name: string, data: Buffer): RawZipEntry {
  return { name, body: data, method: 0, crc: crc32(data), size: data.length };
}

/**
 * DEFLATE `bytes` zero bytes without ever holding them: a 256 MiB bomb costs ~256 KB of memory.
 * Returns the compressed stream and the CRC-32 of the zeros.
 */
export async function deflatedZeros(bytes: number): Promise<{ body: Buffer; crc: number }> {
  const chunk = Buffer.alloc(Math.min(bytes, 1024 * 1024));
  const deflater = createDeflateRaw({ level: 9 });
  const out: Buffer[] = [];
  deflater.on("data", (c: Buffer) => out.push(c));
  const done = new Promise<void>((resolve, reject) => {
    deflater.on("end", resolve);
    deflater.on("error", reject);
  });
  let crc = 0;
  for (let left = bytes; left > 0; left -= chunk.length) {
    const piece = left >= chunk.length ? chunk : chunk.subarray(0, left);
    crc = crc32(piece, crc);
    if (!deflater.write(piece)) await new Promise((r) => deflater.once("drain", r));
  }
  deflater.end();
  await done;
  return { body: Buffer.concat(out), crc };
}

export function buildRawZip(entries: RawZipEntry[]): Buffer {
  const locals: Buffer[] = [];
  const offsets: number[] = [];
  let offset = 0;
  for (const e of entries) {
    const name = Buffer.from(e.name, "utf8");
    if (e.shareLocalWith !== undefined) {
      offsets.push(offsets[e.shareLocalWith]);
      continue;
    }
    const h = Buffer.alloc(30);
    h.writeUInt32LE(0x04034b50, 0);
    h.writeUInt16LE(20, 4);
    h.writeUInt16LE(e.flags ?? 0x0800, 6);
    h.writeUInt16LE(e.method, 8);
    h.writeUInt32LE(e.crc, 14);
    h.writeUInt32LE(e.body.length, 18);
    h.writeUInt32LE(e.size, 22);
    h.writeUInt16LE(name.length, 26);
    offsets.push(offset);
    locals.push(h, name, e.body);
    offset += 30 + name.length + e.body.length;
  }
  const central: Buffer[] = [];
  let cdSize = 0;
  entries.forEach((e, i) => {
    const name = Buffer.from(e.name, "utf8");
    const h = Buffer.alloc(46);
    h.writeUInt32LE(0x02014b50, 0);
    h.writeUInt16LE(20, 4);
    h.writeUInt16LE(20, 6);
    h.writeUInt16LE(e.flags ?? 0x0800, 8);
    h.writeUInt16LE(e.method, 10);
    h.writeUInt32LE(e.crc, 16);
    h.writeUInt32LE(e.body.length, 20);
    h.writeUInt32LE(e.size, 24);
    h.writeUInt16LE(name.length, 28);
    h.writeUInt32LE(offsets[i], 42);
    central.push(h, name);
    cdSize += 46 + name.length;
  });
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(cdSize, 12);
  eocd.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, ...central, eocd]);
}
