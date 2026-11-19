/**
 * A zip archive read member by member from an already-open descriptor (#2714), on yauzl: the
 * central directory only to list, and one member's bytes at a time, streamed from disk. ZIP64 is
 * supported, so a hunt export past 4 GB opens like any other.
 *
 * NAMES ARE DECODED HERE, NOT BY YAUZL. With yauzl's own decoding one unsafe name aborts the whole
 * archive; decoding each name with yauzl's documented low-level helper (CP437, the UTF-8 flag, the
 * Info-ZIP Unicode Path field) lets one bad member be refused while the rest are still read.
 * `validateEntrySizes` stays on: a member whose bytes do not match the size it declares errors out.
 * yauzl does not check CRC-32, so both readers below do: evidence that inflated to the wrong bytes
 * is refused, never imported.
 */
import type { FileHandle } from "node:fs/promises";
import type { Readable } from "node:stream";
import { crc32 } from "node:zlib";
import yauzl from "yauzl";
import type { Entry, ZipFile } from "yauzl";

export type { Entry, ZipFile };

export interface ZipMember {
  /** `/`-separated name (a backslash is read as a separator, as yauzl does by default). */
  name: string;
  entry: Entry;
  dir: boolean;
  /** Why the member must not be read or written, when it must not. */
  refusal?: string;
}

const S_IFMT = 0o170000;
const S_IFLNK = 0o120000;

/**
 * Open the archive on `handle` without taking ownership of it: the caller closes the handle and must
 * NEVER call `zip.close()`, which closes the descriptor underneath that handle (a double close of an
 * fd number that may already be reused). With autoClose off, yauzl never closes it on its own.
 */
export function openZip(handle: FileHandle): Promise<ZipFile> {
  return yauzl.fromFdPromise(handle.fd, {
    lazyEntries: true,
    autoClose: false,
    decodeStrings: false,
    validateEntrySizes: true,
  });
}

/** Every entry of the central directory, each with its decoded name and any refusal. */
export function listZipMembers(zip: ZipFile): Promise<ZipMember[]> {
  return new Promise((resolve, reject) => {
    const out: ZipMember[] = [];
    zip.on("entry", (entry: Entry) => {
      out.push(describe(entry));
      zip.readEntry();
    });
    zip.once("end", () => resolve(out));
    zip.once("error", reject);
    zip.readEntry();
  });
}

function describe(entry: Entry): ZipMember {
  const raw = entry.fileNameRaw ?? Buffer.from(String(entry.fileName));
  const name = yauzl.getFileNameLowLevel(entry.generalPurposeBitFlag, raw, entry.extraFields, false);
  const dir = name.endsWith("/");
  const invalid = yauzl.validateFileName(name);
  if (invalid) return { name, entry, dir, refusal: `unsafe member name (${invalid})` };
  if (((entry.externalFileAttributes >>> 16) & S_IFMT) === S_IFLNK)
    return { name, entry, dir, refusal: "symbolic link member" };
  if (entry.isEncrypted()) return { name, entry, dir, refusal: "encrypted member" };
  if (!entry.canDecodeFileData()) return { name, entry, dir, refusal: "unsupported compression method" };
  return { name, entry, dir };
}

/** One member's bytes, refusing more than `maxBytes`. */
export async function readZipMember(zip: ZipFile, entry: Entry, maxBytes: number): Promise<Buffer> {
  if (entry.uncompressedSize > maxBytes)
    throw new Error(`member is ${entry.uncompressedSize} bytes, over the ${maxBytes}-byte cap`);
  const stream = await zip.openReadStreamPromise(entry);
  const chunks: Buffer[] = [];
  let total = 0;
  let crc = 0;
  for await (const chunk of stream as AsyncIterable<Buffer>) {
    total += chunk.length;
    if (total > maxBytes) {
      stream.destroy();
      throw new Error(`member grew past the ${maxBytes}-byte cap while inflating`);
    }
    crc = crc32(chunk, crc);
    chunks.push(chunk);
  }
  checkCrc(entry, crc);
  return Buffer.concat(chunks);
}

function checkCrc(entry: Entry, crc: number): void {
  if (crc >>> 0 !== entry.crc32 >>> 0) throw new Error("CRC-32 mismatch (the member is corrupt)");
}

/** Stream one member into `out` (opened by the caller, which owns and closes it). */
export async function writeZipMember(zip: ZipFile, entry: Entry, out: FileHandle): Promise<number> {
  const stream: Readable = await zip.openReadStreamPromise(entry);
  let written = 0;
  let crc = 0;
  for await (const chunk of stream as AsyncIterable<Buffer>) {
    crc = crc32(chunk, crc);
    let off = 0;
    while (off < chunk.length) {
      const { bytesWritten } = await out.write(chunk, off, chunk.length - off, written + off);
      off += bytesWritten;
    }
    written += chunk.length;
  }
  checkCrc(entry, crc);
  return written;
}
