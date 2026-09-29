import { createHash } from "node:crypto";
import { open, type FileHandle } from "node:fs/promises";
import { Readable } from "node:stream";
import { createInflateRaw, crc32, inflateRawSync } from "node:zlib";

/**
 * The ZIP reader behind both whole-case imports: the `.dfircase` package (after decryption) and the
 * plain ZIP that "Archive to ZIP" writes (#1828).
 *
 * The earlier reader inflated every entry into memory at once — up to 2 GB from a ~2 MB upload,
 * synchronously. This one never holds an entry's inflated bytes in memory, except for the two small
 * control files (case.json, archive-manifest.json). It works in two steps:
 *
 *   1. {@link listCaseZipEntries} reads the central directory ONLY. Nothing is inflated. It refuses
 *      a malformed or ambiguous structure, and a size or ratio that is over a cap, from the sizes
 *      the archive declares.
 *   2. {@link extractCaseZipEntry} streams one entry to a file. It stops the moment the output
 *      passes the size the header declared, so a header that lies about the size is caught with at
 *      most one zlib chunk extra, not after gigabytes.
 *
 * Every error starts with "not a valid case archive" so the import routes answer 400, not 500.
 */

/** Largest single file a case archive may hold, inflated. */
export const CASE_ZIP_MAX_ENTRY_BYTES = 512 * 1024 * 1024;
/** Largest total a case archive may inflate to, and the largest a staged case may grow to. */
export const CASE_ZIP_MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024;
/**
 * Highest inflated-to-compressed ratio allowed, per entry and for the archive as a whole. DEFLATE
 * tops out near 1032:1 on a bomb; real case files (JSON, JSONL, SQLite, screenshots) stay far below
 * 200:1.
 */
export const CASE_ZIP_MAX_COMPRESSION_RATIO = 200;
/** The ratio is checked only past this size: a tiny, repetitive JSON file can legitimately exceed it. */
export const CASE_ZIP_RATIO_MIN_BYTES = 1024 * 1024;
/** Largest control file (case.json, archive-manifest.json) read into memory. */
export const CASE_ZIP_MAX_CONTROL_BYTES = 64 * 1024 * 1024;
/** Size of the compressed slices fed to the inflater, so no step works on a whole entry at once. */
export const CASE_ZIP_STREAM_SLICE_BYTES = 64 * 1024;

export interface CaseZipLimits {
  maxEntryBytes: number;
  maxTotalBytes: number;
  maxRatio: number;
  ratioMinBytes: number;
}

export const DEFAULT_CASE_ZIP_LIMITS: CaseZipLimits = {
  maxEntryBytes: CASE_ZIP_MAX_ENTRY_BYTES,
  maxTotalBytes: CASE_ZIP_MAX_TOTAL_BYTES,
  maxRatio: CASE_ZIP_MAX_COMPRESSION_RATIO,
  ratioMinBytes: CASE_ZIP_RATIO_MIN_BYTES,
};

/** One entry, as the central directory declares it. */
export interface CaseZipEntry {
  name: string;
  method: number;
  crc: number;
  compressedSize: number;
  /** The declared inflated size. Extraction refuses output that differs from it. */
  size: number;
  dataStart: number;
}

export interface ExtractedEntry {
  bytes: number;
  sha256: string;
}

const SIG_LOCAL = 0x04034b50;
const SIG_CENTRAL = 0x02014b50;
const SIG_EOCD = 0x06054b50;
const EOCD_LEN = 22;
const CENTRAL_LEN = 46;
const LOCAL_LEN = 30;
const METHOD_STORED = 0;
const METHOD_DEFLATE = 8;
const ZIP64_MARK_32 = 0xffffffff;
const ZIP64_MARK_16 = 0xffff;
// Bits 1-2 (DEFLATE options), 3 (data descriptor: the central sizes stay authoritative) and 11
// (UTF-8 names). Anything else — encryption (0), strong encryption (6), masked headers (13) — is
// something this reader cannot decode faithfully.
const ALLOWED_FLAGS = 0x0002 | 0x0004 | 0x0008 | 0x0800;
const FLAG_ENCRYPTED = 0x0001;

function invalid(reason: string): Error {
  return new Error(`not a valid case archive: ${reason}`);
}

function findEocd(archive: Buffer): number {
  for (let i = archive.length - EOCD_LEN; i >= 0; i--) {
    if (archive.readUInt32LE(i) !== SIG_EOCD) continue;
    // Only a record that ends the buffer exactly (comment included) is the real one. A signature
    // inside entry data or a trailing comment would otherwise point the reader at forged records.
    if (i + EOCD_LEN + archive.readUInt16LE(i + 20) === archive.length) return i;
  }
  return -1;
}

interface Region {
  start: number;
  end: number;
  name: string;
}

/**
 * Walk the central directory and return every entry, refusing anything this reader cannot trust.
 * Nothing is inflated here.
 */
export function listCaseZipEntries(
  archive: Buffer,
  limits: CaseZipLimits = DEFAULT_CASE_ZIP_LIMITS,
): CaseZipEntry[] {
  const eocd = findEocd(archive);
  if (eocd < 0) throw invalid("not a ZIP archive");
  const diskFields = [4, 6].map((off) => archive.readUInt16LE(eocd + off));
  const onDisk = archive.readUInt16LE(eocd + 8);
  const total = archive.readUInt16LE(eocd + 10);
  const cdSize = archive.readUInt32LE(eocd + 12);
  const cdOffset = archive.readUInt32LE(eocd + 16);
  if (diskFields.some((d) => d !== 0) || onDisk !== total)
    throw invalid("multi-disk ZIP archives are not supported");
  if (total === ZIP64_MARK_16 || cdSize === ZIP64_MARK_32 || cdOffset === ZIP64_MARK_32) {
    throw invalid("ZIP64 archives are not supported");
  }
  if (cdOffset + cdSize !== eocd)
    throw invalid("corrupt ZIP: central directory does not end at its end record");

  const entries: CaseZipEntry[] = [];
  const regions: Region[] = [];
  let declaredTotal = 0;
  let ptr = cdOffset;
  for (let i = 0; i < total; i++) {
    if (ptr + CENTRAL_LEN > eocd) throw invalid("corrupt ZIP: central directory out of bounds");
    if (archive.readUInt32LE(ptr) !== SIG_CENTRAL) throw invalid("corrupt ZIP: bad central header");
    const flags = archive.readUInt16LE(ptr + 8);
    const method = archive.readUInt16LE(ptr + 10);
    const crc = archive.readUInt32LE(ptr + 16);
    const compressedSize = archive.readUInt32LE(ptr + 20);
    const size = archive.readUInt32LE(ptr + 24);
    const nameLen = archive.readUInt16LE(ptr + 28);
    const extraLen = archive.readUInt16LE(ptr + 30);
    const commentLen = archive.readUInt16LE(ptr + 32);
    const diskStart = archive.readUInt16LE(ptr + 34);
    const localOffset = archive.readUInt32LE(ptr + 42);
    const recordEnd = ptr + CENTRAL_LEN + nameLen + extraLen + commentLen;
    if (recordEnd > eocd) throw invalid("corrupt ZIP: central directory out of bounds");
    const nameBytes = archive.subarray(ptr + CENTRAL_LEN, ptr + CENTRAL_LEN + nameLen);
    const name = nameBytes.toString("utf8");

    if (flags & FLAG_ENCRYPTED) throw invalid(`zip entry "${name}" is encrypted`);
    if (flags & ~ALLOWED_FLAGS) throw invalid(`zip entry "${name}" uses unsupported ZIP features`);
    if (method !== METHOD_STORED && method !== METHOD_DEFLATE) {
      throw invalid(`zip entry "${name}" uses unsupported compression method ${method}`);
    }
    if ([compressedSize, size, localOffset].includes(ZIP64_MARK_32) || diskStart !== 0) {
      throw invalid(`zip entry "${name}" needs ZIP64, which is not supported`);
    }
    if (method === METHOD_STORED && compressedSize !== size) {
      throw invalid(`stored zip entry "${name}" declares two different sizes`);
    }
    assertWithinLimits(name, size, compressedSize, (declaredTotal += size), limits);

    const dataStart = readLocalHeader(archive, localOffset, nameBytes, method, name);
    const dataEnd = dataStart + compressedSize;
    if (dataEnd > cdOffset) throw invalid(`zip entry "${name}" runs into the central directory`);
    regions.push({ start: localOffset, end: dataEnd, name });
    entries.push({ name, method, crc, compressedSize, size, dataStart });
    ptr = recordEnd;
  }
  if (ptr !== eocd) throw invalid("corrupt ZIP: central directory size does not match its records");
  assertNoOverlap(regions);
  // The archive-wide ratio closes the gap the per-entry threshold leaves: a bomb split into many
  // entries just under ratioMinBytes each would pass every per-entry check.
  if (declaredTotal >= limits.ratioMinBytes && declaredTotal > archive.length * limits.maxRatio) {
    throw invalid(
      `the archive inflates ${Math.round(declaredTotal / Math.max(archive.length, 1))}:1, over the ` +
        `${limits.maxRatio}:1 limit — possible zip bomb`,
    );
  }
  return entries;
}

function assertWithinLimits(
  name: string,
  size: number,
  compressedSize: number,
  runningTotal: number,
  limits: CaseZipLimits,
): void {
  if (size > limits.maxEntryBytes) {
    throw invalid(`zip entry "${name}" inflates to ${size} bytes, over the ${limits.maxEntryBytes} byte cap`);
  }
  if (runningTotal > limits.maxTotalBytes) {
    throw invalid(`the archive inflates past the ${limits.maxTotalBytes} byte cap`);
  }
  if (size >= limits.ratioMinBytes && size > compressedSize * limits.maxRatio) {
    throw invalid(
      `zip entry "${name}" inflates ${Math.round(size / Math.max(compressedSize, 1))}:1, over the ` +
        `${limits.maxRatio}:1 limit — possible zip bomb`,
    );
  }
}

/** Check the local header agrees with the central record, and return where the entry's data starts. */
function readLocalHeader(
  archive: Buffer,
  offset: number,
  nameBytes: Buffer,
  method: number,
  name: string,
): number {
  if (offset + LOCAL_LEN > archive.length) throw invalid(`zip entry "${name}" local header out of bounds`);
  if (archive.readUInt32LE(offset) !== SIG_LOCAL) throw invalid(`zip entry "${name}" has a bad local header`);
  const localNameLen = archive.readUInt16LE(offset + 26);
  const localExtraLen = archive.readUInt16LE(offset + 28);
  const nameStart = offset + LOCAL_LEN;
  // Two different names for one entry is a polyglot: another ZIP tool would extract a different path.
  if (
    archive.readUInt16LE(offset + 8) !== method ||
    localNameLen !== nameBytes.length ||
    !archive.subarray(nameStart, nameStart + localNameLen).equals(nameBytes)
  ) {
    throw invalid(`zip entry "${name}" has a local header that does not match its central record`);
  }
  return nameStart + localNameLen + localExtraLen;
}

/** Entries that share bytes are how an overlapping-file bomb multiplies one compressed stream. */
function assertNoOverlap(regions: Region[]): void {
  const sorted = [...regions].sort((a, b) => a.start - b.start);
  for (let i = 1; i < sorted.length; i++) {
    if (sorted[i].start < sorted[i - 1].end) {
      throw invalid(`zip entries "${sorted[i - 1].name}" and "${sorted[i].name}" overlap`);
    }
  }
}

/** Inflate one small entry into memory. For control files only; refuses anything over `maxBytes`. */
export function readCaseZipEntry(
  archive: Buffer,
  entry: CaseZipEntry,
  maxBytes = CASE_ZIP_MAX_CONTROL_BYTES,
): Buffer {
  if (entry.size > maxBytes) throw invalid(`"${entry.name}" is larger than ${maxBytes} bytes`);
  const raw = archive.subarray(entry.dataStart, entry.dataStart + entry.compressedSize);
  let data: Buffer;
  if (entry.method === METHOD_STORED) {
    data = Buffer.from(raw);
  } else {
    try {
      // maxOutputLength is the declared size: a lying header throws here instead of inflating on.
      data = inflateRawSync(raw, { maxOutputLength: Math.max(entry.size, 1) });
    } catch (err) {
      throw invalid(`zip entry "${entry.name}" could not be inflated: ${(err as Error).message}`);
    }
  }
  if (data.length !== entry.size)
    throw invalid(`zip entry "${entry.name}" is not the size its header declares`);
  if (crc32(data) !== entry.crc) throw invalid(`corrupt ZIP: CRC mismatch for ${entry.name}`);
  return data;
}

/**
 * Write every byte of `data`. A file write may complete short (a full disk, a quota); the hash and
 * CRC cover the whole chunk, so a silently short write would publish a truncated file that still
 * passed every check.
 */
export async function writeAll(handle: FileHandle, data: Buffer): Promise<void> {
  for (let off = 0; off < data.length;) {
    const { bytesWritten } = await handle.write(data, off, data.length - off);
    if (bytesWritten <= 0) throw new Error("write made no progress");
    off += bytesWritten;
  }
}

function* slices(raw: Buffer): Generator<Buffer> {
  for (let off = 0; off < raw.length; off += CASE_ZIP_STREAM_SLICE_BYTES) {
    yield raw.subarray(off, off + CASE_ZIP_STREAM_SLICE_BYTES);
  }
}

function entryChunks(archive: Buffer, entry: CaseZipEntry): AsyncIterable<Buffer> | Iterable<Buffer> {
  const raw = archive.subarray(entry.dataStart, entry.dataStart + entry.compressedSize);
  if (entry.method === METHOD_STORED) return slices(raw);
  return Readable.from(slices(raw)).pipe(createInflateRaw());
}

/**
 * Stream one entry into a NEW file at `targetPath`. Stops as soon as the output passes the declared
 * size, then checks size and CRC. The file handle is closed before this returns or throws, so the
 * caller may remove or rename the file at once, Windows included. A refused entry leaves a partial
 * file behind: the caller writes into a private staging directory and removes it on failure.
 */
export async function extractCaseZipEntry(
  archive: Buffer,
  entry: CaseZipEntry,
  targetPath: string,
): Promise<ExtractedEntry> {
  const hash = createHash("sha256");
  let bytes = 0;
  let crc = 0;
  const handle = await open(targetPath, "wx");
  try {
    try {
      for await (const chunk of entryChunks(archive, entry)) {
        bytes += chunk.length;
        if (bytes > entry.size) {
          throw invalid(
            `zip entry "${entry.name}" inflates past the size its header declares — possible zip bomb`,
          );
        }
        hash.update(chunk);
        crc = crc32(chunk, crc);
        await writeAll(handle, chunk);
      }
    } catch (err) {
      if ((err as Error).message.startsWith("not a valid case archive")) throw err;
      throw invalid(`zip entry "${entry.name}" could not be inflated: ${(err as Error).message}`);
    }
    // Check what reached the disk, not only what the inflater produced.
    if ((await handle.stat()).size !== bytes)
      throw invalid(`zip entry "${entry.name}" was not fully written`);
  } finally {
    await handle.close();
  }
  if (bytes !== entry.size) throw invalid(`zip entry "${entry.name}" is not the size its header declares`);
  if (crc !== entry.crc) throw invalid(`corrupt ZIP: CRC mismatch for ${entry.name}`);
  return { bytes, sha256: hash.digest("hex") };
}
