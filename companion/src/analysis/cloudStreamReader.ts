// Read a cloud export's records straight from disk, one at a time (#2303): the streaming half of
// readCloudRecords (cloudRecords.ts). The file is never held whole — a 1M-row UAL export is ~1 GB,
// past V8's ~512 MB string ceiling — so memory is bounded by one record, whatever the file size.
//
//  - gzip (CloudTrail S3 objects as downloaded, `.json.gz`) is detected by its magic bytes and
//    decompressed on the fly, behind a decompression-ratio guard (GZIP_MAX_RATIO) and an absolute
//    output ceiling, so a crafted bomb stops with a clear error instead of filling the disk or heap;
//  - the text is decoded honouring a UTF-8 / UTF-16LE byte-order mark, like decodeImportedText;
//  - `[` / `{` → JSON (array, wrapper, JSON lines, concatenated — jsonRecordStream.ts), anything
//    else → CSV, quoted fields spanning lines included (parseCsvRecordsFromLines), each row passed
//    through the importer's adapter exactly as readCloudRecords does.
//
// Backpressure is the async iterator itself: the file is read only as fast as records are pulled.
// The counts (repairs, parse errors, oversize records, bytes) are read from `stats()` after the
// iteration, for the import note.

import { createReadStream } from "node:fs";
import { open } from "node:fs/promises";
import { createHash } from "node:crypto";
import { StringDecoder } from "node:string_decoder";
import { constants as zlibConstants, createGunzip } from "node:zlib";
import { Transform, type TransformCallback, type Readable } from "node:stream";
import { parseCsvRecordsFromLines } from "./csvImport.js";
import { JsonRecordScanner } from "./jsonRecordStream.js";
import type { JsonRepairs } from "./tolerantJson.js";
import {
  CSV_RECORD_MAX_CHARS,
  GZIP_MAX_OUTPUT_BYTES,
  GZIP_MAX_RATIO,
  GZIP_RATIO_SLACK_BYTES,
  JSON_RECORD_MAX_CHARS,
} from "./cloudStreamLimits.js";

type Row = Record<string, unknown>;

export interface CloudStreamStats {
  format: "json" | "jsonl" | "csv" | "empty";
  gzip: boolean;
  /** Bytes read from disk (compressed bytes for gzip). */
  bytesRead: number;
  /** Bytes after decompression (equal to bytesRead for a plain file). */
  bytesDecoded: number;
  records: number;
  repairs: JsonRepairs;
  /** Records larger than the per-record bound, skipped. */
  oversizeSkipped: number;
  /** `sha256:<hex>` over the decoded text — the whole-file path's sourceArtifactHash. */
  textHash: string;
}

export interface GzipLimits {
  maxRatio: number;
  slackBytes: number;
  maxOutputBytes: number;
}

const DEFAULT_GZIP_LIMITS: GzipLimits = {
  maxRatio: GZIP_MAX_RATIO,
  slackBytes: GZIP_RATIO_SLACK_BYTES,
  maxOutputBytes: GZIP_MAX_OUTPUT_BYTES,
};

/** Thrown when a gzip upload decompresses past its ratio or size ceiling. */
export class DecompressionLimitError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DecompressionLimitError";
  }
}

/** True when the first bytes are the gzip magic (1f 8b). */
export function isGzipMagic(head: Buffer): boolean {
  return head.length >= 2 && head[0] === 0x1f && head[1] === 0x8b;
}

export async function fileIsGzip(path: string): Promise<boolean> {
  const fh = await open(path, "r");
  try {
    const buf = Buffer.alloc(2);
    const { bytesRead } = await fh.read(buf, 0, 2, 0);
    return isGzipMagic(buf.subarray(0, bytesRead));
  } finally {
    await fh.close();
  }
}

/** Counts compressed bytes in (`input`) — the denominator of the ratio guard. */
function countingStream(...counters: Array<{ bytes: number }>): Transform {
  return new Transform({
    transform(chunk: Buffer, _enc, cb: TransformCallback) {
      for (const c of counters) c.bytes += chunk.length;
      cb(null, chunk);
    },
  });
}

/** Passes decompressed bytes through, failing the stream once a ceiling is crossed. */
function ratioGuard(input: { bytes: number }, output: { bytes: number }, limits: GzipLimits): Transform {
  return new Transform({
    transform(chunk: Buffer, _enc, cb: TransformCallback) {
      output.bytes += chunk.length;
      if (output.bytes > limits.maxOutputBytes)
        return cb(
          new DecompressionLimitError(
            `gzip upload decompresses past ${Math.round(limits.maxOutputBytes / 2 ** 30)} GiB — refused as a possible decompression bomb`,
          ),
        );
      if (output.bytes > limits.slackBytes && output.bytes > input.bytes * limits.maxRatio)
        return cb(
          new DecompressionLimitError(
            `gzip upload decompresses more than ${limits.maxRatio}× its compressed size — refused as a possible decompression bomb`,
          ),
        );
      cb(null, chunk);
    },
  });
}

/** The file's bytes, decompressed when it is gzip. */
function byteStream(
  path: string,
  gzip: boolean,
  counters: { read: { bytes: number }; decoded: { bytes: number } },
  limits: GzipLimits,
  chunkBytes = 1 << 20,
): Readable {
  const file = createReadStream(path, { highWaterMark: chunkBytes });
  const counted = file.pipe(
    gzip ? countingStream(counters.read) : countingStream(counters.read, counters.decoded),
  );
  file.on("error", (e) => counted.destroy(e));
  if (!gzip) return counted;
  const gunzip = createGunzip();
  const guard = ratioGuard(counters.read, counters.decoded, limits);
  counted.on("error", (e) => gunzip.destroy(e));
  gunzip.on("error", (e) => guard.destroy(e));
  return counted.pipe(gunzip).pipe(guard);
}

/** Decoded text chunks, BOM honoured (UTF-8 and UTF-16LE) and counted. */
async function* textChunks(
  bytes: AsyncIterable<Buffer>,
  onBom: () => void,
  hash: ReturnType<typeof createHash>,
): AsyncGenerator<string> {
  let decoder: StringDecoder | null = null;
  let pending = Buffer.alloc(0);
  for await (const raw of bytes) {
    let buf: Buffer = raw;
    if (!decoder) {
      pending = Buffer.concat([pending, buf]);
      if (pending.length < 3) continue;
      const head = pending;
      if (head[0] === 0xff && head[1] === 0xfe) {
        decoder = new StringDecoder("utf16le");
        buf = head.subarray(2);
      } else if (head[0] === 0xef && head[1] === 0xbb && head[2] === 0xbf) {
        decoder = new StringDecoder("utf8");
        buf = head.subarray(3);
        onBom();
      } else {
        decoder = new StringDecoder("utf8");
        buf = head;
      }
    }
    const text = decoder.write(buf);
    if (text) {
      hash.update(text);
      yield text;
    }
  }
  if (!decoder && pending.length) {
    const text = pending.toString("utf8");
    hash.update(text);
    yield text;
  }
  const tail = decoder?.end();
  if (tail) {
    hash.update(tail);
    yield tail;
  }
}

const stripCr = (line: string): string => (line.endsWith("\r") ? line.slice(0, -1) : line);

/**
 * Lines of the decoded text, `\r\n` or `\n` terminated. A line longer than `maxChars` is never
 * assembled: the moment its pending text passes the bound it is dropped, the rest of it up to the
 * next newline is skipped, and `onOversize` counts it — the CSV twin of the JSON scanner's bound.
 */
async function* linesOf(
  chunks: AsyncIterable<string>,
  maxChars: number,
  onOversize: () => void,
): AsyncGenerator<string> {
  let rest = "";
  let skipping = false;
  for await (const chunk of chunks) {
    let start = 0;
    for (;;) {
      const nl = chunk.indexOf("\n", start);
      if (nl < 0) {
        if (!skipping && rest.length + chunk.length - start > maxChars) {
          skipping = true;
          rest = "";
          onOversize();
        } else if (!skipping) rest += chunk.slice(start);
        break;
      }
      const line = skipping ? null : rest + chunk.slice(start, nl);
      if (line !== null && line.length > maxChars) onOversize();
      else if (line !== null) yield stripCr(line);
      skipping = false;
      rest = "";
      start = nl + 1;
    }
  }
  if (rest && !skipping) yield stripCr(rest);
}

/** The first chunk(s) up to the first non-whitespace character, and that character. */
async function peekFirst(
  it: AsyncIterator<string>,
): Promise<{ first: string; buffered: string[]; done: boolean }> {
  const buffered: string[] = [];
  for (;;) {
    const r = await it.next();
    if (r.done) return { first: "", buffered, done: true };
    buffered.push(r.value);
    const m = /\S/.exec(r.value);
    if (m) return { first: m[0], buffered, done: false };
  }
}

async function* replay(buffered: string[], it: AsyncIterator<string>, done: boolean): AsyncGenerator<string> {
  yield* buffered;
  if (done) return;
  for (;;) {
    const r = await it.next();
    if (r.done) return;
    yield r.value;
  }
}

async function* jsonRecords(chunks: AsyncIterable<string>, stats: CloudStreamStats): AsyncGenerator<Row> {
  const queue: Row[] = [];
  const scanner = new JsonRecordScanner((row) => queue.push(row), JSON_RECORD_MAX_CHARS);
  for await (const chunk of chunks) {
    scanner.push(chunk);
    while (queue.length) yield queue.shift()!;
  }
  const counts = scanner.end();
  while (queue.length) yield queue.shift()!;
  stats.format = counts.format === "jsonl" ? "jsonl" : counts.format === "empty" ? "empty" : "json";
  stats.repairs.documentsJoined = counts.documentsJoined;
  stats.repairs.garbageSkipped = counts.garbageSkipped;
  stats.oversizeSkipped += counts.oversizeSkipped;
}

async function* csvRecords(
  chunks: AsyncIterable<string>,
  adapt: (row: Row) => Row,
  maxChars: number,
  stats: CloudStreamStats,
): AsyncGenerator<Row> {
  let headers: string[] | null = null;
  const lines = linesOf(chunks, maxChars, () => stats.oversizeSkipped++);
  for await (const cols of parseCsvRecordsFromLines(lines, { maxRecordChars: maxChars })) {
    if (!headers) {
      headers = cols.map((h) => h.trim());
      continue;
    }
    if (cols.length === 1 && cols[0] === "") continue; // a blank line
    yield adapt(Object.fromEntries(headers.map((h, i) => [h, cols[i] ?? ""])));
  }
}

export interface CloudRecordStream {
  records: AsyncGenerator<Row>;
  /** The counts so far — final once `records` is exhausted. */
  stats(): CloudStreamStats;
}

/**
 * The records of a cloud export on disk, streamed. `adapt` is the importer's CSV row adapter (the
 * CloudTrail console CSV rebuilds records with it); JSON records are passed through unchanged.
 */
export async function openCloudRecordStream(
  path: string,
  opts: {
    adapt?: (row: Row) => Row;
    gzipLimits?: GzipLimits;
    /** Test seams: the per-record CSV bound and the file read size. */
    csvRecordMaxChars?: number;
    chunkBytes?: number;
  } = {},
): Promise<CloudRecordStream> {
  const gzip = await fileIsGzip(path);
  const counters = { read: { bytes: 0 }, decoded: { bytes: 0 } };
  const hash = createHash("sha256");
  const stats: CloudStreamStats = {
    format: "empty",
    gzip,
    bytesRead: 0,
    bytesDecoded: 0,
    records: 0,
    repairs: { bomStripped: 0, documentsJoined: 0, garbageSkipped: 0 },
    oversizeSkipped: 0,
    textHash: "",
  };
  const bytes = byteStream(path, gzip, counters, opts.gzipLimits ?? DEFAULT_GZIP_LIMITS, opts.chunkBytes);
  const text = textChunks(bytes, () => (stats.repairs.bomStripped = 1), hash);
  async function* all(): AsyncGenerator<Row> {
    try {
      const it = text[Symbol.asyncIterator]();
      const { first, buffered, done } = await peekFirst(it);
      if (!first) return;
      const chunks = replay(buffered, it, done);
      const isJson = first === "[" || first === "{";
      if (!isJson) stats.format = "csv";
      const csvMax = opts.csvRecordMaxChars ?? CSV_RECORD_MAX_CHARS;
      const rows = isJson
        ? jsonRecords(chunks, stats)
        : csvRecords(chunks, opts.adapt ?? ((r) => r), csvMax, stats);
      for await (const row of rows) {
        stats.records++;
        yield row;
      }
      stats.textHash = `sha256:${hash.digest("hex")}`;
    } finally {
      bytes.destroy();
    }
  }
  return {
    records: all(),
    stats: () => ({
      ...stats,
      repairs: { ...stats.repairs },
      bytesRead: counters.read.bytes,
      bytesDecoded: counters.decoded.bytes,
    }),
  };
}

/**
 * The first `maxBytes` decompressed from the start of a gzip buffer — the import routes' kind sniff.
 * The buffer may stop mid-member: whatever decompressed before the cut is returned, and reading
 * stops at `maxBytes`, so a bomb's head costs the bound, never more.
 */
export async function gunzipBufferHead(buf: Buffer, maxBytes: number): Promise<Buffer> {
  const gunzip = createGunzip({ finishFlush: zlibConstants.Z_SYNC_FLUSH });
  const out: Buffer[] = [];
  let got = 0;
  gunzip.end(buf);
  try {
    for await (const chunk of gunzip as AsyncIterable<Buffer>) {
      out.push(chunk);
      got += chunk.length;
      if (got >= maxBytes) break;
    }
  } catch {
    /* a corrupt or truncated member: keep what decompressed */
  } finally {
    gunzip.destroy();
  }
  return Buffer.concat(out).subarray(0, maxBytes);
}

/**
 * The first `maxBytes` of a gzip file's decompressed content (for kind detection on the import
 * routes). A truncated member is fine: whatever decompressed before the cut is returned.
 */
export async function gunzipHead(path: string, maxBytes: number): Promise<Buffer> {
  const out: Buffer[] = [];
  let got = 0;
  const counters = { read: { bytes: 0 }, decoded: { bytes: 0 } };
  const stream = byteStream(path, true, counters, DEFAULT_GZIP_LIMITS);
  try {
    for await (const chunk of stream as AsyncIterable<Buffer>) {
      out.push(chunk);
      got += chunk.length;
      if (got >= maxBytes) break;
    }
  } catch {
    /* a corrupt or truncated member: keep what decompressed */
  } finally {
    stream.destroy();
  }
  return Buffer.concat(out).subarray(0, maxBytes);
}
