import { createReadStream } from "node:fs";
import type { FileHandle } from "node:fs/promises";
import { isObject } from "./siemImport.js";
import { unwrapSource, type RowStreamItem } from "./velociraptorRowStream.js";
import { abortIfCancelled } from "./ingest/importState.js";

/**
 * Velociraptor JSON Lines read from disk one record at a time (#2705).
 *
 * The in-memory reader (velociraptorRowStream.ts) walks one string, and V8 cannot hold a string much
 * past ~512 MB, so a 748 MB notebook export could never import. This reader splits the file's BYTES
 * on the newline byte and decodes one line at a time: 0x0A never occurs inside a UTF-8 multi-byte
 * sequence, so a character split across two read chunks is joined before it is decoded, and the
 * offsets are bytes. The per-line rules are the in-memory NDJSON reader's: blank and malformed
 * lines skipped, an Elastic `_source` unwrapped, an empty object skipped, a UTF-8 BOM stripped.
 *
 * Nothing is unbounded: a record longer than MAX_NDJSON_RECORD_BYTES is refused with a sentence
 * (a file that is one huge line is not JSON Lines), and a UTF-16 file is refused rather than read
 * as mojibake. Only JSON Lines streams from disk; a top-level array or artifact map does not.
 */

/** The longest one record may be. A longer "line" is a one-line array or map, not JSON Lines. */
export const MAX_NDJSON_RECORD_BYTES = 64 * 1024 * 1024;
const CHUNK_BYTES = 1 << 20;
const NL = 0x0a;
const MB = 1024 * 1024;

/** The refusal for a UTF-16 file: it would otherwise be read as mojibake and import as nothing. */
export const UTF16_REFUSAL =
  "this Velociraptor JSON Lines file is UTF-16 encoded and too large to convert in memory — convert the file to UTF-8 to import it";

export type NdjsonHeadVerdict = "ndjson" | "not-ndjson" | "utf16";

export interface VelociraptorFileRowStream {
  format: "ndjson";
  rows: AsyncGenerator<RowStreamItem, void, undefined>;
}

export function isUtf16Bom(b: Buffer): boolean {
  return b.length >= 2 && ((b[0] === 0xff && b[1] === 0xfe) || (b[0] === 0xfe && b[1] === 0xff));
}

function utf8BomLength(b: Buffer): number {
  return b.length >= 3 && b[0] === 0xef && b[1] === 0xbb && b[2] === 0xbf ? 3 : 0;
}

function isWholeObjectLine(line: string): boolean {
  const t = line.trim();
  if (!t.startsWith("{") || !t.endsWith("}")) return false;
  try {
    return isObject(JSON.parse(t));
  } catch {
    return false;
  }
}

function tooLong(record: number, max: number): Error {
  return new Error(
    `record ${record} is over ${max >= MB ? `${Math.round(max / MB)} MB` : `${max} bytes`} — this file is not JSON Lines (one record per line); ` +
      "export it from Velociraptor as JSON Lines, or split it",
  );
}

// Whether anything but whitespace follows the first line: `rest` is the tail of the chunk that
// held its newline; when that tail is empty, one more chunk is read.
async function moreFollows(fh: FileHandle, rest: Buffer, nextPos: number): Promise<boolean> {
  if (rest.length) return /\S/.test(rest.toString("utf8"));
  const buf = Buffer.allocUnsafe(CHUNK_BYTES);
  const { bytesRead } = await fh.read(buf, 0, CHUNK_BYTES, nextPos);
  return /\S/.test(buf.subarray(0, bytesRead).toString("utf8"));
}

export interface FirstLine {
  /** The first line's bytes, newline excluded, UTF-8 BOM included when there is one. */
  line: Buffer;
  /** Whether a newline ended it (false: the file ended first). */
  terminated: boolean;
  /** The bytes after the newline in the chunk that held it, and the file offset just past them. */
  rest: Buffer;
  nextPos: number;
}

/**
 * The file's first line, read with positional reads on the caller's handle — the one the path guard
 * judged — and never past `maxRecordBytes`: null when the line is longer than that, or the file is
 * UTF-16 (its bytes are not lines of UTF-8).
 */
export async function readFirstLine(
  fh: FileHandle,
  maxRecordBytes = MAX_NDJSON_RECORD_BYTES,
): Promise<FirstLine | null> {
  const parts: Buffer[] = [];
  for (let pos = 0; ;) {
    const buf = Buffer.allocUnsafe(CHUNK_BYTES);
    const { bytesRead } = await fh.read(buf, 0, CHUNK_BYTES, pos);
    const chunk = buf.subarray(0, bytesRead);
    if (pos === 0 && isUtf16Bom(chunk)) return null;
    const nl = chunk.indexOf(NL);
    if (nl === -1) {
      parts.push(chunk);
      pos += bytesRead;
      if (pos > maxRecordBytes) return null;
      if (!bytesRead) return { line: Buffer.concat(parts), terminated: false, rest: chunk, nextPos: pos };
      continue;
    }
    const line = Buffer.concat([...parts, chunk.subarray(0, nl)]);
    if (line.length > maxRecordBytes) return null;
    return { line, terminated: true, rest: chunk.subarray(nl + 1), nextPos: pos + bytesRead };
  }
}

/** A first line decoded for kind detection: UTF-8, BOM stripped. */
export function decodeFirstLine(line: Buffer): string {
  return line.subarray(utf8BomLength(line)).toString("utf8");
}

/**
 * Whether the file the caller holds open is JSON Lines: its first line, read up to `maxRecordBytes`
 * and no further, is one whole JSON object and more follows. Positional reads only, on the caller's
 * handle — the one the path guard judged. No newline within the bound is "not-ndjson", never a throw.
 */
export async function probeNdjsonFileHead(
  fh: FileHandle,
  maxRecordBytes = MAX_NDJSON_RECORD_BYTES,
): Promise<NdjsonHeadVerdict> {
  const magic = Buffer.alloc(2);
  const { bytesRead } = await fh.read(magic, 0, 2, 0);
  if (isUtf16Bom(magic.subarray(0, bytesRead))) return "utf16";
  const first = await readFirstLine(fh, maxRecordBytes);
  if (!first?.terminated || !isWholeObjectLine(decodeFirstLine(first.line))) return "not-ndjson";
  return (await moreFollows(fh, first.rest, first.nextPos)) ? "ndjson" : "not-ndjson";
}

function toItem(raw: string, offset: number): RowStreamItem | null {
  const line = raw.trim();
  if (!line) return null;
  let obj: unknown;
  try {
    obj = JSON.parse(line);
  } catch {
    return null; // the in-memory reader skips a malformed line too
  }
  const row = unwrapSource(obj);
  return row && Object.keys(row).length > 0 ? { row, offset } : null;
}

interface SplitState {
  pending: Buffer[];
  pendingBytes: number;
  record: number;
  base: number; // file offset of the current chunk's first byte
}

// One complete line: the bytes held over from earlier chunks plus `piece`, decoded once.
function takeLine(st: SplitState, piece: Buffer, max: number): string {
  st.record++;
  if (st.pendingBytes + piece.length > max) throw tooLong(st.record, max);
  const bytes = st.pending.length ? Buffer.concat([...st.pending, piece]) : piece;
  st.pending = [];
  st.pendingBytes = 0;
  const text = bytes.toString("utf8");
  return st.record === 1 && text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
}

async function* fileRows(
  path: string,
  max: number,
  signal: AbortSignal | undefined,
): AsyncGenerator<RowStreamItem, void, undefined> {
  abortIfCancelled(signal); // a cancel before the first read opens nothing
  // Created inside the body: a generator opened but never read (the driver opens its mapping
  // stream before the evidence pass) holds no descriptor.
  const stream = createReadStream(path, { highWaterMark: CHUNK_BYTES });
  const st: SplitState = { pending: [], pendingBytes: 0, record: 0, base: 0 };
  try {
    for await (const chunk of stream as AsyncIterable<Buffer>) {
      // Per chunk, not per row: a malformed or empty-object tail yields no row for the caller to
      // check Cancel between, and would otherwise be read to the end (#2705 review).
      abortIfCancelled(signal);
      if (st.base === 0 && isUtf16Bom(chunk)) throw new Error(UTF16_REFUSAL);
      let start = 0;
      for (let nl = chunk.indexOf(NL); nl !== -1; nl = chunk.indexOf(NL, start)) {
        const item = toItem(takeLine(st, chunk.subarray(start, nl), max), st.base + nl + 1);
        start = nl + 1;
        if (item) yield item;
      }
      if (start < chunk.length) {
        st.pending.push(chunk.subarray(start));
        st.pendingBytes += chunk.length - start;
        if (st.pendingBytes > max) throw tooLong(st.record + 1, max);
      }
      st.base += chunk.length;
    }
    if (st.pendingBytes) {
      const item = toItem(takeLine(st, Buffer.alloc(0), max), st.base);
      if (item) yield item;
    }
  } finally {
    stream.destroy(); // a cancel, a failure or an early break closes the file
  }
}

/** A row reader over the JSON Lines file at `path`. Opens the file on the first read, not here. */
export function openVelociraptorFileRowStream(
  path: string,
  opts: { maxRecordBytes?: number; signal?: AbortSignal } = {},
): VelociraptorFileRowStream {
  return {
    format: "ndjson",
    rows: fileRows(path, opts.maxRecordBytes ?? MAX_NDJSON_RECORD_BYTES, opts.signal),
  };
}
