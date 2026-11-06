// Read a stored import file back as the import decoded it, for a Sigma re-grade (#2353).
//
// A plain file is read whole and decoded honouring its byte-order mark, as before. A gzip file (a
// streamed .gz upload, #2303) is decompressed as a stream into memory and decoded the same way, so
// the text hashes to what the streamed import's reader hashed — the hash its rows carry (#2337).
// Both are bounded by `maxBytes` of decoded bytes: the re-grade parses the whole text with the
// importer, so a file past the bound is skipped (and counted by the plan), never read. The gunzip
// runs under stream/promises.pipeline, so the bound, a corrupt member or a read error tears down the
// whole chain — file reader and decompressor — not just the last stage.

import { createReadStream } from "node:fs";
import { open, readFile, stat } from "node:fs/promises";
import { Writable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { createGunzip } from "node:zlib";
import { isGzipMagic } from "../analysis/cloudStreamReader.js";
import { REGRADE_TEXT_MAX_BYTES } from "../analysis/cloudStreamLimits.js";
import { decodeImportedText } from "../ingest/decodeText.js";

export type StoredTextSkip = "file-missing" | "file-too-large" | "file-unreadable";
export type StoredText = { text: string } | { skipped: StoredTextSkip };

class TooLargeError extends Error {}

async function head(path: string): Promise<Buffer> {
  const fh = await open(path, "r");
  try {
    const buf = Buffer.alloc(2);
    const { bytesRead } = await fh.read(buf, 0, 2, 0);
    return buf.subarray(0, bytesRead);
  } finally {
    await fh.close();
  }
}

/** The decompressed bytes of a gzip file, or TooLargeError once they pass `maxBytes`. */
async function gunzipBounded(path: string, maxBytes: number): Promise<Buffer> {
  const out: Buffer[] = [];
  let got = 0;
  const sink = new Writable({
    write(chunk: Buffer, _enc, cb) {
      got += chunk.length;
      if (got > maxBytes) return cb(new TooLargeError());
      out.push(chunk);
      cb();
    },
  });
  await pipeline(createReadStream(path), createGunzip(), sink);
  return Buffer.concat(out);
}

/** The stored file's decoded text, or why the re-grade cannot read it. */
export async function readStoredImportText(
  path: string,
  maxBytes: number = REGRADE_TEXT_MAX_BYTES,
): Promise<StoredText> {
  let size: number;
  let magic: Buffer;
  try {
    const s = await stat(path);
    if (!s.isFile()) return { skipped: "file-missing" };
    size = s.size;
    magic = await head(path);
  } catch {
    return { skipped: "file-missing" };
  }
  if (!isGzipMagic(magic)) {
    if (size > maxBytes) return { skipped: "file-too-large" };
    try {
      return { text: decodeImportedText(await readFile(path)) };
    } catch {
      return { skipped: "file-missing" };
    }
  }
  try {
    return { text: decodeImportedText(await gunzipBounded(path, maxBytes)) };
  } catch (err) {
    return { skipped: err instanceof TooLargeError ? "file-too-large" : "file-unreadable" };
  }
}
