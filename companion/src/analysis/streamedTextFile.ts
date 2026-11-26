import { createReadStream } from "node:fs";
import { createHash } from "node:crypto";
import type { FileHandle } from "node:fs/promises";
import { throwIfImportAborted } from "./siemBuildProgress.js";

/**
 * A stored import file read as text in parts (#2823), for the importers that used to decode it whole.
 *
 * The decode is the one `decodeImportedText` (ingest/decodeText.ts) does for a UTF-8 file: one
 * stateful TextDecoder strips a leading UTF-8 BOM and replaces invalid bytes the WHATWG way, as
 * `Buffer.toString("utf8")` does, so the concatenated chunks are the very string the whole read
 * produced. The source-artifact hash is taken over those decoded chunks as they pass — the same
 * `sha256:` digest `sourceArtifactHash(text)` gives the whole string. Only UTF-8 streams: a caller
 * checks for a UTF-16 BOM first (`hasUtf16Bom`) and keeps the whole read for one.
 */

export const STREAMED_TEXT_CHUNK_BYTES = 1 << 20;

export interface StreamedText {
  /** The decoded text, chunk by chunk; read it once. */
  chunks: AsyncGenerator<string, void, undefined>;
  /** `sha256:<hex>` of the whole decoded text; only once `chunks` has been read to the end. */
  sourceArtifactHash(): string;
}

export function readDecodedText(
  path: string,
  opts: { chunkBytes?: number; signal?: AbortSignal } = {},
): StreamedText {
  const hash = createHash("sha256");
  let digest: string | undefined;
  async function* chunks(): AsyncGenerator<string, void, undefined> {
    throwIfImportAborted(opts.signal);
    const decoder = new TextDecoder("utf-8");
    const stream = createReadStream(path, { highWaterMark: opts.chunkBytes ?? STREAMED_TEXT_CHUNK_BYTES });
    try {
      for await (const buf of stream as AsyncIterable<Buffer>) {
        throwIfImportAborted(opts.signal);
        const text = decoder.decode(buf, { stream: true });
        hash.update(text);
        if (text) yield text;
      }
      const tail = decoder.decode();
      hash.update(tail);
      if (tail) yield tail;
      digest = `sha256:${hash.digest("hex")}`;
    } finally {
      stream.destroy(); // a cancel, a failure or an early break closes the file
    }
  }
  return {
    chunks: chunks(),
    sourceArtifactHash: () => {
      if (digest === undefined) throw new Error("the streamed file was not read to the end");
      return digest;
    },
  };
}

/**
 * The text's lines, split on CR or LF. A CRLF yields one empty piece between the two, which every
 * caller skips as blank — so the non-blank lines are exactly `text.split(/\r\n|\r|\n/)`'s. Only the
 * newest chunk is searched for a terminator, so one very long line is joined once, not rescanned.
 */
export async function* textLines(chunks: AsyncIterable<string>): AsyncGenerator<string, void, undefined> {
  let carry = "";
  for await (const chunk of chunks) {
    const last = Math.max(chunk.lastIndexOf("\n"), chunk.lastIndexOf("\r"));
    if (last === -1) {
      carry += chunk;
      continue;
    }
    const complete = carry + chunk.slice(0, last);
    carry = chunk.slice(last + 1);
    for (const line of complete.split(/[\r\n]/)) yield line;
  }
  if (carry) yield carry;
}

/** Whether the file starts with a UTF-16 byte-order mark (positional read on the caller's handle). */
export async function hasUtf16Bom(fh: FileHandle): Promise<boolean> {
  const magic = Buffer.alloc(2);
  const { bytesRead } = await fh.read(magic, 0, 2, 0);
  return (
    bytesRead === 2 && ((magic[0] === 0xff && magic[1] === 0xfe) || (magic[0] === 0xfe && magic[1] === 0xff))
  );
}
