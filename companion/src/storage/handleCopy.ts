import { createWriteStream } from "node:fs";
import { unlink, type FileHandle } from "node:fs/promises";
import { createHash } from "node:crypto";
import { pipeline } from "node:stream/promises";
import { FileTooLargeError } from "./boundedRead.js";

/** The copy's SHA-256 is not the one the caller expected: the file changed after it was hashed (#2111). */
export class CopyContentChangedError extends Error {
  constructor() {
    super("file changed while it was being imported");
    this.name = "CopyContentChangedError";
  }
}

/**
 * Copy the whole open file to `dest`, which must not exist (never overwrite evidence already on
 * disk, #214), hashing it in the same stream pass. One pass matters: server-path imports run to
 * hundreds of megabytes, and a second read for the hash would double the I/O (#2055). A partial
 * copy this call created is removed on failure; an existing `dest` is never touched. The caller
 * owns case-write admission (#1855).
 */
export async function copyHandleHashed(
  handle: FileHandle,
  dest: string,
): Promise<{ bytes: number; sha256: string; sha1: string }> {
  const out = createWriteStream(dest, { flags: "wx" });
  let created = false;
  out.once("open", () => (created = true));
  let bytes = 0;
  const hash = createHash("sha256");
  const hash1 = createHash("sha1");
  const src = handle.createReadStream({ start: 0, autoClose: false, highWaterMark: 1 << 20 });
  src.on("data", (chunk) => {
    bytes += chunk.length;
    hash.update(chunk);
    hash1.update(chunk);
  });
  try {
    await pipeline(src, out);
  } catch (err) {
    if (created) await unlink(dest).catch(() => undefined);
    throw err;
  }
  return { bytes, sha256: hash.digest("hex"), sha1: hash1.digest("hex") };
}

/**
 * Copy the open file to `dest` (which must not exist, #214) without buffering it, stopping at
 * `maxBytes`. The stream asks for one byte past the bound — the same growth detector as
 * readHandleBounded — so a file appended to after the caller sized it throws FileTooLargeError
 * instead of being copied in full. A partial copy this call created is removed on any failure; an
 * existing `dest` is never touched. Used by the drop folder's cross-filesystem move (#2270).
 */
export async function copyHandleBounded(
  handle: FileHandle,
  dest: string,
  maxBytes: number,
): Promise<{ bytes: number }> {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0) {
    throw new Error(`copyHandleBounded: bound must be a non-negative whole number of bytes, got ${maxBytes}`);
  }
  const out = createWriteStream(dest, { flags: "wx" });
  let created = false;
  out.once("open", () => (created = true));
  let bytes = 0;
  // `end` is inclusive, so this reads at most maxBytes + 1 bytes: the extra byte is the detector.
  const src = handle.createReadStream({
    start: 0,
    end: maxBytes,
    autoClose: false,
    highWaterMark: 1 << 20,
  });
  async function* bounded(source: AsyncIterable<Buffer>): AsyncGenerator<Buffer> {
    for await (const chunk of source) {
      bytes += chunk.length;
      if (bytes > maxBytes) throw new FileTooLargeError(bytes, maxBytes);
      yield chunk;
    }
  }
  try {
    await pipeline(src, bounded, out);
  } catch (err) {
    // pipeline destroys `out` but its fd closes asynchronously; on Windows an unlink of a still-open
    // file fails (EPERM), which would leave the partial copy behind. Wait for the close first.
    if (!out.closed) await new Promise<void>((resolve) => out.once("close", () => resolve()));
    if (created) await unlink(dest).catch(() => undefined);
    throw err;
  }
  return { bytes };
}
