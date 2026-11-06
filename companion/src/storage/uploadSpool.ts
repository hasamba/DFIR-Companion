import { createHash } from "node:crypto";
import { rm, type FileHandle } from "node:fs/promises";
import type { IncomingMessage } from "node:http";

/**
 * Stream a request body to a spool file on disk under a hard byte cap (#2336). The body is never
 * held in memory: each chunk is counted, hashed (SHA-256 and SHA-1, for the custody receipt) and
 * written, with back-pressure. Past the cap the read stops at once and UploadTooLargeError is
 * thrown; a client that hangs up mid-upload throws UploadAbortedError. On every failure the
 * partial spool file is removed before the error reaches the caller, so a refused upload leaves
 * nothing on disk. The request is paused, never destroyed, so the caller can still answer 413.
 */

export class UploadTooLargeError extends Error {
  constructor(readonly maxBytes: number) {
    super(`upload exceeds ${maxBytes} bytes`);
    this.name = "UploadTooLargeError";
  }
}

export class UploadAbortedError extends Error {
  constructor() {
    super("the client closed the connection before the upload finished");
    this.name = "UploadAbortedError";
  }
}

export interface SpooledUpload {
  path: string;
  bytes: number;
  sha256: string;
  sha1: string;
}

/** `open` creates the spool file exclusively (the caller wraps it in its case-write admission). */
export async function spoolUpload(
  req: IncomingMessage,
  path: string,
  maxBytes: number,
  open: (path: string) => Promise<FileHandle>,
): Promise<SpooledUpload> {
  const handle = await open(path);
  try {
    const { bytes, sha256, sha1 } = await pump(req, handle, maxBytes);
    return { path, bytes, sha256, sha1 };
  } catch (err) {
    await rm(path, { force: true }).catch(() => undefined);
    throw err;
  }
}

function pump(
  req: IncomingMessage,
  handle: FileHandle,
  maxBytes: number,
): Promise<{ bytes: number; sha256: string; sha1: string }> {
  const out = handle.createWriteStream({ autoClose: true });
  const h256 = createHash("sha256");
  const h1 = createHash("sha1");
  let bytes = 0;
  return new Promise((resolve, reject) => {
    let settled = false;
    const detach = (): void => {
      req.off("data", onData);
      req.off("end", onEnd);
      req.off("close", onClose);
      req.off("error", fail);
    };
    // Wait for the descriptor to close before the caller may remove the file (Windows holds it).
    const fail = (err: Error): void => {
      if (settled) return;
      settled = true;
      detach();
      req.pause();
      const done = (): void => reject(err);
      if (out.closed) done();
      else {
        out.once("close", done);
        out.destroy();
      }
    };
    const onData = (chunk: Buffer): void => {
      bytes += chunk.length;
      if (bytes > maxBytes) return fail(new UploadTooLargeError(maxBytes));
      h256.update(chunk);
      h1.update(chunk);
      if (!out.write(chunk)) {
        req.pause();
        out.once("drain", () => !settled && req.resume());
      }
    };
    const onEnd = (): void => {
      if (settled) return;
      settled = true;
      detach();
      out.once("error", reject); // a write that fails while flushing the tail
      out.end();
      out.once("close", () => resolve({ bytes, sha256: h256.digest("hex"), sha1: h1.digest("hex") }));
    };
    const onClose = (): void => {
      if (!req.complete) fail(new UploadAbortedError());
    };
    req.on("data", onData);
    req.on("end", onEnd);
    req.on("close", onClose);
    req.on("error", fail);
    out.on("error", fail);
    req.resume();
  });
}
