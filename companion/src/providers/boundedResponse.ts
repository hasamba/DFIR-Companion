// Bounded reading of a fetch Response body (issue #686).
//
// PROBLEM. Every provider/enrichment/integration call site reads a whole response into memory
// with res.json() / res.text() / res.arrayBuffer() before looking at it. A per-request timeout
// bounds how LONG that takes, but not how much memory it costs — a compromised, misconfigured, or
// just unexpectedly verbose upstream can hand back gigabytes and the process holds all of it before
// anything gets a chance to reject it.
//
// FIX. Read the body through a byte-counted stream instead of the convenience methods, and stop as
// soon as either signal says "too big":
//   - the DECLARED Content-Length, checked before a single byte is read (cheap, catches the honest
//     case immediately);
//   - the ACTUAL bytes streamed, checked as they arrive (catches a missing/false Content-Length or
//     a chunked body that grows past what it claimed — the declared header is never trustworthy on
//     its own).
// Either path throws ResponseTooLargeError and cancels the underlying reader so the connection is
// torn down rather than drained to completion.
//
// REDACTION. The thrown error never includes response content — only the limit and an optional
// caller-supplied label (provider name / endpoint). A response that overflows the cap is, by
// definition, one the caller decided not to trust; quoting a slice of it back into a log or error
// message would just relocate the same problem one level up.
//
// SCOPE. This closes the memory-exhaustion half of #686. Redirect-chain SSRF revalidation (the
// other half the issue asks for) is a distinct, separately-reviewable change — see the issue for
// tracking — and is deliberately NOT attempted here so this module stays about response size.

export class ResponseTooLargeError extends Error {
  readonly limitBytes: number;
  readonly context?: string;
  constructor(limitBytes: number, context?: string) {
    super(
      `response exceeded the ${limitBytes}-byte limit` +
        (context ? ` (${context})` : "") +
        " — body discarded",
    );
    this.name = "ResponseTooLargeError";
    this.limitBytes = limitBytes;
    this.context = context;
  }
}

export interface BoundedReadOptions {
  /** Hard cap in bytes. Both the declared Content-Length and the actual stream are checked against it. */
  maxBytes: number;
  /** Short label (provider/endpoint name) folded into the error message. Never response content. */
  context?: string;
}

// Common caps so call sites don't each invent a number. A call site with a genuine reason to expect
// a larger body (e.g. a bulk export) should pass its own maxBytes rather than reuse `binary` as a
// default-for-everything escape hatch.
export const RESPONSE_SIZE_LIMITS = {
  /** Typical threat-intel / chat-completions JSON reply. */
  json: 10 * 1024 * 1024,
  /** Plain-text or small structured (CSV/log) replies. */
  text: 5 * 1024 * 1024,
  /** File-shaped downloads (report exports, attachments, artifacts). */
  binary: 50 * 1024 * 1024,
} as const;

/**
 * Reads a Response body into a Buffer, enforcing `maxBytes` against both the declared
 * Content-Length (rejected before any read) and the actual byte count as it streams in.
 * Throws ResponseTooLargeError on either overflow; the reader is cancelled so the underlying
 * connection is torn down instead of drained to completion.
 */
export async function readBoundedBuffer(res: Response, opts: BoundedReadOptions): Promise<Buffer> {
  const { maxBytes, context } = opts;

  const declared = res.headers.get("content-length");
  if (declared !== null) {
    const declaredBytes = Number(declared);
    if (Number.isFinite(declaredBytes) && declaredBytes > maxBytes) {
      // Reject before reading a byte, but still cancel the body — otherwise the connection and
      // its unread bytes stay alive until the caller's timeout (or GC) tears it down, defeating
      // the whole point of rejecting early.
      await res.body?.cancel("response exceeded byte limit").catch(() => {});
      throw new ResponseTooLargeError(maxBytes, context);
    }
  }

  if (!res.body) return Buffer.alloc(0); // no body (e.g. 204, HEAD, or already consumed)

  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value || value.byteLength === 0) continue;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel("response exceeded byte limit").catch(() => {});
        throw new ResponseTooLargeError(maxBytes, context);
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks.map((c) => Buffer.from(c.buffer, c.byteOffset, c.byteLength)));
}

/**
 * Bounded equivalent of `res.text()`. Strips a leading UTF-8 BOM, same as the WHATWG "UTF-8
 * decode" the native `Response.text()`/`.json()` apply — `Buffer#toString("utf8")` does NOT do
 * this on its own, so without it a BOM-emitting self-hosted server (some do) would parse fine
 * through the native path and fail through this one.
 */
export async function readBoundedText(res: Response, opts: BoundedReadOptions): Promise<string> {
  const buf = await readBoundedBuffer(res, opts);
  const text = buf.toString("utf8");
  return text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
}

/**
 * Bounded equivalent of `res.json()`. A JSON.parse failure throws a plain Error that names the
 * context and body length only — NOT the parser's own message. Modern V8 quotes a snippet of the
 * offending text in that message (e.g. `Unexpected token 'S', "SECRET-PAY"... is not valid
 * JSON`), which would leak response content straight back out through this "redacted" helper.
 */
export async function readBoundedJson<T = unknown>(res: Response, opts: BoundedReadOptions): Promise<T> {
  const text = await readBoundedText(res, opts);
  try {
    return JSON.parse(text) as T;
  } catch {
    const label = opts.context ? ` from ${opts.context}` : "";
    throw new Error(`invalid JSON${label} (${Buffer.byteLength(text, "utf8")} bytes) — body redacted`);
  }
}

/**
 * For a call site that falls back to a default value when a successful response's body doesn't
 * parse the way it expects — use this in that fallback so a genuine `ResponseTooLargeError`
 * doesn't get silently treated the same as "empty/malformed body". Swallowing that distinction
 * turns "the response was too big to trust" into "the response was empty", which for something
 * like a sketch/issue LOOKUP reads as not-found and can drive the caller to create a duplicate.
 *
 *   .catch((err) => rethrowIfTooLarge(err, {}))
 */
export function rethrowIfTooLarge<T>(err: unknown, fallback: T): T {
  if (err instanceof ResponseTooLargeError) throw err;
  return fallback;
}

/** Bounded equivalent of `res.arrayBuffer()`. */
export async function readBoundedArrayBuffer(res: Response, opts: BoundedReadOptions): Promise<ArrayBuffer> {
  const buf = await readBoundedBuffer(res, opts);
  return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) as ArrayBuffer;
}
