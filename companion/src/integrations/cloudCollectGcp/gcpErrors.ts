// A Google API answer that is not a 200, as the collection engine understands it (#2314):
//
//   429, or RESOURCE_EXHAUSTED in the body       → RateLimitedError (the engine backs off, retries)
//   400 about the page token, when one was sent  → CursorExpiredError (tokens expire after 24 h;
//                                                  the engine restarts the sub-window)
//   anything else                                → GcpHttpError (the sub-window fails, with the reason)
//
// The message is Google's, cut short. It never carries the request: the Authorization header and the
// page token stay out of it.

import { CursorExpiredError, RateLimitedError } from "../cloudCollect/collectTypes.js";
import { parseRetryAfter } from "../cloudCollect/collectRateLimit.js";
import type { GcpWireResponse } from "./gcpWire.js";

const MESSAGE_MAX = 200;

export class GcpHttpError extends Error {
  constructor(
    readonly status: number,
    readonly googleStatus: string | undefined,
    message: string,
  ) {
    super(message);
    this.name = "GcpHttpError";
  }
}

interface GoogleErrorBody {
  error?: { code?: number; status?: string; message?: string };
}

function errorOf(body: Uint8Array): GoogleErrorBody["error"] {
  try {
    const parsed = JSON.parse(Buffer.from(body).toString("utf8")) as GoogleErrorBody;
    return parsed && typeof parsed === "object" ? parsed.error : undefined;
  } catch {
    return undefined;
  }
}

const TOKEN_REJECTED = /page.?token/i;

/** Throws the engine's error for a non-2xx answer; returns for a 2xx. */
export function throwForStatus(res: GcpWireResponse, ctx: { hadPageToken: boolean }): void {
  if (res.status >= 200 && res.status < 300) return;
  const err = errorOf(res.body);
  const googleStatus = typeof err?.status === "string" ? err.status : undefined;
  const message = typeof err?.message === "string" ? err.message.slice(0, MESSAGE_MAX) : "";
  if (res.status === 429 || googleStatus === "RESOURCE_EXHAUSTED") {
    const retryAfterMs = parseRetryAfter(res.headers.get("retry-after") ?? undefined, Date.now());
    throw new RateLimitedError(retryAfterMs, `rate limited by Google${message ? `: ${message}` : ""}`);
  }
  if (ctx.hadPageToken && res.status === 400 && TOKEN_REJECTED.test(message))
    throw new CursorExpiredError(`page token rejected: ${message}`);
  const head = `HTTP ${res.status}${googleStatus ? ` ${googleStatus}` : ""}`;
  throw new GcpHttpError(res.status, googleStatus, message ? `${head}: ${message}` : head);
}
