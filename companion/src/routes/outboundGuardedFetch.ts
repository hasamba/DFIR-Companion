import type { FetchFn } from "../enrichment/provider.js";
import { fetchOutbound, type OutboundFetchOptions } from "./outboundFetchGuard.js";

// A fetch-shaped front door to fetchOutbound (issue #2146), for senders whose code takes a FetchFn
// (the notification webhook sender; the audit-export HTTP sender in #2147).
//
// fetchOutbound hands back a dispose() that must run once the body is read, which a plain
// `Response` has no way to carry. So this reads the body here — bounded, because the far side
// decides how long it is — closes the pinned connection, and returns a fresh Response over the
// buffered bytes. Every sender this serves reads, at most, a short status or error body, so the
// cap costs nothing; a body over it is truncated rather than failing a send that succeeded.
//
// It throws OutboundUrlBlockedError for a refused target, before any connection is opened.

export interface GuardedFetchOptions extends Omit<OutboundFetchOptions, "request" | "signal"> {
  /** Bytes of response body kept. Default 64 KiB. */
  maxBodyBytes?: number;
}

const DEFAULT_MAX_BODY_BYTES = 64 * 1024;
// Statuses a Response may not be constructed with a body for.
const NULL_BODY_STATUS = new Set([101, 204, 205, 304]);

function urlOf(input: Parameters<FetchFn>[0]): string {
  if (typeof input === "string") return input;
  if (input instanceof URL) return input.href;
  return input.url;
}

async function readCapped(response: Response, maxBytes: number): Promise<Uint8Array<ArrayBuffer>> {
  if (!response.body) return new Uint8Array(new ArrayBuffer(0));
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (total < maxBytes) {
      const { done, value } = await reader.read();
      if (done) break;
      const room = maxBytes - total;
      const chunk = value.byteLength > room ? value.subarray(0, room) : value;
      chunks.push(chunk);
      total += chunk.byteLength;
    }
  } finally {
    await reader.cancel().catch(() => {});
  }
  const out = new Uint8Array(new ArrayBuffer(total));
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.byteLength;
  }
  return out;
}

export function createGuardedFetch(opts: GuardedFetchOptions): FetchFn {
  const { maxBodyBytes = DEFAULT_MAX_BODY_BYTES, ...guard } = opts;
  return async (input: Parameters<FetchFn>[0], init?: RequestInit) => {
    const { response, dispose } = await fetchOutbound(urlOf(input), {
      ...guard,
      request: { method: init?.method, headers: init?.headers, body: init?.body },
      ...(init?.signal ? { signal: init.signal } : {}),
    });
    try {
      const bytes = await readCapped(response, maxBodyBytes);
      const body = NULL_BODY_STATUS.has(response.status) || bytes.byteLength === 0 ? null : bytes;
      return new Response(body, {
        status: response.status,
        statusText: response.statusText,
        headers: response.headers,
      });
    } finally {
      await dispose();
    }
  };
}
