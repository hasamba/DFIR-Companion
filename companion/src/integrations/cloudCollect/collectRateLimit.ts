// Request pacing for a collection (#2312): per-source rate limiters, and back-off on 429.
//
// The clock is injected so the tests advance time instead of waiting. A limiter is per collection
// run; two collections of the same account in different cases each pace themselves, and a 429
// from the cloud is still handled — the back-off is the safety net, the limiter the courtesy.

import { RateLimitedError, type RateLimitSpec } from "./collectTypes.js";

export interface CollectClock {
  /** Milliseconds since the epoch. */
  now(): number;
  /** Wait `ms`; rejects with an AbortError when `signal` fires. */
  sleep(ms: number, signal?: AbortSignal): Promise<void>;
}

function abortError(): Error {
  return Object.assign(new Error("collection cancelled"), { name: "AbortError" });
}

export const realClock: CollectClock = {
  now: () => Date.now(),
  sleep: (ms, signal) =>
    new Promise<void>((resolve, reject) => {
      if (signal?.aborted) return reject(abortError());
      const timer = setTimeout(() => {
        signal?.removeEventListener("abort", onAbort);
        resolve();
      }, ms);
      const onAbort = (): void => {
        clearTimeout(timer);
        reject(abortError());
      };
      signal?.addEventListener("abort", onAbort, { once: true });
    }),
};

/** Throttle retries one collection run may spend unless the provider says otherwise. */
export const DEFAULT_RETRY_BUDGET = 20;
const BASE_BACKOFF_MS = 1000;
const MAX_BACKOFF_MS = 60_000;
/** A Retry-After longer than this is not waited out in one go: the cap applies. */
const MAX_RETRY_AFTER_MS = 300_000;

/** How long to wait before retry number `attempt` (0-based). Pure. */
export function backoffMs(attempt: number, retryAfterMs?: number): number {
  if (retryAfterMs !== undefined && Number.isFinite(retryAfterMs))
    return Math.min(Math.max(0, retryAfterMs), MAX_RETRY_AFTER_MS);
  return Math.min(BASE_BACKOFF_MS * 2 ** Math.max(0, attempt), MAX_BACKOFF_MS);
}

/** A Retry-After header value: seconds, or an HTTP date. */
export function parseRetryAfter(value: unknown, nowMs: number): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) return value * 1000;
  if (typeof value !== "string" || !value.trim()) return undefined;
  const seconds = Number(value.trim());
  if (Number.isFinite(seconds)) return seconds * 1000;
  const at = Date.parse(value);
  return Number.isFinite(at) ? Math.max(0, at - nowMs) : undefined;
}

const THROTTLE_NAMES = new Set([
  "ThrottlingException",
  "Throttling",
  "TooManyRequestsException",
  "RequestLimitExceeded",
]);

type ErrorShape = {
  name?: unknown;
  code?: unknown;
  status?: unknown;
  statusCode?: unknown;
  retryAfterMs?: unknown;
  $metadata?: { httpStatusCode?: unknown };
  headers?: Record<string, unknown> | { get?: (name: string) => unknown };
};

function headerOf(e: ErrorShape, name: string): unknown {
  const headers = e.headers;
  if (!headers) return undefined;
  if (typeof (headers as { get?: unknown }).get === "function")
    return (headers as { get: (n: string) => unknown }).get(name);
  return (headers as Record<string, unknown>)[name];
}

/**
 * Is `err` the cloud saying slow down? RateLimitedError, or the common SDK shapes: HTTP 429, AWS
 * ThrottlingException, gRPC RESOURCE_EXHAUSTED (code 8). Returns the Retry-After when it has one.
 */
export function rateLimitOf(err: unknown, nowMs: number): { retryAfterMs?: number } | null {
  if (err instanceof RateLimitedError)
    return err.retryAfterMs !== undefined ? { retryAfterMs: err.retryAfterMs } : {};
  if (!err || typeof err !== "object") return null;
  const e = err as ErrorShape;
  const status = e.status ?? e.statusCode ?? e.$metadata?.httpStatusCode;
  const throttled =
    status === 429 ||
    (typeof e.name === "string" && THROTTLE_NAMES.has(e.name)) ||
    e.code === 8 ||
    e.code === "RESOURCE_EXHAUSTED";
  if (!throttled) return null;
  const retryAfterMs =
    typeof e.retryAfterMs === "number" ? e.retryAfterMs : parseRetryAfter(headerOf(e, "retry-after"), nowMs);
  return retryAfterMs !== undefined ? { retryAfterMs } : {};
}

/** A sliding-window limiter: at most `requests` calls per `perMs`, per key. */
export class RateLimiter {
  private readonly calls = new Map<string, number[]>();

  constructor(private readonly clock: CollectClock) {}

  /** Wait until a call under `key` fits `spec`, then count it. */
  async acquire(key: string, spec: RateLimitSpec, signal?: AbortSignal): Promise<void> {
    const limit = Math.max(1, Math.floor(spec.requests));
    for (;;) {
      const now = this.clock.now();
      const recent = (this.calls.get(key) ?? []).filter((t) => t > now - spec.perMs);
      if (recent.length < limit) {
        this.calls.set(key, [...recent, now]);
        return;
      }
      this.calls.set(key, recent);
      await this.clock.sleep(Math.max(1, recent[0] + spec.perMs - now), signal);
    }
  }
}

/** The limiter key of one request: the source (or its shared group), plus the partition value. */
export function rateKey(source: string, spec: RateLimitSpec, partition?: Record<string, string>): string {
  const key = spec.perPartitionKey;
  const base = spec.group ? `group:${spec.group}` : source;
  return key && partition?.[key] ? `${base}|${key}=${partition[key]}` : base;
}
