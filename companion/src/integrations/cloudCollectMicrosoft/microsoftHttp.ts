// The wire the Microsoft collector (#2315) sends on, and how it reads an answer.
//
// Two authorized callers, injected so every test runs on mocks: `graph` (Microsoft Graph, a bearer
// token for graph.microsoft.com added) and `arm` (Azure Resource Manager, a token for
// management.azure.com added). Both hand back the body as BYTES — the collector saves each page
// exactly as the cloud sent it, and only then reads it.
//
// A next-page link comes from the cloud's own answer, and the caller attaches a bearer token to it.
// So a link is followed only to the host the first request went to, over https — never anywhere a
// tampered or unexpected answer points.

import { CursorExpiredError, RateLimitedError } from "../cloudCollect/collectTypes.js";
import { parseRetryAfter } from "../cloudCollect/collectRateLimit.js";

export const GRAPH_HOST = "graph.microsoft.com";
export const ARM_HOST = "management.azure.com";
/** Pinned API versions, per endpoint. Sign-ins are on beta: v1.0 has no `signInEventTypes`. */
export const GRAPH_V1 = `https://${GRAPH_HOST}/v1.0`;
export const GRAPH_BETA = `https://${GRAPH_HOST}/beta`;
export const ARM_BASE = `https://${ARM_HOST}`;
export const ACTIVITY_LOG_API_VERSION = "2015-04-01";
export const SUBSCRIPTIONS_API_VERSION = "2022-12-01";

export interface HttpAnswer {
  status: number;
  /** Lower-case header names. */
  headers: Record<string, string>;
  body: Uint8Array;
}

export interface HttpRequest {
  method: "GET" | "POST";
  url: string;
  /** JSON text, for a POST. */
  body?: string;
  signal?: AbortSignal;
}

export type HttpCall = (request: HttpRequest) => Promise<HttpAnswer>;

/** A failed call, with what the cloud said. Never carries a token or the request itself. */
export class MicrosoftCallError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "MicrosoftCallError";
  }
}

/** Refuse a link that is not https on `host`: a bearer token would be sent with it. */
export function assertLink(url: string, host: string): string {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error("the cloud returned a next-page link that is not a URL");
  }
  if (parsed.protocol !== "https:" || parsed.hostname.toLowerCase() !== host)
    throw new Error(`the cloud returned a next-page link outside ${host}; it was not followed`);
  return parsed.href;
}

const decoder = new TextDecoder("utf-8");

/** The body as JSON. A body that is not JSON is an error, never guessed at. */
export function jsonOf(answer: HttpAnswer): Record<string, unknown> {
  try {
    const value: unknown = JSON.parse(decoder.decode(answer.body));
    if (value && typeof value === "object" && !Array.isArray(value)) return value as Record<string, unknown>;
  } catch {
    // fall through
  }
  throw new Error(`the cloud answered HTTP ${answer.status} with a body that is not a JSON object`);
}

/** A list page: its records and the next link (Graph `@odata.nextLink`, ARM `nextLink`). */
export function listPage(answer: HttpAnswer): { records: number; nextLink?: string } {
  const body = jsonOf(answer);
  const value = body.value;
  if (!Array.isArray(value)) throw new Error("the cloud answered with a list page that has no value array");
  const next = body["@odata.nextLink"] ?? body.nextLink;
  return { records: value.length, ...(typeof next === "string" && next ? { nextLink: next } : {}) };
}

function errorParts(answer: HttpAnswer): { code: string; message: string } {
  try {
    const body = jsonOf(answer) as { error?: { code?: unknown; message?: unknown } };
    const code = typeof body.error?.code === "string" ? body.error.code : "";
    const message = typeof body.error?.message === "string" ? body.error.message : "";
    return { code, message };
  } catch {
    return { code: "", message: "" };
  }
}

// What Graph and ARM say about a page token they no longer accept.
const EXPIRED_TOKEN = /skip ?token|continuation|expired|no longer (valid|available)/i;

/**
 * An answer that is not 2xx, as the error the engine acts on: 429 → RateLimitedError (with the
 * Retry-After), a rejected next-page link → CursorExpiredError, anything else → MicrosoftCallError.
 */
export function failure(answer: HttpAnswer, opts: { pageLink: boolean; nowMs: number }): Error {
  const { code, message } = errorParts(answer);
  if (answer.status === 429)
    return new RateLimitedError(
      parseRetryAfter(answer.headers["retry-after"], opts.nowMs),
      `HTTP 429 ${code || "TooManyRequests"}`.trim(),
    );
  const expired =
    opts.pageLink &&
    (answer.status === 404 ||
      answer.status === 410 ||
      (answer.status === 400 && EXPIRED_TOKEN.test(`${code} ${message}`)));
  if (expired)
    return new CursorExpiredError(`the cloud no longer accepts the next-page link (HTTP ${answer.status})`);
  const text = [`HTTP ${answer.status}`, code].filter(Boolean).join(" ");
  return new MicrosoftCallError(answer.status, code, message ? `${text}: ${message}` : text);
}

/** The cloud's request id, for the manifest. */
export function requestIdOf(answer: HttpAnswer): string | undefined {
  return (
    answer.headers["request-id"] ??
    answer.headers["client-request-id"] ??
    answer.headers["x-ms-request-id"] ??
    undefined
  );
}

/** An ISO time for an OData filter, without a zero millisecond part. */
export function odataTime(iso: string): string {
  return iso.replace(/\.000Z$/, "Z");
}
