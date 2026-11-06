// The one HTTP seam of the GCP collector (#2314). Every Logging and Cloud Storage call goes through
// a GcpWire; production builds it from a google-auth-library client and the cloud transport (#2310),
// tests hand the collector a scripted one.
//
// The body comes back as raw bytes: a page is saved byte for byte as evidence, so the response is
// never parsed and re-serialised before it is written. The auth client only supplies the
// Authorization header (its token refresh runs over the transport's transporter); the request itself
// goes out through cloudFetch, on the transport's agent — never Node's global fetch.

import type { CloudFetch } from "../cloudTransport/cloudFetch.js";

export interface GcpWireRequest {
  method: "GET" | "POST";
  url: string;
  /** A JSON request body, already serialised. */
  body?: string;
  signal?: AbortSignal;
}

export interface GcpWireResponse {
  status: number;
  headers: Headers;
  body: Uint8Array;
}

export type GcpWire = (request: GcpWireRequest) => Promise<GcpWireResponse>;

/** The structural part of a google-auth-library AuthClient the wire uses. */
export interface GcpHeaderSource {
  getRequestHeaders(url?: string | URL): Promise<Headers>;
}

/** One call may wait this long before it is abandoned (a GCS object can be tens of MB). */
export const GCP_CALL_TIMEOUT_MS = 120_000;

function withTimeout(signal: AbortSignal | undefined): AbortSignal {
  const timeout = AbortSignal.timeout(GCP_CALL_TIMEOUT_MS);
  return signal ? AbortSignal.any([signal, timeout]) : timeout;
}

/** A wire that signs each request with `auth` and sends it with `fetch` (the transport's). */
export function authorizedWire(auth: () => Promise<GcpHeaderSource>, fetch: CloudFetch): GcpWire {
  return async (req) => {
    const client = await auth();
    const authHeaders = await client.getRequestHeaders(req.url);
    const headers: Record<string, string> = { accept: "application/json" };
    authHeaders.forEach((value, name) => {
      headers[name] = value;
    });
    if (req.body !== undefined) headers["content-type"] = "application/json";
    const res = await fetch(req.url, {
      method: req.method,
      headers,
      ...(req.body !== undefined ? { body: req.body } : {}),
      signal: withTimeout(req.signal),
    });
    return { status: res.status, headers: res.headers, body: new Uint8Array(await res.arrayBuffer()) };
  };
}
