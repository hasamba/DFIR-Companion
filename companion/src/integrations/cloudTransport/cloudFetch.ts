import { request as httpRequest, type IncomingMessage } from "node:http";
import { request as httpsRequest } from "node:https";
import { Readable } from "node:stream";
import type { CloudTransport } from "./cloudAgent.js";

// A small fetch over the cloud transport (#2310), for the REST calls that need no SDK — Microsoft
// Graph (audit log queries, sign-ins, directory audits) and Google REST endpoints. Node's global
// fetch (undici) cannot take a Node agent, so this goes through node:https with the transport's
// agent: same per-destination CA, insecure and proxy policy as the SDK clients. It returns a
// standard Response; it never retries and never throws on an HTTP error status.

export type CloudFetch = (url: string | URL, init?: CloudFetchInit) => Promise<Response>;

export interface CloudFetchInit {
  method?: string;
  headers?: Record<string, string>;
  body?: string | Uint8Array;
  signal?: AbortSignal;
}

function toHeaders(res: IncomingMessage): Headers {
  const headers = new Headers();
  for (const [name, value] of Object.entries(res.headers)) {
    if (Array.isArray(value)) for (const v of value) headers.append(name, v);
    else if (value !== undefined) headers.set(name, value);
  }
  return headers;
}

const NULL_BODY_STATUS = new Set([101, 204, 205, 304]);

function toResponse(res: IncomingMessage, method: string): Response {
  const status = res.statusCode ?? 0;
  const noBody = method === "HEAD" || NULL_BODY_STATUS.has(status);
  if (noBody) res.resume();
  const body = noBody ? null : (Readable.toWeb(res) as ReadableStream<Uint8Array>);
  return new Response(body, { status, statusText: res.statusMessage ?? "", headers: toHeaders(res) });
}

export function cloudFetch(transport: CloudTransport): CloudFetch {
  return (input, init = {}) =>
    new Promise<Response>((resolve, reject) => {
      const url = new URL(input);
      if (url.protocol !== "https:" && url.protocol !== "http:") {
        reject(new Error(`cloud request refused: unsupported scheme ${url.protocol}`));
        return;
      }
      const method = (init.method ?? "GET").toUpperCase();
      const send = url.protocol === "https:" ? httpsRequest : httpRequest;
      const req = send(
        url,
        { method, headers: init.headers, agent: transport.agent, signal: init.signal },
        (res) => resolve(toResponse(res, method)),
      );
      req.on("error", reject);
      req.end(init.body);
    });
}
