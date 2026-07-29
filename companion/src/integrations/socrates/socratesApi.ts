// Server-side client for the SO-CRATES HTTP API (dougburks/so-crates).
//
// Must be server-side: SO-CRATES sends no CORS headers and a `default-src 'self'` CSP, so the
// dashboard cannot call it from the browser. It also has NO authentication and binds 127.0.0.1 by
// default — see the non-local warning in Settings.
//
// The API is asynchronous and keyed by MD5: upload returns immediately, the caller polls, and the
// results are then read from three separate verdict feeds. Because the key is the file's MD5, an
// already-analyzed file can skip the upload entirely (probeAnalysis).

import { createHash } from "node:crypto";
import type { FetchFn } from "../../enrichment/provider.js";

export interface SocratesStatus {
  status: "ready" | "processing" | "error";
  phase?: string;
  message?: string;
  meta?: { detected_type?: string; original?: string; extracted?: string };
}

export interface SocratesUploadResult {
  status: "ready" | "processing";
  md5: string;
  phase?: string;
}

export interface SocratesVerdicts {
  /** All verdict rows as one JSON array, ready for parseSocrates. */
  text: string;
  alerts: number;
  yara: number;
  sigma: number;
}

// SO-CRATES caps `limit` at MAX_QUERY_LIMIT (100,000) and defaults to 1000. Page at the default.
const PAGE_SIZE = 1000;
// Stop paging regardless, so a misbehaving server cannot spin forever.
const MAX_PAGES = 100;

function trimBase(baseUrl: string): string {
  return baseUrl.replace(/\/+$/, "");
}

/** The MD5 SO-CRATES keys an analysis by. MD5 is the server's choice of key, not a security claim. */
export function md5Buffer(data: Buffer): string {
  return createHash("md5").update(data).digest("hex");
}

async function getJson(url: string, fetchFn: FetchFn): Promise<unknown> {
  const res = await fetchFn(url, { method: "GET" });
  if (!res.ok) throw new Error(`SO-CRATES GET ${new URL(url).pathname} failed: HTTP ${res.status}`);
  return res.json();
}

async function postJson(url: string, body: unknown, fetchFn: FetchFn): Promise<unknown> {
  const res = await fetchFn(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`SO-CRATES POST ${new URL(url).pathname} failed: HTTP ${res.status}`);
  return res.json();
}

/**
 * Ask whether this MD5 has already been analyzed, so an unchanged file skips the upload.
 *
 * Caveat: SO-CRATES never 404s here. A well-formed MD5 with no analysis directory reads as
 * `{status: "processing", phase: ""}`, which is why the poller carries its own attempt ceiling.
 */
export async function probeAnalysis(
  baseUrl: string, md5: string, fetchFn: FetchFn = fetch as FetchFn,
): Promise<SocratesStatus> {
  return await getJson(`${trimBase(baseUrl)}/api/status?md5=${encodeURIComponent(md5)}`, fetchFn) as SocratesStatus;
}

/** Upload a file for analysis as multipart/form-data. */
export async function uploadBuffer(
  baseUrl: string, data: Buffer, filename: string, fetchFn: FetchFn = fetch as FetchFn,
): Promise<SocratesUploadResult> {
  const form = new FormData();
  form.append("file", new Blob([data]), filename);
  const res = await fetchFn(`${trimBase(baseUrl)}/api/upload`, { method: "POST", body: form });
  if (!res.ok) {
    const detail = await res.json().catch(() => ({}));
    const msg = (detail as { error?: string }).error ?? `HTTP ${res.status}`;
    throw new Error(`SO-CRATES upload of "${filename}" failed: ${msg}`);
  }
  return await res.json() as SocratesUploadResult;
}

/** Poll whether analysis has finished. */
export async function checkStatus(
  baseUrl: string, md5: string, fetchFn: FetchFn = fetch as FetchFn,
): Promise<SocratesStatus> {
  return await postJson(`${trimBase(baseUrl)}/api/check-status`, { md5 }, fetchFn) as SocratesStatus;
}

// Page one feed until a short page comes back (or MAX_PAGES trips).
async function fetchAllPages(url: string, fetchFn: FetchFn): Promise<Record<string, unknown>[]> {
  const out: Record<string, unknown>[] = [];
  for (let page = 0; page < MAX_PAGES; page++) {
    const sep = url.includes("?") ? "&" : "?";
    const body = await getJson(`${url}${sep}offset=${page * PAGE_SIZE}&limit=${PAGE_SIZE}`, fetchFn);
    if (!Array.isArray(body)) break;
    for (const row of body) if (row && typeof row === "object") out.push(row as Record<string, unknown>);
    if (body.length < PAGE_SIZE) break;
  }
  return out;
}

/**
 * Fetch the three VERDICT feeds and merge them into one JSON array for parseSocrates.
 *
 * Never requests /api/events without a `type`: the default returns whole-capture dns/http/tls/flow
 * telemetry, which would flood the timeline and break the Companion's post-detection principle.
 * Every row is stamped `_Source: "SO-CRATES"` so importDetect's isSocrates() claims the blob.
 */
export async function fetchVerdicts(
  baseUrl: string, md5: string, fetchFn: FetchFn = fetch as FetchFn,
): Promise<SocratesVerdicts> {
  const base = trimBase(baseUrl);
  const q = encodeURIComponent(md5);
  const [alerts, yara, sigma] = await Promise.all([
    fetchAllPages(`${base}/api/events?md5=${q}&type=alert`, fetchFn),
    fetchAllPages(`${base}/api/events?md5=${q}&type=filealerts`, fetchFn),
    fetchAllPages(`${base}/api/sigma-alerts?md5=${q}`, fetchFn),
  ]);

  const rows = [...alerts, ...yara, ...sigma].map((r) => ({ ...r, _Source: "SO-CRATES" }));
  return { text: JSON.stringify(rows), alerts: alerts.length, yara: yara.length, sigma: sigma.length };
}
