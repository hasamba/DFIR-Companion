// The GCS log sink path of the GCP collector (#2314). A sink is used ONLY after three checks:
//
//   1. its filter routes all four Cloud Audit Logs to it — a strict allowlist (gcpSinkFilter.ts);
//      any filter outside it is unprovable and rejected;
//   2. its history: audit logs are in the bucket from the latest of the sink's creation, its last
//      update (the filter may have been widened then) and the oldest audit object; a sink with no
//      update time is unverified, and a window starting earlier is not the sink's to answer;
//   3. the storage permission: the bucket can be listed (roles/storage.objectViewer).
//
// A sink that fails any check is rejected with the reason, and the collector uses the Logging API.
//
// Sinks write HOURLY batches, and shards of an hour can arrive late
// (https://cloud.google.com/logging/docs/export/storage), so a sink is never assumed settled five
// minutes after the fact: each page states the end of the last whole hour before SINK_LATE_SHARD_MS
// as its estimated cutoff (`acquiredUntil`), and every sink page is marked unverified, so a sink
// collection is never reported plainly complete.
//
// Object names: cloudaudit.googleapis.com/<log>/YYYY/MM/DD/HH:00:00_HH:59:59_S<n>.json, and the
// addendum shards late entries of an hour are written to afterwards, …_A<n>:<epoch seconds>.json.
// Both are collected. (A copied folder may have dashes for the colons.)

import type { CollectWindow } from "../cloudCollect/collectTypes.js";
import { GCP_AUDIT_LOGS, type GcpAuditLog } from "./gcpFilter.js";
import { throwForStatus } from "./gcpErrors.js";
import { sinkFilterMisses } from "./gcpSinkFilter.js";
import type { GcpWire } from "./gcpWire.js";

const HOUR = 3_600_000;
const DAY = 24 * HOUR;
/**
 * Disclosed on every sink page, which the engine never counts as complete: a sink delivers on a
 * best-effort basis, so the 3 h settle delay below is an estimate, not a completeness guarantee.
 */
export const SINK_UNVERIFIED_NOTE =
  "Log sink delivery is not guaranteed complete; collect the same window with the Logging API " +
  '(source "GCP audit logs") for a completeness guarantee.';
/** How long after its hour a batch may still gain a late shard. An estimate, not a guarantee. */
export const SINK_LATE_SHARD_MS = 3 * HOUR;
const AUDIT_PREFIX = "cloudaudit.googleapis.com/";
const STORAGE_DESTINATION = "storage.googleapis.com/";
const BUCKET_NAME = /^[a-z0-9][a-z0-9._-]{1,220}$/;
const STORAGE_API = "https://storage.googleapis.com/storage/v1/b/";
const LIST_PAGE = 1000;

export interface LogSink {
  name: string;
  destination: string;
  filter?: string;
  disabled?: boolean;
  exclusions?: Array<{ name?: string; filter?: string; disabled?: boolean }>;
  createTime?: string;
  /** When the sink (its filter included) last changed: history before it is not the sink's. */
  updateTime?: string;
}

export type SinkVerdict = { ok: true; bucket: string } | { ok: false; reason: string };

/** Checks 1 (filter) and the sink's own shape. Pure. */
export function sinkVerdict(sink: LogSink, projectId: string, logs: readonly GcpAuditLog[]): SinkVerdict {
  const who = `sink "${String(sink.name).slice(0, 100)}"`;
  const bucket = sink.destination?.startsWith(STORAGE_DESTINATION)
    ? sink.destination.slice(STORAGE_DESTINATION.length)
    : undefined;
  if (!bucket || !BUCKET_NAME.test(bucket))
    return { ok: false, reason: `${who}: its destination is not a Cloud Storage bucket` };
  if (sink.disabled) return { ok: false, reason: `${who}: the sink is disabled` };
  if ((sink.exclusions ?? []).some((e) => !e.disabled))
    return { ok: false, reason: `${who}: it has exclusion filters, which may drop audit entries` };
  const { missing, unprovable } = sinkFilterMisses(sink.filter, projectId, logs);
  if (unprovable) return { ok: false, reason: `${who}: ${unprovable}` };
  if (missing.length)
    return { ok: false, reason: `${who}: its filter does not include the ${missing.join(", ")} audit logs` };
  return { ok: true, bucket };
}

const OBJECT_NAME =
  /^cloudaudit\.googleapis\.com\/([a-z_]+)\/(\d{4})\/(\d{2})\/(\d{2})\/(\d{2})[:-]00[:-]00_\d{2}[:-]59[:-]59_(?:S\d+|A\d+[:-]\d+)\.json$/;

/** The log and hour a sink object holds, or null for any other name. */
export function objectHour(name: string): { log: GcpAuditLog; startMs: number; endMs: number } | null {
  const m = OBJECT_NAME.exec(name);
  if (!m || !(GCP_AUDIT_LOGS as readonly string[]).includes(m[1])) return null;
  const startMs = Date.UTC(Number(m[2]), Number(m[3]) - 1, Number(m[4]), Number(m[5]));
  return Number.isFinite(startMs) ? { log: m[1] as GcpAuditLog, startMs, endMs: startMs + HOUR } : null;
}

/** The end of the last hourly batch that can no longer gain a late shard, at `retrievedAtMs`. */
export function lastCompleteBatchEnd(retrievedAtMs: number): string {
  return new Date(Math.floor((retrievedAtMs - SINK_LATE_SHARD_MS) / HOUR) * HOUR).toISOString();
}

const enc = encodeURIComponent;

export function objectMediaUrl(bucket: string, name: string): string {
  return `${STORAGE_API}${enc(bucket)}/o/${enc(name)}?alt=media`;
}

function listUrl(bucket: string, prefix: string, max: number, pageToken?: string): string {
  const q = `prefix=${enc(prefix)}&maxResults=${max}${pageToken ? `&pageToken=${enc(pageToken)}` : ""}`;
  return `${STORAGE_API}${enc(bucket)}/o?${q}`;
}

const parse = <T>(body: Uint8Array): T => JSON.parse(Buffer.from(body).toString("utf8")) as T;

async function listSinks(wire: GcpWire, projectId: string, signal?: AbortSignal): Promise<LogSink[]> {
  const out: LogSink[] = [];
  let token: string | undefined;
  do {
    const url =
      `https://logging.googleapis.com/v2/projects/${enc(projectId)}/sinks?pageSize=200` +
      (token ? `&pageToken=${enc(token)}` : "");
    const res = await wire({ method: "GET", url, ...(signal ? { signal } : {}) });
    throwForStatus(res, { hadPageToken: false });
    const page = parse<{ sinks?: LogSink[]; nextPageToken?: string }>(res.body);
    out.push(...(page.sinks ?? []));
    token = page.nextPageToken;
  } while (token);
  return out;
}

export type SinkChoice = { sink: string; bucket: string; coveredFrom: string } | { rejected: string[] };

/** Checks 2 and 3 on a sink that passed check 1: its history and the bucket permission. */
async function probeBucket(
  wire: GcpWire,
  sink: LogSink,
  bucket: string,
  signal?: AbortSignal,
): Promise<{ reason: string } | { coveredFrom: string }> {
  const who = `sink "${String(sink.name).slice(0, 100)}"`;
  const res = await wire({
    method: "GET",
    url: listUrl(bucket, AUDIT_PREFIX, 1),
    ...(signal ? { signal } : {}),
  });
  try {
    throwForStatus(res, { hadPageToken: false });
  } catch (err) {
    const why = err instanceof Error ? err.message : String(err);
    return { reason: `${who}: its bucket cannot be listed (needs roles/storage.objectViewer): ${why}` };
  }
  const first = parse<{ items?: Array<{ name?: string }> }>(res.body).items?.[0]?.name;
  const oldest = first ? objectHour(first) : null;
  if (!oldest) return { reason: `${who}: its bucket holds no audit log objects` };
  // The filter may have been widened at the last update: only after it is the routing known.
  const updated = sink.updateTime ? Date.parse(sink.updateTime) : NaN;
  if (!Number.isFinite(updated))
    return { reason: `${who}: its last update time is unknown, so its history cannot be verified` };
  const created = sink.createTime ? Date.parse(sink.createTime) : NaN;
  const from = Math.max(updated, Number.isFinite(created) ? created : updated, oldest.startMs);
  return { coveredFrom: new Date(from).toISOString() };
}

/** The first sink that passes every check, or every rejection with its reason. Reads only. */
export async function chooseSink(
  wire: GcpWire,
  projectId: string,
  signal?: AbortSignal,
): Promise<SinkChoice> {
  let sinks: LogSink[];
  try {
    sinks = await listSinks(wire, projectId, signal);
  } catch (err) {
    if ((err as Error)?.name === "AbortError") throw err;
    return { rejected: [`the log sinks could not be listed: ${(err as Error)?.message ?? String(err)}`] };
  }
  if (!sinks.length) return { rejected: ["the project has no log sink"] };
  const rejected: string[] = [];
  for (const sink of sinks) {
    const verdict = sinkVerdict(sink, projectId, GCP_AUDIT_LOGS);
    if (!verdict.ok) {
      rejected.push(verdict.reason);
      continue;
    }
    const probe = await probeBucket(wire, sink, verdict.bucket, signal);
    if ("reason" in probe) rejected.push(probe.reason);
    else return { sink: sink.name, bucket: verdict.bucket, coveredFrom: probe.coveredFrom };
  }
  return { rejected };
}

const day = (ms: number): string => new Date(ms).toISOString().slice(0, 10).replace(/-/g, "/");

/** The day folders a window touches, per log. */
function dayPrefixes(window: CollectWindow, logs: readonly GcpAuditLog[]): string[] {
  const start = Math.floor(Date.parse(window.start) / DAY) * DAY;
  const end = Date.parse(window.end);
  const out: string[] = [];
  for (const log of logs) for (let t = start; t < end; t += DAY) out.push(`${AUDIT_PREFIX}${log}/${day(t)}/`);
  return out;
}

export interface SinkListing {
  /** The objects whose hour overlaps the window, in name order. */
  names: string[];
  /** The last listing response, byte for byte — the evidence of an empty window. */
  lastListing: Uint8Array;
  prefixes: number;
}

/** Every sink object of `logs` whose hour overlaps `window`. */
export async function listSinkObjects(
  wire: GcpWire,
  bucket: string,
  window: CollectWindow,
  logs: readonly GcpAuditLog[],
  signal?: AbortSignal,
): Promise<SinkListing> {
  const ws = Date.parse(window.start);
  const we = Date.parse(window.end);
  const names: string[] = [];
  let lastListing: Uint8Array = new Uint8Array();
  const prefixes = dayPrefixes(window, logs);
  for (const prefix of prefixes) {
    let token: string | undefined;
    do {
      const res = await wire({
        method: "GET",
        url: listUrl(bucket, prefix, LIST_PAGE, token),
        ...(signal ? { signal } : {}),
      });
      throwForStatus(res, { hadPageToken: false });
      lastListing = res.body;
      const page = parse<{ items?: Array<{ name?: string }>; nextPageToken?: string }>(res.body);
      for (const item of page.items ?? []) {
        const hour = item.name ? objectHour(item.name) : null;
        if (hour && item.name && hour.startMs < we && hour.endMs > ws) names.push(item.name);
      }
      token = page.nextPageToken;
    } while (token);
  }
  return { names: [...new Set(names)].sort(), lastListing, prefixes: prefixes.length };
}
