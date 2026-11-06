// The unified audit log through Microsoft Graph's AuditLogQuery (#2315), API v1.0 — never
// Search-UnifiedAuditLog, which retires on 2027-10-15.
//
// The first page of a sub-window is a three-step lifecycle:
//   1. CREATE   POST /v1.0/security/auditLog/queries   { filterStartDateTime, filterEndDateTime,
//                                                          recordTypeFilters? }   → the query id
//               (one submission from the tenant's daily quota — the engine charged it already)
//   2. POLL     GET  /v1.0/security/auditLog/queries/{id} until `succeeded`; every poll reports its
//               status to the panel ("audit query running — 4 min"). Ten minutes is ordinary.
//   3. PAGE     GET  /v1.0/security/auditLog/queries/{id}/records → the first page, saved as is.
// Later pages follow `@odata.nextLink`, which carries the query id. A query that says
// `isRecordCountLimitExceeded` (read from the POLLED query object, never the records page) marks its
// first page `capped`: the engine stops paging it and re-collects the window as two halves, and at
// one minute, once per record type (ualRecordTypes.ts).
//
// A throttled poll is waited out here, inside the step; a throttled CREATE goes back to the engine
// as RateLimitedError (a retried create is a new submission, and the engine charges it again). A
// query created but not yet paged is remembered per sub-window, so a retry after a throttled first
// page reuses it instead of submitting a second one.

import type { CollectPage, CollectPageRequest } from "../cloudCollect/collectTypes.js";
import {
  assertLink,
  failure,
  GRAPH_HOST,
  GRAPH_V1,
  jsonOf,
  listPage,
  requestIdOf,
  type HttpAnswer,
  type HttpCall,
} from "./microsoftHttp.js";

export interface UalTiming {
  now(): number;
  sleep(ms: number, signal?: AbortSignal): Promise<void>;
  /** Give up on a query that has not finished after this long (default 60 min). */
  maxWaitMs?: number;
  /** The poll interval grows from `firstPollMs` to `maxPollMs` (defaults 10 s → 60 s). */
  firstPollMs?: number;
  maxPollMs?: number;
}

const MINUTE = 60_000;
const DEFAULT_MAX_WAIT_MS = 60 * MINUTE;
const DEFAULT_FIRST_POLL_MS = 10_000;
const DEFAULT_MAX_POLL_MS = 60_000;
const THROTTLED_POLL_MS = 30_000;
const QUERIES = `${GRAPH_V1}/security/auditLog/queries`;

/** The query ids created but not yet paged, per sub-window, for one session. */
export type PendingQueries = Map<string, string>;

function minutes(ms: number): string {
  const m = Math.floor(ms / MINUTE);
  return m < 1 ? "under 1 min" : `${m} min`;
}

async function call(
  graph: HttpCall,
  request: Parameters<HttpCall>[0],
  timing: UalTiming,
  pageLink = false,
): Promise<HttpAnswer> {
  const answer = await graph(request);
  if (answer.status >= 200 && answer.status < 300) return answer;
  throw failure(answer, { pageLink, nowMs: timing.now() });
}

async function createQuery(graph: HttpCall, req: CollectPageRequest, timing: UalTiming): Promise<string> {
  const recordType = req.partition?.recordType;
  const body = {
    "@odata.type": "#microsoft.graph.security.auditLogQuery",
    displayName: `DFIR Companion ${req.subWindowId}`.slice(0, 120),
    filterStartDateTime: req.window.start,
    filterEndDateTime: req.window.end,
    ...(recordType ? { recordTypeFilters: [recordType] } : {}),
  };
  const answer = await call(
    graph,
    {
      method: "POST",
      url: QUERIES,
      body: JSON.stringify(body),
      ...(req.signal ? { signal: req.signal } : {}),
    },
    timing,
  );
  const id = jsonOf(answer).id;
  if (typeof id !== "string" || !/^[A-Za-z0-9-]{1,100}$/.test(id))
    throw new Error("Graph created an audit query but returned no usable query id");
  return id;
}

/** Poll until the query succeeds; returns the polled query object. */
async function waitForQuery(
  graph: HttpCall,
  id: string,
  req: CollectPageRequest,
  timing: UalTiming,
): Promise<Record<string, unknown>> {
  const started = timing.now();
  const maxWait = timing.maxWaitMs ?? DEFAULT_MAX_WAIT_MS;
  let interval = timing.firstPollMs ?? DEFAULT_FIRST_POLL_MS;
  for (;;) {
    const answer = await graph({
      method: "GET",
      url: `${QUERIES}/${id}`,
      ...(req.signal ? { signal: req.signal } : {}),
    });
    const elapsed = timing.now() - started;
    if (answer.status === 429) {
      req.onStatus?.(`audit query throttled by Microsoft — waiting (${minutes(elapsed)} so far)`);
      await timing.sleep(THROTTLED_POLL_MS, req.signal);
      continue;
    }
    if (answer.status < 200 || answer.status >= 300)
      throw failure(answer, { pageLink: false, nowMs: timing.now() });
    const query = jsonOf(answer);
    const status = typeof query.status === "string" ? query.status : "unknown";
    if (status === "succeeded") return query;
    if (status === "failed" || status === "cancelled")
      throw new Error(`the audit query ended "${status}" at Microsoft; resume to submit a new one`);
    if (elapsed >= maxWait)
      throw new Error(
        `the audit query was still "${status}" after ${minutes(elapsed)}; resume to submit a new one`,
      );
    req.onStatus?.(`audit query ${status} — ${minutes(elapsed)} (Microsoft often needs 10 min or more)`);
    await timing.sleep(interval, req.signal);
    interval = Math.min(interval * 2, timing.maxPollMs ?? DEFAULT_MAX_POLL_MS);
  }
}

function asPage(answer: HttpAnswer, params: Record<string, string>, capped: boolean): CollectPage {
  const { records, nextLink } = listPage(answer);
  const requestId = requestIdOf(answer);
  return {
    body: answer.body,
    extension: "json",
    recordCount: records,
    ...(nextLink ? { nextPageToken: assertLink(nextLink, GRAPH_HOST) } : {}),
    ...(requestId ? { requestId } : {}),
    requestParams: params,
    ...(capped ? { capped: true } : {}),
  };
}

/** One page of the unified audit log for one sub-window (see the file header). */
export async function fetchUalPage(
  graph: HttpCall,
  req: CollectPageRequest,
  timing: UalTiming,
  pending: PendingQueries,
): Promise<CollectPage> {
  const params: Record<string, string> = {
    api: "Microsoft Graph v1.0",
    endpoint: "security/auditLog/queries/{id}/records",
    filterStartDateTime: req.window.start,
    filterEndDateTime: req.window.end,
    ...(req.partition?.recordType ? { recordTypeFilters: req.partition.recordType } : {}),
  };
  if (req.pageToken) {
    const url = assertLink(req.pageToken, GRAPH_HOST);
    const answer = await call(
      graph,
      { method: "GET", url, ...(req.signal ? { signal: req.signal } : {}) },
      timing,
      true,
    );
    return asPage(answer, { ...params, page: "next" }, false);
  }
  const key = req.subWindowId;
  const id = pending.get(key) ?? (await createQuery(graph, req, timing));
  pending.set(key, id);
  req.onStatus?.(`audit query ${id.slice(0, 8)}… submitted — waiting for Microsoft`);
  let query: Record<string, unknown>;
  try {
    query = await waitForQuery(graph, id, req, timing);
  } catch (err) {
    if ((err as Error)?.name !== "AbortError") pending.delete(key); // a dead query is never reused
    throw err;
  }
  const capped = query.isRecordCountLimitExceeded === true;
  const answer = await call(
    graph,
    { method: "GET", url: `${QUERIES}/${id}/records`, ...(req.signal ? { signal: req.signal } : {}) },
    timing,
  );
  pending.delete(key);
  return asPage(
    answer,
    { ...params, queryId: id, page: "first", ...(capped ? { isRecordCountLimitExceeded: "true" } : {}) },
    capped,
  );
}
