// CrowdStrike Falcon Next-Gen SIEM search client (#2666). Direct Falcon API, never MCP.
//
// It calls exactly three endpoints — start, poll and cancel a query job:
//   POST   /humio/api/v1/repositories/{repo}/queryjobs        (scope NGSIEM: Write)
//   GET    /humio/api/v1/repositories/{repo}/queryjobs/{id}   (scope NGSIEM: Read)
//   DELETE /humio/api/v1/repositories/{repo}/queryjobs/{id}
// `queryJobsPath` is the only URL builder; a test asserts every request matches it.
//
// Falcon facts this follows: a job is deleted after ~90 s without a poll (polls here are at most 5 s
// apart); each poll returns the job's CURRENT result snapshot; a filter query returns a buffer of
// about 200 events even when done, and the next page is a NEW job anchored `around` the oldest event
// of the last one (rows are newest first), deduplicated by `@id`; an aggregate (table, groupBy …)
// returns its whole result in one job. Every job is cancelled when its page is over, fails, times out
// or is aborted. Errors are analyst sentences; the secret and the token never appear in one.

import { readBoundedJson, readBoundedText, RESPONSE_SIZE_LIMITS } from "../../providers/boundedResponse.js";
import { FalconAuthError, FalconTokenSource, resolveFalconBase, type FalconFetch } from "./falconAuth.js";
import type { NgsiemCredentials } from "./ngsiemConfig.js";

export type NgsiemRow = Record<string, unknown>;

const PAGE_EVENTS = 200;
const FIRST_POLL_MS = 250;
const MIN_POLL_MS = 250;
const MAX_POLL_MS = 5_000;
const DEFAULT_POLL_MS = 1_000;
const MAX_RETRY_WAIT_MS = 25_000;
const DEFAULT_RETRY_MS = 5_000;
const MAX_RETRIES = 3;
const ERROR_TEXT_MAX = 400;

export const NGSIEM_SCOPE_MESSAGE =
  "The SIEM API client is missing the NG-SIEM scope it needs: starting a search needs NGSIEM: Write and reading results needs NGSIEM: Read.";
const AUTH_MESSAGE =
  "CrowdStrike NG-SIEM sign-in failed — check DFIR_CROWDSTRIKE_SIEM_CLIENT_ID / _SECRET and the cloud region.";
const EXPIRED_MESSAGE = "The search job expired on Falcon before its results were read.";

/** The one URL builder: `/humio/api/v1/repositories/{repo}/queryjobs[/{id}]`. */
export function queryJobsPath(repository: string, id?: string): string {
  const base = `/humio/api/v1/repositories/${encodeURIComponent(repository)}/queryjobs`;
  return id === undefined ? base : `${base}/${encodeURIComponent(id)}`;
}

/** The wait before the next poll: Falcon's `pollAfter` hint, clamped to 250 ms – 5 s (never > 30 s). */
export function pollDelayMs(pollAfter: unknown): number {
  const n = Number(pollAfter);
  if (pollAfter === undefined || pollAfter === null || !Number.isFinite(n)) return DEFAULT_POLL_MS;
  return Math.min(MAX_POLL_MS, Math.max(MIN_POLL_MS, n));
}

/** A failure the analyst can act on; the message is shown as is. */
export class NgsiemError extends Error {}

export interface NgsiemClientOptions extends NgsiemCredentials {
  repository: string;
  fetchFn?: FalconFetch;
  sleep?: (ms: number, signal?: AbortSignal) => Promise<void>;
  now?: () => number;
  requestTimeoutMs?: number;
  cancelTimeoutMs?: number;
}

export interface NgsiemRunRequest {
  query: string;
  startMs: number;
  endMs: number;
  maxRows: number;
  timeoutMs: number;
  signal?: AbortSignal;
  onProgress?: (rows: number) => void;
}

export interface NgsiemRunResult {
  rows: NgsiemRow[];
  /** The row cap, the timeout, an error or an unpageable buffer cut the result short. */
  truncated: boolean;
  timedOut: boolean;
  /** An aggregate query (table, groupBy …): its rows came from one job. */
  aggregate: boolean;
  /** False for an aggregate that did not finish: its rows are a provisional snapshot. */
  finished: boolean;
  /** Why the search stopped early after reading some rows (not the timeout). */
  error?: string;
  pages: number;
  /** Cleanup problems (a cancel Falcon did not confirm). Never a secret. */
  warnings: string[];
}

interface PageResult {
  events: NgsiemRow[];
  done: boolean;
  aggregate: boolean;
  hasMore: boolean;
  timedOut: boolean;
  error?: string;
}

interface Around {
  eventId: string;
  timestamp: number;
  numberOfEventsBefore: number;
  numberOfEventsAfter: number;
}

const abortError = (): Error => new DOMException("The search was cancelled", "AbortError");

function defaultSleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(abortError());
    const t = setTimeout(resolve, ms);
    signal?.addEventListener(
      "abort",
      () => {
        clearTimeout(t);
        reject(abortError());
      },
      { once: true },
    );
  });
}

const oneLine = (s: string): string => s.replace(/\s+/g, " ").trim().slice(0, ERROR_TEXT_MAX);

/** Falcon's own words from an error body (JSON `errors[0].message` / `message` / `error`, or text). */
function falconMessage(text: string): string {
  try {
    const j = JSON.parse(text) as Record<string, unknown>;
    const errs = Array.isArray(j.errors) ? (j.errors as Array<Record<string, unknown>>) : [];
    const m = errs[0]?.message ?? j.message ?? j.error ?? j.detail;
    if (typeof m === "string" && m.trim()) return oneLine(m);
  } catch {
    /* not JSON: the text itself */
  }
  return oneLine(text);
}

function retryAfterMs(header: string | null): number {
  if (!header) return DEFAULT_RETRY_MS;
  const s = Number(header);
  if (Number.isFinite(s) && s >= 0) return s * 1000;
  const at = Date.parse(header);
  return Number.isFinite(at) ? Math.max(0, at - Date.now()) : DEFAULT_RETRY_MS;
}

function anchorOf(row: NgsiemRow | undefined): { eventId: string; timestamp: number } | null {
  if (!row) return null;
  const id = row["@id"];
  const ts = Number(row["@timestamp"]);
  return typeof id === "string" && id && Number.isFinite(ts) ? { eventId: id, timestamp: ts } : null;
}

export class NgsiemSearchClient {
  private readonly base: string;
  private readonly fetchFn: FalconFetch;
  private readonly sleep: (ms: number, signal?: AbortSignal) => Promise<void>;
  private readonly now: () => number;
  private readonly requestTimeoutMs: number;
  private readonly cancelTimeoutMs: number;
  private readonly tokens: FalconTokenSource;

  constructor(private readonly opts: NgsiemClientOptions) {
    this.base = resolveFalconBase(opts);
    this.fetchFn = opts.fetchFn ?? fetch;
    this.sleep = opts.sleep ?? defaultSleep;
    this.now = opts.now ?? Date.now;
    this.requestTimeoutMs = opts.requestTimeoutMs ?? 20_000;
    this.cancelTimeoutMs = opts.cancelTimeoutMs ?? 10_000;
    this.tokens = new FalconTokenSource({
      clientId: opts.clientId,
      clientSecret: opts.clientSecret,
      base: this.base,
      fetchFn: this.fetchFn,
      timeoutMs: this.requestTimeoutMs,
      authFailedMessage: AUTH_MESSAGE,
      label: "CrowdStrike NG-SIEM",
    });
  }

  /** Run one search to completion, the row cap, the timeout or an error. Throws only when nothing was read. */
  async run(req: NgsiemRunRequest): Promise<NgsiemRunResult> {
    const deadline = this.now() + req.timeoutMs;
    const warnings: string[] = [];
    const rows: NgsiemRow[] = [];
    const seen = new Set<string>();
    const maxPages = Math.ceil(req.maxRows / PAGE_EVENTS) + 5;
    const result = (extra: Partial<NgsiemRunResult>): NgsiemRunResult => ({
      rows,
      truncated: false,
      timedOut: false,
      aggregate: false,
      finished: true,
      pages,
      warnings,
      ...extra,
    });
    let around: Around | undefined;
    let pages = 0;
    for (;;) {
      pages++;
      const p = await this.page(req, deadline, around, warnings);
      if (p.aggregate && pages === 1) {
        rows.push(...p.events.slice(0, req.maxRows));
        req.onProgress?.(rows.length);
        const cut = p.events.length > req.maxRows || p.hasMore || !p.done;
        if (!rows.length && p.error) throw new NgsiemError(p.error);
        const tail = { aggregate: true, finished: p.done, truncated: cut, timedOut: p.timedOut };
        return result({ ...tail, ...(p.error ? { error: p.error } : {}) });
      }
      let fresh = 0;
      let capped = false;
      for (const ev of p.events) {
        const id = typeof ev["@id"] === "string" ? ev["@id"] : "";
        if (id && seen.has(id)) continue;
        if (rows.length >= req.maxRows) {
          capped = true;
          break;
        }
        if (id) seen.add(id);
        rows.push(ev);
        fresh++;
      }
      req.onProgress?.(rows.length);
      if (p.error && !rows.length) throw new NgsiemError(p.error);
      if (capped || (rows.length >= req.maxRows && p.hasMore)) return result({ truncated: true });
      if (p.timedOut) return result({ truncated: true, timedOut: true });
      if (p.error) return result({ truncated: true, error: p.error });
      if (!p.hasMore) return result({});
      const anchor = anchorOf(p.events[p.events.length - 1]);
      if (!fresh || !anchor || pages >= maxPages) return result({ truncated: true });
      around = { ...anchor, numberOfEventsBefore: PAGE_EVENTS, numberOfEventsAfter: 0 };
    }
  }

  /** One query job: start, poll to done (keeping the latest snapshot), always cancel. */
  private async page(
    req: NgsiemRunRequest,
    deadline: number,
    around: Around | undefined,
    warnings: string[],
  ): Promise<PageResult> {
    const out: PageResult = { events: [], done: false, aggregate: false, hasMore: false, timedOut: false };
    let id: string | undefined;
    try {
      id = await this.start(req, deadline, around);
      let delay = FIRST_POLL_MS;
      for (;;) {
        const left = deadline - this.now();
        if (left <= 0) return { ...out, timedOut: true };
        await this.sleep(Math.min(delay, left), req.signal);
        if (deadline - this.now() <= 0) return { ...out, timedOut: true };
        const st = await this.poll(id, req, deadline);
        const meta = (st.metaData ?? {}) as Record<string, unknown>;
        const extra = (meta.extraData ?? {}) as Record<string, unknown>;
        if (Array.isArray(st.events)) out.events = st.events.filter((e) => e && typeof e === "object");
        out.aggregate = meta.isAggregate === true;
        out.hasMore = String(extra.hasMoreEvents) === "true";
        if (st.cancelled === true) return { ...out, error: "Falcon cancelled the search job." };
        if (st.done === true) return { ...out, done: true };
        delay = pollDelayMs(meta.pollAfter);
      }
    } catch (err) {
      if (req.signal?.aborted) throw abortError();
      if (deadline - this.now() <= 0) return { ...out, timedOut: true };
      return { ...out, error: this.describe(err) };
    } finally {
      if (id) await this.cancel(id, warnings);
    }
  }

  private describe(err: unknown): string {
    if (err instanceof NgsiemError || err instanceof FalconAuthError) return err.message;
    const name = (err as { name?: string })?.name;
    if (name === "TimeoutError" || name === "AbortError")
      return "CrowdStrike NG-SIEM did not answer in time.";
    return "Could not reach CrowdStrike NG-SIEM.";
  }

  private async start(req: NgsiemRunRequest, deadline: number, around?: Around): Promise<string> {
    const body = {
      queryString: req.query,
      start: req.startMs,
      end: req.endMs,
      isLive: false,
      ...(around ? { around } : {}),
    };
    const res = await this.call(
      "POST",
      queryJobsPath(this.opts.repository),
      req,
      deadline,
      JSON.stringify(body),
    );
    if (res.status === 400 || res.status === 422) {
      const text = await readBoundedText(res, { maxBytes: 64 * 1024, context: "CrowdStrike NG-SIEM" });
      throw new NgsiemError(`Falcon refused the query: "${falconMessage(text) || `HTTP ${res.status}`}"`);
    }
    if (!res.ok) throw new NgsiemError(`CrowdStrike NG-SIEM answered HTTP ${res.status}.`);
    const json = await readBoundedJson<{ id?: unknown }>(res, {
      maxBytes: RESPONSE_SIZE_LIMITS.json,
      context: "CrowdStrike NG-SIEM",
    });
    if (typeof json.id !== "string" || !json.id || json.id.length > 512) {
      throw new NgsiemError("CrowdStrike NG-SIEM did not return a search job id.");
    }
    return json.id;
  }

  private async poll(id: string, req: NgsiemRunRequest, deadline: number): Promise<Record<string, unknown>> {
    const res = await this.call("GET", queryJobsPath(this.opts.repository, id), req, deadline);
    if (res.status === 404) throw new NgsiemError(EXPIRED_MESSAGE);
    if (!res.ok) throw new NgsiemError(`CrowdStrike NG-SIEM answered HTTP ${res.status}.`);
    return readBoundedJson<Record<string, unknown>>(res, {
      maxBytes: RESPONSE_SIZE_LIMITS.json,
      context: "CrowdStrike NG-SIEM",
    });
  }

  /** DELETE the job on its own short deadline — never the caller's (possibly aborted) signal. */
  private async cancel(id: string, warnings: string[]): Promise<void> {
    try {
      const signal = AbortSignal.timeout(this.cancelTimeoutMs);
      const token = await this.tokens.get(false, signal);
      const res = await this.fetchFn(`${this.base}${queryJobsPath(this.opts.repository, id)}`, {
        method: "DELETE",
        headers: { authorization: `Bearer ${token}`, accept: "application/json" },
        signal,
      });
      if (!res.ok && res.status !== 404)
        warnings.push(`Falcon did not confirm the cancel (HTTP ${res.status}).`);
    } catch {
      warnings.push("Falcon did not confirm the cancel of a search job.");
    }
  }

  /** One authenticated request inside the deadline: one token refresh on 401, Retry-After on 429. */
  private async call(
    method: "POST" | "GET",
    path: string,
    req: NgsiemRunRequest,
    deadline: number,
    body?: string,
  ): Promise<Response> {
    let refreshed = false;
    let force = false;
    for (let attempt = 0; ; attempt++) {
      const signal = this.signalFor(req, deadline);
      const token = await this.tokens.get(force, signal);
      force = false;
      const res = await this.fetchFn(`${this.base}${path}`, {
        method,
        headers: {
          authorization: `Bearer ${token}`,
          accept: "application/json",
          ...(body ? { "content-type": "application/json" } : {}),
        },
        ...(body ? { body } : {}),
        signal,
      });
      if (res.status === 401 && !refreshed) {
        refreshed = true;
        force = true; // the token expired early: sign in again, once
        continue;
      }
      if (res.status === 401 || res.status === 403) throw new NgsiemError(NGSIEM_SCOPE_MESSAGE);
      if (res.status !== 429) return res;
      const wait = retryAfterMs(res.headers.get("retry-after"));
      if (attempt >= MAX_RETRIES || wait > MAX_RETRY_WAIT_MS || this.now() + wait >= deadline) {
        throw new NgsiemError(
          `CrowdStrike rate-limited the search. Try again in ${Math.max(1, Math.ceil(wait / 1000))} seconds.`,
        );
      }
      await this.sleep(wait, req.signal);
    }
  }

  private signalFor(req: NgsiemRunRequest, deadline: number): AbortSignal {
    const left = Math.max(1, Math.min(this.requestTimeoutMs, deadline - this.now()));
    const timeout = AbortSignal.timeout(left);
    return req.signal ? AbortSignal.any([req.signal, timeout]) : timeout;
  }
}
