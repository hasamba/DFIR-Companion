// The network stage of a collection (#2311). Runs OUTSIDE the case's import section: a Graph audit
// query can wait ten minutes and more, and holding the section that long would freeze every other
// import into the case. Nothing here writes the case — only the collection's own evidence folder.
//
// Per page, in this order (collectFs.ts says why each step is there):
//   write <page>.tmp → fsync → rename → fsync pages/ → append the manifest line → fsync the manifest
//   → update the checkpoint.
//
// A failure is classified, never swallowed:
//   - an expired cursor restarts that sub-window from its start (up to MAX_RESTARTS times);
//   - any other provider error fails that sub-window — the others still run, the result is partial;
//   - a write error (disk full, permissions) STOPS the stage: everything committed stays, the result
//     is partial, and the reason names the error code.
//
// #2312 adds, per request: the source's rate limiter; back-off on 429 / Retry-After from a per-run
// retry budget; the tenant's daily query budget before every new query (a used-up budget STOPS the
// stage, "partial — budget used", resumable later); and the split tree — a capped sub-window is
// decided (halves, partitions, or too dense) by a manifest line and its children join the work list.

import { join } from "node:path";
import type { CollectFs } from "./collectFs.js";
import { sha256Hex } from "./collectFs.js";
import { appendManifest, type CollectionPaths } from "./collectManifest.js";
import {
  CursorExpiredError,
  SkippedItemError,
  type CloudCollectSession,
  type CollectPage,
  type CollectSourceInfo,
  type ManifestEntry,
  type ManifestPage,
  type SubWindowStatus,
} from "./collectTypes.js";
import { applySplit, decideSplit, nextWork } from "./collectSplit.js";
import { applySkip } from "./collectReplay.js";
import { NOTE_MAX, withPageDisclosure } from "./collectCoverage.js";
import { budgetStopReason, type QueryBudget } from "./collectBudget.js";
import {
  backoffMs,
  DEFAULT_RETRY_BUDGET,
  RateLimiter,
  rateKey,
  rateLimitOf,
  realClock,
  type CollectClock,
} from "./collectRateLimit.js";

/** How often one sub-window may start over after an expired cursor before it is given up. */
export const MAX_RESTARTS = 3;

/** A write to the evidence folder failed: the stage stops, nothing committed is lost. */
export class EvidenceWriteError extends Error {
  constructor(
    readonly code: string,
    cause: unknown,
  ) {
    super(`evidence write failed (${code}): ${(cause as Error)?.message ?? String(cause)}`);
    this.name = "EvidenceWriteError";
  }
}

async function guardWrite<T>(step: () => Promise<T>): Promise<T> {
  try {
    return await step();
  } catch (err) {
    // Only a filesystem error (it carries an errno code) stops the stage as "partial"; anything
    // else is a bug or a cancel, and propagates as itself.
    const code = (err as NodeJS.ErrnoException)?.code;
    if (typeof code !== "string") throw err;
    throw new EvidenceWriteError(code, err);
  }
}

/** The tenant's query budget is used: the stage stops, the rest stays pending for a later resume. */
export class BudgetStopError extends Error {
  constructor(reason: string) {
    super(reason);
    this.name = "BudgetStopError";
  }
}

export function pageFileName(seq: number, source: string, extension: CollectPage["extension"]): string {
  return `p${String(seq).padStart(6, "0")}-${source}.${extension}`;
}

/** Save one page and its manifest line, in the commit order. Returns the line. */
export async function commitPage(
  fs: CollectFs,
  paths: CollectionPaths,
  page: CollectPage,
  meta: { seq: number; sw: SubWindowStatus; retrievedAt: string; capped?: ManifestPage["capped"] },
): Promise<ManifestPage> {
  const file = pageFileName(meta.seq, meta.sw.source, page.extension);
  const tmp = join(paths.pages, `${file}.tmp`);
  return guardWrite(async () => {
    await fs.writeFileSync(tmp, page.body);
    await fs.rename(tmp, join(paths.pages, file));
    await fs.fsyncDir(paths.pages);
    const line: ManifestPage = {
      type: "page",
      seq: meta.seq,
      source: meta.sw.source,
      subWindowId: meta.sw.id,
      requestParams: page.requestParams,
      ...(page.requestId ? { requestId: page.requestId } : {}),
      retrievedAt: meta.retrievedAt,
      ...(meta.sw.pageToken ? { pageTokenIn: meta.sw.pageToken } : {}),
      ...(page.nextPageToken ? { pageTokenOut: page.nextPageToken } : {}),
      file,
      bytes: page.body.byteLength,
      sha256: sha256Hex(page.body),
      records: page.recordCount,
      ...(meta.capped ? { capped: meta.capped } : {}),
      ...(page.acquiredUntil ? { acquiredUntil: page.acquiredUntil } : {}),
      ...(page.note ? { note: page.note.slice(0, NOTE_MAX) } : {}),
      ...(page.unverified ? { unverified: true as const } : {}),
      ...(page.evidenceOnly ? { evidenceOnly: true as const } : {}),
    };
    await appendManifest(fs, paths, line);
    return line;
  });
}

export interface NetworkStageDeps {
  fs: CollectFs;
  paths: CollectionPaths;
  session: CloudCollectSession;
  now: () => string;
  /** The provider's sources: their split, rate, quota and overlap specs (#2312). */
  sources?: readonly CollectSourceInfo[];
  /** Pacing and back-off; the tests inject a clock that never waits. */
  clock?: CollectClock;
  /** The tenant's daily query budget, for sources with a `queryCost`. */
  budget?: QueryBudget;
  /** Throttle retries this run may spend. */
  retryBudget?: number;
  signal?: AbortSignal;
  /** Persist the checkpoint after a page or a sub-window change (the last commit step). */
  onChange: (subWindows: SubWindowStatus[]) => Promise<void>;
  onPage?: (page: ManifestPage) => void;
}

export interface NetworkStageResult {
  subWindows: SubWindowStatus[];
  pages: ManifestPage[];
  nextSeq: number;
  stopReason?: string;
}

function abortIfCancelled(signal?: AbortSignal): void {
  if (!signal?.aborted) return;
  throw Object.assign(new Error("collection cancelled"), { name: "AbortError" });
}

/** A provider error's message, cut short — never the request itself, which may carry a token. */
function providerReason(err: unknown): string {
  const message = err instanceof Error ? err.message : String(err);
  return `provider error: ${message.slice(0, 300)}`;
}

type Step = { sw: SubWindowStatus; page?: ManifestPage; done: boolean };

/** Per-run state shared by every request: limiter, retry budget, the provider-status reporter. */
interface Pacing {
  clock: CollectClock;
  limiter: RateLimiter;
  retriesLeft: number;
  readonly retryBudget: number;
  status?: (subWindowId: string, status: string) => void;
}

type Fetched = { page: CollectPage } | { failed: string };

async function chargeQuery(deps: NetworkStageDeps, source: CollectSourceInfo | undefined): Promise<void> {
  const cost = source?.queryCost ?? 0;
  if (!deps.budget || cost <= 0) return;
  try {
    if (await deps.budget.reserve(cost)) return;
    throw new BudgetStopError(budgetStopReason(await deps.budget.used(), deps.budget.limit));
  } catch (err) {
    if (err instanceof BudgetStopError || (err as Error)?.name === "AbortError") throw err;
    // The quota record cannot be read or saved: fail closed — stop before sending (#2312 review).
    throw new BudgetStopError(err instanceof Error ? err.message : String(err));
  }
}

/** One request, paced and retried on throttling. Other errors propagate to fetchStep. */
async function requestPage(
  deps: NetworkStageDeps,
  pacing: Pacing,
  sw: SubWindowStatus,
  source: CollectSourceInfo | undefined,
): Promise<Fetched> {
  for (let attempt = 0; ; attempt++) {
    abortIfCancelled(deps.signal);
    if (!sw.pageToken) await chargeQuery(deps, source); // a new query is a submission, every try
    if (source?.rateLimit)
      await pacing.limiter.acquire(
        rateKey(sw.source, source.rateLimit, sw.partition),
        source.rateLimit,
        deps.signal,
      );
    try {
      const page = await deps.session.fetchPage({
        source: sw.source,
        subWindowId: sw.id,
        window: sw.window,
        ...(sw.pageToken ? { pageToken: sw.pageToken } : {}),
        ...(sw.partition ? { partition: sw.partition } : {}),
        ...(deps.signal ? { signal: deps.signal } : {}),
        ...(pacing.status ? { onStatus: (text: string) => pacing.status?.(sw.id, text) } : {}),
      });
      return { page };
    } catch (err) {
      const throttled = rateLimitOf(err, pacing.clock.now());
      if (!throttled) throw err;
      if (pacing.retriesLeft <= 0)
        return {
          failed: `rate limited: the collection's ${pacing.retryBudget} throttle retries are used up`,
        };
      pacing.retriesLeft--;
      await pacing.clock.sleep(backoffMs(attempt, throttled.retryAfterMs), deps.signal);
    }
  }
}

function cappedBy(
  page: CollectPage,
  sw: SubWindowStatus,
  source: CollectSourceInfo | undefined,
): ManifestPage["capped"] {
  if (page.capped) return "provider";
  const cap = source?.maxPagesPerWindow;
  if (cap && page.nextPageToken && sw.pages + 1 >= cap) return "page-cap";
  return undefined;
}

/** One item the cloud refused (#2313): a manifest line, then on to its next token. */
async function skipStep(
  deps: NetworkStageDeps,
  sw: SubWindowStatus,
  err: SkippedItemError,
  note: (e: ManifestEntry) => Promise<void>,
): Promise<Step> {
  const line = {
    type: "skip" as const,
    source: sw.source,
    subWindowId: sw.id,
    item: err.item.slice(0, 1024),
    reason: err.reason.slice(0, 300),
    ...(sw.pageToken ? { pageTokenIn: sw.pageToken } : {}),
    ...(err.nextPageToken ? { pageTokenOut: err.nextPageToken } : {}),
    at: deps.now(),
  };
  await note(line);
  const next = applySkip(sw, line);
  return { sw: next, done: next.state === "done" };
}

async function fetchStep(
  deps: NetworkStageDeps,
  pacing: Pacing,
  sw: SubWindowStatus,
  seq: number,
  note: (e: ManifestEntry) => Promise<void>,
): Promise<Step> {
  const source = deps.sources?.find((s) => s.id === sw.source);
  let fetched: Fetched;
  try {
    fetched = await requestPage(deps, pacing, sw, source);
  } catch (err) {
    const name = (err as Error)?.name;
    if (name === "AbortError" || err instanceof BudgetStopError) throw err;
    if (err instanceof SkippedItemError) return skipStep(deps, sw, err, note);
    if (err instanceof CursorExpiredError && sw.pageToken && sw.restarts < MAX_RESTARTS) {
      await note({ type: "restart", subWindowId: sw.id, reason: "cursor-expired", at: deps.now() });
      // #2402: the restart re-reads the whole window and meets the refused items again, so their
      // skips are counted afresh — exactly as replay's restart does — not added to the old count.
      return {
        sw: {
          ...sw,
          pageToken: undefined,
          capped: undefined,
          skipped: undefined,
          skippedItems: undefined,
          restarts: sw.restarts + 1,
        },
        done: false,
      };
    }
    const reason =
      err instanceof CursorExpiredError
        ? `page token expired ${sw.restarts} time(s); the sub-window was not finished`
        : providerReason(err);
    return { sw: { ...sw, state: "failed", reason }, done: true };
  }
  if ("failed" in fetched) return { sw: { ...sw, state: "failed", reason: fetched.failed }, done: true };
  const { page } = fetched;
  const capped = cappedBy(page, sw, source);
  const retrievedAt = deps.now();
  const line = await commitPage(deps.fs, deps.paths, page, { seq, sw, retrievedAt, capped });
  const counted: SubWindowStatus = withPageDisclosure(
    {
      ...sw,
      pages: sw.pages + 1,
      records: sw.records + line.records,
      firstRetrievedAt: sw.firstRetrievedAt ?? retrievedAt,
      ...(line.acquiredUntil ? { acquiredUntil: line.acquiredUntil } : {}),
      ...(page.walk ? { walk: page.walk } : {}),
      reason: undefined,
    },
    line,
  );
  if (capped)
    return { sw: { ...counted, state: "capped", capped, pageToken: undefined }, page: line, done: false };
  const next: SubWindowStatus = {
    ...counted,
    pageToken: line.pageTokenOut,
    state: line.pageTokenOut ? "pending" : "done",
  };
  return { sw: next, page: line, done: !line.pageTokenOut };
}

/** The partition values a capped minimum window may fall back on. A lookup failure means none. */
async function partitionValuesFor(
  deps: NetworkStageDeps,
  sw: SubWindowStatus,
  source: CollectSourceInfo | undefined,
): Promise<readonly string[] | undefined> {
  if (!source?.partition || sw.partition) return undefined;
  if (!deps.session.partitionValues) return source.partition.values;
  try {
    return await deps.session.partitionValues(source.id, deps.signal);
  } catch (err) {
    if ((err as Error)?.name === "AbortError") throw err;
    return source.partition.values;
  }
}

/** Decide a capped sub-window and write the split line before any child is fetched. */
async function splitCapped(
  deps: NetworkStageDeps,
  subWindows: SubWindowStatus[],
  sw: SubWindowStatus,
  note: (e: ManifestEntry) => Promise<void>,
): Promise<SubWindowStatus[]> {
  const source = deps.sources?.find((s) => s.id === sw.source);
  const values = await partitionValuesFor(deps, sw, source);
  const nodes = subWindows.filter((s) => s.source === sw.source).length;
  const decision = decideSplit(sw, source, values, nodes);
  await note({ type: "split", ...decision, at: deps.now() });
  return applySplit(subWindows, decision);
}

/** Fetch every unfinished sub-window, page by page, splitting the capped ones. */
export async function runNetworkStage(
  deps: NetworkStageDeps,
  start: { subWindows: SubWindowStatus[]; nextSeq: number },
): Promise<NetworkStageResult> {
  let subWindows = start.subWindows.map((s) =>
    s.state === "failed" ? { ...s, state: "pending" as const } : s,
  );
  let seq = start.nextSeq;
  const pages: ManifestPage[] = [];
  const clock = deps.clock ?? realClock;
  const retryBudget = deps.retryBudget ?? DEFAULT_RETRY_BUDGET;
  // A provider status (#2315) is written to the checkpoint as it comes, one write at a time, and
  // every page commit waits for the last one — so an older status never lands after newer state.
  let statusWrites: Promise<void> = Promise.resolve();
  const status = (id: string, text: string): void => {
    subWindows = subWindows.map((s) => (s.id === id ? { ...s, providerStatus: text.slice(0, 200) } : s));
    const snapshot = subWindows;
    statusWrites = statusWrites.then(() => deps.onChange(snapshot)).catch(() => {}); // best effort
  };
  const pacing: Pacing = {
    clock,
    limiter: new RateLimiter(clock),
    retriesLeft: retryBudget,
    retryBudget,
    status,
  };
  const note = (e: ManifestEntry) => guardWrite(() => appendManifest(deps.fs, deps.paths, e));
  const persist = async () => {
    await statusWrites;
    await guardWrite(() => deps.onChange(subWindows));
  };
  try {
    await guardWrite(() => deps.fs.mkdir(deps.paths.pages));
    for (let sw = nextWork(subWindows); sw; sw = nextWork(subWindows)) {
      abortIfCancelled(deps.signal);
      if (sw.state === "capped") {
        subWindows = await splitCapped(deps, subWindows, sw, note);
        await persist();
        continue;
      }
      const step = await fetchStep(deps, pacing, sw, seq, note);
      if (step.page) {
        seq++;
        pages.push(step.page);
        deps.onPage?.(step.page);
      }
      const { providerStatus: _settled, ...next } = step.sw;
      subWindows = subWindows.map((s) => (s.id === next.id ? next : s));
      await persist();
    }
  } catch (err) {
    if (err instanceof BudgetStopError) return { subWindows, pages, nextSeq: seq, stopReason: err.message };
    if (!(err instanceof EvidenceWriteError)) throw err;
    return { subWindows, pages, nextSeq: seq, stopReason: err.message };
  } finally {
    // A status write still in flight must land BEFORE whatever writes the checkpoint next — a
    // cancel's "interrupted" mark must never be overwritten by a late "running" status.
    await statusWrites;
  }
  return { subWindows, pages, nextSeq: seq };
}
