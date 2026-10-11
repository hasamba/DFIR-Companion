/**
 * Admission control for the heavy whole-case reads (#1915, reopened).
 *
 * THE PROBLEM. Each of these GETs reads the whole case and then builds and serialises its answer on
 * the main thread. analysis/wholeCaseLoadLimit.ts bounds the LOADS, but not that per-request work,
 * and nothing stopped work for a client that had given up. A burst of clients with a 30 s timeout
 * built a backlog that kept the event loop busy for minutes after they stopped: /health went dark.
 *
 * THE GATE. At most HEAVY_READ_CONCURRENCY of these requests run at once, process-wide. Up to
 * HEAVY_READ_QUEUE_LIMIT more wait in arrival order. Past that the answer is an immediate 503 with
 * Retry-After and the SERVER_BUSY_HEADER marker, which the dashboard retries on its own. A queued
 * request whose client disconnects leaves the queue and its handler never runs. A running one gives
 * its slot back when its answer is sent, or — once its client has gone — when the uncancellable work
 * it started has settled (analysis/pendingWork.ts: a whole-case load cannot be stopped mid-read, and
 * one caller leaving never cancels a load another caller shares). Freeing the slot at socket close
 * instead let every disconnect start a new handler while the abandoned loads piled up behind the load
 * limiter, out of the gate's sight. A shared load is counted once, on the request that started it: a
 * request that only joined it frees its slot when its own wait ends (#2126, routes/caseOpenState.ts).
 * A handler with nothing pending frees its slot at once; a slot is never held past
 * HEAVY_READ_ABANDONED_MAX_HOLD_MS, so a hung load cannot leak it. The handlers stop early on their
 * own (http/requestAbort.ts).
 *
 * NORMAL USE NEVER SEES A 503. One case open fires 33 of these reads (#2119, #2121, #2127); the caps hold
 * two such fan-outs together (tests/composition/heavyReadGate.test.ts pins it). The numbers are
 * constants, not settings, for the same reason as READ_WORKER_COUNT: they size the server, not the
 * analyst's workflow.
 *
 * MOUNTED PER-EXACT-PATH like composition/aiRateLimit.ts, and only over GET/HEAD: every write, and
 * every light read, passes straight through. /health is never covered. Left out on purpose:
 * report/:file (a pre-generated file read from disk, no case load), and the super-timeline (a paged
 * worker-pool query with its own count ceiling, #2069; if gated, an analyst's search would queue behind
 * the case-open fan-out). /login-graph IS gated although it reads only the super-timeline: it is a
 * case-open panel load that streams every super-timeline row, not an analyst's interactive search
 * (#2121). /ioc-provenance(-chain) are gated by path only: their scan is shared per case (#1447), and
 * one caller leaving must never cancel it. Panels on the overview load (no forensic rows) are left out
 * too: /compliance, /handoff, /intel-retirement (#2127).
 */
import type { Express, NextFunction, Request, Response } from "express";
import { requestAbortSignal } from "../http/requestAbort.js";
import { WorkTracker } from "../analysis/pendingWork.js";

/** Heavy reads running at once, across every case. Two read workers, plus room for cheap cache hits. */
export const HEAVY_READ_CONCURRENCY = 4;
/** Heavy reads waiting for a slot before the next one is refused with 503. */
export const HEAVY_READ_QUEUE_LIMIT = 68;
/** What a refused client is told to wait, in seconds. */
export const HEAVY_READ_RETRY_AFTER_SECONDS = 2;
/** Safety net: the longest a disconnected request's slot waits for its abandoned work to settle. */
export const HEAVY_READ_ABANDONED_MAX_HOLD_MS = 120_000;
/** Marks a 503 as "busy, retry" (not a broken feature), so the dashboard knows to retry it. */
export const SERVER_BUSY_HEADER = "X-DFIR-Server-Busy";
export const SERVER_BUSY_ERROR = "server busy — retry shortly";

/** The covered GETs, relative to /cases/:id: each loads the whole case. */
export const HEAVY_READ_PATHS: ReadonlySet<string> = new Set([
  "/state",
  "/swimlane",
  "/ioc-sources",
  "/timeline-gaps",
  "/export/ioc-blocklist",
  "/export/stix",
  "/report/interactive",
  // #2119: the remaining ReportWriter reads, the panel loaders and the on-demand exports.
  "/asset-graph",
  "/evidence-graph",
  "/lateral-paths",
  "/phases",
  "/beacon-candidates",
  "/anomalies",
  "/host-ranking",
  "/d3fend-countermeasures",
  "/attack-mitigations",
  "/geo-map",
  "/geo-map.csv",
  "/attack-layer.json",
  "/adversary-hints",
  "/mobile-summary",
  "/presentation",
  "/present/export",
  "/incident-timeline.csv",
  "/timeline.jsonl",
  "/report.docx",
  "/timesketch-omitted",
  "/ioc-provenance",
  "/ioc-provenance-chain",
  // #2121: the case-open panel loaders with their own whole-case load (or super-timeline scan).
  "/ioc-risk",
  "/customer-exposure",
  "/cockpit",
  "/sessions",
  "/campaign-scope",
  "/served-exposure",
  "/kerberoast-chain",
  "/tls-graph",
  "/sensitive-access",
  "/playbook-match",
  "/hypotheses",
  "/host-scope",
  "/host-duplicates",
  "/second-look/preview",
  "/known-unknowns",
  "/login-graph",
]);

export interface HeavyReadLimits {
  concurrency: number;
  queueLimit: number;
  retryAfterSeconds: number;
  /** Defaults to HEAVY_READ_ABANDONED_MAX_HOLD_MS. */
  abandonedMaxHoldMs?: number;
}

const DEFAULT_LIMITS: HeavyReadLimits = {
  concurrency: HEAVY_READ_CONCURRENCY,
  queueLimit: HEAVY_READ_QUEUE_LIMIT,
  retryAfterSeconds: HEAVY_READ_RETRY_AFTER_SECONDS,
  abandonedMaxHoldMs: HEAVY_READ_ABANDONED_MAX_HOLD_MS,
};

interface Waiter {
  start: () => void;
  signal: AbortSignal;
}

export class HeavyReadGate {
  private running = 0;
  private readonly queue: Waiter[] = [];
  private readonly limits: Required<HeavyReadLimits>;

  constructor(limits: HeavyReadLimits = DEFAULT_LIMITS) {
    const { concurrency, queueLimit, retryAfterSeconds } = limits;
    const abandonedMaxHoldMs = limits.abandonedMaxHoldMs ?? HEAVY_READ_ABANDONED_MAX_HOLD_MS;
    if (!Number.isInteger(concurrency) || concurrency < 1)
      throw new Error(`heavy read concurrency must be a positive integer, got ${concurrency}`);
    if (!Number.isInteger(queueLimit) || queueLimit < 0)
      throw new Error(`heavy read queue limit must be a non-negative integer, got ${queueLimit}`);
    if (!(retryAfterSeconds > 0)) throw new Error(`retry-after must be positive, got ${retryAfterSeconds}`);
    if (!(abandonedMaxHoldMs > 0))
      throw new Error(`abandoned max hold must be positive, got ${abandonedMaxHoldMs}`);
    this.limits = { concurrency, queueLimit, retryAfterSeconds, abandonedMaxHoldMs };
  }

  /** Requests running now. */
  get active(): number {
    return this.running;
  }

  /** Requests waiting for a slot. */
  get waiting(): number {
    return this.queue.length;
  }

  admit(res: Response, next: NextFunction): void {
    const signal = requestAbortSignal(res);
    if (signal.aborted) return; // the client is already gone: nothing to answer
    if (this.running < this.limits.concurrency) return this.start(res, next);
    if (this.queue.length >= this.limits.queueLimit) return this.refuse(res);
    const waiter: Waiter = { start: () => this.start(res, next), signal };
    this.queue.push(waiter);
    signal.addEventListener(
      "abort",
      () => {
        const at = this.queue.indexOf(waiter);
        if (at >= 0) this.queue.splice(at, 1); // its handler never runs
      },
      { once: true },
    );
  }

  private start(res: Response, next: NextFunction): void {
    this.running++;
    const work = new WorkTracker();
    let released = false;
    const release = (): void => {
      if (released) return;
      released = true;
      this.running--;
      this.drain();
    };
    res.once("finish", release);
    res.once("close", () => {
      if (res.writableEnded) return release(); // answered: nothing left running for it
      // The client left mid-request: hold the slot until the work it started has settled.
      const safetyNet = setTimeout(release, this.limits.abandonedMaxHoldMs);
      safetyNet.unref();
      work.whenIdle(() => {
        clearTimeout(safetyNet);
        release();
      });
    });
    work.run(next);
  }

  private drain(): void {
    while (this.running < this.limits.concurrency) {
      const waiter = this.queue.shift();
      if (!waiter) return;
      if (!waiter.signal.aborted) waiter.start();
    }
  }

  private refuse(res: Response): void {
    const seconds = this.limits.retryAfterSeconds;
    res.setHeader("Retry-After", String(seconds));
    res.setHeader(SERVER_BUSY_HEADER, "1");
    res.status(503).json({ error: SERVER_BUSY_ERROR, retryAfterMs: seconds * 1000 });
  }
}

/** The route suffix after /cases/:id, folded the way Express matches it (case, trailing slash). */
function caseRelativePath(req: Request): string {
  return (
    req.path
      .replace(/^\/cases\/[^/]+\//, "/")
      .replace(/\/+$/, "")
      .toLowerCase() || "/"
  );
}

export function mountHeavyReadGate(app: Express, gate: HeavyReadGate = new HeavyReadGate()): void {
  app.use("/cases/:id", function heavyReadGate(req: Request, res: Response, next: NextFunction) {
    if (req.method !== "GET" && req.method !== "HEAD") return next();
    if (!HEAVY_READ_PATHS.has(caseRelativePath(req))) return next();
    gate.admit(res, next);
  });
}
