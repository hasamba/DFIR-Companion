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
 *
 * A MEMORY BUDGET (#2846). The count cap bounds how many reads run, not how much memory they take;
 * on a large case four of them took a server past what the machine could give. With a budget
 * (composition/heavyReadMemoryBudget.ts) a read also waits, in arrival order, until its estimated
 * memory fits next to the reads already running. When none is running and the read still does not
 * fit, it waits up to HEAVY_READ_IDLE_HOLD_MS for memory to come back, then starts anyway, so a large
 * case on a small machine opens slowly instead of never. A read held back only by the budget is
 * looked at again every HEAVY_READ_BUDGET_RECHECK_MS, as well as whenever a read finishes. The
 * session log gets one line when reads start waiting for memory and one when the queue has drained.
 *
 * IDENTICAL READS SHARE ONE ANSWER (#2846). With a coalescer (composition/heavyReadCoalescer.ts) a
 * case-open panel read identical to one still waiting in the queue joins it instead of taking a queue
 * place, and gets a copy of its answer, so a second dashboard on the same case does not queue a
 * second round of the same work.
 */
import type { Express, NextFunction, Request, Response } from "express";
import { requestAbortSignal } from "../http/requestAbort.js";
import { WorkTracker } from "../analysis/pendingWork.js";
import {
  HEAVY_READ_BUDGET_RECHECK_MS,
  HEAVY_READ_IDLE_HOLD_MS,
  type HeavyReadBudget,
} from "./heavyReadMemoryBudget.js";
import { logLine } from "../logging/serverLogger.js";
import { HeavyReadCoalescer, relPathOf } from "./heavyReadCoalescer.js";

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
  // #2206: the Sigma re-grade preview re-parses the stored import files and scans the super-timeline.
  "/sigma/regrade",
]);

export interface HeavyReadLimits {
  concurrency: number;
  queueLimit: number;
  retryAfterSeconds: number;
  /** Defaults to HEAVY_READ_ABANDONED_MAX_HOLD_MS. */
  abandonedMaxHoldMs?: number;
  /** With a budget: defaults to HEAVY_READ_IDLE_HOLD_MS. */
  idleHoldMs?: number;
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
  /** Estimated bytes it needs (0 without a budget). */
  need: number;
}

export class HeavyReadGate {
  private running = 0;
  private reserved = 0;
  /** When the queue's head started waiting for memory (0 when it is not). */
  private heldSince = 0;
  /** When a read was first refused with nothing running (0 when none is); cleared when any starts. */
  private idleRefusedAt = 0;
  /** Running reads of unknown size: nothing runs beside them. */
  private alone = 0;
  private recheck: NodeJS.Timeout | null = null;
  private readonly queue: Waiter[] = [];
  private readonly limits: Required<HeavyReadLimits>;

  constructor(
    limits: HeavyReadLimits = DEFAULT_LIMITS,
    private readonly budget?: HeavyReadBudget,
  ) {
    const { concurrency, queueLimit, retryAfterSeconds } = limits;
    const abandonedMaxHoldMs = limits.abandonedMaxHoldMs ?? HEAVY_READ_ABANDONED_MAX_HOLD_MS;
    const idleHoldMs = limits.idleHoldMs ?? HEAVY_READ_IDLE_HOLD_MS;
    if (!Number.isInteger(concurrency) || concurrency < 1)
      throw new Error(`heavy read concurrency must be a positive integer, got ${concurrency}`);
    if (!Number.isInteger(queueLimit) || queueLimit < 0)
      throw new Error(`heavy read queue limit must be a non-negative integer, got ${queueLimit}`);
    if (!(retryAfterSeconds > 0)) throw new Error(`retry-after must be positive, got ${retryAfterSeconds}`);
    if (!(abandonedMaxHoldMs > 0))
      throw new Error(`abandoned max hold must be positive, got ${abandonedMaxHoldMs}`);
    if (!(idleHoldMs >= 0)) throw new Error(`idle hold must be non-negative, got ${idleHoldMs}`);
    this.limits = { concurrency, queueLimit, retryAfterSeconds, abandonedMaxHoldMs, idleHoldMs };
  }

  /** Requests running now. */
  get active(): number {
    return this.running;
  }

  /** Requests waiting for a slot. */
  get waiting(): number {
    return this.queue.length;
  }

  /** Estimated bytes the running reads hold. */
  get reservedBytes(): number {
    return this.reserved;
  }

  /** Admit a heavy read of `caseId`; with a budget its memory estimate is read first. */
  admit(res: Response, next: NextFunction, caseId?: string): void {
    if (!this.budget || !caseId) return this.enter(res, next, 0);
    this.budget.estimate(caseId).then(
      (need) => this.enter(res, next, need),
      () => this.enter(res, next, Number.POSITIVE_INFINITY), // unknown size: it runs alone
    );
  }

  /** Whether a read needing `need` may start now. */
  private canStart(need: number): boolean {
    if (!this.budget) return this.running < this.limits.concurrency;
    if (this.running === 0) {
      // An unknown size (the count failed) has no estimate to wait for: it starts, and runs alone.
      if (!Number.isFinite(need) || this.budget.fits(need, 0)) return true;
      // Nothing running and still no room: the memory is held by garbage the runtime has not handed
      // back yet, by an import, or by other programs. Wait for it, at most HEAVY_READ_IDLE_HOLD_MS:
      // then one read starts anyway, so a case too large for the machine opens slowly, never not at
      // all. The hold is the gate's, not the read's: it starts when a read is first refused with
      // nothing running, so a read that waited behind others still waits the full hold for memory.
      if (this.idleRefusedAt === 0) this.idleRefusedAt = Date.now();
      return Date.now() - this.idleRefusedAt >= this.limits.idleHoldMs;
    }
    if (this.alone > 0 || !Number.isFinite(need)) return false;
    return this.running < this.limits.concurrency && this.budget.fits(need, this.reserved);
  }

  /**
   * The session log for memory waits (#2846): one line when a read first waits for memory, one when
   * the queue has drained, and one whenever a read starts without room after the idle hold. Not one
   * per read.
   */
  private noteHeld(held: boolean, head?: Waiter): void {
    if (held === this.heldSince > 0) return;
    if (held) {
      this.heldSince = Date.now();
      const each =
        head && Number.isFinite(head.need) ? ` (about ${(head.need / 1024 ** 3).toFixed(1)} GB each)` : "";
      logLine(
        `[heavy-read] short of memory: case reads wait for memory${each}; ${this.running} running, ${this.queue.length} queued`,
      );
      return;
    }
    const waited = Math.round((Date.now() - this.heldSince) / 1000);
    this.heldSince = 0;
    logLine(`[heavy-read] memory wait over after ${waited}s`);
  }

  private enter(res: Response, next: NextFunction, need: number): void {
    const signal = requestAbortSignal(res);
    if (signal.aborted) return; // the client is already gone: nothing to answer
    if (this.queue.length === 0 && this.canStart(need)) return this.start(res, next, need);
    if (this.queue.length >= this.limits.queueLimit) return this.refuse(res);
    const waiter: Waiter = { start: () => this.start(res, next, need), signal, need };
    this.queue.push(waiter);
    this.scheduleRecheck();
    signal.addEventListener(
      "abort",
      () => {
        const at = this.queue.indexOf(waiter);
        if (at >= 0) this.queue.splice(at, 1); // its handler never runs
      },
      { once: true },
    );
  }

  private start(res: Response, next: NextFunction, need: number): void {
    const unknown = !Number.isFinite(need);
    const held = unknown ? 0 : need;
    this.idleRefusedAt = 0;
    this.running++;
    this.reserved += held;
    if (unknown) this.alone++;
    const work = new WorkTracker();
    let released = false;
    const release = (): void => {
      if (released) return;
      released = true;
      this.running--;
      this.reserved -= held;
      if (unknown) this.alone--;
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

  /** Start waiters in arrival order while the head fits; a head that does not fit holds the rest. */
  private drain(): void {
    for (;;) {
      const head = this.queue[0];
      if (!head) break;
      if (head.signal.aborted) {
        this.queue.shift();
        continue;
      }
      if (!this.canStart(head.need)) {
        if (this.budget && this.running < this.limits.concurrency) this.noteHeld(true, head);
        return this.scheduleRecheck();
      }
      this.queue.shift();
      if (this.budget && this.running === 0 && this.idleRefusedAt > 0 && !this.fitsAlone(head)) {
        const waited = Math.round((Date.now() - this.idleRefusedAt) / 1000);
        logLine(`[heavy-read] starting a case read without enough free memory after waiting ${waited}s`);
      }
      head.start();
    }
    if (this.heldSince > 0) this.noteHeld(false); // the queue is empty
  }

  private fitsAlone(head: Waiter): boolean {
    return !Number.isFinite(head.need) || !this.budget || this.budget.fits(head.need, 0);
  }

  /** Memory frees as GC runs, which no event announces: a head held back by the budget looks again. */
  private scheduleRecheck(): void {
    if (!this.budget || this.recheck || this.queue.length === 0) return;
    if (this.running >= this.limits.concurrency) return; // a finishing read drains it
    this.recheck = setTimeout(() => {
      this.recheck = null;
      this.drain();
    }, HEAVY_READ_BUDGET_RECHECK_MS);
    this.recheck.unref();
  }

  private refuse(res: Response): void {
    const seconds = this.limits.retryAfterSeconds;
    res.setHeader("Retry-After", String(seconds));
    res.setHeader(SERVER_BUSY_HEADER, "1");
    res.status(503).json({ error: SERVER_BUSY_ERROR, retryAfterMs: seconds * 1000 });
  }
}

export function mountHeavyReadGate(
  app: Express,
  gate: HeavyReadGate = new HeavyReadGate(),
  coalescer?: HeavyReadCoalescer,
): void {
  app.use("/cases/:id", function heavyReadGate(req: Request, res: Response, next: NextFunction) {
    if (req.method !== "GET" && req.method !== "HEAD") return next();
    const path = relPathOf(req);
    if (!HEAVY_READ_PATHS.has(path)) return next();
    const admit = (start: NextFunction): void => gate.admit(res, start, req.params.id);
    if (!coalescer) return admit(next);
    coalescer.handle(req, res, path, next, admit);
  });
}
