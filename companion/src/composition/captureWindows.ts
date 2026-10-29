/**
 * The live screenshot window, failed-window recovery, and the one "what is still owed" re-derivation
 * that backfill and recovery share (#2248). Split out of captureAnalysis.ts, which keeps synthesis.
 *
 * WHY FLUSH AND RECOVERY ARE SERIALIZED PER CASE. Recovery re-derives the owed captures from
 * captures.jsonl minus the live buffer. A flush that had already taken its buffer and was still
 * running would otherwise be analyzed twice. A queued flush takes its buffer when it starts.
 *
 * The watermark rule itself (the hold, the cap, the backoff) is in captureRecovery.ts.
 */
import { join } from "node:path";
import { readFile, rm } from "node:fs/promises";
import { warnLine } from "../logging/serverLogger.js";
import { atomicWrite } from "../storage/atomicWrite.js";
import type { CaseStore } from "../storage/caseStore.js";
import type { AppOptions } from "./appOptions.js";
import type { AiControl } from "../analysis/aiControl.js";
import type { CaptureMetadata } from "../types.js";
import { runInCaseScope } from "../storage/caseIncarnation.js";
import { CaseKeyedMap, CaseKeyedSet } from "../storage/caseKeyedState.js";
import {
  afterWindowFailure,
  afterWindowSuccess,
  parseCaptureLog,
  pendingCaptures,
  recoveryDue,
  recoveryPolicy,
  releaseHold,
} from "./captureRecovery.js";

export interface CaptureWindowsDeps {
  store: CaseStore;
  options: AppOptions;
  hasAiProvider: () => boolean;
  getControl: (caseId: string) => Promise<AiControl>;
  setControl: (caseId: string, patch: Partial<AiControl>) => Promise<AiControl>;
  recordAiError: (caseId: string, phase: string, err: unknown) => void;
  captureBuffers: CaseKeyedMap<CaptureMetadata[]>;
  windowSize: number;
  scheduleSynthesis: (caseId: string) => void;
}

// "stopped": AI was paused (or the vision model removed) between windows (#2250).
export type OwedOutcome = "no-log" | "none" | "done" | "stopped";

/**
 * Why an owed-capture pass runs. "recovery" retries a held window and counts against its cap;
 * "backfill" is the analyst's AI off→on; "restart" picks up what a restart stranded (#2249) and
 * retries a held window only when recovery would have.
 */
export type OwedMode = "backfill" | "recovery" | "restart";

export interface CaptureWindows {
  flush(caseId: string): Promise<void>;
  recover(caseId: string): Promise<void>;
  /** After a restart (#2249): analyze what the case still owes, if AI is on. */
  resume(caseId: string): Promise<void>;
  /** Analyze everything the case owes, queued behind its flush/recovery so they never overlap (#2250). */
  analyzeOwedExclusive(caseId: string, mode: OwedMode): Promise<OwedOutcome>;
  /** Cases holding a failed window, for the safety-net sweep. */
  readonly heldCases: CaseKeyedSet;
}

export function createCaptureWindows(deps: CaptureWindowsDeps): CaptureWindows {
  const {
    store,
    options,
    hasAiProvider,
    getControl,
    setControl,
    recordAiError,
    captureBuffers,
    windowSize,
    scheduleSynthesis,
  } = deps;
  // Cases holding a failed window. In memory only — the hold itself is in the AI control.
  const heldCases = new CaseKeyedSet(() => store.casesRoot);
  const policy = recoveryPolicy(options.captureRecovery);
  // #2248: flush and recovery run one at a time per case. Recovery re-derives "what is owed" from
  // the log minus the live buffer, so a flush that had already taken its buffer and was still
  // running would otherwise be analyzed twice. A queued flush takes its buffer when it starts.
  const caseQueues = new CaseKeyedMap<Promise<void>>(() => store.casesRoot);
  function serialized<T>(caseId: string, fn: () => Promise<T>): Promise<T> {
    const run = (caseQueues.get(caseId) ?? Promise.resolve()).then(fn);
    const tail = run.then(
      () => {},
      () => {},
    );
    caseQueues.set(caseId, tail);
    void tail.then(() => {
      if (caseQueues.get(caseId) === tail) caseQueues.delete(caseId);
    });
    return run;
  }

  // The pending_analysis.json failure marker the diagnostics report counts. Shared by the live
  // window (flush), the AI off→on catch-up (backfill) and recovery — #2179: backfill used to write
  // none. #2152: atomic (never torn JSON) and best-effort — it never throws, so a failed marker
  // write cannot swallow the caller's error status. No `pending` list: the owed captures are
  // re-derived from captures.jsonl and the hold in the AI control (#2248), which also keeps this
  // marker in place until they are analyzed.
  async function recordFailureMarker(caseId: string, err: unknown, control?: AiControl): Promise<void> {
    const markerPath = join(store.stateDir(caseId), "pending_analysis.json");
    const hold = control?.analysisHold;
    const marker = JSON.stringify(
      {
        error: (err as Error).message,
        at: new Date().toISOString(),
        ...(hold ? { heldScreenshots: hold.failedSeqs.length, retriesGivenUp: hold.gaveUp === true } : {}),
      },
      null,
      2,
    );
    try {
      await atomicWrite(markerPath, marker); // carries the #1855 case guard itself
    } catch (writeErr) {
      warnLine(
        `[capture-analysis] ${caseId}: could not record failure marker: ${(writeErr as Error).message}`,
      );
    }
  }

  function flush(caseId: string): Promise<void> {
    return runInCaseScope(store.casesRoot, caseId, () => flushInScope(caseId));
  }

  function flushInScope(caseId: string): Promise<void> {
    return serialized(caseId, () => flushNow(caseId));
  }

  async function flushNow(caseId: string): Promise<void> {
    const buf = captureBuffers.get(caseId) ?? [];
    if (buf.length === 0 || !options.pipeline || !hasAiProvider()) return;
    captureBuffers.set(caseId, []);
    options.onAiStatus?.(caseId, {
      status: "analyzing",
      phase: "extracting",
      at: new Date().toISOString(),
      detail: `${buf.length} screenshot(s)`,
    });
    // #2248: the buffer is NOT put back on failure — a permanent error would resend a batch that
    // grows with every capture. The failed captures are held instead and recovered from the log.
    const seqs = buf.filter((c) => !c.isDuplicate).map((c) => c.sequenceNumber);
    try {
      await options.pipeline.analyzeWindow(caseId, buf);
      if (seqs.length > 0) await windowAnalyzed(caseId, seqs);
      await clearMarkerUnlessHeld(caseId);
      options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() });
      scheduleSynthesis(caseId); // live findings/attacker path
    } catch (err) {
      await windowFailed(caseId, seqs, err, false);
    }
  }

  /** Move the watermark for an analyzed window — never past a held failure (#2248). */
  async function windowAnalyzed(caseId: string, seqs: number[]): Promise<void> {
    const patch = afterWindowSuccess(await getControl(caseId), seqs);
    if (Object.keys(patch).length > 0) await setControl(caseId, patch);
  }

  /** Release a hold whose captures are all dealt with, then drop the marker if nothing is owed. */
  async function settleHold(caseId: string): Promise<void> {
    const patch = releaseHold(await getControl(caseId));
    if (Object.keys(patch).length > 0) await setControl(caseId, patch);
    await clearMarkerUnlessHeld(caseId);
  }

  /**
   * Hold a failed window's captures, then report the failure (#2248). The hold write is
   * best-effort like the marker: neither may swallow the error status the analyst sees.
   */
  async function windowFailed(
    caseId: string,
    seqs: number[],
    err: unknown,
    recovery: boolean,
  ): Promise<void> {
    recordAiError(caseId, "extracting", err);
    let control: AiControl | undefined;
    try {
      const cur = await getControl(caseId);
      control = seqs.length
        ? await setControl(caseId, afterWindowFailure(cur, seqs, (err as Error).message, recovery, policy))
        : cur;
      if (control.analysisHold) heldCases.add(caseId);
    } catch (holdErr) {
      warnLine(
        `[capture-analysis] ${caseId}: could not hold the failed window: ${(holdErr as Error).message}`,
      );
    }
    await recordFailureMarker(caseId, err, control);
    options.onAiStatus?.(caseId, {
      status: "error",
      at: new Date().toISOString(),
      detail: (err as Error).message,
    });
  }

  /** Drop the failure marker once nothing is owed any more; a held window keeps it (#2248). */
  async function clearMarkerUnlessHeld(caseId: string): Promise<void> {
    if ((await getControl(caseId)).analysisHold) return;
    heldCases.delete(caseId);
    const markerPath = join(store.stateDir(caseId), "pending_analysis.json");
    await store.withCaseWrite(markerPath, () => rm(markerPath, { force: true })); // #1855
  }

  /**
   * Analyze every capture still owed, re-derived from captures.jsonl (#2248): the backlog captured
   * while AI was off, a failed window's held captures, and anything newer than the last analyzed
   * window that is not in the live buffer. Shared by backfill and recovery so the two can never
   * disagree on what "owed" means. Emits its own terminal status once it has started analyzing.
   */
  async function analyzeOwed(caseId: string, mode: OwedMode): Promise<OwedOutcome> {
    const control = await getControl(caseId);
    // A restart pass leaves a held window alone unless its backoff has run out and it has tries
    // left — the cap must hold across restarts. When it does include it, it counts as an attempt.
    const includeHeld = mode !== "restart" || recoveryDue(control);
    const recovery =
      mode === "recovery" || (mode === "restart" && Boolean(control.analysisHold) && includeHeld);
    let log: string;
    try {
      log = await readFile(store.capturesLogPath(caseId), "utf8");
    } catch (err) {
      // ENOENT alone means "no capture log" (an import-only case). Any other read failure
      // (EACCES, EIO, …) degrades the same way — synthesis still runs — but must be SAID:
      // silently equating the two is how a whole screenshot backlog went missing without a trace.
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
        warnLine(`[backfill] ${caseId}: cannot read captures.jsonl: ${(err as Error).message}`);
      }
      return "no-log";
    }
    // Per line, skipping only a malformed line: captures.jsonl is appendFile-written, so a crash
    // or ENOSPC mid-append can truncate exactly one line, and it must not sink the whole backlog.
    const { captures, skipped } = parseCaptureLog(log);
    if (skipped > 0) warnLine(`[backfill] ${caseId}: skipped ${skipped} malformed captures.jsonl line(s)`);
    const inBuffer = new Set((captureBuffers.get(caseId) ?? []).map((c) => c.sequenceNumber));
    const pending = pendingCaptures(captures, control, inBuffer, !includeHeld);
    if (pending.length === 0) {
      // A held capture missing from the log can never be analyzed — unless it was left out above.
      if (includeHeld) await settleHold(caseId);
      return "none";
    }
    options.onAiStatus?.(caseId, {
      status: "analyzing",
      phase: "extracting",
      at: new Date().toISOString(),
      detail: recovery
        ? `retrying ${pending.length} screenshot(s) from a failed analysis`
        : `catching up on ${pending.length} screenshot(s)`,
    });
    for (let i = 0; i < pending.length; i += windowSize) {
      const seqs = pending.slice(i, i + windowSize).map((c) => c.sequenceNumber);
      // #2250: pausing AI must stop the next paid call. The rest stays owed above the watermark.
      if (i > 0 && !((await getControl(caseId)).enabled && hasAiProvider())) {
        options.onAiStatus?.(caseId, {
          status: "idle",
          at: new Date().toISOString(),
          detail: `AI paused — ${pending.length - i} screenshot(s) left for the next catch-up`,
        });
        return "stopped";
      }
      try {
        await options.pipeline!.analyzeWindow(caseId, pending.slice(i, i + windowSize));
      } catch (err) {
        await windowFailed(caseId, seqs, err, recovery);
        return "done";
      }
      await windowAnalyzed(caseId, seqs);
    }
    if (includeHeld) await settleHold(caseId);
    options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() });
    scheduleSynthesis(caseId);
    return "done";
  }

  function recover(caseId: string): Promise<void> {
    return runInCaseScope(store.casesRoot, caseId, () => recoverInScope(caseId));
  }

  async function recoverInScope(caseId: string): Promise<void> {
    if (!options.pipeline || !hasAiProvider()) return;
    const control = await getControl(caseId);
    if (!control.enabled || !recoveryDue(control)) return;
    await serialized(caseId, async () => {
      // Re-checked in the queue: a flush ahead of this one may have changed the hold.
      if (!recoveryDue(await getControl(caseId))) return;
      try {
        await analyzeOwed(caseId, "recovery");
      } catch (err) {
        await windowFailed(caseId, [], err, true);
      }
    });
  }

  function resume(caseId: string): Promise<void> {
    return runInCaseScope(store.casesRoot, caseId, () => resumeInScope(caseId));
  }

  /**
   * #2249: the live buffer is memory only, so a restart strands the captures it held. Re-derive
   * them from the log through the same path as recovery, and re-register a held case so later
   * sweeps keep recovering it — the in-memory set of held cases is empty after a restart too.
   */
  async function resumeInScope(caseId: string): Promise<void> {
    if (!options.pipeline || !hasAiProvider()) return;
    const control = await getControl(caseId);
    if (!control.enabled) return;
    if (control.analysisHold) heldCases.add(caseId);
    await serialized(caseId, async () => {
      try {
        await analyzeOwed(caseId, "restart");
      } catch (err) {
        await windowFailed(caseId, [], err, false);
      }
    });
  }

  return {
    flush,
    recover,
    resume,
    analyzeOwedExclusive: (caseId, mode) => serialized(caseId, () => analyzeOwed(caseId, mode)),
    heldCases,
  };
}
