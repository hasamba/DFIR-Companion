/**
 * The AI analysis loop over screenshot captures, and the debounced synthesis that follows it.
 * Lifted out of createApp by #416.
 *
 * Four entry points, all reaching the same pipeline:
 *   captureBuffers  the per-case window of un-analyzed captures the /captures route appends to
 *   flush           analyze one window now (a full window, a navigation, or the safety-net sweep)
 *   backfill        catch up everything captured while AI was off, when it is switched back on
 *   scheduleSynthesis / resynthesizeInBackground   re-derive findings once evidence has landed
 *
 * TWO GATES THAT LOOK ALIKE AND ARE NOT. `hasAiProvider()` asks about the VISION model, which is
 * what analyzeWindow needs; `pipeline.hasSynthesisProvider()` asks about the TEXT model, which is
 * what synthesize needs. Gating synthesis on the first would break an OCR-less install that only
 * sets DFIR_AI_SYNTH_PROVIDER — it imports evidence fine and would then never synthesize it.
 *
 * EVERY EXIT PATH IN `backfill` EMITS A TERMINAL STATUS. The dashboard optimistically renders
 * "AI on — catching up on un-analyzed screenshots…" the instant the toggle flips, and that text is
 * not a live progress indicator. A path that returns without a terminal status leaves it on screen
 * forever — a real bug report ("this message is stuck, I don't know if it finished"), which is why
 * the early returns below all route through `idle()` or `catchUpSynthesis()`.
 */
import { join } from "node:path";
import { writeFile, readFile, rm } from "node:fs/promises";
import type { CaseStore } from "../storage/caseStore.js";
import type { AppOptions } from "./appOptions.js";
import type { AiControl } from "../analysis/aiControl.js";
import type { CaptureMetadata } from "../types.js";
import type { NotificationEvent } from "../analysis/notifications.js";
import { milestoneEvent } from "../analysis/notifications.js";
import { loadPendingHostDuplicates } from "../analysis/hostScopeLoad.js";
import { isAnalystDecisionGate } from "../routes/presidioApproval.js";

export interface CaptureAnalysisDeps {
  store: CaseStore;
  options: AppOptions;
  /** Is a VISION model configured — i.e. can analyzeWindow run at all. */
  hasAiProvider: () => boolean;
  getControl: (caseId: string) => Promise<AiControl>;
  setControl: (caseId: string, patch: Partial<AiControl>) => Promise<AiControl>;
  recordAiError: (caseId: string, phase: string, err: unknown) => void;
  /** Enrich any IOCs a synthesis run just produced, when the case has enrichment on. */
  autoEnrichIfEnabled: (caseId: string) => void;
  /** Fire a notification event (best-effort, fire-and-forget). See composition/caseNotifier.ts. */
  dispatchNotify: (event: NotificationEvent) => void;
}

export interface CaptureAnalysis {
  /** Per-case window of captures awaiting analysis. The /captures route appends to it in place. */
  readonly captureBuffers: Map<string, CaptureMetadata[]>;
  /** Cases whose auto-synthesis is running right now (read by the synth-meta route). */
  readonly synthInFlight: Set<string>;
  /** How many captures make a full window. */
  readonly windowSize: number;
  flush(caseId: string): Promise<void>;
  backfill(caseId: string): Promise<void>;
  /** Debounced auto-synthesis after captures/imports land. No-op unless autoSynthesize is on. */
  scheduleSynthesis(caseId: string): void;
  /**
   * Immediate background re-synthesis after an import or a false-positive change. Self-coalescing:
   * a newer kick supersedes an older one for the same case, so N rapid changes (a multi-file
   * import, a batch false-positive) cost one synthesis, not N.
   */
  resynthesizeInBackground(caseId: string): void;
}

export function createCaptureAnalysis(deps: CaptureAnalysisDeps): CaptureAnalysis {
  const {
    store,
    options,
    hasAiProvider,
    getControl,
    setControl,
    recordAiError,
    autoEnrichIfEnabled,
    dispatchNotify,
  } = deps;
  const windowSize = options.windowSize ?? 4;
  const captureBuffers = new Map<string, CaptureMetadata[]>();

  // Debounced live synthesis: after capture windows are analyzed, re-derive the
  // findings / MITRE / attacker path so the dashboard updates as you browse.
  const autoSynth = options.autoSynthesize ?? false;
  const synthDebounceMs = options.autoSynthesizeDebounceMs ?? 8000;
  const synthTimers = new Map<string, ReturnType<typeof setTimeout>>();
  const synthInFlight = new Set<string>();

  /**
   * What both synthesis paths in this file do when the run rejects.
   *
   * ONE FUNCTION BECAUSE THERE ARE TWO CALLERS AND THEY MUST NOT DIVERGE. They were separate
   * near-identical catch blocks, and the first attempt at the gate fix changed only one of them —
   * so the debounced live-synthesis path kept reporting a held run as a crash while the unit tests,
   * which only drove the other path, stayed green.
   *
   * A GATE IS NOT A FAILURE. `HostMergeDecisionRequired` is thrown before any prompt is built, so
   * the run never started: it is cancelled rather than failed (a `failed` job is what put "synthesis
   * failed" in the cockpit), it is not written to the AI-error ledger (it is not an AI error), and
   * it reports "blocked" so the header pill says "on hold" instead of turning red.
   *
   * @param errorPhase  when set, a genuine failure is recorded against this phase; a gate never is.
   */
  async function settleSynthesisRejection(
    caseId: string,
    job: { jobId: string; signal?: AbortSignal } | undefined,
    err: unknown,
    errorPhase?: string,
  ): Promise<void> {
    const aborted = job?.signal?.aborted === true;
    const held = isAnalystDecisionGate(err);
    if (job) {
      if (held) await options.jobManager?.cancel(job.jobId);
      else await options.jobManager?.fail(job.jobId, err); // no-op if already cancelled
    }
    if (!held && errorPhase) recordAiError(caseId, errorPhase, err);
    if (held) {
      // Reported even when a newer run is queued, unlike the supersede guard below: superseding
      // changes nothing about a gate. The newer run reads the same case and stops at the same
      // unresolved pair, so staying quiet would hide the hold behind a run that cannot clear it.
      options.onAiStatus?.(caseId, {
        status: "blocked",
        at: new Date().toISOString(),
        detail: (err as Error).message,
      });
      return;
    }
    // A newer exclusive registration may have superseded this run — if a synthesis job for this
    // case is still active, that newer run owns the status; don't stomp it to idle.
    if (aborted && options.jobManager?.hasActive(caseId, "synthesis")) return;
    options.onAiStatus?.(
      caseId,
      aborted
        ? { status: "idle", at: new Date().toISOString(), detail: "synthesis cancelled" }
        : { status: "error", at: new Date().toISOString(), detail: (err as Error).message },
    );
  }

  function scheduleSynthesis(caseId: string): void {
    // synthesize() is TEXT work — it runs on the synthesis provider (falling back to the vision
    // provider), so gate on that, not hasAiProvider(): an OCR-less install (only
    // DFIR_AI_SYNTH_PROVIDER set) must still auto-synthesize after imports.
    if (!autoSynth || !options.pipeline || !options.pipeline.hasSynthesisProvider()) return;
    const existing = synthTimers.get(caseId);
    if (existing) clearTimeout(existing);
    synthTimers.set(
      caseId,
      setTimeout(() => {
        synthTimers.delete(caseId);
        if (synthInFlight.has(caseId)) {
          scheduleSynthesis(caseId);
          return;
        } // busy — retry after debounce
        synthInFlight.add(caseId);
        options.onAiStatus?.(caseId, {
          status: "analyzing",
          phase: "synthesizing",
          at: new Date().toISOString(),
          detail: "synthesizing conclusions",
        });
        // #225: this debounced/auto path (live re-synth after captures, and the AI off→on backfill
        // catch-up) previously ran outside the job registry, so it never showed up in the Jobs panel
        // or offered a Cancel button — only the manual "re-synthesize" button did. Track it the same way.
        // exclusive: a manual re-synthesize racing this live run (synthInFlight only serializes
        // auto-vs-auto) supersedes rather than running alongside it.
        const job = options.jobManager?.register({
          caseId,
          kind: "synthesis",
          label: "live synthesis",
          cancellable: true,
          exclusive: true,
        });
        (job?.ready ?? Promise.resolve())
          .then(() => options.pipeline!.synthesize(caseId, job?.signal ? { signal: job.signal } : {}))
          .then(async () => {
            if (job) await options.jobManager?.finish(job.jobId);
            options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() });
            autoEnrichIfEnabled(caseId);
          })
          .catch((err) => settleSynthesisRejection(caseId, job, err, "synthesizing"))
          .finally(() => synthInFlight.delete(caseId));
      }, synthDebounceMs),
    );
  }

  async function flush(caseId: string): Promise<void> {
    const buf = captureBuffers.get(caseId) ?? [];
    if (buf.length === 0 || !options.pipeline || !hasAiProvider()) return;
    captureBuffers.set(caseId, []);
    options.onAiStatus?.(caseId, {
      status: "analyzing",
      phase: "extracting",
      at: new Date().toISOString(),
      detail: `${buf.length} screenshot(s)`,
    });
    try {
      await options.pipeline.analyzeWindow(caseId, buf);
      // Analysis recovered — drop any stale failure marker from a prior window.
      await rm(join(store.stateDir(caseId), "pending_analysis.json"), { force: true });
      const maxSeq = Math.max(...buf.map((c) => c.sequenceNumber));
      const cur = await getControl(caseId);
      if (maxSeq > cur.lastAnalyzedSeq) await setControl(caseId, { lastAnalyzedSeq: maxSeq });
      options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() });
      scheduleSynthesis(caseId); // live findings/attacker path
    } catch (err) {
      recordAiError(caseId, "extracting", err);
      const seqs = buf.map((c) => c.sequenceNumber);
      await writeFile(
        join(store.stateDir(caseId), "pending_analysis.json"),
        JSON.stringify({ pending: seqs, error: (err as Error).message }, null, 2),
        "utf8",
      );
      options.onAiStatus?.(caseId, {
        status: "error",
        at: new Date().toISOString(),
        detail: (err as Error).message,
      });
    }
  }

  // Safety-net periodic flush. A `timer`/`click` capture buffers until `windowSize` accumulates
  // (only a `navigation`/`tab_switch` flushes early), so a single (or sub-window) capture could
  // otherwise sit unanalyzed indefinitely. Every `flushIntervalMs` (default 5 min) drain any
  // non-empty buffer so even one screenshot gets analyzed. `flush` is a no-op on an empty buffer
  // or when AI is unconfigured, and per-case buffers only hold captures for AI-enabled cases
  // (the route gates on `enabled`; pausing clears the buffer). `unref()` so the timer never keeps
  // the process — or a test runner — alive.
  const flushIntervalMs = options.flushIntervalMs ?? 5 * 60_000;
  if (flushIntervalMs > 0 && options.pipeline) {
    const sweep = setInterval(() => {
      for (const [caseId, buf] of captureBuffers) {
        if (buf.length > 0) void flush(caseId);
      }
    }, flushIntervalMs);
    sweep.unref?.();
  }

  // Analyze every non-duplicate capture taken since lastAnalyzedSeq — used when AI
  // is switched back on after capturing with it off. Runs in the background.
  async function backfill(caseId: string): Promise<void> {
    // Fired on an AI off→on transition. EVERY exit path must emit a terminal status — see the
    // file header for why a missing one is a visible bug rather than a cosmetic one.
    const idle = (detail?: string) =>
      options.onAiStatus?.(caseId, {
        status: "idle",
        at: new Date().toISOString(),
        ...(detail ? { detail } : {}),
      });
    // No screenshots to analyze, but evidence IMPORTED while AI was off (deterministic Velociraptor/
    // CSV/… imports populate the timeline without an AI call) still needs synthesis. Trigger it —
    // skip-if-unchanged makes it a no-op when nothing actually changed — so turning AI on analyzes
    // the imported data, not just screenshots. If synthesis can't run, clear the optimistic message.
    const catchUpSynthesis = () => {
      if (autoSynth && options.pipeline && hasAiProvider()) {
        options.onAiStatus?.(caseId, {
          status: "analyzing",
          phase: "synthesizing",
          at: new Date().toISOString(),
          detail: "synthesizing imported evidence",
        });
        scheduleSynthesis(caseId);
      } else {
        idle();
      }
    };
    if (!options.pipeline || !hasAiProvider()) {
      idle("AI on — no AI model configured"); // can't analyze, but clear the optimistic message
      return;
    }
    let control = await getControl(caseId);
    let captures: CaptureMetadata[];
    try {
      const log = await readFile(store.capturesLogPath(caseId), "utf8");
      captures = log
        .split("\n")
        .filter((l) => l.trim().length > 0)
        .map((l) => JSON.parse(l) as CaptureMetadata);
    } catch {
      catchUpSynthesis(); // no capture log (import-only case) → still synthesize imported evidence
      return;
    }
    const pending = captures.filter((c) => !c.isDuplicate && c.sequenceNumber > control.lastAnalyzedSeq);
    if (pending.length === 0) {
      catchUpSynthesis(); // no new screenshots → still synthesize anything imported while off
      return;
    }
    options.onAiStatus?.(caseId, {
      status: "analyzing",
      phase: "extracting",
      at: new Date().toISOString(),
      detail: `catching up on ${pending.length} screenshot(s)`,
    });
    try {
      for (let i = 0; i < pending.length; i += windowSize) {
        const win = pending.slice(i, i + windowSize);
        await options.pipeline.analyzeWindow(caseId, win);
        control = await setControl(caseId, {
          lastAnalyzedSeq: Math.max(...win.map((c) => c.sequenceNumber)),
        });
      }
      await rm(join(store.stateDir(caseId), "pending_analysis.json"), { force: true });
      options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() });
      scheduleSynthesis(caseId);
    } catch (err) {
      options.onAiStatus?.(caseId, {
        status: "error",
        at: new Date().toISOString(),
        detail: (err as Error).message,
      });
    }
  }

  // Tell someone the case is holding on a merge decision. The gate itself lives in synthesize(),
  // but a case with AI disabled never reaches it — and that case still needs the badge raised, so
  // detection runs here too. Fully guarded: notifications are a side channel and must never break
  // an import.
  //
  // NOTE the per-channel `milestone` toggle defaults to FALSE, so on a default configuration this
  // reaches nobody. The dashboard badge is the reliable surface; this is opt-in escalation.
  async function notifyHostDuplicates(caseId: string): Promise<void> {
    try {
      const dismissalStore = options.hostDuplicateDismissalStore;
      if (!dismissalStore || !options.stateStore || !options.assetOverridesStore) return;
      const pending = await loadPendingHostDuplicates(
        {
          state: options.stateStore,
          assetOverrides: options.assetOverridesStore,
          dismissals: dismissalStore,
          ...(options.velociraptorClientStore ? { fleet: options.velociraptorClientStore } : {}),
        },
        caseId,
      );
      if (!pending.length) return;
      dispatchNotify(
        milestoneEvent(
          caseId,
          `Analysis on hold: ${pending.length} possible duplicate host${pending.length === 1 ? "" : "s"}`,
          pending.map((p) => `• ${p.other} and ${p.canonical} may be the same machine`),
          new Date().toISOString(),
        ),
      );
    } catch {
      /* never break an import on a notification */
    }
  }

  function resynthesizeInBackground(caseId: string): void {
    // FIRST, above every early return below. The two guards that follow (no pipeline, no synthesis
    // provider) are exactly the AI-disabled install this notification exists to serve: put this
    // inside the IIFE and the case that can never reach the synthesize() gate also never gets told.
    void notifyHostDuplicates(caseId);
    const pipeline = options.pipeline;
    if (!pipeline) return;
    // Gate text synthesis on its provider (with vision fallback), preserving OCR-less installs.
    if (!pipeline.hasSynthesisProvider()) {
      autoEnrichIfEnabled(caseId);
      return;
    }
    void (async () => {
      // Synthesis is an LLM call — respect the per-case AI toggle, exactly like the /captures
      // path (AI analysis only runs when enabled for the case). With AI off, a deterministic
      // import still populates the forensic timeline + IOCs; it just doesn't trigger LLM
      // synthesis — findings / attacker-path / MITRE wait until AI is turned on and the case is
      // re-synthesized. Enrichment is a separate, independently-gated feature (threat-intel
      // lookups, not an LLM call), so it still runs regardless of the AI toggle.
      if (!(await getControl(caseId)).enabled) {
        autoEnrichIfEnabled(caseId);
        return;
      }
      // #225: track synthesis as a cancellable job so the dashboard can list it + abort a long/stuck run.
      // exclusive, like the two sibling synthesis registrations: EVERY caller of this function is a
      // "the case changed, re-derive it" kick, and synthesize() reads the case fresh, so the newest
      // kick subsumes every older one — running them in series would spend N LLM calls to reach the
      // answer the last one produces on its own. That matters most for a multi-file import, where
      // the dashboard POSTs each file separately and each completed import kicks again: without
      // exclusive, a six-file import stacked six full re-syntheses behind the case's single
      // concurrency slot instead of running one after the last file landed.
      const job = options.jobManager?.register({
        caseId,
        kind: "synthesis",
        label: "re-synthesis",
        cancellable: true,
        exclusive: true,
      });
      try {
        // Inside the try: superseding a still-QUEUED run rejects its admission (never resolving it),
        // and this function is fired-and-forgotten, so a rejection escaping here is an unhandled
        // one rather than a cancellation the catch below can report.
        if (job) await job.ready;
        options.onAiStatus?.(caseId, {
          status: "analyzing",
          phase: "synthesizing",
          at: new Date().toISOString(),
          detail: "re-synthesizing without legitimate items",
        });
        await pipeline.synthesize(caseId, job?.signal ? { signal: job.signal } : {});
        if (job) await options.jobManager?.finish(job.jobId);
        options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() });
        autoEnrichIfEnabled(caseId);
      } catch (err) {
        // No errorPhase: this path never wrote to the AI-error ledger, and adding it here would be
        // a behaviour change unrelated to the gate.
        await settleSynthesisRejection(caseId, job, err);
      }
    })();
  }

  return {
    captureBuffers,
    synthInFlight,
    windowSize,
    flush,
    backfill,
    scheduleSynthesis,
    resynthesizeInBackground,
  };
}
