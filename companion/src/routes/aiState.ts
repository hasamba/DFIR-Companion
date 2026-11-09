import type { Express, Request, Response } from "express";
import { deriveAiState, effectiveOutOfDate, type AiState } from "../analysis/aiState.js";
import { loadPendingHostDuplicates } from "../analysis/hostScopeLoad.js";
import { PresidioPendingStore } from "../analysis/presidioPending.js";
import { AiControlStore, describeAnalysisHold, holdToken } from "../analysis/aiControl.js";
import { logActivityWithWarning } from "../analysis/activityLog.js";
import { frozenCaseRefusal } from "./importCaseGuard.js";
import { SynthMetaStore } from "../analysis/synthMeta.js";
import type { RouteContext } from "./context.js";

/**
 * `GET /cases/:id/ai-state` — what this case's AI is actually doing, derived rather than remembered.
 *
 * The header pill's state used to live only in the pushed `ai_status` stream, with nothing to
 * correct it when an event was wrong, absent, or simply never seen because the page had just
 * loaded. See analysis/aiState.ts for the three bugs that came out of that. This is the endpoint the
 * dashboard reads whenever it needs the truth instead of the latest rumour: on case connect, on
 * websocket reconnect, after a terminal event, and after resolving a gate.
 *
 * Composes stores exactly like routes/cockpit.ts, and reuses loadPendingHostDuplicates so this is
 * not a fourth hand-rolled copy of "load state, alias index, dismissals".
 *
 * `:id` needs no isValidCaseId check: createApp mounts createCaseIdGate() on `/cases/:id`.
 */
export function registerAiStateRoutes(app: Express, ctx: RouteContext): void {
  const { options, store } = ctx;

  /**
   * Each gate's pending list, or empty when its feature is not wired.
   *
   * Fail-quiet per gate rather than for the request as a whole: one unreadable store must not turn
   * the whole answer into a 500, because a 500 here leaves the pill showing whatever stale thing it
   * had — which is the failure mode this endpoint exists to end.
   */
  async function hostDuplicates(caseId: string) {
    const { stateStore, assetOverridesStore, hostDuplicateDismissalStore } = options;
    if (!stateStore || !assetOverridesStore || !hostDuplicateDismissalStore) return [];
    try {
      return await loadPendingHostDuplicates(
        {
          state: stateStore,
          assetOverrides: assetOverridesStore,
          dismissals: hostDuplicateDismissalStore,
          ...(options.velociraptorClientStore ? { fleet: options.velociraptorClientStore } : {}),
          ...(options.superTimelineStore ? { superTimeline: options.superTimelineStore } : {}),
        },
        caseId,
      );
    } catch {
      return [];
    }
  }

  async function presidioPending(caseId: string) {
    try {
      return await new PresidioPendingStore(store).load(caseId);
    } catch {
      return [];
    }
  }

  /**
   * The per-case AI toggle (defaults to enabled on a read failure) and the failed-window hold
   * (#2265), from one read of the control record.
   */
  async function control(caseId: string) {
    try {
      const c = await new AiControlStore(store).load(caseId);
      const detail = describeAnalysisHold(c.analysisHold);
      const hold = c.analysisHold;
      const screenshotHold = detail ? { detail, gaveUp: hold?.gaveUp === true } : null;
      // #2498: what the dashboard needs to offer "skip": how many, why, and which (the token).
      const offer =
        hold && detail
          ? {
              count: hold.failedSeqs.length,
              gaveUp: hold.gaveUp === true,
              token: holdToken(hold),
              ...(hold.lastError ? { lastError: hold.lastError } : {}),
            }
          : null;
      return { enabled: c.enabled, screenshotHold, offer };
    } catch {
      return { enabled: true, screenshotHold: null, offer: null };
    }
  }

  /** #1599: the "conclusions out of date" marker, or null. Fail-quiet like the gates above. */
  async function outOfDate(caseId: string) {
    try {
      const meta = await (options.synthMetaStore ?? new SynthMetaStore(store)).load(caseId);
      return effectiveOutOfDate(meta.outOfDate, meta.lastSynthesizedAt);
    } catch {
      return null;
    }
  }

  app.get("/cases/:id/ai-state", async (req: Request, res: Response) => {
    const caseId = req.params.id;
    try {
      if (!(await store.caseExists(caseId))) {
        return res.status(404).json({ error: `case ${caseId} does not exist` });
      }
      const [dupes, presidio, ctl, stale] = await Promise.all([
        hostDuplicates(caseId),
        presidioPending(caseId),
        control(caseId),
        outOfDate(caseId),
      ]);
      const state: AiState = deriveAiState({
        // Mirrors server.ts's own hasAiProvider: the explicit flag wins, the pipeline answers
        // otherwise. Without this an install that sets aiConfigured directly would derive "off".
        aiConfigured: options.aiConfigured ?? Boolean(options.pipeline?.hasAiProvider()),
        enabled: ctl.enabled,
        screenshotHold: ctl.screenshotHold,
        hostDuplicates: dupes,
        presidioPending: presidio,
        jobs: options.jobManager?.list(caseId) ?? [],
        outOfDate: stale,
      });
      return res.status(200).json({ ...state, screenshotHold: ctl.offer });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  /**
   * #2498: `POST /cases/:id/ai-state/skip-held-screenshots { token }` — the analyst accepts the gap
   * left by screenshots the AI could not analyze. The screenshots stay saved as evidence; they are
   * only no longer owed to the AI, so the red pill clears and nothing retries them. `token` is the
   * one GET ai-state handed out: a hold that changed since then is refused (409), never skipped
   * blind. A closed or archived case is refused by the central case-write gate.
   */
  app.post("/cases/:id/ai-state/skip-held-screenshots", async (req: Request, res: Response) => {
    const caseId = req.params.id;
    const token = (req.body as { token?: unknown } | undefined)?.token;
    if (typeof token !== "string" || !token) return res.status(400).json({ error: "token is required" });
    try {
      if (!(await store.caseExists(caseId))) {
        return res.status(404).json({ error: `case ${caseId} does not exist` });
      }
      const result = await ctx.skipHeldScreenshots(caseId, token);
      if (result.outcome === "stale") {
        return res.status(409).json({
          error: "the screenshots waiting for analysis changed — check them again before skipping",
        });
      }
      if (result.outcome === "frozen") {
        const refusal = await frozenCaseRefusal(store, caseId, "skipping screenshots");
        return res.status(423).json({ error: refusal ?? `Case "${caseId}" is closed` });
      }
      if (result.outcome === "none")
        return res.status(200).json({ skipped: 0, remaining: 0, sequenceNumbers: [] });
      const warning = await logActivityWithWarning(options.activityLogStore, options.onActivity, caseId, {
        category: "ai",
        action: "screenshots-skipped",
        detail: describeSkip(result.skipped, result.remaining.length, result.lastError),
      });
      return res.status(200).json({
        skipped: result.skipped.length,
        remaining: result.remaining.length,
        sequenceNumbers: result.skipped,
        ...(warning ? { warning } : {}),
      });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}

/** The activity-log line for a skip: which captures, why they were owed, and that they are kept. */
function describeSkip(skipped: number[], remaining: number, lastError?: string): string {
  const which = skipped.map((seq) => `#${seq}`).join(", ");
  const reason = lastError ? ` Last error: ${lastError}.` : "";
  const rest = remaining > 0 ? ` ${remaining} screenshot(s) stay queued behind a newer capture.` : "";
  return (
    `Analyst skipped AI analysis of ${skipped.length} screenshot(s) the AI could not analyze ` +
    `(capture ${which}).${reason} The screenshots stay saved as evidence.${rest}`
  );
}
