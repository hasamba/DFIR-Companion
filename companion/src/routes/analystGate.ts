import type { Response } from "express";
import { isAnalystDecisionGate, sendPipelineError } from "./presidioApproval.js";
import { logActivity } from "../analysis/activityLog.js";
// Via RouteContext, NOT `composition/appOptions.js` directly: routes are Delivery and composition is
// above them, so that import is a layer violation the boundary gate rejects (it caught this). Every
// other route reads the same type the same way, through the ctx it is handed.
import type { RouteContext } from "./context.js";

/**
 * What a ROUTE does when its synthesis run rejects.
 *
 * Its own module rather than another block inside routes/aiSynthesis.ts, because that file is on the
 * size ledger — a freeze on files that were already too big (#384), not a budget. The gate handling
 * has to live somewhere; this is somewhere.
 *
 * The background equivalent is `settleSynthesisRejection` in composition/captureAnalysis.ts. The two
 * are deliberately NOT merged: a route also has to answer an HTTP status and the background path has
 * nothing to answer, so a single function would take a nullable `res` and branch on it throughout.
 * Both consult the same `isAnalystDecisionGate` predicate, which is the part that must not diverge.
 */
export interface SynthesisRouteFailureDeps {
  caseId: string;
  options: RouteContext["options"];
  job?: { jobId: string; signal?: AbortSignal };
  /** Activity-log action name, e.g. "synthesis". Omit to skip logging entirely. */
  activityAction?: string;
}

/**
 * Settle a rejected synthesis route: mark the job, broadcast a status, log it, and answer.
 *
 * THE GATE CHECK IS FIRST, ABOVE THE ABORT BRANCH, and that ordering is load-bearing. A gate is a
 * fact about the CASE; supersession is a fact about the RUN. A held run that was also superseded
 * would otherwise take the 499 "cancelled" path and report nothing at all — even though the newer
 * run reads the same case and stops at exactly the same unresolved pair. This is the code behind the
 * "Re-synthesize" button, which is what an analyst presses when they notice analysis is stuck, so a
 * silent or red answer here is the worst possible place for one.
 */
export async function sendSynthesisRouteFailure(
  res: Response,
  err: unknown,
  deps: SynthesisRouteFailureDeps,
): Promise<Response> {
  const { caseId, options, job, activityAction } = deps;
  const message = (err as Error)?.message ?? String(err);
  const note = (detail: string, outcome?: "error") => {
    if (!activityAction) return;
    void logActivity(options.activityLogStore, options.onActivity, caseId, {
      category: "ai",
      action: activityAction,
      detail,
      ...(outcome ? { outcome } : {}),
    });
  };

  if (isAnalystDecisionGate(err)) {
    // cancel, not fail: the gate throws before a prompt is built, so nothing ran to fail. A `failed`
    // job is what put "synthesis failed" in the Now cockpit for a run that never started.
    if (job) await options.jobManager?.cancel(job.jobId);
    options.onAiStatus?.(caseId, { status: "blocked", at: new Date().toISOString(), detail: message });
    note(`synthesis on hold — ${message}`); // no outcome: a hold is not an errored synthesis
    return sendPipelineError(res, err);
  }

  if (job) await options.jobManager?.fail(job.jobId, err); // no-op if a cancel already marked it cancelled
  if (job?.signal?.aborted === true) {
    // A newer exclusive registration may have superseded this run — if a synthesis job for this case
    // is still active, that newer run owns the status; don't stomp it to idle.
    if (!options.jobManager?.hasActive(caseId, "synthesis")) {
      options.onAiStatus?.(caseId, {
        status: "idle",
        at: new Date().toISOString(),
        detail: "synthesis cancelled",
      });
    }
    return res.status(499).json({ error: "synthesis cancelled" });
  }

  options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: message });
  note(message, "error");
  return sendPipelineError(res, err);
}
