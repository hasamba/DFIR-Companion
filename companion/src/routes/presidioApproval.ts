import type { Response } from "express";
import { PresidioApprovalRequired } from "../analysis/presidio.js";
import { HostMergeDecisionRequired } from "../analysis/hostDuplicateGate.js";
import type { AiStatusEvent } from "../server.js";

/**
 * What sendPipelineError needs to ALSO broadcast the approval gate over ai_status, for routes
 * that don't already emit that status themselves. Optional: a caller with no case-scoped status
 * emitter to give (e.g. a route with no case id in scope, or a direct unit test of this helper)
 * keeps the original two-argument behaviour — see the two-arg call sites still in this codebase
 * and presidioRoutes.test.ts's direct tests of sendPipelineError.
 */
export interface PipelineErrorContext {
  caseId: string;
  onAiStatus?: (caseId: string, event: AiStatusEvent) => void;
}

/**
 * Is this error a GATE — the pipeline stopping to ask the analyst something — rather than a failure?
 *
 * WHY THIS IS A SHARED PREDICATE AND NOT AN `instanceof` AT EACH CATCH. `pipeline.synthesize()`
 * throws the merge gate, and FIVE call sites catch it, each with its own error handling: the manual
 * /synthesize route, /second-opinion, /deep-pass, the debounced live synthesis, and the post-import
 * background re-synthesis. Every one of them reported the gate as a failed job plus ai_status
 * "error". Fixing them one at a time is how four of the five stay broken while the tests pass — the
 * first version of this change fixed exactly one and looked complete. When a third gate class is
 * added, this function is the only place that has to learn about it.
 *
 * Presidio is in here for the same reason the merge gate is: both stop the run to ask a question,
 * and one helper reporting two different truths for the same kind of event is what made the gate
 * unreadable in the first place.
 */
export function isAnalystDecisionGate(err: unknown): boolean {
  return err instanceof PresidioApprovalRequired || err instanceof HostMergeDecisionRequired;
}

// Routes in this codebase catch their own errors and answer 500 directly, so there is no error
// middleware to hook. This helper is the drop-in replacement for that catch body wherever a
// route can reach an AI call: it distinguishes the approval gate from a genuine failure.
//
// Task 9 review finding: several routes (explain-event, executive-summary, narrative,
// remediation-plan, hypothesis-review, starred-report, view-summary, second-opinion/apply[-all])
// threw PresidioApprovalRequired through this helper with NEITHER a client-side 409 handler NOR an
// ai_status broadcast of their own — so the dashboard's store-driven approval panel (loaded on
// case-connect and re-checked on ai_status:error) never learned the gate had fired. Rather than
// hand-wire each of those call sites, the broadcast lives HERE: any caller that passes a `ctx`
// gets covered automatically, including routes added after this comment. /synthesize and
// /second-opinion (the two-model run, not apply/apply-all) already broadcast their own
// ai_status:error unconditionally before reaching this helper, so they're deliberately left on the
// plain two-argument form — adding ctx there would just double-emit the same event.
export function sendPipelineError(res: Response, err: unknown, ctx?: PipelineErrorContext): Response {
  // BOTH gates broadcast "blocked", not "error". They are the two cases in this helper where the
  // pipeline stopped on purpose to ask the analyst something, and reporting a question as a crash is
  // what sent people hunting for a broken provider instead of the decision waiting for them. A
  // genuine failure below still answers 500 and broadcasts nothing.
  if (err instanceof PresidioApprovalRequired) {
    ctx?.onAiStatus?.(ctx.caseId, { status: "blocked", at: new Date().toISOString(), detail: err.message });
    return res.status(409).json({ error: "presidio_approval_required", findings: err.findings });
  }
  if (err instanceof HostMergeDecisionRequired) {
    ctx?.onAiStatus?.(ctx.caseId, { status: "blocked", at: new Date().toISOString(), detail: err.message });
    return res.status(409).json({ error: "host_merge_decision_required", pairs: err.pairs });
  }
  return res.status(500).json({ error: (err as Error)?.message ?? String(err) });
}
