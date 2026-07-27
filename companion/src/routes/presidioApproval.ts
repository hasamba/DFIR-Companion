import type { Response } from "express";
import { PresidioApprovalRequired } from "../analysis/presidio.js";
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
  if (err instanceof PresidioApprovalRequired) {
    ctx?.onAiStatus?.(ctx.caseId, { status: "error", at: new Date().toISOString(), detail: err.message });
    return res.status(409).json({ error: "presidio_approval_required", findings: err.findings });
  }
  return res.status(500).json({ error: (err as Error)?.message ?? String(err) });
}
