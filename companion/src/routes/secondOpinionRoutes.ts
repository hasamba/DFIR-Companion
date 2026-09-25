import type { Express, Request, Response } from "express";
import { logActivity } from "../analysis/activityLog.js";
import { PresidioApprovalRequired } from "../analysis/presidio.js";
import { isAnalystDecisionGate, sendPipelineError } from "./presidioApproval.js";
import type { RouteContext } from "./context.js";
import type { SecondOpinion } from "../analysis/secondOpinion.js";
import type { Finding } from "../analysis/stateTypes.js";
import { freshDeltas, markUnappliedDecisions } from "../analysis/secondOpinionTargets.js";

/**
 * The Second LLM Opinion routes (#116): the two-model run, the saved record, the analyst's
 * accept/reject, and the referee-only re-run (#1587).
 *
 * Moved out of routes/aiSynthesis.ts, whose file-size ledger had one line of headroom left. Called
 * from registerAiSynthesisRoutes at the position these routes always held, so the express stack
 * order is unchanged (tests/architecture/route-inventory.json pins it).
 */
export function registerSecondOpinionRoutes(app: Express, ctx: RouteContext): void {
  const { options } = ctx;

  // #1590 — every record the panel receives marks the accepted decisions that match no finding
  // now, against the case as it is at this moment, so none of them is skipped silently.
  async function marked(caseId: string, record: SecondOpinion | null, findings?: readonly Finding[]) {
    if (!record) return record;
    const current = findings ?? (await options.stateStore?.load(caseId))?.findings;
    return current ? markUnappliedDecisions(record, current) : record;
  }

  // Second LLM opinion (issue #116): run a DIFFERENT model over the same case (independent
  // re-synthesis + reconcile) and surface where it disagrees, for analyst QA. On-demand, two
  // text-only AI calls; NON-DESTRUCTIVE — the deltas are stored, not applied, until the analyst
  // accepts them per item. 501 when no second-opinion model is configured (DFIR_AI_SECOND_OPINION_MODEL).
  app.post("/cases/:id/second-opinion", async (req: Request, res: Response) => {
    if (!options.pipeline || !options.secondOpinionEnabled) {
      return res
        .status(501)
        .json({ error: "second-opinion model not configured — set DFIR_AI_SECOND_OPINION_MODEL" });
    }
    const caseId = req.params.id;
    // Same per-run deep-reasoning toggle (#121) as /synthesize — flows into both model A & B passes.
    const deepReasoning = (req.body as { deepReasoning?: unknown })?.deepReasoning === true;
    options.onAiStatus?.(caseId, {
      status: "analyzing",
      phase: "synthesizing",
      at: new Date().toISOString(),
      detail: deepReasoning ? "running second opinion (deep reasoning)" : "running second opinion",
    });
    try {
      const record = await options.pipeline.secondOpinion(caseId, { deepReasoning });
      options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() });
      options.onSecondOpinion?.(caseId);
      void logActivity(options.activityLogStore, options.onActivity, caseId, {
        category: "ai",
        action: "second-opinion",
        detail: `second opinion ran — ${freshDeltas(record).length} delta(s)${deepReasoning ? " (deep reasoning)" : ""}`,
      });
      return res.status(200).json(await marked(caseId, record));
    } catch (err) {
      // secondOpinion() calls synthesize() twice (secondOpinionRun.ts), so it inherits the merge
      // gate — and a gate is a question, not a failed second opinion.
      options.onAiStatus?.(caseId, {
        status: isAnalystDecisionGate(err) ? "blocked" : "error",
        at: new Date().toISOString(),
        detail: (err as Error).message,
      });
      return sendPipelineError(res, err);
    }
  });

  // Fetch the last second-opinion record for a case (or null). Read-only; no AI.
  app.get("/cases/:id/second-opinion", async (req: Request, res: Response) => {
    if (!options.secondOpinionStore) return res.status(200).json(null);
    try {
      const record = await options.secondOpinionStore.load(req.params.id);
      return res.status(200).json(await marked(req.params.id, record));
    } catch (err) {
      return sendPipelineError(res, err);
    }
  });

  // Accept or reject ONE second-opinion delta. Accept (re-)applies all accepted deltas onto the
  // case (idempotent; durable across re-synthesis); reject only records the decision. The case
  // state is otherwise untouched. Body: { deltaId, accept }.
  app.post("/cases/:id/second-opinion/apply", async (req: Request, res: Response) => {
    if (!options.pipeline || !options.secondOpinionStore)
      return res.status(501).json({ error: "second opinion not configured" });
    const deltaId = typeof req.body?.deltaId === "string" ? req.body.deltaId.trim() : "";
    const accept = req.body?.accept === true;
    if (!deltaId) return res.status(400).json({ error: "deltaId is required" });
    try {
      const { record, state } = await options.pipeline.applySecondOpinion(req.params.id, deltaId, accept);
      options.onSecondOpinion?.(req.params.id);
      void logActivity(options.activityLogStore, options.onActivity, req.params.id, {
        category: "ai",
        action: "second-opinion-apply",
        detail: `delta ${deltaId} — ${accept ? "accepted" : "rejected"}`,
      });
      return res.status(200).json(await marked(req.params.id, record, state.findings));
    } catch (err) {
      if (err instanceof PresidioApprovalRequired)
        return sendPipelineError(res, err, { caseId: req.params.id, onAiStatus: options.onAiStatus });
      const msg = (err as Error).message;
      const code = /unknown second-opinion delta/.test(msg) ? 404 : /no second opinion/.test(msg) ? 409 : 500;
      return res.status(code).json({ error: msg });
    }
  });

  // Bulk accept-all / reject-all over the still-pending second-opinion deltas, in one pass. Body:
  // { accept } or { followReferee: true } (accept_b → accept, keep_a → reject, no call → pending).
  app.post("/cases/:id/second-opinion/apply-all", async (req: Request, res: Response) => {
    if (!options.pipeline || !options.secondOpinionStore)
      return res.status(501).json({ error: "second opinion not configured" });
    const accept = req.body?.followReferee === true ? "referee" : req.body?.accept === true;
    try {
      const { record, state } = await options.pipeline.applyAllSecondOpinion(req.params.id, accept);
      options.onSecondOpinion?.(req.params.id);
      void logActivity(options.activityLogStore, options.onActivity, req.params.id, {
        category: "ai",
        action: "second-opinion-apply-all",
        detail: `all pending deltas — ${accept === "referee" ? "per the referee" : accept ? "accepted" : "rejected"}`,
      });
      return res.status(200).json(await marked(req.params.id, record, state.findings));
    } catch (err) {
      if (err instanceof PresidioApprovalRequired)
        return sendPipelineError(res, err, { caseId: req.params.id, onAiStatus: options.onAiStatus });
      const msg = (err as Error).message;
      const code = /no second opinion/.test(msg) ? 409 : 500;
      return res.status(code).json({ error: msg });
    }
  });

  // Re-run ONLY the referee over a saved second opinion whose referee failed (#1587). No synthesis
  // runs; the saved prompt is replayed. 200 + record on success; 502 + { error, record } when the
  // referee fails again (the record carries the fresh failure for the panel); 409 when there is
  // nothing to re-run or a newer second opinion replaced this one; a gate answers as a gate.
  app.post("/cases/:id/second-opinion/referee", async (req: Request, res: Response) => {
    if (!options.pipeline || !options.secondOpinionStore)
      return res.status(501).json({ error: "second opinion not configured" });
    const caseId = req.params.id;
    try {
      const { record, failed } = await options.pipeline.rerunSecondOpinionReferee(caseId);
      options.onSecondOpinion?.(caseId);
      void logActivity(options.activityLogStore, options.onActivity, caseId, {
        category: "ai",
        action: "second-opinion-referee",
        detail: failed
          ? `referee re-run failed — ${record.refereeError?.message ?? "unknown error"}`
          : `referee re-run — ${record.referee}`,
      });
      if (failed)
        return res.status(502).json({
          error: record.refereeError?.message ?? "referee failed",
          record: await marked(caseId, record),
        });
      return res.status(200).json(await marked(caseId, record));
    } catch (err) {
      if (isAnalystDecisionGate(err))
        return sendPipelineError(res, err, { caseId, onAiStatus: options.onAiStatus });
      const msg = (err as Error).message;
      const code = /no second opinion|did not fail|newer second opinion|no referee|already running/.test(msg)
        ? 409
        : 500;
      return res.status(code).json({ error: msg });
    }
  });
}
