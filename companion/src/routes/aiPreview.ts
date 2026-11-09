import type { Express, Request, Response } from "express";
import { runAiPreview, type AiPreviewResult } from "../analysis/ai/aiPreviewScope.js";
import { HostMergeDecisionRequired } from "../analysis/hostDuplicateGate.js";
import { ReadOnlyScopeWriteError } from "../storage/readOnlyScope.js";
import { AI_PREVIEW_ACTIONS } from "./aiPreviewActions.js";
import type { RouteContext } from "./context.js";

/**
 * POST /cases/:id/ai-preview — "Preview what the AI will see" (#2491).
 *
 * Body: `{ action, params }`, `action` a key of AI_PREVIEW_ACTIONS. Runs the real action inside an AI
 * preview (analysis/ai/aiPreviewScope.ts): it stops at the AI-call gate, so NOTHING is sent to a
 * provider, nothing is spent and nothing in the case changes. Answers with the first request the
 * action would send — clear text and masked text side by side — and the system prompt, which is sent
 * unmasked.
 *
 * The clear text exists only in this response. Nothing here writes an activity entry, a run record or
 * a job, and nothing logs the prompt: the log line names the action and the outcome only. Team mode:
 * a POST under /cases/:id is the case "write" permission (auth/policy.ts) — the same every AI action
 * needs. Demo mode refuses it with every other POST.
 */
export function registerAiPreviewRoutes(app: Express, ctx: RouteContext): void {
  const { options, store } = ctx;

  app.post("/cases/:id/ai-preview", async (req: Request, res: Response) => {
    if (!options.pipeline || !options.pipeline.hasSynthesisProvider())
      return res
        .status(501)
        .json({ error: "AI provider not configured — there is no AI request to preview" });
    const caseId = req.params.id;
    const key = typeof req.body?.action === "string" ? req.body.action : "";
    const action = Object.hasOwn(AI_PREVIEW_ACTIONS, key) ? AI_PREVIEW_ACTIONS[key] : undefined;
    if (!action) return res.status(400).json({ error: `unknown AI action "${key.slice(0, 60)}"` });
    const rawParams: unknown = req.body?.params;
    const params =
      rawParams && typeof rawParams === "object" && !Array.isArray(rawParams)
        ? (rawParams as Record<string, unknown>)
        : {};
    res.set("Cache-Control", "no-store");
    try {
      if (!(await store.caseExists(caseId)))
        return res.status(404).json({ error: `case ${caseId} does not exist` });
      const prepared = await action.prepare(options.pipeline, options, caseId, params);
      if (typeof prepared === "string") return res.status(400).json({ error: prepared });
      const result = await runAiPreview(prepared);
      ctx.serverLogger.info(`[ai-preview] ${key}: ${result.outcome}`, { caseId });
      return sendResult(res, key, action, result);
    } catch (err) {
      ctx.serverLogger.warn(`[ai-preview] ${key} failed: ${(err as Error).message}`, { caseId });
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}

function sendResult(
  res: Response,
  key: string,
  action: (typeof AI_PREVIEW_ACTIONS)[string],
  result: AiPreviewResult,
): Response {
  const base = { action: key, label: action.label };
  if (result.outcome === "captured")
    return res.status(200).json({
      ...base,
      outcome: "captured",
      call: result.call,
      ...(action.multiRequest ? { multiRequest: action.multiRequest } : {}),
    });
  if (result.outcome === "no-ai-call")
    return res.status(200).json({
      ...base,
      outcome: "no-ai-call",
      message: "This action would not call the AI right now — there is nothing for it to send.",
    });
  return res.status(409).json({ ...base, outcome: "error", error: errorSentence(result.error) });
}

/** What the real action would have stopped on, in a sentence for the analyst. */
function errorSentence(err: unknown): string {
  if (err instanceof HostMergeDecisionRequired)
    return "The real action would stop first and ask you to decide on near-duplicate host names (the merge panel).";
  if (err instanceof ReadOnlyScopeWriteError)
    return (
      "This action has to update the case's storage before it can read it (a pending storage upgrade " +
      "or retention clean-up), and a preview never changes the case. Open the case's timeline or " +
      "super-timeline once so the upkeep runs, then preview again."
    );
  return err instanceof Error ? err.message : String(err);
}
