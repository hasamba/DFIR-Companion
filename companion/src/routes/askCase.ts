import type { Express, Request, Response } from "express";
import { logActivity } from "../analysis/activityLog.js";
import { parseAskRequest } from "../analysis/askHistory.js";
import { sendPipelineError } from "./presidioApproval.js";
import type { RouteContext } from "./context.js";

/**
 * Ask the LLM a free-form question about the case ("was data exfiltrated?"). Single-shot, no
 * state change — returns a grounded answer + status + collection guidance (`pointer`), plus how
 * many in-scope events the prompt carried (`usedEvents` / `eventCount`, #1411) so the panel can say
 * when the timeline was trimmed. The body may carry the panel's last few Q&A pairs (`history`);
 * parseAskRequest bounds them.
 *
 * Called from registerAiSynthesisRoutes at the position the route always held, so the express
 * stack order is unchanged (tests/architecture/route-inventory.json pins it).
 */
export function registerAskCaseRoute(app: Express, ctx: RouteContext): void {
  const { options } = ctx;

  app.post("/cases/:id/ask", async (req: Request, res: Response) => {
    if (!options.pipeline || !options.pipeline.hasSynthesisProvider())
      return res.status(501).json({ error: "AI provider not configured for case questions" });
    const { question, history } = parseAskRequest(req.body);
    if (!question) return res.status(400).json({ error: "question is required" });
    try {
      const answer = await options.pipeline.ask(req.params.id, question, { history });
      void logActivity(options.activityLogStore, options.onActivity, req.params.id, {
        category: "ai",
        action: "ask",
        detail: `asked: "${question.slice(0, 120)}"`,
      });
      return res.status(200).json(answer);
    } catch (err) {
      return sendPipelineError(res, err);
    }
  });
}
