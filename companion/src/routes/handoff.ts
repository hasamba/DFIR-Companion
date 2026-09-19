import type { Express, Request, Response } from "express";
import { buildHandoffBrief } from "../analysis/handoffBrief.js";
import { renderHandoffMarkdown } from "../reports/handoffMarkdown.js";
import type { RouteContext } from "./context.js";

/**
 * The shift-handoff brief (#1406): what the case holds, what is open, what to check next, and the
 * outgoing analyst's own note — derived on every call from the case's state and its side stores.
 *   - GET /cases/:id/handoff → { brief, markdown }
 *
 * The note itself is a notebook entry of type `handoff`, written through the existing
 * POST /cases/:id/notebook; nothing here writes. Side stores that are not configured are simply
 * absent from the brief (owners, hypotheses, last import), never an error.
 */
export function registerHandoffRoutes(app: Express, ctx: RouteContext): void {
  const { options } = ctx;
  app.get("/cases/:id/handoff", async (req: Request, res: Response) => {
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    try {
      const caseId = req.params.id;
      const [state, notebook, hypotheses, workflow, importMeta] = await Promise.all([
        options.stateStore.load(caseId),
        options.notebookStore?.load(caseId),
        options.hypothesisStore?.load(caseId),
        options.findingWorkflowStore?.load(caseId),
        options.importMetaStore?.load(caseId),
      ]);
      const brief = buildHandoffBrief(state, {
        ...(notebook ? { notebook } : {}),
        ...(hypotheses ? { hypotheses } : {}),
        ...(workflow ? { workflow } : {}),
        ...(importMeta ? { importMeta } : {}),
      });
      return res.status(200).json({ brief, markdown: renderHandoffMarkdown(brief) });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
