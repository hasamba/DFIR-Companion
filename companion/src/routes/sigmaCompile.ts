// Sigma rule → VQL, as a route (#798). Compile only — it never launches anything. Launch stays on
// POST /cases/:id/velociraptor/deploy-hunt, which records the outcome in the hunting profile.
//
// Needs no AI provider and no Velociraptor API: the compile step is offline and deterministic
// (sigmaToVql.ts), so an analyst can paste and review a rule before the API is ever configured.
// A refusal is an answer, not a server error: it comes back 200 with the list the parser and the
// compiler wrote for the analyst. Only text that is not a YAML document at all is a 400.
//
// Dry-run (#2211) adds "would match N events in this case" over the stored timelines. Read-only and
// analyst-only: it writes nothing to the case and reaches no AI (sigmaDryRun.ts).

import type { Express, Request, Response } from "express";
import { z } from "zod";
import { SIGMA_MAX_RULE_BYTES } from "../analysis/sigmaRule.js";
import { compileSigmaText } from "../analysis/sigmaToVql.js";
import { dryRunSigmaText } from "../analysis/sigmaDryRun.js";
import { SqliteHuntEventSource } from "../analysis/huntQuerySource.js";
import type { HuntDataset } from "../analysis/huntQueryTypes.js";
import type { RouteContext } from "./context.js";

// Twice the parser's cap, so an over-long rule reaches the parser and comes back with ITS
// sentence ("the rule text is too large…") rather than a bare schema error.
const bodySchema = z.object({
  yaml: z
    .string()
    .min(1)
    .max(SIGMA_MAX_RULE_BYTES * 2),
});

const BAD_BODY = "yaml is required: the Sigma rule text, as one string";

export function registerSigmaCompileRoutes(app: Express, ctx: RouteContext): void {
  const { options } = ctx;
  app.post("/cases/:id/sigma/compile", (req: Request, res: Response) => {
    const body = bodySchema.safeParse(req.body);
    if (!body.success) {
      return res.status(400).json({ ok: false, error: BAD_BODY });
    }
    const result = compileSigmaText(body.data.yaml);
    if (result.ok) return res.status(200).json(result);
    const notYaml = result.refusals.some((r) => r.path === "yaml");
    return res.status(notYaml ? 400 : 200).json(result);
  });

  app.post("/cases/:id/sigma/dry-run", async (req: Request, res: Response) => {
    const body = bodySchema.safeParse(req.body);
    if (!body.success) return res.status(400).json({ ok: false, error: BAD_BODY });
    if (!options.stateStore) return res.status(501).json({ error: "indexed state store is not configured" });
    const compiled = compileSigmaText(body.data.yaml);
    if (!compiled.ok && compiled.refusals.some((r) => r.path === "yaml"))
      return res.status(400).json(compiled);
    // Abort the scan when the analyst goes away, as the Hunt Workbench execute route does.
    const controller = new AbortController();
    const abortOnClose = (): void => {
      if (!res.writableEnded) controller.abort();
    };
    req.once("aborted", abortOnClose);
    res.once("close", abortOnClose);
    const datasets: HuntDataset[] = options.superTimelineStore ? ["forensic", "super"] : ["forensic"];
    try {
      const dryRun = await dryRunSigmaText(
        body.data.yaml,
        new SqliteHuntEventSource(options.stateStore, options.superTimelineStore),
        { caseId: req.params.id, datasets, signal: controller.signal },
      );
      return res.status(200).json({ ...compiled, dryRun });
    } catch (error) {
      if (controller.signal.aborted) return undefined;
      return res.status(500).json({ error: (error as Error).message });
    } finally {
      req.off("aborted", abortOnClose);
      res.off("close", abortOnClose);
    }
  });
}
