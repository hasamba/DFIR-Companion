// Sigma rule → VQL, as a route (#798). Compile only — it never launches anything. Launch stays on
// POST /cases/:id/velociraptor/deploy-hunt, which records the outcome in the hunting profile.
//
// Needs no AI provider and no Velociraptor API: the compile step is offline and deterministic
// (sigmaToVql.ts), so an analyst can paste and review a rule before the API is ever configured.
// A refusal is an answer, not a server error: it comes back 200 with the list the parser and the
// compiler wrote for the analyst. Only text that is not a YAML document at all is a 400.

import type { Express, Request, Response } from "express";
import { z } from "zod";
import { SIGMA_MAX_RULE_BYTES } from "../analysis/sigmaRule.js";
import { compileSigmaText } from "../analysis/sigmaToVql.js";

// Twice the parser's cap, so an over-long rule reaches the parser and comes back with ITS
// sentence ("the rule text is too large…") rather than a bare schema error.
const bodySchema = z.object({
  yaml: z
    .string()
    .min(1)
    .max(SIGMA_MAX_RULE_BYTES * 2),
});

export function registerSigmaCompileRoutes(app: Express): void {
  app.post("/cases/:id/sigma/compile", (req: Request, res: Response) => {
    const body = bodySchema.safeParse(req.body);
    if (!body.success) {
      return res
        .status(400)
        .json({ ok: false, error: "yaml is required: the Sigma rule text, as one string" });
    }
    const result = compileSigmaText(body.data.yaml);
    if (result.ok) return res.status(200).json(result);
    const notYaml = result.refusals.some((r) => r.path === "yaml");
    return res.status(notYaml ? 400 : 200).json(result);
  });
}
