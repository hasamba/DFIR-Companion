/**
 * The AI-off gate: a case whose AI switch is off refuses every request that would call a model
 * (#2757), with one 409 and `aiOff: true`, before the handler runs and before any provider call.
 *
 * Before this gate only Watson and the AI-dependent imports read the switch. Every manual AI button
 * checked only that a provider was configured, so with the switch off — the default on every new
 * case — synthesize, explain, the executive summary, deep pass, second opinion and the rest still
 * sent case data to the model. Twenty inline checks were the alternative; inline checks are how the
 * gap happened. Which routes count is decided in composition/aiCallRoutes.ts.
 *
 * MOUNTED THIRD among the /cases/:id gates (routeRegistry.ts): after caseWriteExistsGate (a case
 * that was never created is still a 404) and caseWriteGuard (a closed case still answers 423), and
 * before the MCP routes and the AI rate limiter, so a refusal spends no AI-budget slot. A gate only
 * covers what is registered after it.
 *
 * The middleware's NAME and arity are what tests/architecture/routeInventory.test.ts records — hence
 * the named `aiOffGate` below.
 */
import type { Express, Request, Response, NextFunction } from "express";
import type { AiControl } from "../analysis/aiControl.js";
import { isNonCasePath } from "../auth/policy.js";
import { sendAiOff } from "../routes/aiOffRefusal.js";
import { aiOffGateApplies } from "./aiCallRoutes.js";

export function mountAiOffGate(
  app: Express,
  getControl: (caseId: string) => Promise<AiControl>,
  caseExists: (caseId: string) => Promise<boolean> = async () => true,
): void {
  app.use("/cases/:id", function aiOffGate(req: Request, res: Response, next: NextFunction) {
    if (req.method !== "POST") return next();
    if (isNonCasePath(req.baseUrl + req.path)) return next();
    // Folded and trimmed like the rate limiter's key: Express routes case-insensitively and without
    // strict routing, so /SYNTHESIZE/ reaches the same handler as /synthesize.
    const rel =
      req.path
        .replace(/^\/cases\/[^/]+\//, "/")
        .replace(/\/+$/, "")
        .toLowerCase() || "/";
    if (!aiOffGateApplies(req.method, rel, req.body)) return next();

    // An unknown case is not "AI off": let it fall through to the route's own 404 (the
    // /velociraptor family has its exists gate mounted after this one).
    const caseId = req.params.id;
    caseExists(caseId)
      .then((exists) => (exists ? getControl(caseId) : null))
      .then((control) => {
        if (!control || control.enabled) return next();
        sendAiOff(res);
      }, next);
  });
}
