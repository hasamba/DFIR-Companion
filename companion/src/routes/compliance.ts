import type { Express, Request, Response } from "express";
import { mapFindings, loadComplianceMap } from "../analysis/complianceMap.js";
import type { RouteContext } from "./context.js";

/**
 * Compliance mapping domain: regulatory/control-failure projection of a case's confirmed findings
 * against NIST 800-53, PCI-DSS, HIPAA, GDPR, SEC, and ISO 27001 (issue #234). Read-only; derived on
 * demand from the current state — no AI, no Velociraptor required.
 *   - GET /cases/:id/compliance — compliance mapping for confirmed findings.
 */
export function registerComplianceRoutes(app: Express, ctx: RouteContext): void {
  const { options } = ctx;

  app.get("/cases/:id/compliance", async (req: Request, res: Response) => {
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    try {
      const state = await options.stateStore.load(req.params.id);
      const results = mapFindings(state.findings);
      return res.status(200).json({
        caseId: req.params.id,
        source: loadComplianceMap().source,
        results,
      });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}