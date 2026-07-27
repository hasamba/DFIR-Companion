import type { Express, Request, Response } from "express";
import { mapFindings, loadComplianceMap } from "../analysis/complianceMap.js";
import type { RouteContext } from "./context.js";

/**
 * Compliance mapping domain: regulatory/control-failure projection of a case's confirmed findings
 * against NIST 800-53, PCI-DSS, HIPAA, GDPR, SEC, and ISO 27001 (issue #234). Read-only; derived on
 * demand from the current state — no AI, no Velociraptor required.
 *   - GET /cases/:id/compliance — compliance mapping for confirmed findings.
 *
 * `:id` needs no isValidCaseId check here: createApp mounts createCaseIdGate() on `/cases/:id`
 * ahead of every route file, so an id that could escape the cases root is rejected with 400 before
 * reaching this handler (see analysis/caseIdGate.ts).
 */
export function registerComplianceRoutes(app: Express, ctx: RouteContext): void {
  const { store, options } = ctx;

  app.get("/cases/:id/compliance", async (req: Request, res: Response) => {
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    try {
      // 404 rather than an empty mapping. StateStore.load answers a missing case with emptyState,
      // so without this a typo'd case id returns `{results: []}` — which on a compliance endpoint
      // reads as "no obligations triggered", the single worst way for this route to fail.
      if (!(await store.caseExists(req.params.id))) {
        return res.status(404).json({ error: `case ${req.params.id} does not exist` });
      }
      const state = await options.stateStore.load(req.params.id);
      const dataset = loadComplianceMap();
      return res.status(200).json({
        caseId: req.params.id,
        source: dataset.source,
        generated: dataset.generated,
        // The "not legal advice" note and the framework editions travel WITH the mapping. A caller
        // cannot render this payload honestly without them, so they are not optional extras on a
        // separate endpoint.
        disclaimer: dataset.note,
        frameworkVersions: dataset.frameworkVersions,
        results: mapFindings(state.findings),
      });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
