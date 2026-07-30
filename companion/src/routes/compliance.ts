import type { Express, Request, Response } from "express";
import { mapFindings, loadComplianceMap } from "../analysis/complianceMap.js";
import { buildComplianceView, availableFrameworks } from "../analysis/complianceView.js";
import type { RouteContext } from "./context.js";

/**
 * Compliance mapping domain: regulatory/control-failure projection of a case's confirmed findings
 * against NIST 800-53, PCI-DSS, HIPAA, GDPR, SEC, and ISO 27001 (issues #234, #336). Read-only
 * mapping; derived on demand from the current state — no AI, no Velociraptor required.
 *   - GET   /cases/:id/compliance         — the mapping, framework-filtered, with deadlines.
 *   - GET   /cases/:id/compliance/control — the analyst's discovery date + framework filter.
 *   - PATCH /cases/:id/compliance/control — set either. Both are analyst inputs the mapping
 *                                           cannot derive: the notification clocks start on a
 *                                           legal determination, not on a forensic timestamp.
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
      const control = options.complianceControlStore
        ? await options.complianceControlStore.load(req.params.id)
        : {};
      const raw = mapFindings(state.findings);
      return res.status(200).json({
        caseId: req.params.id,
        source: dataset.source,
        generated: dataset.generated,
        // The "not legal advice" note and the framework editions travel WITH the mapping. A caller
        // cannot render this payload honestly without them, so they are not optional extras on a
        // separate endpoint.
        disclaimer: dataset.note,
        frameworkVersions: dataset.frameworkVersions,
        // Every framework the UNFILTERED mapping contains, so the filter UI offers the real roster
        // rather than a hardcoded one — and so narrowing the filter cannot hide its own options.
        availableFrameworks: availableFrameworks(raw),
        discoveredAt: control.discoveredAt ?? null,
        frameworks: control.frameworks ?? null,
        results: buildComplianceView(raw, { control }),
      });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.get("/cases/:id/compliance/control", async (req: Request, res: Response) => {
    if (!options.complianceControlStore) {
      return res.status(501).json({ error: "compliance control not configured" });
    }
    try {
      const control = await options.complianceControlStore.load(req.params.id);
      return res.status(200).json({
        discoveredAt: control.discoveredAt ?? null,
        frameworks: control.frameworks ?? null,
      });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.patch("/cases/:id/compliance/control", async (req: Request, res: Response) => {
    if (!options.complianceControlStore) {
      return res.status(501).json({ error: "compliance control not configured" });
    }
    try {
      const body = (req.body ?? {}) as { discoveredAt?: unknown; frameworks?: unknown };
      const patch: { discoveredAt?: string; frameworks?: string[] } = {};

      if ("discoveredAt" in body) {
        const raw = body.discoveredAt;
        // null/"" clears the date, which must switch every countdown off rather than be ignored.
        if (raw === null || raw === "") patch.discoveredAt = undefined;
        else if (typeof raw === "string") {
          if (Number.isNaN(Date.parse(raw))) {
            return res.status(400).json({ error: "discoveredAt must be a parseable date" });
          }
          patch.discoveredAt = raw;
        } else {
          return res.status(400).json({ error: "discoveredAt must be a string or null" });
        }
      }

      if ("frameworks" in body) {
        const raw = body.frameworks;
        // null restores "all frameworks"; an array (even empty) is a deliberate narrowing.
        if (raw === null) patch.frameworks = undefined;
        else if (Array.isArray(raw) && raw.every((f) => typeof f === "string")) {
          patch.frameworks = raw;
        } else {
          return res.status(400).json({ error: "frameworks must be an array of strings or null" });
        }
      }

      const next = await options.complianceControlStore.set(req.params.id, patch);
      return res.status(200).json({
        discoveredAt: next.discoveredAt ?? null,
        frameworks: next.frameworks ?? null,
      });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
