import type { Express, Request, Response } from "express";
import { applyIncidentTypeToState } from "../analysis/incidentTypes.js";
import type { RouteContext } from "./context.js";

/**
 * Incident-type domain (#236): list/get the built-in + custom incident-type library, and apply a
 * type to a case (auto-configures key questions, next steps, and expected-finding seeds).
 *   - GET  /incident-types               — list every available incident type.
 *   - GET  /incident-types/:id           — a single incident type definition.
 *   - POST /cases/:id/incident-type      — set + apply an incident type to a case.
 *   - GET  /cases/:id/incident-type      — the case's currently chosen incident type.
 *
 * The apply path mutates InvestigationState (keyQuestions, nextSteps) and persists both the new
 * state and the per-case incident-type record — which is also where the synthesis prompt reads the
 * type's hint from. Apply MERGES by default so a re-pick preserves analyst edits; { replace: true }
 * is the "I picked the wrong type" escape hatch and overwrites.
 *
 * `:id` needs no isValidCaseId check: createApp mounts createCaseIdGate() on `/cases/:id`.
 */
export function registerIncidentTypeRoutes(app: Express, ctx: RouteContext): void {
  const { options } = ctx;

  app.get("/incident-types", async (_req: Request, res: Response) => {
    if (!options.incidentTypeStore) return res.status(200).json([]);
    try {
      return res.status(200).json(await options.incidentTypeStore.listAll());
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.get("/incident-types/:id", async (req: Request, res: Response) => {
    if (!options.incidentTypeStore)
      return res.status(404).json({ error: "incident-type store not configured" });
    try {
      const type = await options.incidentTypeStore.get(req.params.id);
      if (!type) return res.status(404).json({ error: `incident type "${req.params.id}" not found` });
      return res.status(200).json(type);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.get("/cases/:id/incident-type", async (req: Request, res: Response) => {
    if (!options.incidentTypeStore)
      return res.status(501).json({ error: "incident-type store not configured" });
    try {
      const record = await options.incidentTypeStore.loadRecord(req.params.id);
      const type = record.typeId ? await options.incidentTypeStore.get(record.typeId) : null;
      return res.status(200).json({ record, type });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/cases/:id/incident-type", async (req: Request, res: Response) => {
    if (!options.incidentTypeStore)
      return res.status(501).json({ error: "incident-type store not configured" });
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    const { typeId } = req.body ?? {};
    if (typeof typeId !== "string" || !typeId.trim()) {
      return res.status(400).json({ error: "typeId is required" });
    }
    const replace = req.body?.replace === true;
    try {
      const type = await options.incidentTypeStore.get(typeId);
      if (!type) return res.status(404).json({ error: `incident type "${typeId}" not found` });
      const state = await options.stateStore.load(req.params.id);
      const {
        state: next,
        questionsAdded,
        nextStepsAdded,
      } = applyIncidentTypeToState(state, type, { replace });
      await options.stateStore.save(next);
      const record = await options.incidentTypeStore.saveRecord(req.params.id, typeId);
      return res.status(200).json({ record, type, questionsAdded, nextStepsAdded });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
