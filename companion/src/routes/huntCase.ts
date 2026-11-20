import type { Express, Request, Response } from "express";
import { isHuntType } from "../analysis/incidentTypes.js";
import { loadHuntFramingFor } from "../analysis/huntFramingLoad.js";
import { huntCoverageFromJobs } from "../analysis/huntFraming.js";
import { loadHuntJobsSafe } from "../analysis/huntFramingLoad.js";
import { hasHighOrCritical, reportItemOf } from "../analysis/huntReport.js";
import { convertedState, convertRefusal, DEFAULT_CONVERT_TYPE_ID } from "../analysis/huntCase.js";
import { logActivity } from "../analysis/activityLog.js";
import type { RouteContext } from "./context.js";

/**
 * Hunt-case routes (#2670):
 *   - GET  /cases/:id/hunt/status              — hunt mode?, coverage, and whether to offer Convert.
 *   - POST /cases/:id/hunt/convert-to-incident — switch a hunt case to incident framing.
 *
 * "Convert to incident" is offered whenever the hunt case holds any High or Critical finding or
 * detection (D6): a deterministic rule that needs no change to the synthesis prompt. The analyst
 * still decides. Conversion keeps all evidence and analyst work and marks the AI conclusions out of
 * date. `:id` needs no isValidCaseId check: createApp mounts the case-id gate on `/cases/:id`.
 */
/** D6 from the overview's findings and a severity-keyed row read — never the whole timeline. */
async function holdsHighOrCritical(
  store: NonNullable<RouteContext["options"]["stateStore"]>,
  caseId: string,
): Promise<boolean> {
  const overview = await store.loadOverview(caseId);
  const high = await store.forensicRowsOutsideSeverities(caseId, ["Info", "Low", "Medium"]);
  return hasHighOrCritical({ findings: overview.findings, forensicTimeline: high.map((r) => r.event) });
}

const CONVERT_REASON = "Converted from a threat hunt to an incident: the conclusions were framed as a hunt";

export function registerHuntCaseRoutes(app: Express, ctx: RouteContext): void {
  const { options } = ctx;

  app.get("/cases/:id/hunt/status", async (req: Request, res: Response) => {
    const caseId = req.params.id;
    if (!options.incidentTypeStore || !options.stateStore)
      return res.status(501).json({ error: "incident-type store not configured" });
    try {
      const record = await options.incidentTypeStore.loadRecord(caseId);
      const type = record.typeId ? await options.incidentTypeStore.get(record.typeId) : null;
      const hunt = isHuntType(type);
      const stores = { incidentTypeStore: options.incidentTypeStore, veloHuntStore: options.veloHuntStore };
      const coverage = hunt ? huntCoverageFromJobs(await loadHuntJobsSafe(stores, caseId)) : null;
      const convertOffered = hunt ? await holdsHighOrCritical(options.stateStore, caseId) : false;
      const rec = hunt ? await options.huntInventoryStore?.load(caseId).catch(() => null) : null;
      return res.status(200).json({
        hunt,
        typeId: record.typeId,
        coverage,
        convertOffered,
        items: (rec?.grades ?? []).map(reportItemOf),
        ...(rec?.baselineVersion !== undefined ? { baselineVersion: rec.baselineVersion } : {}),
        ...(record.convertedFrom
          ? { convertedFrom: record.convertedFrom, convertedAt: record.convertedAt }
          : {}),
      });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/cases/:id/hunt/convert-to-incident", async (req: Request, res: Response) => {
    const caseId = req.params.id;
    const types = options.incidentTypeStore;
    const stateStore = options.stateStore;
    if (!types || !stateStore) return res.status(501).json({ error: "incident-type store not configured" });
    const raw = req.body?.typeId;
    if (raw !== undefined && (typeof raw !== "string" || !raw.trim() || raw.length > 100))
      return res.status(400).json({ error: "typeId must be a non-empty string" });
    const targetId = typeof raw === "string" ? raw.trim() : DEFAULT_CONVERT_TYPE_ID;
    try {
      const record = await types.loadRecord(caseId);
      const current = record.typeId ? await types.get(record.typeId) : null;
      const target = await types.get(targetId);
      const refusal = convertRefusal(current, target);
      if (refusal === "not-hunt") return res.status(409).json({ error: "this case is not a threat hunt" });
      if (refusal) return res.status(400).json({ error: `cannot convert to "${targetId}" (${refusal})` });
      const now = new Date().toISOString();
      const run = ctx.runStateExclusive;
      await run(caseId, async () => {
        const state = await stateStore.load(caseId);
        await stateStore.save(convertedState(state, target!, now));
      });
      const saved = await types.saveRecord(caseId, targetId, now, {
        convertedFrom: record.typeId,
        convertedAt: now,
      });
      await ctx.markConclusionsOutOfDate(caseId, CONVERT_REASON);
      void logActivity(options.activityLogStore, options.onActivity, caseId, {
        category: "hunt",
        action: "hunt-convert-to-incident",
        detail: `Threat hunt converted to incident type "${targetId}"; AI conclusions marked out of date`,
      });
      options.onStateChanged?.(caseId);
      const framing = await loadHuntFramingFor({ incidentTypeStore: types }, caseId);
      return res.status(200).json({ record: saved, type: target, hunt: framing.hunt });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
