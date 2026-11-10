import type { Express, Request, Response } from "express";
import { logActivity } from "../analysis/activityLog.js";
import {
  IOC_ATTRIBUTION_LABELS,
  cleanActor,
  cleanAttributionValue,
  isIocAttributionLabel,
} from "../analysis/iocAttribution.js";
import { IocAttributionStore } from "../analysis/iocAttributionStore.js";
import type { RouteContext } from "./context.js";

// The analyst's attribution label on an IOC (#2543 part 1b): attacker / ours / responder / unknown.
// GET lists every label of the case; PUT sets one value's label, or clears it with `label: null`.
// Every change is written to the case activity log with the analyst and the old → new label, like
// the false-positive routes. A label never starts a run and never marks conclusions out of date:
// the AI does not read it (iocAttribution.ts).
//
// Its own module rather than routes/findings.ts because that file sits at its size ledger.
export function registerIocAttributionRoutes(app: Express, ctx: RouteContext): void {
  const { store, options } = ctx;
  const labels = new IocAttributionStore(store);

  app.get("/cases/:id/ioc-attribution", async (req: Request, res: Response) => {
    try {
      return res.status(200).json(await labels.load(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.put("/cases/:id/ioc-attribution", async (req: Request, res: Response) => {
    const value = cleanAttributionValue(req.body?.value);
    if (!value)
      return res.status(400).json({ error: "value is required (one line, at most 2048 characters)" });
    const raw = req.body?.label;
    if (raw !== null && !isIocAttributionLabel(raw))
      return res
        .status(400)
        .json({ error: `label must be one of ${IOC_ATTRIBUTION_LABELS.join(", ")} (or null to clear)` });
    const actor = cleanActor(req.body?.actor);
    try {
      const { map, change } = await labels.set(req.params.id, value, raw, actor || "anonymous");
      if (change.before !== change.after) {
        void logActivity(options.activityLogStore, options.onActivity, req.params.id, {
          category: "triage",
          action: change.after ? "set-ioc-attribution" : "clear-ioc-attribution",
          actor,
          detail: `ioc ${value}: ${change.before ?? "unset"} → ${change.after ?? "unset"}`,
          targetType: "ioc",
          targetId: value,
        });
      }
      return res.status(200).json(map);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
