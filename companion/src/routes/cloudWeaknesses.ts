import type { Express, Request, Response } from "express";
import { CloudWeaknessStore } from "../analysis/cloudWeaknessStore.js";
import { summarizeWeaknesses } from "../analysis/awsAccountWeaknessSummary.js";
import { cloudWeaknessCsv } from "../reports/cloudWeaknessSection.js";
import type { RouteContext } from "./context.js";

// AWS account weaknesses (#2560), read-only. The list the CloudTrail importer folded into the case
// side file: GET .../cloud-weaknesses for the Cloud Coverage panel, .csv for a spreadsheet. Offline,
// no AI, no timeline or super-timeline read.
export function registerCloudWeaknessRoutes(app: Express, ctx: RouteContext): void {
  const store = new CloudWeaknessStore(ctx.store);

  app.get("/cases/:id/cloud-weaknesses", async (req: Request, res: Response) => {
    try {
      return res.status(200).json(summarizeWeaknesses(await store.load(req.params.id)));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.get("/cases/:id/cloud-weaknesses.csv", async (req: Request, res: Response) => {
    try {
      const csv = cloudWeaknessCsv(summarizeWeaknesses(await store.load(req.params.id)));
      res.type("text/csv; charset=utf-8");
      res.setHeader("Content-Disposition", 'attachment; filename="cloud-weaknesses.csv"');
      res.setHeader("Cache-Control", "private, no-cache");
      return res.send(csv);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
