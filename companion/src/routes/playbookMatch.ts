import type { Express, Request, Response } from "express";
import { buildPlaybookMatchResult } from "../analysis/playbookMatch.js";
import { loadKnownPlaybooks } from "../analysis/knownPlaybooksData.js";
import type { RouteContext } from "./context.js";

/**
 * Attack-sequence matching against known ransomware / intrusion playbooks (issue #230).
 *   - GET /cases/:id/playbook-match — top-N ranked playbook matches for the case's chronological
 *     technique sequence, with a per-step matched/missing/out-of-order breakdown.
 *
 * Pure structural move following routes/timeline.ts conventions. Reads the case's forensic
 * timeline through the graduated ctx surface (options.stateStore), the playbooks dataset through
 * the cached loader (knownPlaybooksData.ts), and the pure matcher (playbookMatch.ts). No AI, no
 * network — the catalog is a committed JSON file computed offline.
 */
export function registerPlaybookMatchRoutes(app: Express, ctx: RouteContext): void {
  const { options, store } = ctx;

  app.get("/cases/:id/playbook-match", async (req: Request, res: Response) => {
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    try {
      if (!(await store.caseExists(req.params.id))) {
        return res.status(404).json({ error: `case ${req.params.id} does not exist` });
      }
      const state = await options.stateStore.load(req.params.id);
      const dataset = loadKnownPlaybooks();
      const topN = Math.max(1, Math.floor(Number(req.query.topN) || 3));
      const result = buildPlaybookMatchResult(state.forensicTimeline, dataset, { topN });
      return res.status(200).json(result);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
