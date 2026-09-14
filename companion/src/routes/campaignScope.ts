import type { Express, Request, Response } from "express";
import { campaignScope } from "../analysis/campaignScope.js";
import type { RouteContext } from "./context.js";

// Phishing campaign scope (#930 item 2): per message, who was addressed, which mailbox a header
// indicates, and what each host's own rows establish about the attachment's digest. Read-only —
// nothing here contacts a recipient, collects a mailbox or sends an attachment anywhere.
export function registerCampaignScopeRoutes(app: Express, ctx: RouteContext): void {
  const { options } = ctx;
  app.get("/cases/:id/campaign-scope", async (req: Request, res: Response) => {
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    try {
      return res.status(200).json(campaignScope(await options.stateStore.load(req.params.id)));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
