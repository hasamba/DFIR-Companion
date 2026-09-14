import type { Express, Request, Response } from "express";
import { kerberoastChain } from "../analysis/kerberoastChain.js";
import type { RouteContext } from "./context.js";

// Suspected Kerberoasting → service-account use (#930 item 6). Per service account named by a
// ticket request: the requests, the baseline before the earliest RC4 request, every later row
// where the exact account acts, and the stage the rows reach. Read-only; nothing here says a
// password was cracked.
export function registerKerberoastChainRoutes(app: Express, ctx: RouteContext): void {
  const { options } = ctx;
  app.get("/cases/:id/kerberoast-chain", async (req: Request, res: Response) => {
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    try {
      return res.status(200).json(kerberoastChain(await options.stateStore.load(req.params.id)));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
