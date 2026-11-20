import type { Express, Request, Response } from "express";
import { z } from "zod";
import type { RouteContext } from "./context.js";
import { huntArtifactLimitsFromEnv } from "../analysis/huntArtifactLimits.js";
import { huntHeldStoreFor } from "../analysis/huntHeldStore.js";

/**
 * Hunt-zip result files held over the size limits (#2746): the list the dashboard shows, and the
 * analyst's Import anyway / Skip. A decision only marks an entry that exists for that exact archive;
 * the next drop sweep acts on it (imports it, or records it as skipped), then the entry goes.
 */

export const MAX_DECISIONS = 1000;

const zipDecision = z.object({
  archiveId: z.string().regex(/^[0-9a-f]{8,64}$/),
  member: z.string().min(1).max(4096),
  decision: z.enum(["import", "skip"]),
});
// A bundle hunt's held artifact (#2753).
const huntDecision = z.object({
  huntId: z.string().regex(/^H\.[A-Za-z0-9]{1,64}$/),
  artifact: z.string().min(1).max(256),
  decision: z.enum(["import", "skip"]),
});

const decideSchema = z.object({
  decisions: z
    .array(z.union([zipDecision, huntDecision]))
    .min(1)
    .max(MAX_DECISIONS),
});

async function caseVisible(ctx: RouteContext, req: Request, res: Response, caseId: string): Promise<boolean> {
  const meta = await ctx.store.getCaseMeta(caseId).catch(() => null);
  const visible = ctx.options.teamAuth?.visibleCaseIds(req);
  if (!meta || (visible && !visible.has(caseId))) {
    res.status(404).json({ error: `case ${caseId} does not exist` });
    return false;
  }
  return true;
}

export function registerDropHeldRoutes(app: Express, ctx: RouteContext): void {
  const held = huntHeldStoreFor(ctx.store);

  app.get("/cases/:id/drop/held", async (req: Request, res: Response) => {
    const caseId = req.params.id;
    if (!(await caseVisible(ctx, req, res, caseId))) return;
    try {
      const [archives, hunts] = [await held.list(caseId), await held.listHunts(caseId)];
      return res.status(200).json({ archives, hunts, limits: huntArtifactLimitsFromEnv() });
    } catch (err) {
      return res.status(500).json({ error: `could not read the held hunt files: ${(err as Error).message}` });
    }
  });

  app.post("/cases/:id/drop/held/decide", async (req: Request, res: Response) => {
    const caseId = req.params.id;
    if (!(await caseVisible(ctx, req, res, caseId))) return;
    if (ctx.options.teamAuth && !ctx.options.teamAuth.canWriteCase(req, caseId))
      return res
        .status(403)
        .json({ error: "you need write access to this case to decide on held hunt files" });
    const parsed = decideSchema.safeParse(req.body);
    if (!parsed.success)
      return res.status(400).json({
        error: `send { decisions: [{ archiveId, member, decision } or { huntId, artifact, decision }] } with decision "import" or "skip", 1 to ${MAX_DECISIONS} at a time`,
      });
    const all = parsed.data.decisions;
    const zips = all.flatMap((d) => ("archiveId" in d ? [d] : []));
    const hunts = all.flatMap((d) => ("huntId" in d ? [d] : []));
    try {
      const updatedZips = zips.length ? await held.decide(caseId, zips) : 0;
      const applied = hunts.length ? await held.decideHunts(caseId, hunts) : [];
      // Import anyway on a bundle hunt: a fresh collect re-reads the hunt and imports it (#2753).
      const recollect = [...new Set(applied.filter((d) => d.decision === "import").map((d) => d.huntId))];
      for (const huntId of recollect) ctx.startVeloHuntCollect(caseId, huntId);
      const updated = updatedZips + applied.length;
      return res.status(200).json({ updated, ignored: all.length - updated, collecting: recollect });
    } catch (err) {
      return res.status(500).json({ error: `could not record the decision: ${(err as Error).message}` });
    }
  });
}
