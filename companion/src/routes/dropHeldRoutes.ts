import type { Express, Request, Response } from "express";
import { join } from "node:path";
import { z } from "zod";
import type { RouteContext } from "./context.js";
import { huntArtifactLimitsFromEnv } from "../analysis/huntArtifactLimits.js";
import { huntHeldStoreFor } from "../analysis/huntHeldStore.js";
import { decideHeldFile, listHeld } from "../analysis/dropHeldFiles.js";

/**
 * Hunt results held over the size limits (#2746, #2753, #2755). Each is a file under drop/_held/; the
 * list is read from the folder itself, with what the store knows about each file.
 *
 * - Import anyway moves the file back to its place in drop/ and approves it, so the next drop sweep
 *   imports it (a bundle hunt artifact: no new download). A bundle hunt also remembers the decision,
 *   so its later collects import that artifact.
 * - Skip moves it to `_skipped/` and approves it there, so moving it back into drop/ imports it. A
 *   bundle hunt's later collects leave that artifact out.
 */

export const MAX_DECISIONS = 1000;

const decideSchema = z.object({
  decisions: z
    .array(
      z.object({
        rel: z.string().min(1).max(4096),
        decision: z.enum(["import", "skip"]),
      }),
    )
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
  const dropDir = (caseId: string) => join(ctx.store.caseDir(caseId), "drop");

  app.get("/cases/:id/drop/held", async (req: Request, res: Response) => {
    const caseId = req.params.id;
    if (!(await caseVisible(ctx, req, res, caseId))) return;
    try {
      const files = await listHeld(dropDir(caseId));
      await held.forgetMissing(caseId, new Set(files.map((f) => f.rel)));
      const state = await held.load(caseId);
      const known = new Map(state.held.map((h) => [h.rel, h]));
      const listed = files.map((f) => ({ ...known.get(f.rel), rel: f.rel, size: f.size }));
      return res.status(200).json({ files: listed, limits: huntArtifactLimitsFromEnv() });
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
        error: `send { decisions: [{ rel: "_held/…", decision: "import" | "skip" }] }, 1 to ${MAX_DECISIONS} at a time`,
      });
    const dir = dropDir(caseId);
    const moved: { rel: string; to: string }[] = [];
    const ignored: { rel: string; why: string }[] = [];
    for (const d of parsed.data.decisions) {
      const r = await decideHeldFile(held, caseId, dir, d.rel, d.decision);
      if (r.to) moved.push({ rel: r.rel, to: r.to });
      else ignored.push({ rel: r.rel, why: r.error ?? "not moved" });
    }
    return res.status(200).json({ updated: moved.length, moved, ignored });
  });
}
