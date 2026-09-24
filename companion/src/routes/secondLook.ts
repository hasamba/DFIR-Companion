import type { Express, Request, Response } from "express";
import { logActivity } from "../analysis/activityLog.js";
import { isAnalystDecisionGate, sendPipelineError } from "./presidioApproval.js";
import type { RouteContext } from "./context.js";

/**
 * The second look (#1554) — analyst-pressed.
 *
 * It re-queries the raw record for the terms the case's open questions imply, promotes what it
 * finds into the forensic timeline with provenance tags, and re-synthesises so the conclusions
 * account for it. Until now it ran on its own at the tail of every synthesis, which made it the one
 * automatic writer to the evidence record. A tool used in real investigations should not have one.
 *
 * A PLAIN REQUEST/RESPONSE, not the deep-pass job machinery. The sweep itself makes ZERO AI calls —
 * it is a deterministic keyword search — and the optional re-synthesis is exactly the one call
 * POST /cases/:id/synthesize already makes without a job wrapper. A job registration here would buy
 * cancellation of a search that does not need cancelling.
 */
export function registerSecondLookRoutes(app: Express, ctx: RouteContext): void {
  const { store, options } = ctx;

  // A case with no super-timeline has no raw record to re-query, so the button has nothing to offer.
  // 501 is the same answer the Jev review gives for the same missing store.
  const unconfigured = (res: Response): Response =>
    res.status(501).json({ error: "super-timeline not configured" });

  app.get("/cases/:id/second-look/preview", async (req: Request, res: Response) => {
    if (!options.pipeline || !options.superTimelineStore) return unconfigured(res);
    const caseId = req.params.id;
    if (!(await store.getCaseMeta(caseId).catch(() => null))) {
      return res.status(404).json({ error: "case not found" });
    }
    try {
      const preview = await options.pipeline.secondLookPreview(caseId);
      if (!preview.configured) return unconfigured(res);
      return res.status(200).json(preview);
    } catch (error) {
      return res.status(500).json({ error: String((error as Error).message) });
    }
  });

  // Cases with a second look in flight (#1576). The re-synthesis is FORCED, so two overlapping
  // presses would each plan the same promotions from the pre-promotion state and each pay for a full
  // synthesis. The Jev review holds the same guard for the same reason (#1551). Held per app, so one
  // test's app never locks another's.
  const running = new Set<string>();

  app.post("/cases/:id/second-look", async (req: Request, res: Response) => {
    if (!options.pipeline || !options.superTimelineStore) return unconfigured(res);
    const caseId = req.params.id;
    const caseMeta = await store.getCaseMeta(caseId).catch(() => null);
    if (!caseMeta) return res.status(404).json({ error: "case not found" });
    if (caseMeta.status === "closed" || caseMeta.status === "archived") {
      const action = caseMeta.status === "archived" ? "restore it" : "reopen it";
      return res.status(423).json({
        error: `Case "${caseId}" is ${caseMeta.status} — ${action} before running a second look`,
      });
    }

    // DEFAULTS TO TRUE, and only an explicit `false` turns it off. Promoting evidence and leaving
    // the conclusions that were written before it arrived is a case that disagrees with itself; a
    // missing, misspelled or non-boolean field must never be what produces that state.
    const resynthesize = (req.body as { resynthesize?: unknown })?.resynthesize !== false;

    if (running.has(caseId)) {
      return res.status(409).json({ error: "a second look is already running for this case" });
    }
    running.add(caseId);
    // The finally covers every await after entry, so a run that throws never leaves the case locked.
    try {
      const result = await options.pipeline.secondLook(caseId, { resynthesize });
      if (!result) return unconfigured(res);
      void logActivity(options.activityLogStore, options.onActivity, caseId, {
        category: "ai",
        action: "second-look",
        detail:
          `second look promoted ${result.promoted} raw event(s) from ${result.leads.length} unresolved ` +
          `lead(s)` +
          (result.shapeCapped ? `; ${result.shapeCapped} repeat row(s) held back` : "") +
          (result.truncated ? "; sweep cap reached" : "") +
          (result.resynthesized ? " — conclusions re-synthesized" : " — conclusions NOT re-synthesized"),
      });
      return res.status(200).json(result);
    } catch (error) {
      // The re-synthesis inherits the host-merge gate, so a held case reaches here as a decision
      // gate rather than a failure. Report the hold, the way the deep-pass route does.
      if (isAnalystDecisionGate(error)) return sendPipelineError(res, error);
      return res.status(500).json({ error: String((error as Error).message) });
    } finally {
      running.delete(caseId);
    }
  });
}
