import type { Express, Request, Response } from "express";
import { segmentSessions, DEFAULT_SESSION_GAP_SECONDS } from "../analysis/sessionSegmentation.js";
import type { RouteContext } from "./context.js";

/**
 * Session-segmentation domain (#229): the attacker's per-host story segmented into labeled
 * sessions — a contiguous run of events on one host with no gap larger than the threshold.
 *
 *   - GET  /cases/:id/sessions   — attacker sessions for the case (no AI).
 *
 * Pure structural move out of createApp (see routes/system.ts for the conventions). The
 * handler reaches its dependency through the STABLE ctx.options field only (stateStore); no
 * domain-local state, no new RouteContext graduations were needed. The deterministic
 * scope/false-positive filtering the report applies is intentionally NOT re-applied here —
 * sessions operate on the raw forensic timeline so the analyst sees the complete per-host
 * story (mirroring how /phases behaves off the unfiltered reportWriter path when no filters
 * are set); a future refinement could thread the reportWriter through if scope/FP-aware
 * sessions become useful.
 */
export function registerSessionSegmentationRoutes(app: Express, ctx: RouteContext): void {
  const { store, options } = ctx;

  // Attacker sessions for the case — the forensic timeline segmented into per-host runs with
  // no gap larger than the threshold (default 5 min; configurable via DFIR_SESSION_GAP_S
  // seconds). Pure/offline; no AI, no Velociraptor required. Returns the sessions in
  // chronological order, each with a dominant-tactic label.
  app.get("/cases/:id/sessions", async (req: Request, res: Response) => {
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    try {
      // 404 rather than an empty list. StateStore.load answers a missing case with emptyState, so
      // without this a typo'd case id returns `{sessions: []}` — which reads as "the attacker was
      // never active here", the single worst way for this route to fail.
      if (!(await store.caseExists(req.params.id))) {
        return res.status(404).json({ error: `case ${req.params.id} does not exist` });
      }
      const state = await options.stateStore.load(req.params.id);
      const gapSeconds = Number(process.env.DFIR_SESSION_GAP_S) || DEFAULT_SESSION_GAP_SECONDS;
      const sessions = segmentSessions(state.forensicTimeline, { gapSeconds });
      return res.status(200).json({ sessions });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}