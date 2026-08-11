import type { Express, Request, Response } from "express";
import { segmentSessions, sessionEnvOptions } from "../analysis/sessionSegmentation.js";
import { logActivity } from "../analysis/activityLog.js";
import { sendPipelineError } from "./presidioApproval.js";
import type { RouteContext } from "./context.js";

/**
 * Session-segmentation domain (#229): the attacker's per-host story segmented into labeled
 * sessions — a contiguous run of events on one host with no gap larger than the threshold.
 *
 *   - GET  /cases/:id/sessions                  — attacker sessions for the case (no AI).
 *   - POST /cases/:id/sessions/:sid/summary     — focused AI account of ONE session (#342).
 *
 * Pure structural move out of createApp (see routes/system.ts for the conventions). The
 * handlers reach their dependencies through the STABLE ctx.options fields only (stateStore,
 * pipeline); no domain-local state, no new RouteContext graduations were needed.
 *
 * FILTERING: the GET operates on the RAW forensic timeline — the analyst browsing the story view
 * should see the complete per-host story, including events scope/FP filtering would hide. The
 * REPORT's sessions section deliberately differs: it segments the already-filtered state the report
 * renders from, so the written deliverable can never cite an event the rest of it excludes. Two
 * different consumers, two correct answers; see reports/markdown.ts sessionsSection().
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
      const sessions = segmentSessions(state.forensicTimeline, sessionEnvOptions());
      return res.status(200).json({ sessions });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Focused AI account of ONE session (#342) — a single text-only call over just that session's
  // events, far cheaper than full synthesis and more coherent than a flat pass over the whole
  // timeline. EPHEMERAL: nothing is persisted, the analyst copies what they want.
  app.post("/cases/:id/sessions/:sid/summary", async (req: Request, res: Response) => {
    // Gate on the SYNTHESIS (text) provider, not hasAiProvider() (the VISION/OCR provider): this is
    // a text-only call, so it must work whenever the synthesis provider is configured.
    if (!options.pipeline || !options.pipeline.hasSynthesisProvider()) {
      return res.status(501).json({ error: "AI provider not configured for session summary" });
    }
    try {
      if (!(await store.caseExists(req.params.id))) {
        return res.status(404).json({ error: `case ${req.params.id} does not exist` });
      }
      const result = await options.pipeline.sessionSummary(req.params.id, req.params.sid);
      void logActivity(options.activityLogStore, options.onActivity, req.params.id, {
        category: "ai",
        action: "session-summary",
        detail: `session ${req.params.sid} summarized (${result.usedEvents}/${result.eventCount} events)`,
      });
      return res.status(200).json(result);
    } catch (err) {
      const msg = (err as Error).message;
      // A session id that does not exist in the CURRENT segmentation is a 404, not a 500 — the ids
      // are derived, so a stale dashboard card or a changed gap threshold reaches here routinely.
      if (msg.startsWith("session not found")) return res.status(404).json({ error: msg });
      return sendPipelineError(res, err, { caseId: req.params.id, onAiStatus: options.onAiStatus });
    }
  });
}
