import type { Express, Request, Response } from "express";
import { logActivity } from "../analysis/activityLog.js";
import type { ConfidenceControl } from "../analysis/confidenceControl.js";
import { sendPipelineError } from "./presidioApproval.js";
import type { RouteContext } from "./context.js";

// Findings-panel display preferences: per-case, persisted, purely presentational settings that
// shape what the panel shows without touching case state. Three preferences: the min-confidence
// floor (#226, `minConfidence`) and the two finding-origin lenses, `hideAutoFindings` and
// `hideGapFindings`, which hide the deterministic backfill / gap-analysis findings the AI did not
// produce. GET reads the stored preferences; PUT patches only the keys the request carries, so the
// floor (written on keystrokes) and the lenses (written on click) — two independent dashboard code
// paths — never clobber each other.
//
// Lifted out of routes/aiSynthesis.ts, which the file-size ledger had frozen at 918 lines. The
// confidence-control endpoint had lived there since #226 as "AI output presentation" — the floor
// gates what an AI-derived confidence score is allowed to show. That rationale stopped covering the
// whole endpoint once the two origin lenses arrived: they hide findings the AI never produced, so
// what they gate is the Findings panel's display, not AI output. The size gate forced the question
// the design already had an answer to.
//
// MOVED VERBATIM. Route bodies, status codes and log lines are unchanged; only the registration
// point moved.
export function registerFindingsDisplayRoutes(app: Express, ctx: RouteContext): void {
  const { options } = ctx;

  // Findings-panel display preferences: the min-confidence floor (#226) and the two finding-origin
  // lenses. Per-case and persisted so they survive a page reload; purely display (nothing is
  // removed from state). `minConfidence: null` means "show all" (0); each lens defaults to false.
  const confidenceControlBody = (c: ConfidenceControl) => ({
    minConfidence: c.minConfidence ?? null,
    hideAutoFindings: c.hideAutoFindings ?? false,
    hideGapFindings: c.hideGapFindings ?? false,
  });

  app.get("/cases/:id/confidence-control", async (req: Request, res: Response) => {
    if (!options.confidenceControlStore)
      return res.status(501).json({ error: "confidence control not configured" });
    try {
      return res
        .status(200)
        .json(confidenceControlBody(await options.confidenceControlStore.load(req.params.id)));
    } catch (err) {
      return sendPipelineError(res, err);
    }
  });

  app.put("/cases/:id/confidence-control", async (req: Request, res: Response) => {
    if (!options.confidenceControlStore)
      return res.status(501).json({ error: "confidence control not configured" });
    const body = (req.body ?? {}) as Record<string, unknown>;
    // PATCH ONLY THE KEYS THE REQUEST CARRIES. The dashboard writes the floor (debounced, on
    // keystrokes) and the lenses (immediate, on click) from two independent paths, so a PUT naming
    // one must not disturb the others. Reading an ABSENT minConfidence as "clear it" — which is
    // what this handler used to do — would let a checkbox click wipe the analyst's floor.
    const patch: ConfidenceControl = {};
    if ("minConfidence" in body) {
      const raw = body.minConfidence;
      const cleared = raw === null || raw === undefined || raw === "";
      if (!cleared && (typeof raw !== "number" || !Number.isFinite(raw) || raw < 0 || raw > 100)) {
        return res.status(400).json({ error: "minConfidence must be a number 0-100, or null" });
      }
      patch.minConfidence = cleared ? undefined : raw;
    }
    for (const key of ["hideAutoFindings", "hideGapFindings"] as const) {
      if (!(key in body)) continue;
      const raw = body[key];
      if (raw !== null && raw !== undefined && typeof raw !== "boolean") {
        return res.status(400).json({ error: `${key} must be a boolean, or null` });
      }
      patch[key] = raw == null ? undefined : raw;
    }
    try {
      await options.confidenceControlStore.set(req.params.id, patch);
      options.onConfidenceControl?.(req.params.id);
      const saved = await options.confidenceControlStore.load(req.params.id);
      const detail =
        [
          "minConfidence" in patch
            ? saved.minConfidence === undefined
              ? "minConfidence cleared"
              : `minConfidence set to ${saved.minConfidence}`
            : null,
          "hideAutoFindings" in patch ? `hideAutoFindings ${saved.hideAutoFindings ?? false}` : null,
          "hideGapFindings" in patch ? `hideGapFindings ${saved.hideGapFindings ?? false}` : null,
        ]
          .filter(Boolean)
          .join("; ") || "no change";
      void logActivity(options.activityLogStore, options.onActivity, req.params.id, {
        category: "settings",
        action: "confidence-control",
        detail,
      });
      return res.status(200).json(confidenceControlBody(saved));
    } catch (err) {
      return sendPipelineError(res, err);
    }
  });
}
