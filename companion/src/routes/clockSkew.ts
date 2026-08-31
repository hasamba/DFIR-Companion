import type { Express, Request, Response } from "express";
import {
  detectClockSkew,
  detectHostTimeGaps,
  effectiveOffsets,
  hostKey,
  DEFAULT_SKEW_ALERT_MS,
  DEFAULT_MIN_ANCHORS,
  DEFAULT_MIN_TIME_GAP_MS,
} from "../analysis/clockSkew.js";
import { correlationGroups } from "../analysis/correlate.js";
import { logActivity } from "../analysis/activityLog.js";
import type { RouteContext } from "./context.js";

/**
 * Clock-skew domain (#228): per-host clock offsets and cross-host timeline alignment.
 *   - GET   /cases/:id/clock-skew            — stored offsets, overrides and the toggle.
 *   - POST  /cases/:id/clock-skew/recompute  — re-measure from the current timeline.
 *   - POST  /cases/:id/clock-skew/align      — turn alignment on/off for the case.
 *   - PUT   /cases/:id/clock-skew/override   — set/clear one host's manual offset.
 *
 * None of these return the timeline. Alignment is a projection applied on the READ paths (GET
 * /cases/:id/state and every report/graph export), so the dashboard re-fetches the timeline it
 * already knows how to render instead of receiving a second, differently-shaped copy here.
 */
export function registerClockSkewRoutes(app: Express, ctx: RouteContext): void {
  const { options } = ctx;

  // What detectClockSkew is tuned with, and separately what the dashboard is told it was measured
  // against. minTimeGapMs belongs only to the second: it is the standalone gap WARNING's floor
  // (#740), which the offset detector knows nothing about.
  const detectOpts = { alertThresholdMs: DEFAULT_SKEW_ALERT_MS, minAnchors: DEFAULT_MIN_ANCHORS };
  const thresholds = { ...detectOpts, minTimeGapMs: DEFAULT_MIN_TIME_GAP_MS };

  app.get("/cases/:id/clock-skew", async (req: Request, res: Response) => {
    if (!options.clockSkewStore) return res.status(501).json({ error: "clock-skew store not configured" });
    try {
      const record = await options.clockSkewStore.load(req.params.id);
      return res.status(200).json({ ...record, thresholds });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Explicit re-measurement. Synthesis measures skew on the PRE-merge timeline, where the anchors
  // still exist; by the time this route runs the stored timeline is correlated, so a recompute here
  // sees fewer anchors and is offered as a deliberate action rather than a side effect of a GET.
  app.post("/cases/:id/clock-skew/recompute", async (req: Request, res: Response) => {
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    if (!options.clockSkewStore) return res.status(501).json({ error: "clock-skew store not configured" });
    try {
      const state = await options.stateStore.load(req.params.id);
      const skew = detectClockSkew(
        correlationGroups(state.forensicTimeline, { crossHostArtifacts: true }),
        detectOpts,
      );
      // The gap warning reads the host's own distribution, so unlike the anchors it survives the
      // merge intact and is just as good here as it is during synthesis (#740).
      const report = { ...skew, timeGaps: detectHostTimeGaps(state.forensicTimeline) };
      const record = await options.clockSkewStore.recordDetection(req.params.id, report, {
        replace: req.body?.replace === true,
      });
      options.onClockSkew?.(req.params.id);
      return res
        .status(200)
        .json({
          ...record,
          thresholds,
          anchorGroups: report.anchorGroups,
          groupsExamined: report.groupsExamined,
        });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/cases/:id/clock-skew/align", async (req: Request, res: Response) => {
    if (!options.clockSkewStore) return res.status(501).json({ error: "clock-skew store not configured" });
    const enable = req.body?.enable !== false;
    try {
      const record = await options.clockSkewStore.setAlign(req.params.id, enable);
      const shifted = effectiveOffsets(record.results, record.overrides).size;
      // Alignment changes every timestamp the analyst reads and every report generated after it, so
      // it belongs in the case's activity log like any other evidence-affecting decision.
      await logActivity(options.activityLogStore, options.onActivity, req.params.id, {
        category: "settings",
        action: "clock-skew-align",
        detail: enable
          ? `Timeline alignment enabled — ${shifted} host${shifted === 1 ? "" : "s"} virtually shifted`
          : "Timeline alignment disabled — recorded timestamps restored",
      });
      options.onClockSkew?.(req.params.id);
      return res.status(200).json({ ...record, thresholds });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Analyst override: `offsetMs: null` clears it, `0` pins the host as correct (see effectiveOffsets).
  app.put("/cases/:id/clock-skew/override", async (req: Request, res: Response) => {
    if (!options.clockSkewStore) return res.status(501).json({ error: "clock-skew store not configured" });
    const host = typeof req.body?.host === "string" ? req.body.host.trim() : "";
    if (!host || !hostKey(host)) return res.status(400).json({ error: "host is required" });
    const raw = req.body?.offsetMs;
    if (raw !== null && (typeof raw !== "number" || !Number.isFinite(raw))) {
      return res.status(400).json({ error: "offsetMs must be a finite number or null" });
    }
    try {
      const record = await options.clockSkewStore.setOverride(req.params.id, host, raw);
      await logActivity(options.activityLogStore, options.onActivity, req.params.id, {
        category: "settings",
        action: "clock-skew-override",
        detail:
          raw === null
            ? `Cleared manual clock offset for ${host}`
            : `Manual clock offset for ${host}: ${Math.round(raw / 1000)}s`,
        targetType: "host",
        targetId: host,
      });
      options.onClockSkew?.(req.params.id);
      return res.status(200).json({ ...record, thresholds });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
