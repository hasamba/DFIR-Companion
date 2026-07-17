import type { Express, Request, Response } from "express";
import { logActivity } from "../analysis/activityLog.js";
import { toTimesketchJsonlFromList } from "../integrations/timesketch/timesketchMap.js";
import type { ForensicEvent } from "../analysis/stateTypes.js";
import type { RouteContext } from "./context.js";

/**
 * Timeline domain: the timeline VIEWS + EXPORTS derived from a case's state.
 *   - GET  /cases/:id/swimlane                    — forensic events grouped into visual lanes (no AI).
 *   - GET  /cases/:id/timeline-gaps               — suspiciously long silent periods (log-tampering leads).
 *   - POST /cases/:id/timeline-gaps/hypothesize   — AI hypotheses + shadow-artifact collections per gap.
 *   - GET  /cases/:id/incident-timeline.csv       — forensic timeline as CSV (scope/legit filtered).
 *   - GET  /cases/:id/timeline.jsonl              — forensic timeline as Timesketch JSONL (filtered).
 *   - GET  /cases/:id/super-timeline              — the complete raw record, filter/paginate.
 *   - GET  /cases/:id/super-timeline.jsonl        — the complete raw record as Timesketch JSONL.
 *   - POST /cases/:id/super-timeline/label        — set analyst labels on a super-timeline row.
 *   - POST /cases/:id/super-timeline/promote      — pull raw events up into the analyzed timeline.
 *
 * Pure structural move out of createApp (see routes/system.ts for the conventions). Nothing here is
 * shared back with createApp beyond the stable ctx surface (options, serverLogger) and
 * one already-graduated member reused via ctx:
 *   - resynthesizeInBackground — the shared post-mutation re-synthesis kick (owned by createApp; fired
 *     here after /super-timeline/promote merges events into the forensic timeline). No new graduations.
 *
 * BOUNDARY: the interleaved /cases/:id/dwell-windows routes (analysisGraph domain) and
 * /cases/:id/activity-log route (caseLifecycle domain) were intentionally LEFT in createApp — they
 * happen to sit between these handlers but belong to other domains. Likewise the other read-only
 * report projections around swimlane (phases, beacon-candidates, anomalies, host-ranking, etc.) stay
 * in createApp; only the timeline/super-timeline views + exports move here.
 */
export function registerTimelineRoutes(app: Express, ctx: RouteContext): void {
  const { options, resynthesizeInBackground } = ctx;
  // Module-private wrapper mirroring createApp's logLine (serverLogger.info), so the moved handler
  // bodies keep their original `logLine(...)` calls verbatim.
  const logLine = (msg: string): void => ctx.serverLogger.info(msg);

  // Swimlane data for the visual timeline chart — forensic events grouped into lanes by the
  // chosen groupBy axis (asset | severity | tactic). Derived on demand, no AI, same filtering.
  app.get("/cases/:id/swimlane", async (req: Request, res: Response) => {
    if (!options.reportWriter) return res.status(501).json({ error: "report writer not configured" });
    const groupBy = (req.query.groupBy as string) === "severity" ? "severity"
      : (req.query.groupBy as string) === "tactic" ? "tactic" : "asset";
    try {
      return res.status(200).json(await options.reportWriter.swimlane(req.params.id, groupBy));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Timeline gaps (#83): suspiciously long silent periods in the forensic timeline — a complete gap
  // (every source dark) is the classic log-tampering signature, a partial gap a single-tool coverage
  // blindspot. Derived on demand, no AI, same scope/legitimate filtering as the report. Powers the
  // dashboard Timeline Gaps panel; thresholds DFIR_GAP_MIN_MINUTES / _DENSITY_FACTOR / _ACTIVE_HOURS.
  app.get("/cases/:id/timeline-gaps", async (req: Request, res: Response) => {
    if (!options.reportWriter) return res.status(501).json({ error: "report writer not configured" });
    try {
      return res.status(200).json(await options.reportWriter.timelineGaps(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // AI hypothesis generation for timeline gaps (#96): for each flagged silent period, hypothesise the
  // attacker activity that fits the surrounding events, and pair each gap with the deterministic
  // SHADOW-ARTIFACT collections (USN journal, SRUM, Prefetch, Amcache, …) that reconstruct the missing
  // window. Single text-only AI call, EPHEMERAL (no state change) — the dashboard shows the hypotheses +
  // collections for review, then deploys a chosen shadow-artifact collection via POST /velociraptor/hunt.
  // Needs an AI provider; does NOT need the Velociraptor API (the VQL is useful to copy even when off).
  app.post("/cases/:id/timeline-gaps/hypothesize", async (req: Request, res: Response) => {
    if (!options.pipeline || !options.pipeline.hasSynthesisProvider()) return res.status(501).json({ error: "AI provider not configured for gap hypotheses" });
    try {
      const result = await options.pipeline.hypothesizeGaps(req.params.id);
      logLine(`[gaps] hypothesised ${result.hypotheses.length} timeline gap(s) for ${req.params.id}`);
      logActivity(options.activityLogStore, options.onActivity, req.params.id, {
        category: "ai", action: "hypothesize-gaps", detail: `hypothesized ${result.hypotheses.length} timeline gap(s)`,
      });
      return res.status(200).json(result);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Evidence gaps / known unknowns (investigation-guidance #9): the kill-chain phases with no covering
  // finding (each carrying a deterministic "collect X from host Y" directive), silent-window coverage
  // gaps, and lookalike-actor likely-next techniques. The SAME structured items the synthesis prompt
  // consumes, so the panel and the model see one list. Pure/offline; no AI, no Velociraptor required.
  app.get("/cases/:id/known-unknowns", async (req: Request, res: Response) => {
    if (!options.pipeline) return res.status(501).json({ error: "pipeline not configured" });
    try {
      return res.status(200).json({ items: await options.pipeline.knownUnknownsForCase(req.params.id) });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Export just the incident (forensic) timeline as CSV, generated on demand from the
  // current state (same scope/legitimate filtering as the report) — no full report needed.
  app.get("/cases/:id/incident-timeline.csv", async (req: Request, res: Response) => {
    if (!options.reportWriter) return res.status(501).json({ error: "report writer not configured" });
    try {
      const csv = await options.reportWriter.incidentTimelineCsv(req.params.id);
      res.type("text/csv; charset=utf-8");
      res.setHeader("Content-Disposition", 'attachment; filename="incident-timeline.csv"');
      res.setHeader("Cache-Control", "private, no-cache");
      return res.send(csv);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Export the incident (forensic) timeline as Timesketch-compatible JSONL, generated on demand
  // from the current state (same scope/legitimate filtering as the report). Upload it into a
  // Timesketch sketch manually, or use the Push-to-Timesketch button below to do it in one click.
  app.get("/cases/:id/timeline.jsonl", async (req: Request, res: Response) => {
    if (!options.reportWriter) return res.status(501).json({ error: "report writer not configured" });
    try {
      const jsonl = await options.reportWriter.timesketchJsonl(req.params.id);
      res.type("application/x-ndjson; charset=utf-8");
      res.setHeader("Content-Disposition", 'attachment; filename="timesketch-timeline.jsonl"');
      res.setHeader("Cache-Control", "private, no-cache");
      return res.send(jsonl);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Super-timeline: the complete record of every imported event (a copy of the forensic timeline +
  // raw host-triage artifacts routed here exclusively). Filter by time/origin/label + paginate.
  app.get("/cases/:id/super-timeline", async (req: Request, res: Response) => {
    if (!options.superTimelineStore) return res.status(501).json({ error: "super-timeline not configured" });
    const csv = (v: unknown): string[] => String(v ?? "").split(",").map((s) => s.trim()).filter(Boolean);
    const num = (v: unknown): number | undefined => { const n = Number(v); return Number.isFinite(n) ? n : undefined; };
    try {
      // The Labels filter + labelsAvailable facet now come from the case's analyst TAGS (unifying the
      // super-timeline's per-row labelling with the forensic timeline's tags), not the legacy per-event
      // label sidecar. Build a { eventId: labels[] } map from tags targeting events and pass it as the
      // querySuper labelMap. When the tags store isn't wired, query() falls back to the sidecar.
      let tagLabelMap: Record<string, string[]> | undefined;
      if (options.tagsStore) {
        const tags = await options.tagsStore.load(req.params.id);
        tagLabelMap = {};
        for (const t of tags) {
          if (t.targetType !== "event") continue;
          (tagLabelMap[t.targetId] ??= []).push(t.label);
        }
      }
      const result = await options.superTimelineStore.query(req.params.id, {
        from: typeof req.query.from === "string" && req.query.from ? req.query.from : undefined,
        to: typeof req.query.to === "string" && req.query.to ? req.query.to : undefined,
        origins: csv(req.query.origins),
        exclude: csv(req.query.exclude),
        excludeHosts: csv(req.query.excludeHosts),
        labels: csv(req.query.labels),
        taggedOnly: req.query.tagged === "1" || req.query.tagged === "true",
        starred: req.query.starred === "1" || req.query.starred === "true",
        search: typeof req.query.q === "string" ? req.query.q : undefined,
        excludeText: csv(req.query.excludeText),
        offset: num(req.query.offset),
        limit: num(req.query.limit),
      }, tagLabelMap);
      // Mark rows already pulled into the forensic timeline (promote's mergeDelta dedups by id, so
      // "promoted" means this event's id is already there) so the UI can show persistent state instead
      // of a fire-and-forget button that gives no lasting feedback.
      const promotedIds = options.stateStore
        ? new Set((await options.stateStore.load(req.params.id)).forensicTimeline.map((e) => e.id))
        : new Set<string>();
      const events = result.events.map((e) => ({ ...e, promoted: promotedIds.has(e.id) }));
      return res.status(200).json({ ...result, events });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Export the super-timeline (forensic timeline + raw host-triage artifacts) as Timesketch-
  // compatible JSONL, generated on demand from the full unfiltered store. NOT scope/false-positive
  // filtered — the super-timeline is the raw complete record (mirrors GET .../super-timeline).
  app.get("/cases/:id/super-timeline.jsonl", async (req: Request, res: Response) => {
    if (!options.superTimelineStore) return res.status(501).json({ error: "super-timeline not configured" });
    try {
      const { events } = await options.superTimelineStore.query(req.params.id, { limit: Number.MAX_SAFE_INTEGER });
      const jsonl = toTimesketchJsonlFromList(events);
      res.type("application/x-ndjson; charset=utf-8");
      res.setHeader("Content-Disposition", 'attachment; filename="timesketch-super-timeline.jsonl"');
      res.setHeader("Cache-Control", "private, no-cache");
      return res.send(jsonl);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/cases/:id/super-timeline/label", async (req: Request, res: Response) => {
    if (!options.superTimelineStore) return res.status(501).json({ error: "super-timeline not configured" });
    const eventId = typeof req.body?.eventId === "string" ? req.body.eventId.trim() : "";
    if (!eventId) return res.status(400).json({ error: "eventId is required" });
    const labels = Array.isArray(req.body?.labels) ? req.body.labels.map(String) : [];
    try {
      await options.superTimelineStore.setLabels(req.params.id, eventId, labels);
      options.onSuperTimeline?.(req.params.id);
      return res.status(200).json({ eventId, labels });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Promote selected super-timeline events into the forensic timeline so AI synthesizes them. The raw
  // super-timeline is never synthesized; this is how the analyst pulls the events that matter up into the
  // analyzed timeline. Delegates the merge to the pipeline (mergeDelta dedups by id → idempotent), then
  // re-synthesizes — with AI off that no-ops, but the state is still saved, exactly like every other
  // state-mutating route.
  app.post("/cases/:id/super-timeline/promote", async (req: Request, res: Response) => {
    if (!options.superTimelineStore) return res.status(501).json({ error: "super-timeline not configured" });
    if (!options.pipeline) return res.status(501).json({ error: "pipeline not configured" });
    const ids = Array.isArray(req.body?.eventIds) ? req.body.eventIds.map(String).filter(Boolean) : [];
    if (!ids.length) return res.status(400).json({ error: "eventIds is required" });
    try {
      const events: ForensicEvent[] = [];
      for (const id of ids) {
        const e = await options.superTimelineStore.get(req.params.id, id);
        if (e) events.push(e);
      }
      if (!events.length) return res.status(404).json({ error: "no matching super-timeline events" });
      await options.pipeline.promoteSuperTimeline(req.params.id, events, { importedAt: new Date().toISOString() });
      resynthesizeInBackground(req.params.id);
      return res.status(200).json({ promoted: events.length });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
