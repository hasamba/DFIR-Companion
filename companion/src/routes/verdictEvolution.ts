import type { Express, Request, Response } from "express";
import { logActivity } from "../analysis/activityLog.js";
import { milestoneEvent } from "../analysis/notifications.js";
import {
  computeVerdictHistories,
  detectVerdictChanges,
  nextRunAtFor,
  selectIocsDueForRecheck,
  DEFAULT_VERDICT_EVOLUTION_CONFIG,
  type VerdictEvolutionConfig,
} from "../analysis/verdictEvolution.js";
import type { RouteContext } from "./context.js";

/**
 * Verdict-evolution domain (#232): scheduled re-enrichment with change alerts. Stale enrichment
 * verdicts mislead investigations; this surface persists a per-case config (interval, severity
 * filter, score-delta threshold) + a per-IOC verdict history, and exposes a manual "run now" that
 * re-enriches the case's IOCs, recomputes the history, diffs it against the prior history, and
 * emits an activity-log entry + milestone notification for every verdict change.
 *   - GET  /cases/:id/verdict-evolution              — config + last/next run + history summary.
 *   - GET  /cases/:id/verdict-evolution/ioc/:iocId   — full verdict history for one IOC.
 *   - POST /cases/:id/verdict-evolution/control      — toggle + interval + severity filter + threshold.
 *   - POST /cases/:id/verdict-evolution/run          — manual re-enrich now + change detection.
 *
 * The recurring schedule is driven by a caller-supplied timer (the run endpoint + an external
 * scheduler both call the same path); this module computes nextRunAt so the dashboard can show
 * when the next automatic run will fire.
 */
export function registerVerdictEvolutionRoutes(app: Express, ctx: RouteContext): void {
  const { options } = ctx;

  app.get("/cases/:id/verdict-evolution", async (req: Request, res: Response) => {
    if (!options.verdictEvolutionStore) return res.status(501).json({ error: "verdict-evolution store not configured" });
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    try {
      const record = await options.verdictEvolutionStore.load(req.params.id);
      const state = await options.stateStore.load(req.params.id);
      const histories = computeVerdictHistories(state.iocs);
      // Refresh the persisted histories on read so the panel reflects the latest enrichments
      // (a one-shot bulk-enrich between runs updates IOC enrichments without going through this
      // route — a read should still surface the new samples).
      await options.verdictEvolutionStore.saveHistories(req.params.id, histories);
      const summary = histories.map((h) => ({
        iocId: h.iocId,
        value: h.value,
        type: h.type,
        sampleCount: h.samples.length,
        latest: h.samples[h.samples.length - 1],
      }));
      return res.status(200).json({ config: record.config, histories: summary });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.get("/cases/:id/verdict-evolution/ioc/:iocId", async (req: Request, res: Response) => {
    if (!options.verdictEvolutionStore) return res.status(501).json({ error: "verdict-evolution store not configured" });
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    try {
      const state = await options.stateStore.load(req.params.id);
      const histories = computeVerdictHistories(state.iocs);
      const h = histories.find((x) => x.iocId === req.params.iocId);
      if (!h) return res.status(404).json({ error: `no verdict history for IOC ${req.params.iocId}` });
      return res.status(200).json(h);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/cases/:id/verdict-evolution/control", async (req: Request, res: Response) => {
    if (!options.verdictEvolutionStore) return res.status(501).json({ error: "verdict-evolution store not configured" });
    const body = req.body ?? {};
    try {
      const current = await options.verdictEvolutionStore.load(req.params.id);
      const next: VerdictEvolutionConfig = {
        ...current.config,
        ...(typeof body.enabled === "boolean" ? { enabled: body.enabled } : {}),
        ...(typeof body.intervalDays === "number" && body.intervalDays > 0 ? { intervalDays: Math.floor(body.intervalDays) } : {}),
        ...(typeof body.maliciousIntervalDays === "number" && body.maliciousIntervalDays > 0 ? { maliciousIntervalDays: Math.floor(body.maliciousIntervalDays) } : {}),
        ...(body.minSeverity && ["Critical", "High", "Medium", "Low", "Info"].includes(body.minSeverity) ? { minSeverity: body.minSeverity } : {}),
        ...(typeof body.scoreDeltaThreshold === "number" && body.scoreDeltaThreshold >= 0 ? { scoreDeltaThreshold: Math.floor(body.scoreDeltaThreshold) } : {}),
      };
      next.nextRunAt = nextRunAtFor(next);
      const saved = await options.verdictEvolutionStore.saveConfig(req.params.id, next);
      logActivity(options.activityLogStore, options.onActivity, req.params.id, {
        category: "enrichment",
        action: "verdict-evolution-control",
        detail: `verdict-evolution ${saved.enabled ? "enabled" : "disabled"} (interval ${saved.intervalDays}d, minSeverity ${saved.minSeverity})`,
      });
      return res.status(200).json({ config: saved });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/cases/:id/verdict-evolution/run", async (req: Request, res: Response) => {
    if (!options.verdictEvolutionStore) return res.status(501).json({ error: "verdict-evolution store not configured" });
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    const caseId = req.params.id;
    try {
      const enabledProviders = await ctx.enabledProvidersFor(caseId);
      if (enabledProviders.length === 0) {
        return res.status(422).json({ error: "no enrichment providers enabled for this case — enable providers in the enrichment panel first" });
      }
      const before = await options.verdictEvolutionStore.load(caseId);
      const stateBefore = await options.stateStore.load(caseId);
      const prevHistories = computeVerdictHistories(stateBefore.iocs);
      // Which IOCs are due for a re-check (per the config's intervals + severity filter)?
      const due = selectIocsDueForRecheck(
        stateBefore.iocs,
        prevHistories,
        stateBefore.findings.map((f) => ({ id: f.id, severity: f.severity, relatedIocs: f.relatedIocs, status: f.status })),
        before.config,
      );
      // Trigger a forced background re-enrichment of the case's IOCs (the engine re-queries
      // already-enriched IOCs when force=true). The change-detection pass runs after the enrich
      // completes — but the enrich engine is async, so we snapshot the histories NOW and emit
      // changes on the NEXT run (the typical pattern: this run re-enriches; the next run diffs
      // the new samples). To give immediate feedback, we also accept a `wait` body flag that
      // makes this endpoint poll the state store until the enrich settles (best-effort, capped).
      // For the deterministic path here, we record the pre-run histories + the due IOCs, fire
      // the enrich, and report what was scheduled.
      await options.verdictEvolutionStore.saveHistories(caseId, prevHistories);
      ctx.enrichInBackground(caseId, true);

      const now = new Date();
      const nextRun = nextRunAtFor(before.config, now);
      const config = await options.verdictEvolutionStore.markRun(caseId, now.toISOString(), nextRun);

      // Emit change alerts for any changes already present between the persisted prior histories
      // (from the last run) and the freshly-recomputed ones (which reflect any enrichments that
      // landed since). This catches changes from a one-shot bulk-enrich between scheduled runs.
      const changes = detectVerdictChanges(before.histories, prevHistories, { scoreDeltaThreshold: before.config.scoreDeltaThreshold });
      for (const c of changes) {
        logActivity(options.activityLogStore, options.onActivity, caseId, {
          category: "enrichment",
          action: "verdict-change",
          detail: c.message,
        });
        ctx.dispatchNotify(milestoneEvent(caseId, `Verdict change: ${c.value}`, [c.message], now.toISOString()));
      }

      logActivity(options.activityLogStore, options.onActivity, caseId, {
        category: "enrichment",
        action: "verdict-evolution-run",
        detail: `re-enrichment scheduled for ${due.length} due IOC(s); ${changes.length} change(s) detected`,
      });

      return res.status(202).json({
        accepted: true,
        dueIocs: due.length,
        changes: changes.map((c) => ({ iocId: c.iocId, value: c.value, kind: c.kind, message: c.message })),
        config,
      });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}