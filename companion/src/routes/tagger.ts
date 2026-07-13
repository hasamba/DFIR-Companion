import type { Express, Request, Response } from "express";
import { logActivity } from "../analysis/activityLog.js";
import type { ForensicEvent } from "../analysis/stateTypes.js";
import { runAndApplyTagger, readTaggerSettings, TAGGER_AUTHOR_PREFIX } from "../analysis/taggerRun.js";
import type { RouteContext } from "./context.js";

/**
 * Tagger domain: the content-based event tagger (Timesketch tagger analyzer, ported). Rules live in
 * a YAML file; matching events get tags (always), and — on the forensic timeline — raised severity /
 * unioned MITRE, per analysis/tagger.ts. Manual runs and rule editing live here; the automatic
 * post-import run lives in the pipeline.
 *
 *   - GET  /tagger/rules            — the active ruleset (raw YAML + a parsed summary + its source).
 *   - PUT  /tagger/rules            — validate + persist edited rule YAML (400 on an invalid ruleset).
 *   - POST /cases/:id/tagger/run    — run the ruleset over the case; report per-rule match counts.
 *   - POST /cases/:id/tagger/clear  — remove every tagger-authored tag (reversible; analyst tags kept).
 */
export function registerTaggerRoutes(app: Express, ctx: RouteContext): void {
  const { options } = ctx;
  const logLine = (msg: string): void => ctx.serverLogger.info(msg);

  // The active ruleset: raw YAML for the editor + a compact per-rule summary + where it came from
  // (env override / user file / bundled default).
  app.get("/tagger/rules", async (_req: Request, res: Response) => {
    if (!options.taggerStore) return res.status(501).json({ error: "tagger not configured" });
    try {
      const active = await options.taggerStore.readActive();
      let ruleSummary: Array<{ id: string; description?: string; tags: string[]; mitre: string[]; severity?: string; view?: string }> = [];
      let error: string | undefined;
      try {
        const compiled = await options.taggerStore.load();
        ruleSummary = compiled.rules.map((r) => ({
          id: r.id, description: r.description, tags: r.tags, mitre: r.mitre, severity: r.severity, view: r.view,
        }));
      } catch (err) {
        error = (err as Error).message; // a hand-edited file can be invalid; report it, still return the text
      }
      return res.status(200).json({ text: active.text, source: active.source, ruleCount: ruleSummary.length, rules: ruleSummary, error });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Validate + persist edited rule YAML. An invalid ruleset is rejected (400) BEFORE the file is
  // written, so a bad edit never clobbers a working ruleset.
  app.put("/tagger/rules", async (req: Request, res: Response) => {
    if (!options.taggerStore) return res.status(501).json({ error: "tagger not configured" });
    const text = typeof req.body?.text === "string" ? req.body.text : "";
    try {
      const compiled = await options.taggerStore.save(text);
      logLine(`[tagger] rules updated — ${compiled.rules.length} rule(s)`);
      return res.status(200).json({ ruleCount: compiled.rules.length });
    } catch (err) {
      return res.status(400).json({ error: (err as Error).message });
    }
  });

  // Run the ruleset over the case and apply the results. Scope (both | forensic | super) comes from
  // settings. Serializes the forensic-timeline write on the per-case state mutex so a concurrent
  // import/synthesis can't clobber it. Reports per-rule match counts for the dashboard.
  app.post("/cases/:id/tagger/run", async (req: Request, res: Response) => {
    if (!options.taggerStore || !options.tagsStore || !options.stateStore) {
      return res.status(501).json({ error: "tagger not configured" });
    }
    const caseId = req.params.id;
    const { scope } = readTaggerSettings();
    try {
      const ruleset = await options.taggerStore.load(); // throws on an invalid ruleset → 400 below
      if (!ruleset.rules.length) return res.status(200).json({ scope, totalMatched: 0, tagsWritten: 0, mutatedCount: 0, perRule: [] });

      const summary = await ctx.runStateExclusive(caseId, async () => {
        const state = await options.stateStore!.load(caseId);
        const superEvents = scope !== "forensic" && options.superTimelineStore
          ? await options.superTimelineStore.all(caseId)
          : [];
        // Build the scoped evaluation set. For "both", union the forensic timeline with the super
        // timeline by id (the super timeline is a superset in practice, but a capped one).
        const events: ForensicEvent[] =
          scope === "super" ? superEvents
          : scope === "forensic" ? state.forensicTimeline
          : dedupeById(state.forensicTimeline, superEvents);

        const applied = await runAndApplyTagger({
          caseId, events, ruleset,
          forensicTimeline: state.forensicTimeline,
          tagsStore: options.tagsStore!,
          mutateForensic: scope !== "super",
        });
        if (applied.mutatedCount > 0) {
          await options.stateStore!.save({ ...state, forensicTimeline: applied.forensicTimeline, updatedAt: new Date().toISOString() });
        }
        return applied;
      });

      options.onTags?.(caseId);
      if (summary.mutatedCount > 0) options.onState?.(await options.stateStore.load(caseId));
      logActivity(options.activityLogStore, options.onActivity, caseId, {
        category: "triage", action: "tagger-run", actor: "tagger",
        detail: `tagged ${summary.result.totalMatched} event(s), ${summary.tagsWritten} tag(s), ${summary.mutatedCount} severity/MITRE update(s)`,
      });
      return res.status(200).json({
        scope,
        totalMatched: summary.result.totalMatched,
        tagsWritten: summary.tagsWritten,
        mutatedCount: summary.mutatedCount,
        perRule: summary.result.perRule.map((r) => ({ id: r.id, description: r.description, matched: r.matched, view: r.view })),
      });
    } catch (err) {
      return res.status(400).json({ error: (err as Error).message });
    }
  });

  // Remove every tagger-authored tag (author prefixed "tagger:"), leaving analyst tags untouched.
  app.post("/cases/:id/tagger/clear", async (req: Request, res: Response) => {
    if (!options.tagsStore) return res.status(501).json({ error: "tags not configured" });
    const caseId = req.params.id;
    try {
      const removed = await options.tagsStore.removeByAuthorPrefix(caseId, TAGGER_AUTHOR_PREFIX);
      if (removed) options.onTags?.(caseId);
      logActivity(options.activityLogStore, options.onActivity, caseId, {
        category: "triage", action: "tagger-cleared", actor: "tagger", detail: `removed ${removed} tagger tag(s)`,
      });
      return res.status(200).json({ removed });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}

/** Union two event lists by id, keeping the first occurrence (forensic events win over super copies). */
function dedupeById(a: readonly ForensicEvent[], b: readonly ForensicEvent[]): ForensicEvent[] {
  const seen = new Set(a.map((e) => e.id));
  return [...a, ...b.filter((e) => !seen.has(e.id))];
}
