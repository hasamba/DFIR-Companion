import type { Express, Request, Response } from "express";
import { logActivity } from "../analysis/activityLog.js";
import type { ForensicEvent } from "../analysis/stateTypes.js";
import { runTagger, selectScopedEvents } from "../analysis/tagger.js";
import { compileText } from "../analysis/taggerStore.js";
import { runAndApplyTagger, readTaggerSettings, TAGGER_AUTHOR_PREFIX } from "../analysis/taggerRun.js";
import type { RouteContext } from "./context.js";

/**
 * Tagger domain: the content-based event tagger (Timesketch tagger analyzer, ported). Rules live in
 * a YAML file; matching events get tags (always), and — on the forensic timeline — raised severity /
 * unioned MITRE, per analysis/tagger.ts. Manual runs and rule editing live here; the automatic
 * post-import run lives in the pipeline.
 *
 *   - GET    /tagger/rules               — the active ruleset (raw YAML + a parsed summary + its source).
 *   - PUT    /tagger/rules               — validate + persist edited rule YAML (400 on an invalid ruleset).
 *   - POST   /tagger/rules/add           — merge one reviewed rule (single-entry YAML) into the ruleset.
 *   - DELETE /tagger/rules/:ruleId       — remove one rule by id (any rule; 404 if absent).
 *   - POST   /tagger/rules/reset         — restore the shipped default ruleset (discard customizations).
 *   - POST   /cases/:id/tagger/run       — run the ruleset over the case; report per-rule match counts.
 *   - POST   /cases/:id/tagger/clear     — remove every tagger-authored tag (reversible; analyst tags kept).
 *   - POST   /cases/:id/tagger/suggest-rule — AI: draft one rule from a plain-English description (ephemeral).
 *   - POST   /cases/:id/tagger/preview   — dry-run a candidate rule; report its match count (no writes).
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
        const events: ForensicEvent[] = selectScopedEvents(scope, state.forensicTimeline, superEvents);

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

  // Suggest ONE tagger rule from a plain-English description (PR #112 follow-up). AI-gated. Returns
  // a candidate for review — nothing is persisted here. Body: { description }.
  app.post("/cases/:id/tagger/suggest-rule", async (req: Request, res: Response) => {
    if (!options.pipeline || !options.pipeline.hasSynthesisProvider()) return res.status(501).json({ error: "AI provider not configured for tagger rule suggestion" });
    const description = typeof req.body?.description === "string" ? req.body.description.trim() : "";
    if (!description) return res.status(400).json({ error: "description is required" });
    try {
      const outcome = await options.pipeline.suggestTaggerRule(req.params.id, description);
      logActivity(options.activityLogStore, options.onActivity, req.params.id, {
        category: "ai", action: "tagger-suggest-rule",
        detail: `suggested rule from: "${description.slice(0, 120)}" — ${outcome.kind}`,
      });
      return res.status(200).json(outcome);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Dry-run a candidate rule over the case's scoped events and report how many it would match PLUS a
  // capped sample of the matching events (so the analyst can see WHAT it covers, not just a count).
  // No AI, no tags written, no state mutated. Body: { ruleYaml } (a single-entry rule map). 400 on invalid.
  app.post("/cases/:id/tagger/preview", async (req: Request, res: Response) => {
    if (!options.stateStore) return res.status(501).json({ error: "tagger not configured" });
    const ruleYaml = typeof req.body?.ruleYaml === "string" ? req.body.ruleYaml : "";
    const { scope } = readTaggerSettings();
    try {
      const ruleset = compileText(ruleYaml); // throws on invalid → 400 below
      const state = await options.stateStore.load(req.params.id);
      const superEvents = scope !== "forensic" && options.superTimelineStore
        ? await options.superTimelineStore.all(req.params.id)
        : [];
      const events = selectScopedEvents(scope, state.forensicTimeline, superEvents);
      const result = runTagger(events, ruleset);
      // A capped, trimmed view of the matching events for the dashboard preview list.
      const PREVIEW_SAMPLE_CAP = 100;
      const byId = new Map(events.map((e) => [e.id, e]));
      const sample = result.perEvent.slice(0, PREVIEW_SAMPLE_CAP).map((m) => {
        const e = byId.get(m.eventId);
        return {
          id: m.eventId,
          timestamp: e?.timestamp ?? "",
          asset: e?.asset ?? "",
          description: (e?.description ?? "").slice(0, 200),
        };
      });
      return res.status(200).json({ matched: result.totalMatched, scope, sample });
    } catch (err) {
      return res.status(400).json({ error: (err as Error).message });
    }
  });

  // Merge one reviewed rule into the ruleset. No AI. Body: { ruleYaml } (single-entry map). 400 on
  // invalid; the store de-collides the id and validates before persisting.
  app.post("/tagger/rules/add", async (req: Request, res: Response) => {
    if (!options.taggerStore) return res.status(501).json({ error: "tagger not configured" });
    const ruleYaml = typeof req.body?.ruleYaml === "string" ? req.body.ruleYaml : "";
    try {
      const { id, ruleCount } = await options.taggerStore.addRuleYaml(ruleYaml);
      logLine(`[tagger] rule added: ${id} — ${ruleCount} rule(s)`);
      return res.status(200).json({ id, ruleCount });
    } catch (err) {
      return res.status(400).json({ error: (err as Error).message });
    }
  });

  // Remove one rule by id (any rule, default or added). 404 when the id isn't present.
  app.delete("/tagger/rules/:ruleId", async (req: Request, res: Response) => {
    if (!options.taggerStore) return res.status(501).json({ error: "tagger not configured" });
    try {
      const { removed, ruleCount } = await options.taggerStore.removeRule(req.params.ruleId);
      if (!removed) return res.status(404).json({ error: `rule "${req.params.ruleId}" not found` });
      logLine(`[tagger] rule removed: ${req.params.ruleId} — ${ruleCount} rule(s)`);
      return res.status(200).json({ ruleCount });
    } catch (err) {
      return res.status(400).json({ error: (err as Error).message });
    }
  });

  // Reset the ruleset to the shipped default (discards all customizations).
  app.post("/tagger/rules/reset", async (_req: Request, res: Response) => {
    if (!options.taggerStore) return res.status(501).json({ error: "tagger not configured" });
    try {
      const { ruleCount } = await options.taggerStore.resetToDefault();
      logLine(`[tagger] rules reset to default — ${ruleCount} rule(s)`);
      return res.status(200).json({ ruleCount });
    } catch (err) {
      return res.status(400).json({ error: (err as Error).message });
    }
  });
}
