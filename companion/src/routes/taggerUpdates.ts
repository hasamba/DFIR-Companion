import type { Express, Request, Response } from "express";
import { stringify as stringifyYaml } from "yaml";
import { NothingToMergeError, TaggerRulesConflictError } from "../analysis/taggerStore.js";
import type { RuleChoice, RuleUpdateItem } from "../analysis/taggerRulesMerge.js";
import type { RouteContext } from "./context.js";

/**
 * Tagger rule updates (#2344): bring rules added or changed in the built-in set into an analyst's
 * edited copy. All under /tagger, so in team mode every one is the instance administrator's — the
 * same users who may edit rules at all (auth/policy.ts).
 *
 *   - GET  /tagger/rules/updates          — the notice + review: added, changed, conflicts, removed by you.
 *   - POST /tagger/rules/updates/apply    — apply a selection through the editor's lock + revision check.
 *   - POST /tagger/rules/updates/export   — the merged YAML as a download; writes nothing (env source).
 *   - POST /tagger/rules/updates/dismiss  — hide the notice until the built-in set changes again.
 *
 * Applying never re-grades a case: open cases keep their grades until the analyst presses
 * Super-Timeline → Content tagger → Run tagger, and the dashboard says so.
 */

const MAX_CHOICES = 5000;

/** Body `choices` → a clean key → choice map. Anything else is dropped, never trusted. */
function parseChoices(raw: unknown): Record<string, RuleChoice> {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return {};
  const out: Record<string, RuleChoice> = {};
  for (const [key, value] of Object.entries(raw as Record<string, unknown>).slice(0, MAX_CHOICES)) {
    if (value === "upstream" || value === "mine") {
      Object.defineProperty(out, key, { value, enumerable: true, writable: true, configurable: true });
    }
  }
  return out;
}

export interface RuleSide {
  description?: string;
  severity?: string;
  tags?: string[];
  /** The rule as YAML, for the side-by-side view of a changed rule or a conflict. */
  yaml: string;
}

export function side(key: string, rule: unknown): RuleSide {
  const r = rule && typeof rule === "object" ? (rule as Record<string, unknown>) : {};
  return {
    description: typeof r.description === "string" ? r.description : undefined,
    severity: typeof r.severity === "string" ? r.severity : undefined,
    tags: Array.isArray(r.tags) ? r.tags.filter((t): t is string => typeof t === "string") : undefined,
    yaml: stringifyYaml({ [key]: rule }),
  };
}

export function itemView(i: RuleUpdateItem) {
  return {
    key: i.key,
    uncertain: i.uncertain,
    upstream: side(i.key, i.upstream),
    ...(i.mine !== undefined ? { mine: side(i.key, i.mine) } : {}),
  };
}

export function registerTaggerUpdateRoutes(app: Express, ctx: RouteContext): void {
  const { options } = ctx;
  const logLine = (msg: string): void => ctx.serverLogger.info(msg);

  app.get("/tagger/rules/updates", async (_req: Request, res: Response) => {
    if (!options.taggerStore) return res.status(501).json({ error: "tagger not configured" });
    try {
      const view = await options.taggerStore.ruleUpdates();
      const base = {
        source: view.source,
        revision: view.revision,
        readOnly: view.readOnly,
        dismissed: view.dismissed,
        // The built-in set, or the installed rule pack (#2349): the dashboard names it in the notice.
        upstreamLabel: view.upstream?.label ?? null,
      };
      const report = view.report;
      if (!report) return res.status(200).json({ ...base, notice: false });
      return res.status(200).json({
        ...base,
        notice: report.hasNews && !view.dismissed,
        tracked: report.tracked,
        upstreamRevision: report.upstreamRevision,
        counts: {
          added: report.added.length,
          changed: report.changed.length,
          conflicts: report.conflicts.length,
          removedByYou: report.removedByYou.length,
          analystEdited: report.analystEdited.length,
          analystAdded: report.analystAdded.length,
          retiredUpstream: report.retiredUpstream.length,
        },
        added: report.added.map(itemView),
        changed: report.changed.map(itemView),
        conflicts: report.conflicts.map(itemView),
        removedByYou: report.removedByYou.map(itemView),
      });
    } catch (err) {
      // An active file that does not parse cannot be compared; say so rather than show no notice.
      return res.status(400).json({ error: (err as Error).message });
    }
  });

  app.post("/tagger/rules/updates/apply", async (req: Request, res: Response) => {
    if (!options.taggerStore) return res.status(501).json({ error: "tagger not configured" });
    const revision = typeof req.body?.revision === "string" ? req.body.revision : "";
    if (!revision) return res.status(400).json({ error: "revision is required — reload the review first" });
    try {
      const out = await options.taggerStore.applyRuleUpdates(parseChoices(req.body?.choices), revision);
      logLine(
        `[tagger] built-in rule updates applied — ${out.applied.length} brought in, ${out.kept.length} kept as yours, ${out.ruleCount} rule(s)`,
      );
      return res.status(200).json(out);
    } catch (err) {
      if (err instanceof TaggerRulesConflictError) {
        logLine("[tagger] rule update refused — the review was out of date");
        return res.status(409).json({ error: err.message, revision: err.currentRevision });
      }
      if (err instanceof NothingToMergeError) return res.status(400).json({ error: err.message });
      return res.status(400).json({ error: (err as Error).message });
    }
  });

  app.post("/tagger/rules/updates/export", async (req: Request, res: Response) => {
    if (!options.taggerStore) return res.status(501).json({ error: "tagger not configured" });
    try {
      const text = await options.taggerStore.exportMergedRules(parseChoices(req.body?.choices));
      res.setHeader("Content-Disposition", 'attachment; filename="tagger-rules-merged.yaml"');
      return res.type("application/yaml").status(200).send(text);
    } catch (err) {
      return res.status(400).json({ error: (err as Error).message });
    }
  });

  app.post("/tagger/rules/updates/dismiss", async (req: Request, res: Response) => {
    if (!options.taggerStore) return res.status(501).json({ error: "tagger not configured" });
    const upstreamRevision =
      typeof req.body?.upstreamRevision === "string" ? req.body.upstreamRevision.trim() : "";
    if (!/^[0-9a-f]{16}$/.test(upstreamRevision)) {
      return res.status(400).json({ error: "upstreamRevision is required" });
    }
    try {
      await options.taggerStore.dismissRuleUpdates(upstreamRevision);
      return res.status(200).json({ dismissed: true });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
