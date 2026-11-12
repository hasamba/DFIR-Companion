import type { Express, Request, Response } from "express";
import { logActivity } from "../analysis/activityLog.js";
import {
  computeMainSource,
  FAMILY_LABELS,
  parseMainSourceOverride,
  SOURCE_FAMILIES,
  type MainSourceResult,
} from "../analysis/caseMainSource.js";
import { CaseMainSourceStore } from "../analysis/caseMainSourceStore.js";
import { enabledHuntPlatforms, huntLanguageFor, LANGUAGE_LABELS } from "../analysis/huntLanguage.js";
import type { RouteContext } from "./context.js";

/**
 * The case's main evidence source (#2559) — the line and override dropdown at the top of the Hunts
 * panel.
 *   - GET /cases/:id/main-source — the computed choice (file counts per family, over the forensic
 *     timeline only), the analyst's override, the effective choice and the hunt language it gives.
 *   - PUT /cases/:id/main-source — `{ override: <family> | "mixed" | null }`; anything else → 400.
 * Refused on a closed or archived case by the deny-by-default write guard (#2437).
 */

export interface MainSourceView extends Omit<MainSourceResult, "counts"> {
  counts: Array<{ family: string; label: string; files: number }>;
  language: { language: string | null; label: string; note: string } | null;
  families: Array<{ family: string; label: string }>;
}

function view(result: MainSourceResult): MainSourceView {
  const family = result.effective === "mixed" ? undefined : result.effective;
  const choice = family === undefined ? null : huntLanguageFor(family, enabledHuntPlatforms());
  return {
    ...result,
    counts: result.counts.map((c) => ({ ...c, label: FAMILY_LABELS[c.family] })),
    language: choice
      ? { ...choice, label: choice.language ? LANGUAGE_LABELS[choice.language] : "none" }
      : null,
    families: SOURCE_FAMILIES.map((f) => ({ family: f, label: FAMILY_LABELS[f] })),
  };
}

/**
 * #2594: store the main source picked in the New case dialog. The body was validated before the case
 * was created, so a bad value never gets here. Runs after the case exists — a failed save is
 * returned as a message for the 201 answer instead of a 500, so the analyst is not told a case
 * that exists failed to create.
 */
export async function saveCreationMainSource(
  ctx: RouteContext,
  caseId: string,
  raw: unknown,
): Promise<string | undefined> {
  const parsed = parseMainSourceOverride(raw);
  if (!parsed.ok || parsed.value === null) return undefined;
  try {
    await new CaseMainSourceStore(ctx.store).save(caseId, parsed.value);
    void logActivity(ctx.options.activityLogStore, ctx.options.onActivity, caseId, {
      category: "settings",
      action: "main-source",
      detail: `Main evidence source set to ${parsed.value} at case creation`,
    });
    return undefined;
  } catch (err) {
    ctx.serverLogger.warn(
      `[main-source] case ${caseId}: could not save the picked main source — ${(err as Error).message}`,
    );
    return "the case was created, but its main evidence source was not saved — set it in Suggested Fleet Hunts";
  }
}

export function registerCaseMainSourceRoutes(app: Express, ctx: RouteContext): void {
  const { options } = ctx;
  const store = new CaseMainSourceStore(ctx.store);

  const current = async (caseId: string): Promise<MainSourceView> => {
    const state = options.stateStore ? await options.stateStore.load(caseId) : null;
    return view(computeMainSource(state?.forensicTimeline ?? [], await store.load(caseId)));
  };

  app.get("/cases/:id/main-source", async (req: Request, res: Response) => {
    try {
      if (!(await ctx.store.caseExists(req.params.id)))
        return res.status(404).json({ error: "case not found" });
      return res.status(200).json(await current(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.put("/cases/:id/main-source", async (req: Request, res: Response) => {
    if (!req.body || typeof req.body !== "object" || !("override" in req.body))
      return res.status(400).json({ error: 'override is required (a source family, "mixed" or null)' });
    const parsed = parseMainSourceOverride(req.body.override);
    if (!parsed.ok)
      return res
        .status(400)
        .json({ error: `override must be one of ${SOURCE_FAMILIES.join(", ")}, "mixed" or null` });
    try {
      // A missing case gets a 404, never a fresh state/ directory under the cases root.
      if (!(await ctx.store.caseExists(req.params.id)))
        return res.status(404).json({ error: "case not found" });
      await store.save(req.params.id, parsed.value);
      void logActivity(options.activityLogStore, options.onActivity, req.params.id, {
        category: "settings",
        action: "main-source",
        detail: `Main evidence source ${parsed.value ? `set to ${parsed.value}` : "set to automatic"}`,
      });
      return res.status(200).json(await current(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
