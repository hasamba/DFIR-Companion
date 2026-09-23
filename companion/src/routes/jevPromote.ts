import type { Express, Request, Response } from "express";
import { logActivity } from "../analysis/activityLog.js";
import { resolveJevSettings } from "../analysis/ai/jev/jevConfig.js";
import { isLabProduced } from "../analysis/labIntel.js";
import {
  worstSeverity,
  type ForensicEvent,
  type InvestigationState,
  type Severity,
} from "../analysis/stateTypes.js";
import type { RouteContext } from "./context.js";

/**
 * The WRITE half of the missed-evidence review (#1568) — one route, and a separate module from
 * routes/jevReview.ts on purpose.
 *
 * The grading pass promotes nothing and must keep being able to say so: it is the third bounded
 * exception to the forensic / super-timeline boundary, and its module header is the claim.
 * Promotion lives here instead, behind an explicit analyst selection — the same shape as
 * `starred-report` and `explain`, which promote exactly the rows the analyst picked and nothing
 * else. An automatic promotion out of a grading pass is what the boundary exists to prevent; a
 * promotion the analyst ticked row by row is a different act. See ARCHITECTURE.md, "The Jev second
 * grader is the third exception", and tests/analysis/forensicBoundary.test.ts, which asserts both
 * halves.
 *
 * NO RE-SYNTHESIS. Promoting spends nothing; an AI call the analyst did not ask for would. The
 * panel promotes, the analyst re-synthesizes when they have finished picking.
 */

const SEVERITIES: readonly Severity[] = ["Info", "Low", "Medium", "High", "Critical"];

const isSeverity = (value: unknown): value is Severity => SEVERITIES.includes(value as Severity);

/** One ticked row, as the panel sends it: the id plus the decision the model returned for it. */
interface PromoteSelection {
  readonly id: string;
  readonly grade: Severity;
  readonly confidence: number;
  readonly score: number;
}

/** How much of a model id the provenance tag carries before it is cut. */
const MODEL_ID_MAX = 48;

/**
 * THE PROVENANCE TAG, and why this shape.
 *
 * A severity in the forensic timeline is read as fact. This one was chosen by a model, so the row
 * has to carry enough for someone who was not in the room six months later to tell it from a
 * severity the deterministic content tagger set (which stamps no provenance at all) and from
 * `[promoted]`, which means a human's own judgement. So the tag names four things: the review it
 * came from, the grade, the confidence behind that grade, and the model that gave it.
 *
 * One bracketed tag, in the same shape as `[promoted]` and `[second-look: h2]`, because provenance
 * is rendered inline on a timeline row — anything longer is not read, and a form nobody reads is
 * not an audit trail. Confidence to two decimals; the model id is cut at MODEL_ID_MAX so a long
 * provider-prefixed id cannot push the rest of the row off the line.
 *
 * The raw `score` is deliberately NOT in the tag. It is the unrounded form of the grade that is
 * already there, and the review response and the panel both keep it; spending tag width on it
 * would cost the thing that makes the tag worth having.
 */
function reviewProvenance(sel: PromoteSelection, model: string): string {
  const confidence = Number.isFinite(sel.confidence) ? sel.confidence.toFixed(2) : "?";
  return `[missed-evidence: ${sel.grade} conf ${confidence} by ${model.slice(0, MODEL_ID_MAX)}]`;
}

/**
 * Validate the selection at the boundary: a malformed tick list is refused whole rather than
 * half-promoted. Duplicate ids collapse — the same row ticked twice is one promotion, and the
 * merge would dedup it anyway.
 */
function parseSelection(body: unknown): { rows: PromoteSelection[] } | { error: string } {
  const raw = (body as { rows?: unknown } | null | undefined)?.rows;
  if (!Array.isArray(raw) || raw.length === 0) return { error: "rows is required" };
  const byId = new Map<string, PromoteSelection>();
  for (const entry of raw) {
    const row = entry as Partial<Record<keyof PromoteSelection, unknown>> | null;
    const id = typeof row?.id === "string" ? row.id.trim() : "";
    if (!id) return { error: "every row needs an id" };
    if (!isSeverity(row?.grade)) return { error: `row ${id}: grade must be one of ${SEVERITIES.join(", ")}` };
    if (typeof row?.confidence !== "number" || !Number.isFinite(row.confidence))
      return { error: `row ${id}: confidence must be a number` };
    if (typeof row?.score !== "number" || !Number.isFinite(row.score))
      return { error: `row ${id}: score must be a number` };
    byId.set(id, { id, grade: row.grade, confidence: row.confidence, score: row.score });
  }
  return { rows: [...byId.values()] };
}

/** The counts the panel refreshes from, in the shape POST /cases/:id/synthesize already returns. */
const freshCounts = (state: InvestigationState) => ({
  forensicEvents: state.forensicTimeline.length,
  findings: state.findings.length,
  mitreTechniques: state.mitreTechniques.length,
});

export function registerJevPromoteRoutes(app: Express, ctx: RouteContext): void {
  const { store, options } = ctx;

  app.post("/cases/:id/jev/promote", async (req: Request, res: Response) => {
    const caseId = req.params.id;
    if (!options.superTimelineStore || !options.stateStore || !options.pipeline) {
      return res.status(501).json({ error: "super-timeline not configured" });
    }
    const superStore = options.superTimelineStore;
    const caseMeta = await store.getCaseMeta(caseId).catch(() => null);
    if (!caseMeta) return res.status(404).json({ error: "case not found" });
    if (caseMeta.status === "closed" || caseMeta.status === "archived") {
      const action = caseMeta.status === "archived" ? "restore it" : "reopen it";
      return res.status(423).json({
        error: `Case "${caseId}" is ${caseMeta.status} — ${action} before promoting evidence`,
      });
    }
    const parsed = parseSelection(req.body);
    if ("error" in parsed) return res.status(400).json({ error: parsed.error });

    // The model that graded the selection. The panel sends it, because a review's rows may have
    // been graded by a model the settings no longer name; the live setting is the fallback, and
    // "unknown model" is the honest last resort rather than a silently plausible id.
    const bodyModel = (req.body as { model?: unknown }).model;
    const model =
      (typeof bodyModel === "string" && bodyModel.trim()) ||
      resolveJevSettings().settings?.model ||
      "unknown model";

    try {
      const state = await options.stateStore.load(caseId);
      const inForensic = new Set(state.forensicTimeline.map((e) => e.id));
      const toPromote: ForensicEvent[] = [];
      const tagById: Record<string, string[]> = {};
      let already = 0;
      let missing = 0;
      let lab = 0;
      let stayedInfo = 0;

      for (const sel of parsed.rows) {
        // Already analyzed is a no-op, not an error: the analyst ticked a row a previous press (or
        // an import) already pulled up, and failing the batch over it would lose the rest.
        if (inForensic.has(sel.id)) {
          already++;
          continue;
        }
        const row = await superStore.get(caseId, sel.id);
        if (!row) {
          missing++;
          continue;
        }
        // Refused here as well as in promoteSuperTimeline, so the analyst is TOLD rather than
        // seeing a row silently not arrive.
        if (isLabProduced(row)) {
          lab++;
          continue;
        }
        // RAISE ONLY. worstSeverity is the canonical "more severe of the two": a model grading a
        // row below the severity it already carries can never demote it, whatever the panel sends.
        const severity = worstSeverity(row.severity, sel.grade);
        if (severity === "Info") stayedInfo++;
        toPromote.push({ ...row, severity });
        tagById[sel.id] = [reviewProvenance(sel, model)];
      }

      const after = toPromote.length
        ? await options.pipeline.promoteSuperTimeline(caseId, toPromote, {
            importedAt: new Date().toISOString(),
            intent: "missed-evidence",
            tagById,
            note: `Missed-evidence review: promoted ${toPromote.length} archive row(s) at the grade a decision model gave them`,
          })
        : state;

      // Counted from the saved state rather than from the request, so a row the promotion seam
      // refused is reported as skipped instead of claimed as promoted.
      const landed = new Set(after.forensicTimeline.map((e) => e.id));
      const promoted = toPromote.filter((e) => landed.has(e.id)).length;
      const refused = toPromote.length - promoted;
      const skipped = parsed.rows.length - promoted;

      const reasons: string[] = [];
      if (already) reasons.push(`${already} row(s) were already in the forensic timeline`);
      if (missing) reasons.push(`${missing} row(s) are no longer in the archive`);
      if (lab) reasons.push(`${lab} sandbox-produced row(s) cannot be promoted by this review`);
      if (refused) reasons.push(`${refused} row(s) were refused by the promotion seam`);
      // Said out loud, because a promoted Info row is visible to the analyst and invisible to
      // synthesis (see promptIncludesInfo in analysis/synthGroup.ts) — which looks like the feature
      // working right up until the model never mentions the row.
      if (stayedInfo) reasons.push(`${stayedInfo} row(s) stayed Info, so AI synthesis will not read them`);

      void logActivity(options.activityLogStore, options.onActivity, caseId, {
        category: "ai",
        action: "jev-promote",
        detail:
          `missed-evidence review: promoted ${promoted} archive row(s) at the grade ${model} gave them` +
          (skipped ? `; ${skipped} skipped (${reasons.join("; ")})` : ""),
      });

      return res.status(200).json({ promoted, skipped, reasons, state: freshCounts(after) });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
