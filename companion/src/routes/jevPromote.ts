import type { Express, Request, Response } from "express";
import { logActivity } from "../analysis/activityLog.js";
import { JevGradeStore, type JevGradeEntry } from "../analysis/ai/jev/jevGradeRecord.js";
import { isLabProduced } from "../analysis/labIntel.js";
import { worstSeverity, type ForensicEvent, type InvestigationState } from "../analysis/stateTypes.js";
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
 *
 * THE BROWSER SENDS IDS, AND NOTHING ELSE IS READ FROM IT (#1578). The grade, the confidence and the
 * model all come from the server's own record of what the review graded. They used to come from the
 * request body, so a tampered body — or any session at all — could write a severity no review gave
 * and tag it with a model that never saw the row. An older tab still sends those fields; they are
 * ignored rather than refused, because the ids it sends beside them are still a real selection.
 */

/** Stands in for a model id only if a stored entry somehow has none. Never a plausible-looking id. */
const UNKNOWN_MODEL = "unknown model";

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
function reviewProvenance(entry: JevGradeEntry): string {
  const confidence = Number.isFinite(entry.confidence) ? entry.confidence.toFixed(2) : "?";
  const model = entry.model.trim() || UNKNOWN_MODEL;
  return `[missed-evidence: ${entry.grade} conf ${confidence} by ${model.slice(0, MODEL_ID_MAX)}]`;
}

/**
 * Validate the selection at the boundary: a malformed tick list is refused whole rather than
 * half-promoted. Duplicate ids collapse — the same row ticked twice is one promotion, and the
 * merge would dedup it anyway. Only `id` is read from each row.
 */
function parseSelection(body: unknown): { ids: string[] } | { error: string } {
  const raw = (body as { rows?: unknown } | null | undefined)?.rows;
  if (!Array.isArray(raw) || raw.length === 0) return { error: "rows is required" };
  const ids = new Set<string>();
  for (const entry of raw) {
    const row = entry as { id?: unknown } | null;
    const id = typeof row?.id === "string" ? row.id.trim() : "";
    if (!id) return { error: "every row needs an id" };
    ids.add(id);
  }
  return { ids: [...ids] };
}

/** The counts the panel refreshes from, in the shape POST /cases/:id/synthesize already returns. */
const freshCounts = (state: InvestigationState) => ({
  forensicEvents: state.forensicTimeline.length,
  findings: state.findings.length,
  mitreTechniques: state.mitreTechniques.length,
});

export function registerJevPromoteRoutes(app: Express, ctx: RouteContext): void {
  const { store, options } = ctx;
  const grades = options.jevGradeStore ?? new JevGradeStore(store);

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

    try {
      // Each row carries the model that graded it, so a row graded by a model the settings no
      // longer name is still tagged with the model that actually graded it.
      const record = await grades.load(caseId);
      const state = await options.stateStore.load(caseId);
      const inForensic = new Set(state.forensicTimeline.map((e) => e.id));
      const toPromote: ForensicEvent[] = [];
      const tagById: Record<string, string[]> = {};
      let already = 0;
      let missing = 0;
      let lab = 0;
      let stayedInfo = 0;
      let ungraded = 0;
      const models = new Set<string>();

      for (const id of parsed.ids) {
        // Already analyzed is a no-op, not an error: the analyst ticked a row a previous press (or
        // an import) already pulled up, and failing the batch over it would lose the rest.
        if (inForensic.has(id)) {
          already++;
          continue;
        }
        // No review in this case graded the row, so there is no grade to write. The browser's word
        // for one is exactly what this route no longer takes.
        const graded = record.get(id);
        if (!graded) {
          ungraded++;
          continue;
        }
        const row = await superStore.get(caseId, id);
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
        // row below the severity it already carries can never demote it.
        const severity = worstSeverity(row.severity, graded.grade);
        if (severity === "Info") stayedInfo++;
        toPromote.push({ ...row, severity });
        tagById[id] = [reviewProvenance(graded)];
        models.add(graded.model.trim() || UNKNOWN_MODEL);
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
      const skipped = parsed.ids.length - promoted;

      const reasons: string[] = [];
      if (already) reasons.push(`${already} row(s) were already in the forensic timeline`);
      if (ungraded) reasons.push(`${ungraded} row(s) were not graded by a review in this case`);
      if (missing) reasons.push(`${missing} row(s) are no longer in the archive`);
      if (lab) reasons.push(`${lab} sandbox-produced row(s) cannot be promoted by this review`);
      if (refused) reasons.push(`${refused} row(s) were refused by the promotion seam`);
      // Said out loud, because a promoted Info row reaches synthesis only once (#1586): the next run
      // shows it as newly promoted evidence, and after that Info rows are left out of the prompt
      // again (see promptIncludesInfo in analysis/synthGroup.ts). Without this, a row the model
      // stops mentioning looks like the feature failing.
      if (stayedInfo)
        reasons.push(
          `${stayedInfo} row(s) stayed Info — the next synthesis reads them once as newly promoted evidence; after that, Info rows are not shown to it`,
        );

      void logActivity(options.activityLogStore, options.onActivity, caseId, {
        category: "ai",
        action: "jev-promote",
        detail:
          `missed-evidence review: promoted ${promoted} archive row(s) at the grade ` +
          `${models.size ? [...models].join(", ") : "the review"} gave them` +
          (skipped ? `; ${skipped} skipped (${reasons.join("; ")})` : ""),
      });

      return res.status(200).json({ promoted, skipped, reasons, state: freshCounts(after) });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
