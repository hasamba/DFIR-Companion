// Re-grade an imported case with the current Sigma rules (#2206).
//
//   GET  /cases/:id/sigma/regrade — the preview: what a re-grade would change. Writes nothing.
//        With ?release=<preview token> (#2209) it measures the STAGED, not-yet-installed release
//        instead: the same read-only preview, graded with that release's snapshot.
//   POST /cases/:id/sigma/regrade — the apply: re-grades the stored rows and reports the counts.
//
// The apply holds the case's import section (no import runs beside it) and takes the state lock
// one step at a time, never nested: (1) the super-timeline copies are rewritten by id, (2) changed
// rows are merged through the same-id merge a re-import uses (pipeline.mergeSigmaRegrade), (3) the
// fields the merge unions are replaced, (4) the forensic gate's demote removes rows now below it.
// It never promotes: no `promotedAt`, no promoted marker. It starts no synthesis (#1599) — it marks
// the conclusions out of date, as a manual promotion does. The content tagger does not re-run.
// A step that throws puts both timelines back before the section is released: the forensic rows
// from the import journal (the checkpoint Undo would build), the super copies from the plan.
//
// POST is refused in the public demo (demoModeReadOnlyGate), for a missing case
// (caseWriteExistsGate) and, below, for a closed or archived case (423).

import type { Express, Request, Response } from "express";
import type { RouteContext } from "./context.js";
import { logActivity } from "../analysis/activityLog.js";
import { resolveForensicMinSeverity } from "../analysis/forensicGate.js";
import { rewriteRows } from "../analysis/forensicRowRewrite.js";
import { sigmaImportNote, type SigmaGradingSnapshot } from "../analysis/sigmaImportGrade.js";
import {
  finalizeRegradedRow,
  regradeMergeRow,
  type RegradePlan,
  type RegradeRow,
} from "../analysis/sigmaRegrade.js";
import { sigmaRuleMitreIndex } from "../analysis/sigmaRegradeSources.js";
import { SigmaStoreError } from "../analysis/sigmaRuleStore.js";
import type { SuperRowsUndo } from "../analysis/importUndo.js";
import type { ImportBaseline } from "../analysis/importBaseline.js";
import { restoreImportBaseline } from "../analysis/importUndoRows.js";
import { frozenCaseRefusal } from "./importCaseGuard.js";
import { beginImportSection } from "./importSection.js";
import { loadRegradePlan, regradeNotes } from "./sigmaRegradePlan.js";

type Prepared = { plan: RegradePlan; snapshot: SigmaGradingSnapshot };

export function registerSigmaRegradeRoutes(app: Express, ctx: RouteContext): void {
  const { options, store: cases } = ctx;

  async function prepare(caseId: string, snapshot: SigmaGradingSnapshot): Promise<Prepared> {
    const gate = resolveForensicMinSeverity(
      options.forensicGateControlStore
        ? (await options.forensicGateControlStore.load(caseId)).minSeverity
        : undefined,
      process.env.DFIR_FORENSIC_MIN_SEVERITY,
    );
    const plan = await loadRegradePlan(
      {
        stateStore: options.stateStore!,
        superTimelineStore: options.superTimelineStore,
        importsDir: cases.importsDir(caseId),
        snapshot,
        gate,
        ruleMitre: sigmaRuleMitreIndex(snapshot.ruleSet, options.sigmaRuleStore?.lookupRuleSet()),
      },
      caseId,
    );
    return { plan, snapshot };
  }

  const summary = ({ plan, snapshot }: Prepared, staged = false) => ({
    enabled: true,
    ...(staged ? { staged: true } : {}),
    release: snapshot.ruleSet.release,
    token: snapshot.token,
    current: plan.files.length > 0 && plan.files.every((f) => f.status === "current"),
    counts: plan.counts,
    files: plan.files,
    notes: regradeNotes(plan),
  });

  const unavailable = (res: Response): boolean => {
    if (options.pipeline && options.stateStore) return false;
    res.status(501).json({ error: "re-grading needs the analysis pipeline and the state store" });
    return true;
  };

  app.get("/cases/:id/sigma/regrade", async (req: Request, res: Response) => {
    if (unavailable(res)) return;
    const caseId = req.params.id;
    try {
      if (!(await cases.caseExists(caseId)))
        return res.status(404).json({ error: `case ${caseId} not found` });
      const release = stagedToken(req.query.release);
      if (release !== undefined && !options.sigmaRuleStore)
        return res.status(501).json({ error: "Sigma rules are not configured on this server" });
      const active = options.pipeline!.sigmaSnapshot();
      if (!active) return res.json({ enabled: false, notes: ["Sigma grading is switched off."] });
      // #2209: the staged release, filtered the way it would be once installed. Read-only.
      const snapshot =
        release === undefined ? active : await options.sigmaRuleStore!.pendingSnapshot(release);
      return res.json(summary(await prepare(caseId, snapshot), release !== undefined));
    } catch (err) {
      const status = err instanceof SigmaStoreError ? err.status : 500;
      return res.status(status).json({ error: (err as Error).message });
    }
  });

  app.post("/cases/:id/sigma/regrade", async (req: Request, res: Response) => {
    if (unavailable(res)) return;
    const caseId = req.params.id;
    const refusal = await frozenCaseRefusal(cases, caseId, "re-grading its evidence");
    if (refusal) return res.status(423).json({ error: refusal });
    const snapshot = options.pipeline!.sigmaSnapshot();
    if (!snapshot)
      return res.status(409).json({ error: "Sigma grading is switched off — switch it on to re-grade" });
    const section = await beginImportSection(ctx.importLock, caseId, options.stateStore);
    try {
      const prepared = await prepare(caseId, snapshot);
      const work = prepared.plan.rows.filter((r) => r.kind !== "unchanged");
      const applied = work.length ? await applyRegrade(caseId, prepared, work, section.baseline) : undefined;
      const demoted = applied?.demoted ?? 0;
      if (work.some((r) => r.kind === "changed")) {
        const label = regradeLabel(snapshot);
        // #2220: the checkpoint carries the super copies, so Undo puts both timelines back.
        if (section.baseline)
          await ctx.pushImportCheckpoint(caseId, section.baseline, label, undefined, applied?.superRows);
        await ctx.markConclusionsOutOfDate(caseId, "Sigma re-grade"); // #1599: no run of its own
      }
      const c = prepared.plan.counts;
      void logActivity(options.activityLogStore, options.onActivity, caseId, {
        category: "triage",
        action: "sigma-regrade",
        detail: `Sigma re-grade with SigmaHQ ${snapshot.ruleSet.release}: ${c.raised} raised, ${c.lowered} lowered, ${c.unchanged} unchanged, ${demoted} left the forensic timeline`,
      });
      return res.json({ ...summary(prepared), applied: true, demoted });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    } finally {
      section.release();
    }
  });

  /**
   * The write: super copies, merge, cleanup, demote. Returns how many rows the demote removed and,
   * when super rows were rewritten, their before and after copies for the undo checkpoint (#2220).
   * When a step throws, both timelines are put back to `baseline` and the error is rethrown.
   */
  async function applyRegrade(
    caseId: string,
    prepared: Prepared,
    work: RegradeRow[],
    baseline: ImportBaseline | null,
  ): Promise<{ demoted: number; superRows?: SuperRowsUndo }> {
    const rehomed = work.flatMap((r) => (r.super ? [r.super] : []));
    let superRows: SuperRowsUndo | undefined;
    try {
      if (rehomed.length && options.superTimelineStore) {
        // Set first: a partial super write is rolled back as well.
        superRows = { restore: rehomed.map((s) => s.before), reapply: rehomed.map((s) => s.after) };
        await options.superTimelineStore.rehome(caseId, superRows.reapply);
        options.onSuperTimeline?.(caseId);
      }
      const demoted = await writeForensic(caseId, prepared, work);
      return { demoted, ...(superRows ? { superRows } : {}) };
    } catch (err) {
      await rollBack(caseId, baseline, superRows);
      throw err;
    }
  }

  /** The forensic half of the write: merge, cleanup, demote. Returns how many rows left. */
  async function writeForensic(caseId: string, { plan, snapshot }: Prepared, work: RegradeRow[]) {
    const stateStore = options.stateStore!;
    const merged = work.filter((r) => r.kind === "changed" && (r.forensic || r.entersForensic));
    const c = plan.counts;
    await options.pipeline!.mergeSigmaRegrade(caseId, merged.map(regradeMergeRow), {
      label: regradeLabel(snapshot),
      at: new Date().toISOString(),
      note:
        `Sigma re-grade: ${c.raised} row(s) raised, ${c.lowered} lowered, ${c.unchanged} unchanged` +
        sigmaImportNote(
          snapshot,
          plan.rows.filter((r) =>
            /Sigma rule: /.test(r.forensic?.after.message ?? r.super?.after.message ?? ""),
          ).length,
        ),
    });
    const planned = new Map(work.map((r) => [r.id, r]));
    await ctx.runStateExclusive(caseId, async () => {
      const rows = await stateStore.forensicRowsById(caseId, [...planned.keys()]);
      await rewriteRows(stateStore, caseId, rows, (e) => {
        const r = planned.get(e.id);
        if (!r) return e;
        const lifted = !r.forensic && r.super ? r.super.before : undefined;
        return finalizeRegradedRow(e, (r.forensic ?? r.super)!.after, lifted);
      });
    });
    const demoted = await ctx.demoteForensic(caseId);
    options.onStateChanged?.(caseId);
    return demoted.length;
  }

  /**
   * Undo a failed apply in place (#2206): the forensic timeline from the armed import journal, then
   * the super copies the plan read. Each half runs even when the other fails; a half that cannot be
   * put back is logged, never hidden. The caller still answers with the original error.
   */
  async function rollBack(caseId: string, baseline: ImportBaseline | null, superRows?: SuperRowsUndo) {
    const fail = (what: string, why: string) =>
      ctx.serverLogger.error(`[sigma-regrade] case=${caseId} apply failed and ${what} (${why})`);
    try {
      const restored =
        baseline &&
        (await ctx.runStateExclusive(caseId, () => restoreImportBaseline(options.stateStore!, baseline)));
      if (!restored) fail("the forensic timeline could not be put back", "no import journal");
    } catch (err) {
      fail("the forensic timeline could not be put back", (err as Error).message);
    }
    options.onStateChanged?.(caseId);
    if (!superRows || !options.superTimelineStore) return;
    try {
      await options.superTimelineStore.rehome(caseId, superRows.restore);
    } catch (err) {
      fail("the super-timeline rows could not be put back", (err as Error).message);
    }
    options.onSuperTimeline?.(caseId);
  }
}

/** The `release` query value: a preview token, or undefined when absent. Only ever a lookup key. */
function stagedToken(raw: unknown): string | undefined {
  if (raw === undefined) return undefined;
  return typeof raw === "string" ? raw.slice(0, 200) : "";
}

function regradeLabel(snapshot: SigmaGradingSnapshot): string {
  return `Sigma re-grade (SigmaHQ ${snapshot.ruleSet.release})`;
}
