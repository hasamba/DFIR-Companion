import type { Express, Request, Response } from "express";
import { clientGone, requestAbortSignal } from "../http/requestAbort.js";
import { abortError, isAbortError } from "../analysis/abortable.js";
import { CaseKeyedSet } from "../storage/caseKeyedState.js";
import { logActivity } from "../analysis/activityLog.js";
import { isAnalystDecisionGate, sendPipelineError } from "./presidioApproval.js";
import type { RouteContext } from "./context.js";
import { caseOpenStateOf } from "./caseOpenState.js";

/**
 * The second look (#1554) — analyst-pressed.
 *
 * It re-queries the raw record for the terms the case's open questions imply, promotes what it
 * finds into the forensic timeline with provenance tags, and re-synthesises so the conclusions
 * account for it. Until now it ran on its own at the tail of every synthesis, which made it the one
 * automatic writer to the evidence record. A tool used in real investigations should not have one.
 *
 * A request/response that RUNS AS A JOB (#2407). The sweep makes zero AI calls, but the forced
 * re-synthesis is a full synthesis, and with no job it ran beside whatever synthesis the case
 * already had — the later one overwriting the earlier. The job takes the case's one-job slot (the
 * durable ledger admits one job per case at a time), shows in the Jobs panel, and counts as "busy".
 *
 * Cancellable at safe points (#2425). A cancel frees the slot at once, so Cancel is CLOSED while the
 * promotion writes rows (`guardWrite`, below) and open everywhere else: while queued, during the
 * sweep (read-only), and during the re-synthesis, which stops on the job's signal like any
 * cancellable synthesis. A run that promoted rows and then did not finish (failed, held at an
 * analyst gate, or cancelled) marks the conclusions out of date before the job reports its end.
 */
export function registerSecondLookRoutes(app: Express, ctx: RouteContext): void {
  const { store, options, markConclusionsOutOfDate } = ctx;

  // A case with no super-timeline has no raw record to re-query, so the button has nothing to offer.
  // 501 is the same answer the Jev review gives for the same missing store.
  const unconfigured = (res: Response): Response =>
    res.status(501).json({ error: "super-timeline not configured" });

  app.get("/cases/:id/second-look/preview", async (req: Request, res: Response) => {
    if (!options.pipeline || !options.superTimelineStore) return unconfigured(res);
    const caseId = req.params.id;
    if (!(await store.getCaseMeta(caseId).catch(() => null))) {
      return res.status(404).json({ error: "case not found" });
    }
    try {
      const preview = await options.pipeline.secondLookPreview(
        caseId,
        requestAbortSignal(res),
        caseOpenStateOf(ctx),
      );
      if (clientGone(res)) return; // #2121
      if (!preview.configured) return unconfigured(res);
      return res.status(200).json(preview);
    } catch (error) {
      return clientGone(res) ? undefined : res.status(500).json({ error: String((error as Error).message) });
    }
  });

  // Cases with a second look in flight (#1576). The re-synthesis is FORCED, so two overlapping
  // presses would each plan the same promotions from the pre-promotion state and each pay for a full
  // synthesis. The Jev review holds the same guard for the same reason (#1551). Held per app, so one
  // test's app never locks another's.
  const running = new CaseKeyedSet(() => ctx.store.casesRoot); // #1866: per case incarnation

  app.post("/cases/:id/second-look", async (req: Request, res: Response) => {
    if (!options.pipeline || !options.superTimelineStore) return unconfigured(res);
    const caseId = req.params.id;
    const caseMeta = await store.getCaseMeta(caseId).catch(() => null);
    if (!caseMeta) return res.status(404).json({ error: "case not found" });
    if (caseMeta.status === "closed" || caseMeta.status === "archived") {
      const action = caseMeta.status === "archived" ? "restore it" : "reopen it";
      return res.status(423).json({
        error: `Case "${caseId}" is ${caseMeta.status} — ${action} before running a second look`,
      });
    }

    // DEFAULTS TO TRUE, and only an explicit `false` turns it off. Promoting evidence and leaving
    // the conclusions that were written before it arrived is a case that disagrees with itself; a
    // missing, misspelled or non-boolean field must never be what produces that state.
    const resynthesize = (req.body as { resynthesize?: unknown })?.resynthesize !== false;

    // Refuse BEFORE the sweep. The sweep writes promoted rows into the forensic timeline, and a
    // re-synthesis that then threw for want of a provider answered "did not run" over a record it
    // had already changed. The opt-out needs no AI, so the refusal names it (the checkbox label).
    if (resynthesize && !options.pipeline.hasSynthesisProvider()) {
      return res.status(501).json({
        error:
          'Re-synthesis needs an AI provider. Untick "Re-synthesise afterwards" to promote the rows only.',
      });
    }

    if (running.has(caseId)) {
      return res.status(409).json({ error: "a second look is already running for this case" });
    }
    running.add(caseId);
    let job: { jobId: string; ready: Promise<void>; signal?: AbortSignal } | undefined;
    let promotionStarted = false;
    let promoted = 0;
    // The finally covers every await after entry, so a run that throws never leaves the case locked.
    try {
      job = options.jobManager?.register({
        caseId,
        kind: "second-look",
        label: resynthesize ? "second look + re-synthesis" : "second look",
        cancellable: true,
        parameters: { resynthesize },
      });
      await job?.ready; // a cancel while queued rejects this with an AbortError → 499 below
      const result = await options.pipeline.secondLook(caseId, {
        resynthesize,
        ...(job?.signal ? { signal: job.signal } : {}),
        guardWrite: (write) => guardPromotion(ctx, job, write),
        onPromotionStarted: (count) => {
          promotionStarted = true;
          promoted = count;
        },
      });
      if (!result) {
        if (job) await options.jobManager?.finish(job.jobId);
        return unconfigured(res);
      }
      promoted = result.promoted;
      // Promoted rows the conclusions never saw: say so on the AI chip (#1599). A re-synthesis
      // already refreshed them, so only the opt-out path marks. Before finish(): the job reports its
      // end only after its last case write.
      if (result.promoted > 0 && !result.resynthesized) {
        await markConclusionsOutOfDate(caseId, "rows promoted by second look");
      }
      if (job) await options.jobManager?.finish(job.jobId);
      void logActivity(options.activityLogStore, options.onActivity, caseId, {
        category: "ai",
        action: "second-look",
        detail:
          `second look promoted ${result.promoted} raw event(s) from ${result.leads.length} unresolved ` +
          `lead(s)` +
          (result.shapeCapped ? `; ${result.shapeCapped} repeat row(s) held back` : "") +
          (result.truncated ? "; sweep cap reached" : "") +
          (result.resynthesized ? " — conclusions re-synthesized" : " — conclusions NOT re-synthesized"),
      });
      return res.status(200).json(result);
    } catch (error) {
      // #2425: rows may already be in the forensic timeline (promotion started, even if it threw
      // after saving). The conclusions do not account for them, so say so before the job ends.
      if (promotionStarted) {
        await markConclusionsOutOfDate(caseId, "rows promoted by second look; re-synthesis did not finish");
      }
      // The re-synthesis inherits the host-merge gate, so a held case reaches here as a decision
      // gate rather than a failure. Report the hold, the way the deep-pass route does.
      if (isAnalystDecisionGate(error)) {
        if (job) await options.jobManager?.hold(job.jobId, String((error as Error).message));
        return sendPipelineError(res, error);
      }
      if (isAbortError(error) || job?.signal?.aborted) {
        // finish() is a no-op on the cancelled row; it reports the work's end (#1831).
        if (job) await options.jobManager?.finish(job.jobId);
        return res.status(499).json({ error: cancelledMessage(promoted), promoted });
      }
      if (job) await options.jobManager?.fail(job.jobId, error, { code: "second_look_failed" });
      return res.status(500).json({ error: String((error as Error).message), promoted });
    } finally {
      running.delete(caseId);
    }
  });
}

/**
 * The promotion's write, with Cancel closed around it (#2425). Closing and checking the signal run
 * in one synchronous turn — no await between them — which makes the pair atomic with
 * JobManager.cancel(): either the cancel already landed (throw, nothing written) or it is refused
 * until the write is done. Re-opened afterwards, so the re-synthesis can be stopped.
 */
async function guardPromotion<T>(
  ctx: RouteContext,
  job: { jobId: string; signal?: AbortSignal } | undefined,
  write: () => Promise<T>,
): Promise<T> {
  const manager = ctx.options.jobManager;
  if (!job || !manager) return write();
  manager.setCancellable(job.jobId, false);
  if (job.signal?.aborted) throw abortError();
  try {
    return await write();
  } finally {
    manager.setCancellable(job.jobId, true);
  }
}

function cancelledMessage(promoted: number): string {
  if (promoted === 0) return "second look cancelled — nothing was promoted";
  return (
    `second look cancelled — ${promoted} raw event(s) were already promoted; the re-synthesis did ` +
    "not finish, so the conclusions are marked out of date"
  );
}
