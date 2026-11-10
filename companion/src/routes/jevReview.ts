import type { Express, Request, Response } from "express";
import { CaseKeyedSet } from "../storage/caseKeyedState.js";
import { logActivity } from "../analysis/activityLog.js";
import { assertAnonRevision } from "../analysis/anonRevision.js";
import { askJev } from "../analysis/ai/jev/jevClient.js";
import { describeJevKeySource, resolveJevSettings, type JevSettings } from "../analysis/ai/jev/jevConfig.js";
import { gradeEvents, type JevReviewSpend } from "../analysis/ai/jev/jevGrader.js";
import { createDecisionModelCatalog } from "../analysis/ai/jev/decisionModels.js";
import { JevGradeStore } from "../analysis/ai/jev/jevGradeRecord.js";
import { getServerLogger } from "../logging/serverLogger.js";
import { markAiBudgetUnspent } from "../http/rateLimiter.js";
import type { RouteContext } from "./context.js";
import { jevMasking } from "./jevMasking.js";
import { reviewCaseContext, selectReviewRows } from "./jevReviewPrepare.js";
import { jevPresidioCheck, sendJevPresidioStop } from "./jevPresidioGate.js";
import { runAsRouteJob, type RecordRouteJobFailure } from "./routeJob.js";

/**
 * The Jev second-grader review (#1540) — READ ONLY, analyst-pressed.
 *
 * Grades the archive rows the content tagger left at Info, which never reach the forensic timeline
 * and so are invisible to synthesis. It promotes NOTHING and writes no investigation state. It
 * persists two things: the run's cost, into the existing per-case cost store, and the grades
 * themselves, into the review grade record (analysis/ai/jev/jevGradeRecord.ts). The promote route
 * reads a row's grade from that record, never from the browser (#1578).
 *
 * It reads the raw record, so it carries the same three bounds viewSummary carries: analyst
 * initiated, ephemeral, and capped with the truncation disclosed. See ARCHITECTURE.md, "The
 * forensic / super-timeline boundary", and tests/analysis/forensicBoundary.test.ts, which pins
 * every clause.
 *
 * The analyst CAN act on what it finds, but never from here: ticking rows and promoting them is
 * POST /cases/:id/jev/promote, in routes/jevPromote.ts. The two halves are separate modules so
 * that "the grading pass promotes nothing" stays a property of this file and not a promise.
 */
/** Shown as-is by the panel, after "The review did not run: ". */
const REVIEW_RUNNING = "a missed-evidence review of this case is already running — wait for it to finish";

/** One per process: the catalog is the same for every case and its cache is the point. */
const sharedDecisionModelCatalog = createDecisionModelCatalog();

export function registerJevReviewRoutes(app: Express, ctx: RouteContext): void {
  const { store, options } = ctx;
  const grades = options.jevGradeStore ?? new JevGradeStore(store);

  // Not case-scoped: the settings screen asks this before any case is open, so it can say whether
  // the key field may be left blank instead of promising an inheritance that may not exist (#1547).
  // It answers with the NAME of the setting a key would come from and never with a key.
  app.get("/settings/jev/key-source", (_req: Request, res: Response) => res.json(describeJevKeySource()));

  // The Settings model picker's list (#2224): OpenRouter's decision models only, fetched and cached
  // by the server because the page's CSP keeps the browser off openrouter.ai. Free and keyless, so
  // it is not an AI call and is not budgeted as one.
  const catalog = options.decisionModelCatalog ?? sharedDecisionModelCatalog;
  app.get("/settings/jev/models", async (_req: Request, res: Response) => {
    try {
      return res.json(await catalog.list());
    } catch (err) {
      const detail = err instanceof Error ? err.message : String(err);
      getServerLogger().warn(`[decision-model] model list unavailable — ${detail}`);
      return res.status(502).json({ error: `Could not load the decision model list: ${detail}` });
    }
  });

  app.get("/cases/:id/jev/status", (_req: Request, res: Response) => {
    const resolved = resolveJevSettings();
    if (!resolved.settings) return res.json({ configured: false, reason: resolved.reason });
    if (!options.superTimelineStore) {
      return res.json({ configured: false, reason: "The super-timeline is not configured." });
    }
    return res.json({ configured: true, model: resolved.settings.model });
  });

  // Cases with a review in flight. Every run bills the analyst, so a double-click or a second tab
  // must not buy the same review twice (#1551). Held per app, so one test's app never locks another's.
  const running = new CaseKeyedSet(() => ctx.store.casesRoot); // per case incarnation (#1866)

  app.post("/cases/:id/jev/review", async (req: Request, res: Response) => {
    const caseId = req.params.id;
    const resolved = resolveJevSettings();
    if (!resolved.settings) return res.status(501).json({ error: resolved.reason });
    if (!options.superTimelineStore || !options.stateStore) {
      return res.status(501).json({ error: "super-timeline not configured" });
    }
    // BEFORE either store is touched: opening the per-case database creates the case directory, so
    // a typo'd id would otherwise leave a case on disk that nobody made (#1549).
    if (!(await store.getCaseMeta(caseId).catch(() => null))) {
      return res.status(404).json({ error: "case not found" });
    }
    if (running.has(caseId)) {
      return res.status(409).json({ error: REVIEW_RUNNING });
    }
    running.add(caseId);
    // The finally covers every await after entry, so a store that throws never leaves the case locked.
    // #2425: a job — in the Jobs panel, "busy", and in the case's one-job slot. Not cancellable.
    const settings = resolved.settings;
    const job = { caseId, kind: "jev-review" as const, label: "missed-evidence review" };
    try {
      return await runAsRouteJob(
        options.jobManager,
        res,
        { ...job, model: { model: settings.model, provider: "jev" } },
        "jev_review_failed",
        (recordFailure) => review(req, res, caseId, settings, recordFailure),
      );
    } finally {
      running.delete(caseId);
    }
  });

  async function review(
    req: Request,
    res: Response,
    caseId: string,
    settings: JevSettings,
    recordFailure: RecordRouteJobFailure,
  ): Promise<Response> {
    // The rows a review reads, and what it sets aside — shared with the AI preview (#2515).
    const { state, candidates, coverage } = await selectReviewRows(options, caseId, settings, req.body ?? {});
    const total = coverage.matched;
    const collectorFootprint = coverage.collectorFootprint;

    if (!candidates.length) {
      if (coverage.buildWindow || collectorFootprint)
        void logActivity(options.activityLogStore, options.onActivity, caseId, {
          category: "ai",
          action: "jev-review",
          detail:
            `missed-evidence review graded nothing: ` +
            (coverage.buildWindow
              ? `${coverage.buildWindow} archive row(s) sit inside the host's own build window and were set aside, `
              : "") +
            (collectorFootprint ? `${collectorFootprint} set aside: collector footprint, ` : "") +
            `${coverage.alreadyAnalyzed} already analyzed`,
        });
      markAiBudgetUnspent(res); // nothing sent to Jev: the AI-budget slot goes back (#1825)
      return res.json({
        model: settings.model,
        rows: [],
        ...coverage,
        usage: { inputTokens: 0, outputTokens: 0 },
      });
    }

    // The shared masking step (#2515) — the same (known entities, anonymizer) pair every chat model
    // sits behind; the identity function when the analyst turned masking off for this case.
    // #1840: the review masks every batch with this one snapshot, so it records the revision the
    // snapshot was built at (read BEFORE the lists load) and holds any batch that would leave after
    // a Hide or a settings change. Batches already sent cannot be recalled; the rest are not sent.
    const { maskedAt, masker } = await jevMasking(store, caseId, state);
    const mask = masker.mask;
    // The Presidio gate on each masked batch, right before it leaves (#1952).
    const presidioCheck = jevPresidioCheck(options, caseId, masker);

    // The analyst's choice in Settings (DFIR_JEV_GRADING), read per request like every Jev setting.
    const shape = settings.shape;
    // #2235: what a review that halts part way already spent, so the catch can put it on the ledger.
    let spentBeforeHalt: JevReviewSpend | undefined;
    try {
      // The analyst's own authorized/known-good records (#1924), masked like the rows. Read only when
      // the decomposed shape will ask about them, and inside the try: a damaged marker file must not
      // break a single-shape review that never reads it.
      const caseContext = await reviewCaseContext(store, caseId, shape, mask);
      const result = await gradeEvents(
        {
          mask,
          ask: (jevState, questions, halted) =>
            presidioCheck(jevState).then(() =>
              askJev(
                {
                  baseUrl: settings.baseUrl,
                  model: settings.model,
                  apiKey: settings.apiKey,
                  timeoutMs: settings.timeoutMs,
                  // Before every attempt, retries included: a retry resends the same masked body.
                  // #2224: and once another batch of this review has failed, nothing more is sent.
                  beforeSend: () => {
                    if (halted()) throw new Error("review halted after an earlier batch failed");
                    assertAnonRevision(caseId, maskedAt, "the missed-evidence review");
                  },
                },
                jevState,
                questions,
              ),
            ),
        },
        candidates,
        {
          batchSize: settings.batchSize,
          shape,
          caseContext,
          onSpendOnFailure: (spend) => (spentBeforeHalt = spend),
        },
      );

      await recordJevSpend(options, caseId, result, settings.model);

      // AFTER the cost, so money already spent is on the books whatever happens next. BEFORE the
      // answer, and a failure here is the whole answer: grades the analyst can see and tick but the
      // promote route cannot find would turn every tick into a "not graded" skip, and a table that
      // cannot be acted on is worse than an error that says why.
      try {
        await grades.record(caseId, result.model, result.rows);
      } catch (err) {
        recordFailure(err);
        const detail = err instanceof Error ? err.message : String(err);
        getServerLogger().error(`[jev] ${caseId}: review grades not saved — ${detail}`, { caseId });
        return res.status(500).json({
          error: `The review ran, but its grades could not be saved, so none of them can be promoted: ${detail}`,
        });
      }

      const promoted = result.rows.filter((r) => r.grade !== "Info").length;
      void logActivity(options.activityLogStore, options.onActivity, caseId, {
        category: "ai",
        action: "jev-review",
        detail:
          `missed-evidence review graded ${coverage.graded} archive row(s) of ${total} matching ` +
          `(${coverage.alreadyAnalyzed} already analyzed` +
          (coverage.buildWindow ? `, ${coverage.buildWindow} set aside: host build window` : "") +
          (collectorFootprint ? `, ${collectorFootprint} set aside: collector footprint` : "") +
          (coverage.capped ? `, ${total - coverage.read} not read: row cap` : "") +
          `); ${promoted} above Info — nothing was promoted`,
      });

      return res.json({ ...result, ...coverage, shape });
    } catch (err) {
      recordFailure(err); // the job holds on a Presidio approval, and fails otherwise (#2425)
      // Before either answer: the requests that did run were billed whichever way the review stopped.
      if (spentBeforeHalt) await recordJevSpend(options, caseId, spentBeforeHalt, settings.model);
      if (sendJevPresidioStop(res, err, caseId, options)) return res;
      const detail = err instanceof Error ? err.message : String(err);
      getServerLogger().warn(`[jev] ${caseId}: review failed — ${detail}`, { caseId });
      return res.status(502).json({ error: `Decision model review failed: ${detail}` });
    }
  }
}

/**
 * Put a review's spend on the per-case cost ledger, best effort (#2235) — the contract providerCall
 * keeps for every chat-model call. The ledger is diagnostics-only: a failed write is logged, and
 * never turns a review the analyst already paid for into an error.
 */
async function recordJevSpend(
  options: RouteContext["options"],
  caseId: string,
  spend: Pick<JevReviewSpend, "model" | "usage">,
  fallbackModel: string,
): Promise<void> {
  try {
    await options.aiCostStore?.record(caseId, "other", "jev", spend.model || fallbackModel, {
      inputTokens: spend.usage.inputTokens,
      outputTokens: spend.usage.outputTokens,
      ...(spend.usage.costUSD !== undefined ? { costUSD: spend.usage.costUSD } : {}),
    });
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    getServerLogger().warn(`[jev] ${caseId}: review cost not recorded — ${detail}`, { caseId });
  }
}
