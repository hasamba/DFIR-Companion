import type { Express, Request, Response } from "express";
import { logActivity } from "../analysis/activityLog.js";
import { buildImportAnonContext } from "../analysis/ai/providerCall.js";
import { askJev } from "../analysis/ai/jev/jevClient.js";
import { describeJevKeySource, resolveJevSettings, type JevSettings } from "../analysis/ai/jev/jevConfig.js";
import { gradeEvents } from "../analysis/ai/jev/jevGrader.js";
import { JevGradeStore } from "../analysis/ai/jev/jevGradeRecord.js";
import { getServerLogger } from "../logging/serverLogger.js";
import type { SuperQuery } from "../analysis/superTimeline.js";
import { rowsInBuildWindow } from "./jevBuildWindow.js";
import type { ForensicEvent } from "../analysis/stateTypes.js";
import type { RouteContext } from "./context.js";

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
/**
 * A single super-timeline query is ceilinged by the store, so reading more than one page means
 * paging. Stops at `cap` rows, or when the matched total is in hand, or when a page comes back
 * empty — that last guard is what keeps a filter whose total disagrees with its rows from looping.
 */
const SUPER_PAGE_ROWS = 2000;

async function readMatchingRows(
  store: NonNullable<RouteContext["options"]["superTimelineStore"]>,
  caseId: string,
  filters: SuperQuery,
  cap: number,
): Promise<{ events: ForensicEvent[]; total: number }> {
  const events: ForensicEvent[] = [];
  let total = 0;
  for (;;) {
    const want = Math.min(SUPER_PAGE_ROWS, cap - events.length);
    if (want <= 0) break;
    const page = await store.query(caseId, { ...filters, offset: events.length, limit: want });
    total = page.total;
    if (!page.events.length) break;
    events.push(...page.events);
    if (events.length >= total) break;
  }
  return { events, total };
}

/** Shown as-is by the panel, after "The review did not run: ". */
const REVIEW_RUNNING = "a missed-evidence review of this case is already running — wait for it to finish";

export function registerJevReviewRoutes(app: Express, ctx: RouteContext): void {
  const { store, options } = ctx;
  const grades = options.jevGradeStore ?? new JevGradeStore(store);

  // Not case-scoped: the settings screen asks this before any case is open, so it can say whether
  // the key field may be left blank instead of promising an inheritance that may not exist (#1547).
  // It answers with the NAME of the setting a key would come from and never with a key.
  app.get("/settings/jev/key-source", (_req: Request, res: Response) => res.json(describeJevKeySource()));

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
  const running = new Set<string>();

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
    try {
      return await review(req, res, caseId, resolved.settings);
    } finally {
      running.delete(caseId);
    }
  });

  async function review(
    req: Request,
    res: Response,
    caseId: string,
    settings: JevSettings,
  ): Promise<Response> {
    const superStore = options.superTimelineStore!;
    const stateStore = options.stateStore!;

    // `all` is the analyst saying "read every row, never mind the cap". Everything else caps at
    // the configured default. One query cannot answer either: the store ceilings a single page, so
    // a full read pages until the matched total is in hand.
    const readAll = req.body?.all === true;
    const requested = Number(req.body?.limit);
    const cap = readAll
      ? Number.POSITIVE_INFINITY
      : Math.min(
          settings.maxRows,
          Number.isFinite(requested) && requested > 0 ? Math.floor(requested) : Number.POSITIVE_INFINITY,
        );
    const capForWire = Number.isFinite(cap) ? cap : settings.maxRows;
    const filters: SuperQuery = { ...(req.body?.filters ?? {}) };

    const state = await stateStore.load(caseId);
    const { events: read, total } = await readMatchingRows(superStore, caseId, filters, cap);

    // Rows already in the forensic timeline are the ones synthesis can ALREADY see. Reviewing them
    // would spend the analyst's money re-grading what is not missing.
    const analyzed = new Set(state.forensicTimeline.map((e) => e.id));
    const unanalyzed = read.filter((e) => !analyzed.has(e.id));
    // Rows inside the host's own build window are the machine being built (#1529). The grader is not
    // told that, so it grades a Chocolatey firewall change Medium and a provisioning log clear Critical
    // (#1700). They are set aside here, before anything is spent, and counted so the sum still closes.
    const inBuild = await rowsInBuildWindow(superStore, caseId, state, unanalyzed);
    const candidates = unanalyzed.filter((e) => !inBuild.has(e.id));

    // Coverage, as four facts rather than one flag. `capped` is the ONLY one that may blame the
    // cap, and it is true only when the cap actually held rows back: an earlier version inferred
    // truncation from "graded < matched" and told an analyst the cap had stopped a read of 1,344
    // rows against a 2,000 cap, when the shortfall was 366 rows already in the forensic timeline.
    const coverage = {
      matched: total,
      read: read.length,
      alreadyAnalyzed: read.length - unanalyzed.length,
      buildWindow: inBuild.size,
      graded: candidates.length,
      capped: read.length < total,
      cap: capForWire,
      readAll,
    };

    if (!candidates.length) {
      if (inBuild.size)
        void logActivity(options.activityLogStore, options.onActivity, caseId, {
          category: "ai",
          action: "jev-review",
          detail:
            `missed-evidence review graded nothing: ${inBuild.size} archive row(s) sit inside the ` +
            `host's own build window and were set aside, ${coverage.alreadyAnalyzed} already analyzed`,
        });
      return res.json({
        model: settings.model,
        rows: [],
        ...coverage,
        usage: { inputTokens: 0, outputTokens: 0 },
      });
    }

    // The same (known entities, anonymizer) pair every chat model sits behind. Null means the
    // analyst turned masking off for this case; the identity function is then the honest mask.
    const anon = await buildImportAnonContext({ log: getServerLogger(), opts: options }, caseId, state);
    const mask = anon ? (text: string) => anon.anon.apply(text) : (text: string) => text;

    try {
      const result = await gradeEvents(
        {
          mask,
          ask: (jevState, questions) =>
            askJev(
              {
                baseUrl: settings.baseUrl,
                model: settings.model,
                apiKey: settings.apiKey,
                timeoutMs: settings.timeoutMs,
              },
              jevState,
              questions,
            ),
        },
        candidates,
        { batchSize: settings.batchSize },
      );

      await options.aiCostStore?.record(caseId, "other", "jev", result.model, {
        inputTokens: result.usage.inputTokens,
        outputTokens: result.usage.outputTokens,
        ...(result.usage.costUSD !== undefined ? { costUSD: result.usage.costUSD } : {}),
      });

      // AFTER the cost, so money already spent is on the books whatever happens next. BEFORE the
      // answer, and a failure here is the whole answer: grades the analyst can see and tick but the
      // promote route cannot find would turn every tick into a "not graded" skip, and a table that
      // cannot be acted on is worse than an error that says why.
      try {
        await grades.record(caseId, result.model, result.rows);
      } catch (err) {
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
          (coverage.capped ? `, ${total - coverage.read} not read: row cap` : "") +
          `); ${promoted} above Info — nothing was promoted`,
      });

      return res.json({ ...result, ...coverage });
    } catch (err) {
      const detail = err instanceof Error ? err.message : String(err);
      getServerLogger().warn(`[jev] ${caseId}: review failed — ${detail}`, { caseId });
      return res.status(502).json({ error: `Jev review failed: ${detail}` });
    }
  }
}
