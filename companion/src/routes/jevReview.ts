import type { Express, Request, Response } from "express";
import { logActivity } from "../analysis/activityLog.js";
import { buildImportAnonContext } from "../analysis/ai/providerCall.js";
import { askJev } from "../analysis/ai/jev/jevClient.js";
import { describeJevKeySource, resolveJevSettings } from "../analysis/ai/jev/jevConfig.js";
import { gradeEvents } from "../analysis/ai/jev/jevGrader.js";
import { getServerLogger } from "../logging/serverLogger.js";
import type { SuperQuery } from "../analysis/superTimeline.js";
import type { ForensicEvent } from "../analysis/stateTypes.js";
import type { RouteContext } from "./context.js";

/**
 * The Jev second-grader review (#1540) — READ ONLY, analyst-pressed.
 *
 * Grades the archive rows the content tagger left at Info, which never reach the forensic timeline
 * and so are invisible to synthesis. It promotes NOTHING and writes no case state; the only thing
 * it persists is the run's cost, into the existing per-case cost store.
 *
 * It reads the raw record, so it carries the same three bounds viewSummary carries: analyst
 * initiated, ephemeral, and capped with the truncation disclosed. See ARCHITECTURE.md, "The
 * forensic / super-timeline boundary", and tests/analysis/forensicBoundary.test.ts, which pins
 * every clause.
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

export function registerJevReviewRoutes(app: Express, ctx: RouteContext): void {
  const { options } = ctx;

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

  app.post("/cases/:id/jev/review", async (req: Request, res: Response) => {
    const caseId = req.params.id;
    const resolved = resolveJevSettings();
    if (!resolved.settings) return res.status(501).json({ error: resolved.reason });
    if (!options.superTimelineStore || !options.stateStore) {
      return res.status(501).json({ error: "super-timeline not configured" });
    }
    const settings = resolved.settings;

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

    const state = await options.stateStore.load(caseId);
    const { events: read, total } = await readMatchingRows(options.superTimelineStore, caseId, filters, cap);

    // Rows already in the forensic timeline are the ones synthesis can ALREADY see. Reviewing them
    // would spend the analyst's money re-grading what is not missing.
    const analyzed = new Set(state.forensicTimeline.map((e) => e.id));
    const candidates = read.filter((e) => !analyzed.has(e.id));

    // Coverage, as four facts rather than one flag. `capped` is the ONLY one that may blame the
    // cap, and it is true only when the cap actually held rows back: an earlier version inferred
    // truncation from "graded < matched" and told an analyst the cap had stopped a read of 1,344
    // rows against a 2,000 cap, when the shortfall was 366 rows already in the forensic timeline.
    const coverage = {
      matched: total,
      read: read.length,
      alreadyAnalyzed: read.length - candidates.length,
      graded: candidates.length,
      capped: read.length < total,
      cap: capForWire,
      readAll,
    };

    if (!candidates.length) {
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

      const promoted = result.rows.filter((r) => r.grade !== "Info").length;
      void logActivity(options.activityLogStore, options.onActivity, caseId, {
        category: "ai",
        action: "jev-review",
        detail:
          `missed-evidence review graded ${coverage.graded} archive row(s) of ${total} matching ` +
          `(${coverage.alreadyAnalyzed} already analyzed` +
          (coverage.capped ? `, ${total - coverage.read} not read: row cap` : "") +
          `); ${promoted} above Info — nothing was promoted`,
      });

      return res.json({ ...result, ...coverage });
    } catch (err) {
      const detail = err instanceof Error ? err.message : String(err);
      getServerLogger().warn(`[jev] ${caseId}: review failed — ${detail}`, { caseId });
      return res.status(502).json({ error: `Jev review failed: ${detail}` });
    }
  });
}
