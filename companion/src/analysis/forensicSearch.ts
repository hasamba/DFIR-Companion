import type { EntityPage, EntityQuery, InvestigationStateStorage } from "./stateStore.js";
import { eventMatchesSearch } from "./searchFilter.js";
import { searchLikePattern, searchPrefilterPlan, type SearchPrefilterPlan } from "./searchFoldPrefilter.js";
import type { ForensicEvent } from "./stateTypes.js";

// Rows pulled per round-trip while scanning for matches. Only rows whose raw JSON already contains
// the term reach this stage, so a batch is normally far smaller than the cap.
const SCAN_BATCH = 1000;
const DEFAULT_LIMIT = 500;
/**
 * How far the exact match count will go before it gives up and reports a lower bound.
 *
 * Measured on a 100,000-event case (single term, limit 200): a rare term answers in 1.2s and an
 * absent one in 1.2s, because the LIKE prefilter rejects almost everything and nothing is parsed.
 * A term that matches EVERY event took 13.6s — and the same query with includeTotal:false took
 * 239ms. So the cost is not the search, it is insisting on an exact total: that pass parses every
 * candidate payload, ~12s of the 13.6s.
 *
 * A search matching 100,000 events is not one the analyst reads to the end, so counting past this
 * buys nothing and costs everything. Past the ceiling the page reports totalIsLowerBound, and the
 * caller should render it as "10,000+" rather than as a total.
 */
const TOTAL_CEILING = 10_000;

// The LIKE pattern builder moved with the rest of the prefilter planning (#1914); re-exported
// because callers and tests know it by this module.
export { searchLikePattern };

/**
 * Full-text search over the WHOLE forensic timeline (#928), not just a page of it.
 *
 * The dashboard used to filter the events it had already fetched, which quietly meant "search the
 * first 10,000" — on a larger case the analyst was shown no results for evidence that had never
 * been sent to the browser. Search has to be a question the case answers, not a filter over
 * whatever happened to be loaded.
 *
 * Two-stage on purpose, and the split follows the layering. The STORE knows only how to prefilter
 * with LIKE over the raw JSON payload: a full scan, but one that happens in C and parses nothing.
 * Which FIELDS are searchable is an analysis question, so eventMatchesSearch decides it here — and
 * that is what keeps a term that only appears as a JSON key ("description", "severity") from
 * matching, where the raw LIKE alone would have handed back the entire case.
 *
 * This is a scan, not an index. The prefilter (analysis/searchFoldPrefilter.ts) keeps it cheap: on a
 * 70,000-event case a term that matches nothing used to parse every payload twice (~5 s, #1914).
 */
export async function searchForensicTimeline(
  stateStore: InvestigationStateStorage,
  caseId: string,
  term: string,
  query: EntityQuery = {},
): Promise<EntityPage<ForensicEvent>> {
  const needle = term.trim();
  if (!needle) return stateStore.queryForensicTimeline(caseId, query);

  const limit = Math.max(0, Math.floor(query.limit ?? DEFAULT_LIMIT));
  // The matcher compares lower(value) against lower(term), so the term the prefilter has to model
  // is the folded one — U+212A KELVIN SIGN typed in "bacKup" folds to plain ASCII "backup".
  const plan = searchPrefilterPlan(needle.toLowerCase());
  const wantTotal = query.includeTotal !== false;
  // ONE scan when the page and the count both start at the top of the case — the dashboard's first
  // request for every term. A cursor (Load more) still needs the count from the top, so it scans twice.
  if (wantTotal && query.cursor === undefined)
    return pageAndCount(stateStore, caseId, needle, query, plan, limit);

  const entities: ForensicEvent[] = [];
  let nextCursor: number | null = null;
  if (limit > 0) {
    scan: for await (const page of candidates(stateStore, caseId, query, plan, query.cursor)) {
      for (let index = 0; index < page.entities.length; index++) {
        const event = page.entities[index];
        if (!eventMatchesSearch(event, needle)) continue;
        entities.push(event);
        if (entities.length >= limit) {
          // Resume AFTER this row. A page that fills on the very last match costs one extra empty
          // request; looking ahead for another match would cost a scan on every page, and dropping
          // the cursor would lose events outright.
          nextCursor = page.ordinals?.[index] ?? null;
          break scan;
        }
      }
    }
  }

  // The count is over MATCHES, not over the case — the UI shows it as "n of m", and a filtered view
  // reporting the unfiltered size tells the analyst nothing.
  if (!wantTotal) return { entities, nextCursor, total: -1 };
  const tally = { total: 0, lowerBound: false };
  count: for await (const page of candidates(stateStore, caseId, query, plan, undefined)) {
    for (const event of page.entities) {
      if (eventMatchesSearch(event, needle) && countMatch(tally)) break count;
    }
  }
  return withTally(entities, nextCursor, tally);
}

/**
 * The page and the match count from one scan. Same answers as the two-pass path: the page holds the
 * first `limit` matches, the cursor is the ordinal of the match that filled it, and the count stops
 * one match PAST the ceiling. The scan ends only when both are done.
 */
async function pageAndCount(
  stateStore: InvestigationStateStorage,
  caseId: string,
  needle: string,
  query: EntityQuery,
  plan: SearchPrefilterPlan,
  limit: number,
): Promise<EntityPage<ForensicEvent>> {
  const entities: ForensicEvent[] = [];
  let nextCursor: number | null = null;
  const tally = { total: 0, lowerBound: false };
  scan: for await (const page of candidates(stateStore, caseId, query, plan, undefined)) {
    for (let index = 0; index < page.entities.length; index++) {
      const event = page.entities[index];
      if (!eventMatchesSearch(event, needle)) continue;
      if (entities.length < limit) {
        entities.push(event);
        if (entities.length === limit) nextCursor = page.ordinals?.[index] ?? null;
      }
      const countDone = tally.lowerBound || countMatch(tally);
      if (countDone && entities.length >= limit) break scan;
    }
  }
  return withTally(entities, nextCursor, tally);
}

/** Count one match. True once the count has passed the ceiling and is now a floor. */
function countMatch(tally: { total: number; lowerBound: boolean }): boolean {
  tally.total++;
  // One match PAST the ceiling, not one at it. A case with exactly 10,000 matches has an exact
  // total, and reporting it as "10,000+" would invent evidence that is not there.
  if (tally.total > TOTAL_CEILING) {
    tally.total = TOTAL_CEILING;
    tally.lowerBound = true;
  }
  return tally.lowerBound;
}

function withTally(
  entities: ForensicEvent[],
  nextCursor: number | null,
  tally: { total: number; lowerBound: boolean },
): EntityPage<ForensicEvent> {
  return {
    entities,
    nextCursor,
    total: tally.total,
    ...(tally.lowerBound ? { totalIsLowerBound: true } : {}),
  };
}

/** Pages of rows whose raw payload contains the term, in ordinal order, with their ordinals. */
async function* candidates(
  stateStore: InvestigationStateStorage,
  caseId: string,
  query: EntityQuery,
  plan: SearchPrefilterPlan,
  afterOrdinal: number | undefined,
): AsyncGenerator<EntityPage<ForensicEvent>> {
  let cursor = afterOrdinal;
  for (;;) {
    const page = await stateStore.queryForensicTimeline(caseId, {
      ...query,
      cursor,
      limit: SCAN_BATCH,
      // A term holding a lone surrogate has no sound prefilter: every row is a candidate.
      searchPrefilter: !plan.scanAll,
      searchLike: plan.like,
      searchFoldChars: plan.foldChars,
      searchFoldNeedle: plan.foldNeedle,
      searchEdgeObserved: plan.edgeObserved,
      includeTotal: false,
    });
    if (!page.entities.length) return;
    yield page;
    if (page.nextCursor == null) return;
    cursor = page.nextCursor;
  }
}
