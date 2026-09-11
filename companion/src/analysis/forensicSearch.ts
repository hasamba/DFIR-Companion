import type { EntityPage, EntityQuery, InvestigationStateStorage } from "./stateStore.js";
import { eventMatchesSearch } from "./searchFilter.js";
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

/**
 * A term as a SQL LIKE pattern to be matched against the raw STORED JSON text.
 *
 * Two escapings, and getting only the second one right is a silent evidence-loss bug. The pattern
 * is compared against JSON source, where a Windows path is held as "C:\\\\Users\\\\bob" — two characters
 * per backslash. An analyst types ONE backslash, so a pattern built from the raw term matched
 * nothing at all for the most common search in Windows forensics, while the in-memory matcher on
 * the same event said yes. The term is therefore JSON-encoded first (quotes, backslashes, control
 * characters — exactly what the payload holds), and only then are LIKE's own wildcards escaped so
 * "100%" and "foo_bar" stay literal.
 */
export function searchLikePattern(term: string): string {
  const asStoredJson = JSON.stringify(term).slice(1, -1);
  return "%" + asStoredJson.replace(/[\\%_]/g, (char) => "\\" + char) + "%";
}

/**
 * WHY THE STORE'S PREFILTER HAS TWO CLAUSES (caseSqliteWorker's `searchPrefilter`).
 *
 * It must never reject a row this module's matcher would accept, or the analyst is told "no
 * results" for evidence the case holds — which in an investigation reads as proof of absence.
 * LIKE folds case for ASCII ONLY, while the matcher folds with toLowerCase(), which folds the whole
 * of Unicode: LIKE alone silently loses "ÉVIL.exe" searched as "évil.exe", or "Администратор"
 * searched in lower case. So any row carrying a character outside printable ASCII is ALWAYS a
 * candidate and gets parsed (the GLOB), and a pure-ASCII payload cannot case-fold into a non-ASCII
 * character, so nothing is lost by filtering those with LIKE.
 */

/**
 * Whether SQL LIKE can be trusted to find this term at all.
 *
 * LIKE folds case for ASCII only; the matcher folds with toLowerCase(), which folds all of Unicode.
 * For a term that stays non-ASCII once folded the two disagree — "évil.exe" never finds the stored
 * "ÉVIL.exe" — so the pattern is dropped and the store falls back to offering every row holding a
 * non-ASCII character, the only set such a term can match.
 *
 * The test is on the FOLDED term, not the typed one, and that distinction is the whole point.
 * Folding is not closed over the ASCII boundary: U+212A KELVIN SIGN folds to plain "k", so "bacKup"
 * typed with one is a non-ASCII term that matches the pure-ASCII stored word "backup". Judging the
 * typed term instead dropped the LIKE, left the non-ASCII GLOB as the only prefilter, and rejected
 * the very ASCII row the matcher accepts.
 */
function likeCanMatch(folded: string): boolean {
  return !/[^\u0000-\u007f]/.test(folded);
}

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
 * This is a scan, not an index. It is correct on any case size; whether it is fast enough on a
 * large one has not been measured, and an FTS5 index is the answer if it turns out not to be.
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
  // is the folded one — see likeCanMatch. LIKE is ASCII-case-insensitive, so a folded pattern still
  // finds the stored original whatever case it was written in.
  const folded = needle.toLowerCase();
  const like = likeCanMatch(folded) ? searchLikePattern(folded) : undefined;
  const entities: ForensicEvent[] = [];
  let nextCursor: number | null = null;

  if (limit > 0) {
    scan: for await (const page of candidates(stateStore, caseId, query, like, query.cursor)) {
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
  let total = -1;
  let totalIsLowerBound = false;
  if (query.includeTotal !== false) {
    total = 0;
    count: for await (const page of candidates(stateStore, caseId, query, like, undefined)) {
      for (const event of page.entities) {
        if (!eventMatchesSearch(event, needle)) continue;
        total++;
        // One match PAST the ceiling, not one at it. A case with exactly 10,000 matches has an
        // exact total, and reporting it as "10,000+" would invent evidence that is not there.
        if (total > TOTAL_CEILING) {
          total = TOTAL_CEILING;
          totalIsLowerBound = true;
          break count;
        }
      }
    }
  }
  return { entities, nextCursor, total, ...(totalIsLowerBound ? { totalIsLowerBound } : {}) };
}

/** Pages of rows whose raw payload contains the term, in ordinal order, with their ordinals. */
async function* candidates(
  stateStore: InvestigationStateStorage,
  caseId: string,
  query: EntityQuery,
  like: string | undefined,
  afterOrdinal: number | undefined,
): AsyncGenerator<EntityPage<ForensicEvent>> {
  let cursor = afterOrdinal;
  for (;;) {
    const page = await stateStore.queryForensicTimeline(caseId, {
      ...query,
      cursor,
      limit: SCAN_BATCH,
      searchLike: like,
      searchPrefilter: true,
      includeTotal: false,
    });
    if (!page.entities.length) return;
    yield page;
    if (page.nextCursor == null) return;
    cursor = page.nextCursor;
  }
}
