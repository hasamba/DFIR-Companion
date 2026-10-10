// #2120: concurrent GET /cases/:id/state requests for one case and page share one read.
//
// Every live broadcast makes each open dashboard re-fetch /state, so several tabs or analysts on one
// case send a burst of identical requests. Each used to run its own overview read plus a page of up
// to 10,000 forensic rows, deserialised and upgraded on the main thread. They now go through the same
// CaseLoadCoalescer as the report loads (reports/stateLoadGate.ts), with the same freshness rule:
//
//   - A read is shared only while it is QUEUED. Once it starts reading it is never joined again, so a
//     request that arrives after a write finished never receives a read that started before it.
//   - A queued read whose every caller has left is dropped before it starts (requestAbortSignal).
//     One caller leaving never cancels a read another caller still waits for.
//
// THE SHARE KEY is everything that changes the read: case id, cursor, limit and search term, as JSON.
// The search term is free analyst text, so a delimiter join could make two searches collide.
//
// THE RESULT IS SHARED between callers: no caller may modify it (CLAUDE.md §5). Everything built
// after the read (clock-skew alignment, technique corrections, tagger tags, aliases) stays per caller
// in routes/caseState.ts and returns copies; tests/server/caseStateShare.test.ts deep-freezes it.
//
// Its own limiter, not wholeCaseLoads: /state must not wait behind cold whole-case report loads. The
// heavy-read gate already caps this route, so this limiter exists for the coalescer and rarely binds.

import { LoadLimiter } from "../analysis/wholeCaseLoadLimit.js";
import { searchForensicTimeline } from "../analysis/forensicSearch.js";
import type { EntityQuery, StateStore } from "../analysis/stateStore.js";
import { CaseLoadCoalescer } from "../reports/stateLoadGate.js";

/** /state reads running at once, across every case. Local on purpose: independent of the gate's cap. */
const STATE_READ_CONCURRENCY = 4;

type TimelinePage = Awaited<ReturnType<StateStore["queryForensicTimeline"]>>;
type Overview = Awaited<ReturnType<StateStore["loadOverview"]>>;

export interface CaseStateRead {
  readonly timeline: TimelinePage;
  readonly overview: Overview;
}

export interface CaseStateReadQuery {
  search?: string;
  timelineQuery: { cursor?: number; limit: number };
}

const stateReads = new CaseLoadCoalescer<CaseStateRead>(new LoadLimiter(STATE_READ_CONCURRENCY));

/** The /state read for one case and page, shared with concurrent callers asking for the same one. */
export function readCaseState(
  stateStore: StateStore,
  caseId: string,
  { search, timelineQuery }: CaseStateReadQuery,
  signal?: AbortSignal,
): Promise<CaseStateRead> {
  const key = JSON.stringify([caseId, timelineQuery.cursor ?? null, timelineQuery.limit, search ?? null]);
  const query: EntityQuery = timelineQuery;
  return stateReads.load(
    key,
    async () => {
      const timeline = search
        ? await searchForensicTimeline(stateStore, caseId, search, query)
        : await stateStore.queryForensicTimeline(caseId, query);
      const overview = await stateStore.loadOverview(caseId);
      return { timeline, overview };
    },
    signal,
  );
}
