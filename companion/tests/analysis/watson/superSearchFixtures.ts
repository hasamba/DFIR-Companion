import {
  searchSuperTimeline,
  type WatsonRawReader,
} from "../../../src/analysis/ai/watson/superTimelineSearch.js";
import type { WatsonLookup } from "../../../src/analysis/ai/watson/types.js";
import { eventMatchesSearch } from "../../../src/analysis/searchFilter.js";
import type { SuperQuery } from "../../../src/analysis/superTimeline.js";
import type { ForensicEvent, InvestigationState } from "../../../src/analysis/stateTypes.js";

// Shared fixtures for the super-timeline search tests (Watson phase 4, Task 2).

export const F = "2026-01-01T00:00:00Z";
export const T = "2026-01-02T00:00:00Z";
export const H = "ab".repeat(32);
export const H2 = "cd".repeat(32);

export const ev = (over: Partial<ForensicEvent> & { id: string }): ForensicEvent => ({
  timestamp: "2026-01-01T10:00:00Z",
  description: `raw row ${over.id}`,
  severity: "Info",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
  ...over,
});

export const rows = (n: number, over: Partial<ForensicEvent> = {}): ForensicEvent[] =>
  Array.from({ length: n }, (_, i) =>
    ev({ id: `r${String(i).padStart(5, "0")}`, description: `x row ${i}`, ...over }),
  );

export const stateOf = (forensic: ForensicEvent[] = [], extra: Partial<InvestigationState> = {}) =>
  ({ forensicTimeline: forensic, findings: [], ...extra }) as unknown as InvestigationState;

export type Ctx = Parameters<typeof searchSuperTimeline>[0];
export const ctxOf = (over: Record<string, unknown> = {}, opts: Record<string, unknown> = {}): Ctx =>
  ({ opts: { stateStore: {}, ...opts }, ...over }) as unknown as Ctx;
export const ctx = ctxOf();

/** A store stand-in: applies the search and time filter as the real store does (undated rows kept). */
export function readerOf(
  all: ForensicEvent[],
  o: { evictedTotal?: number; total?: (q: SuperQuery, matched: number) => number } = {},
) {
  const calls: SuperQuery[] = [];
  const reader: WatsonRawReader & { calls: SuperQuery[] } = {
    calls,
    async query(_caseId, q) {
      calls.push(q);
      const hit = all.filter((e) => {
        if (q.search && !eventMatchesSearch(e, q.search)) return false;
        const t = Date.parse(e.timestamp);
        if (!Number.isFinite(t)) return true;
        if (q.from && t < Date.parse(q.from)) return false;
        if (q.to && t > Date.parse(q.to)) return false;
        return true;
      });
      const events = hit.slice(q.offset ?? 0, (q.offset ?? 0) + (q.limit ?? hit.length));
      return { events, total: o.total ? o.total(q, hit.length) : hit.length };
    },
    async meta() {
      return { evictedTotal: o.evictedTotal ?? 0 };
    },
  };
  return reader;
}

export const sup = (q: Omit<WatsonLookup, "source">): WatsonLookup => ({ source: "supertimeline", ...q });
