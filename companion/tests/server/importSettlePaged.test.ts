import { describe, it, expect, vi } from "vitest";
import { settleForensicImport } from "../../src/routes/importSettle.js";
import { SCAN_PAGE_ROWS } from "../../src/analysis/forensicRows.js";
import type { ForensicEvent, InvestigationState } from "../../src/analysis/stateTypes.js";
import { memoryRowStore } from "../helpers/memoryRowStore.js";

// #2713: the settle no longer holds every row an import added, as full events, from the stamp to the
// last step. It reads, stamps and dual-writes them a page of SCAN_PAGE_ROWS at a time, so its row
// reads are bounded by the page, not by the file. A single-page import makes exactly today's calls.

function ev(
  id: string,
  severity: ForensicEvent["severity"],
  extra: Partial<ForensicEvent> = {},
): ForensicEvent {
  return {
    id,
    timestamp: "2026-05-02T10:00:00Z",
    description: `row ${id}`,
    severity,
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...extra,
  };
}

const state = (events: ForensicEvent[]): InvestigationState =>
  ({ caseId: "c1", forensicTimeline: events, iocs: [] }) as unknown as InvestigationState;

/** The row store, with the largest row read it was asked for recorded. */
function spiedStore(merged: InvestigationState) {
  const store = memoryRowStore(merged);
  const reads = { maxById: 0, maxByRowId: 0 };
  const byId = store.forensicRowsById.bind(store);
  const byRowId = store.forensicRowsByRowId.bind(store);
  store.forensicRowsById = async (caseId: string, ids: readonly string[]) => {
    reads.maxById = Math.max(reads.maxById, ids.length);
    return byId(caseId, ids);
  };
  store.forensicRowsByRowId = async (caseId: string, rowIds: readonly number[]) => {
    reads.maxByRowId = Math.max(reads.maxByRowId, rowIds.length);
    return byRowId(caseId, rowIds);
  };
  return { store, reads };
}

describe("settleForensicImport in pages (#2713)", () => {
  it("stamps, dual-writes and tags every added row while never reading more than a page at once", async () => {
    const n = 2 * SCAN_PAGE_ROWS + 7;
    const added = Array.from({ length: n }, (_, i) => ev(`e${i}`, i % 3 ? "Medium" : "Info"));
    const { store, reads } = spiedStore(state([ev("old", "High"), ...added]));
    const appended: number[] = [];
    const tagged: string[] = [];
    const settled = await settleForensicImport(
      {
        stateStore: store,
        superTimelineStore: {
          append: vi.fn(async (_c: string, events: ForensicEvent[]) => {
            appended.push(events.length);
            return events.length;
          }),
        },
        autoTagImported: async (_c: string, events: ForensicEvent[]) => {
          tagged.push(...events.map((e) => e.id));
        },
        demoteForensic: () => store.demoteInfo(),
      },
      "c1",
      state([ev("old", "High")]),
    );
    expect(appended).toEqual([SCAN_PAGE_ROWS, SCAN_PAGE_ROWS, 7]);
    expect(settled.superTimelineAddedCount).toBe(n);
    expect(tagged).toEqual(added.map((e) => e.id)); // every row once, in timeline order
    expect(reads.maxById).toBeLessThanOrEqual(SCAN_PAGE_ROWS);
    // One instant and one batch id for the whole import, across pages.
    const rows = (await store.load()).forensicTimeline.filter((e) => e.id !== "old");
    expect(new Set(rows.map((e) => e.importBatchId)).size).toBe(1);
    expect(new Set(rows.map((e) => e.importedAt)).size).toBe(1);
    expect(rows.every((e) => e.severity !== "Info")).toBe(true); // demote still ran after the tagger
  });

  it("makes one append and one tagger call for an import that fits one page", async () => {
    const { store } = spiedStore(state([ev("a", "High"), ev("b", "Medium")]));
    const append = vi.fn(async (_c: string, events: ForensicEvent[]) => events.length);
    const tag = vi.fn(async () => {});
    await settleForensicImport(
      {
        stateStore: store,
        superTimelineStore: { append },
        autoTagImported: tag,
        demoteForensic: () => store.demoteInfo(),
      },
      "c1",
      state([]),
    );
    expect(append).toHaveBeenCalledTimes(1);
    expect(tag).toHaveBeenCalledTimes(1);
  });
});
