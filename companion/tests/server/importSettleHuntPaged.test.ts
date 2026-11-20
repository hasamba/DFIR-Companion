import { describe, expect, it } from "vitest";
import { registerHuntSettle } from "../../src/analysis/huntSettleHook.js";
import { SCAN_PAGE_ROWS, type ForensicRowStore } from "../../src/analysis/forensicRows.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";
import { huntSettlePaged } from "../../src/routes/importSettlePaged.js";

// Hunt grading (#2670) runs in pages of the added ids (#2713): every added row reaches the hunt
// inventory exactly once, page by page, and an import that added nothing still gets its one call.

function fakeStore(): { store: ForensicRowStore; reads: number[] } {
  const reads: number[] = [];
  const store = {
    forensicRowsById: async (_caseId: string, ids: readonly string[]) => {
      reads.push(ids.length);
      return ids.map((id) => ({ rowId: id, event: { id } as ForensicEvent }));
    },
  } as unknown as ForensicRowStore;
  return { store, reads };
}

const unlocked = <T>(_caseId: string, fn: () => Promise<T>): Promise<T> => fn();

describe("huntSettlePaged (#2670 in pages, #2713)", () => {
  it("hands every added row on once, one page at a time, and sums the changes", async () => {
    const { store, reads } = fakeStore();
    const seen: string[][] = [];
    registerHuntSettle(store, async (_caseId, added) => {
      seen.push(added.map((e) => e.id));
      return 1;
    });
    const ids = Array.from({ length: SCAN_PAGE_ROWS * 2 + 3 }, (_, i) => `r${i}`);

    const changed = await huntSettlePaged(store, unlocked, "case-a", ids, () => undefined);

    expect(seen).toHaveLength(3);
    expect(reads).toEqual([SCAN_PAGE_ROWS, SCAN_PAGE_ROWS, 3]);
    expect(seen.flat()).toEqual(ids);
    expect(changed).toBe(3);
  });

  it("still calls the hunt step once when the import added nothing, so a coverage change regrades", async () => {
    const { store, reads } = fakeStore();
    const seen: number[] = [];
    registerHuntSettle(store, async (_caseId, added) => {
      seen.push(added.length);
      return 2;
    });

    expect(await huntSettlePaged(store, unlocked, "case-a", [], () => undefined)).toBe(2);
    expect(seen).toEqual([0]);
    expect(reads).toEqual([]);
  });

  it("returns 0 and reports the error when a page's grading throws", async () => {
    const { store } = fakeStore();
    const errors: string[] = [];
    registerHuntSettle(store, async () => {
      throw new Error("inventory unavailable");
    });

    expect(await huntSettlePaged(store, unlocked, "case-a", ["r1"], (e) => errors.push(e.message))).toBe(0);
    expect(errors).toEqual(["inventory unavailable"]);
  });
});
