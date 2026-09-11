import { describe, it, expect } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// #937. `fpMarkers` is one page-level global with no case ownership. loadFalsePositives(caseId)
// took a case id and threw it away: the response, whenever it landed, overwrote the global and
// repainted. A slow answer for case A arriving after case B loaded installed A's markers over B
// and repainted B with them — across the Findings panel, the MITRE panel, the forensic timeline
// and the IOC panel, because all four derive their hidden sets from this one global. Findings are
// matched by two-way title substring, so a collision needs no exact match: a marker reading
// "PsExec service install" on case A hides a case B finding whose title contains it.
//
// Same shape as the asset-graph race guard (assetGraphPanel.test.ts): responses settled BY THE
// TEST, in the order the test chooses, because the whole point is answering A after B.

interface FpApi {
  loadFalsePositives(caseId: string): void;
  fpFindingTitleSet(): Set<string>;
  fpEventIdSet(): Set<string>;
  fpMarkers: unknown[];
}

interface PendingFetch {
  url: string;
  resolve(response: unknown): void;
  reject(reason: unknown): void;
}

function deferredFetch() {
  const pending: PendingFetch[] = [];
  const fetch = (url: string) =>
    new Promise((resolve, reject) => {
      pending.push({ url, resolve, reject });
    });
  return { pending, fetch };
}

// One macrotask turn, so every already-settled promise chain runs to completion.
const drain = () => new Promise((r) => setImmediate(r));

function fpPanel(fetchStub: unknown) {
  return loadDashboardModule<FpApi>("dashboard-exposure-fp.js", ["dashboard-escape.js"], {
    fetch: fetchStub,
    // The two page-level `let`s the module writes and reads (dashboard.html declares them).
    fpMarkers: [],
    fpReasonFilter: "",
    document: {
      getElementById: () => ({ innerHTML: "", textContent: "", style: {}, value: "" }),
      querySelectorAll: () => [],
    },
    DfirTimelineView: { search: () => "", excludeTerms: () => [] },
    // No last state → renderFalsePositives skips its render() call; the sets are what we assert.
    DfirState: { lastState: () => null },
  });
}

function markersFor(caseId: string) {
  return {
    ok: true,
    json: async () => [
      {
        id: `${caseId}-f`,
        kind: "finding",
        ref: `${caseId} finding title`,
        markedAt: "2026-09-11T00:00:00Z",
      },
      { id: `${caseId}-e`, kind: "event", ref: `${caseId}-event-1`, markedAt: "2026-09-11T00:00:00Z" },
    ],
  };
}

describe("false-positive markers — case ownership (#937)", () => {
  it("ignores a stale case's late response — case B keeps B's markers, not A's", async () => {
    const { pending, fetch } = deferredFetch();
    const p = fpPanel(fetch);
    p.loadFalsePositives("case-a");
    p.loadFalsePositives("case-b");
    // B answers first, then A's slow response lands.
    pending[1].resolve(markersFor("case-b"));
    await drain();
    pending[0].resolve(markersFor("case-a"));
    await drain();

    expect([...p.fpFindingTitleSet()]).toEqual(["case-b finding title"]);
    expect([...p.fpEventIdSet()]).toEqual(["case-b-event-1"]);
  });

  it("clears the previous case's markers synchronously on a case switch, before any response", async () => {
    const { pending, fetch } = deferredFetch();
    const p = fpPanel(fetch);
    p.loadFalsePositives("case-a");
    pending[0].resolve(markersFor("case-a"));
    await drain();
    expect(p.fpFindingTitleSet().size).toBe(1);

    p.loadFalsePositives("case-b");
    // Nothing has answered for B yet; A's markers must already be gone. Between here and B's
    // response the page renders B's state, and it must render it unfiltered rather than through A.
    expect(p.fpFindingTitleSet().size).toBe(0);
    expect(p.fpEventIdSet().size).toBe(0);
  });

  it("does NOT clear on a same-case refresh — the websocket path keeps the panel filled", async () => {
    const { pending, fetch } = deferredFetch();
    const p = fpPanel(fetch);
    p.loadFalsePositives("case-a");
    pending[0].resolve(markersFor("case-a"));
    await drain();

    p.loadFalsePositives("case-a"); // false_positive_changed → reload for the SAME case
    expect(p.fpFindingTitleSet().size).toBe(1); // still A's until the refresh lands
  });

  it("on a same-case refresh the latest response wins, even when the earlier one lands last", async () => {
    const { pending, fetch } = deferredFetch();
    const p = fpPanel(fetch);
    p.loadFalsePositives("case-a");
    p.loadFalsePositives("case-a");
    pending[1].resolve({
      ok: true,
      json: async () => [{ id: "n", kind: "finding", ref: "newer", markedAt: "" }],
    });
    await drain();
    pending[0].resolve({
      ok: true,
      json: async () => [{ id: "o", kind: "finding", ref: "older", markedAt: "" }],
    });
    await drain();

    expect([...p.fpFindingTitleSet()]).toEqual(["newer"]);
  });

  it("a failed load for a new case leaves it unfiltered rather than filtered through the old case", async () => {
    const { pending, fetch } = deferredFetch();
    const p = fpPanel(fetch);
    p.loadFalsePositives("case-a");
    pending[0].resolve(markersFor("case-a"));
    await drain();

    p.loadFalsePositives("case-b");
    pending[1].reject(new Error("companion restarting"));
    await drain();

    expect(p.fpFindingTitleSet().size).toBe(0);
  });
});
