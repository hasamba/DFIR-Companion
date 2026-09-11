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
  commitFalsePositives(caseId: string, markers: unknown): void;
  fpFindingTitleSet(): Set<string>;
  fpEventIdSet(): Set<string>;
  fpMarkers: unknown[];
  /** The page-level active-case identity dashboard-case-connect.js sets before the loaders run. */
  activeCaseId: string | null;
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
    activeCaseId: null,
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

/** What dashboard-case-connect.js does on a switch: activeCaseId first, then the loader. */
function switchTo(p: FpApi, caseId: string) {
  p.activeCaseId = caseId;
  p.loadFalsePositives(caseId);
}

describe("false-positive markers — case ownership (#937)", () => {
  it("ignores a stale case's late response — case B keeps B's markers, not A's", async () => {
    const { pending, fetch } = deferredFetch();
    const p = fpPanel(fetch);
    switchTo(p, "case-a");
    switchTo(p, "case-b");
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
    switchTo(p, "case-a");
    pending[0].resolve(markersFor("case-a"));
    await drain();
    expect(p.fpFindingTitleSet().size).toBe(1);

    switchTo(p, "case-b");
    // Nothing has answered for B yet; A's markers must already be gone. Between here and B's
    // response the page renders B's state, and it must render it unfiltered rather than through A.
    expect(p.fpFindingTitleSet().size).toBe(0);
    expect(p.fpEventIdSet().size).toBe(0);
  });

  it("does NOT clear on a same-case refresh — the websocket path keeps the panel filled", async () => {
    const { pending, fetch } = deferredFetch();
    const p = fpPanel(fetch);
    switchTo(p, "case-a");
    pending[0].resolve(markersFor("case-a"));
    await drain();

    p.loadFalsePositives("case-a"); // false_positive_changed → reload for the SAME case
    expect(p.fpFindingTitleSet().size).toBe(1); // still A's until the refresh lands
  });

  it("on a same-case refresh the latest response wins, even when the earlier one lands last", async () => {
    const { pending, fetch } = deferredFetch();
    const p = fpPanel(fetch);
    switchTo(p, "case-a");
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
    switchTo(p, "case-a");
    pending[0].resolve(markersFor("case-a"));
    await drain();

    switchTo(p, "case-b");
    pending[1].reject(new Error("companion restarting"));
    await drain();

    expect(p.fpFindingTitleSet().size).toBe(0);
  });
});

// The review of the first cut. A generation keyed on "the latest caller" is not case ownership:
// a false_positive_changed frame already queued on case A's closing socket still fires A's handler
// after B is active (the switch closes the socket without detaching onmessage), and under a
// latest-caller rule that late call made A the newest owner, cleared B, and rejected B's own
// response. And four other writers install markers straight from their own responses — mark,
// un-mark, NSRL apply, whitelist apply — none of which went through the loader at all. Ownership
// has to be decided against the page's ACTIVE case, at every commit, not against who called last.
describe("false-positive markers — the active case owns every commit", () => {
  it("a late load for the old case after a switch changes nothing — B's response still lands", async () => {
    const { pending, fetch } = deferredFetch();
    const p = fpPanel(fetch);
    switchTo(p, "case-a");
    pending[0].resolve(markersFor("case-a"));
    await drain();

    switchTo(p, "case-b"); // request 1, in flight
    p.loadFalsePositives("case-a"); // the stale socket frame: must not clear B, fetch, or take ownership
    expect(pending.length).toBe(2); // no request was issued for the stale case
    pending[1].resolve(markersFor("case-b"));
    await drain();

    expect([...p.fpFindingTitleSet()]).toEqual(["case-b finding title"]);
  });

  it("commitFalsePositives installs markers for the active case only", async () => {
    const { pending, fetch } = deferredFetch();
    const p = fpPanel(fetch);
    switchTo(p, "case-b");
    pending[0].resolve(markersFor("case-b"));
    await drain();

    // A mark/un-mark/NSRL/whitelist response for case A, landing after the switch to B.
    p.commitFalsePositives("case-a", await markersFor("case-a").json());
    expect([...p.fpFindingTitleSet()]).toEqual(["case-b finding title"]);

    // The same call for the active case is applied.
    p.commitFalsePositives("case-b", [{ id: "x", kind: "finding", ref: "b-updated", markedAt: "" }]);
    expect([...p.fpFindingTitleSet()]).toEqual(["b-updated"]);
  });

  it("every marker writer outside the loader commits through the case-aware path", async () => {
    // A static gate for the review's list: the four modules that install markers from their own
    // responses must name the case they fetched for. A bare renderFalsePositives(<response>) in any
    // of them is the bypass this suite exists to close; the two remaining bare calls are repaints
    // of the current fpMarkers, which carry no case data.
    const { readFile } = await import("node:fs/promises");
    for (const file of [
      "dashboard-false-positive.js",
      "dashboard-nsrl.js",
      "dashboard-ioc-whitelist.js",
      "dashboard-exposure-fp.js",
    ]) {
      const src = await readFile(new URL(`../../../public/js/${file}`, import.meta.url), "utf8");
      const code = src.replace(/^\s*\/\/.*$/gm, ""); // prose mentions are not call sites
      const bare = [...code.matchAll(/renderFalsePositives\(([^)]*)\)/g)]
        .map((m) => m[1].trim())
        .filter((arg) => arg !== "fpMarkers" && !arg.startsWith("fpMarkers,") && arg !== "markers, redraw");
      // The one permitted response-install is the body of commitFalsePositives itself.
      const allowed = file === "dashboard-exposure-fp.js" ? ["markers"] : [];
      expect(bare, `${file} installs markers without naming the case: ${bare.join(" | ")}`).toEqual(allowed);
    }
  });
});
