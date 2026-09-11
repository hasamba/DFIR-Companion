// The search box asks the CASE, not just the rows on screen (#928) — and an answer to a question
// nobody is asking any more must never paint.
//
// Both failures here are silent in a browser and wrong in the way that matters in an investigation:
// one shows a filtered timeline while the search box is empty (evidence missing, no reason given),
// the other shows one case's events under another case's name.
import { describe, it, expect } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface SearchApi {
  loadSearchedTimeline: () => void;
  loadMoreMatches: () => void;
  hasMoreMatches: () => boolean;
  DfirTimelineSearch: { loadSearchedTimeline: () => void; paintedKey: () => string | null };
  DfirTimelineView: {
    setSearch: (term: string) => void;
    search: () => string;
    wire: (painters: Record<string, () => void>) => void;
  };
  DfirState: {
    lastState: () => { forensicTimeline?: { id: string }[] } | null;
    setLastState: (s: unknown) => void;
  };
}

const PRELOAD = ["dashboard-state.js", "dashboard-time.js", "dashboard-timeline-view.js"];

function harness(caseId = "INC-1") {
  const caseEl = { value: caseId };
  const urls: string[] = [];
  const pending: { resolve: (body: unknown) => void; reject: (e: Error) => void }[] = [];
  const rendered: unknown[] = [];
  const globals = {
    document: {
      getElementById: (id: string) => (id === "caseId" ? caseEl : null),
      addEventListener: () => {},
    },
    render: (state: unknown) => {
      rendered.push(state);
      // The page's render() is the single writer of the state snapshot; the module keys its
      // "somebody else repainted" detection off that write, so the fake has to perform it too.
      (globals as { DfirState?: { setLastState: (s: unknown) => void } }).DfirState?.setLastState(state);
    },
    fetch: (url: string) => {
      urls.push(url);
      return new Promise((resolve, reject) => {
        pending.push({
          resolve: (body) => resolve({ ok: true, status: 200, json: () => Promise.resolve(body) }),
          reject,
        });
      });
    },
  };
  const api = loadDashboardModule<SearchApi>("dashboard-timeline-search.js", PRELOAD, globals);
  (globals as { DfirState?: unknown }).DfirState = api.DfirState;
  return { api, caseEl, urls, pending, rendered };
}

const settle = () => new Promise((r) => setTimeout(r, 0));
const answer = (ids: string[]) => ({ caseId: "INC-1", forensicTimeline: ids.map((id) => ({ id })) });

describe("the search load path", () => {
  it("asks the server for the term, not just the loaded page", async () => {
    const { api, urls } = harness();
    api.DfirTimelineView.setSearch("certutil");
    api.loadSearchedTimeline();
    expect(urls).toEqual(["/cases/INC-1/state?q=certutil"]);
  });

  it("does not re-ask for an answer already on screen", async () => {
    const { api, urls, pending } = harness();
    api.DfirTimelineView.setSearch("certutil");
    api.loadSearchedTimeline();
    pending[0].resolve(answer(["e1"]));
    await settle();
    api.loadSearchedTimeline();
    expect(urls).toHaveLength(1);
  });

  // The race: revert a term before its answer lands. The reverted view is already correct, so the
  // reload short-circuits — and the abandoned answer then arrives and narrows the timeline to a
  // term the search box no longer holds.
  it("drops an abandoned answer when the analyst reverts to what is already painted", async () => {
    const { api, pending, rendered } = harness();

    api.loadSearchedTimeline(); // unfiltered
    pending[0].resolve(answer(["e1", "e2", "e3"]));
    await settle();
    expect(rendered).toHaveLength(1);

    api.DfirTimelineView.setSearch("foo"); // types a term
    api.loadSearchedTimeline();
    expect(pending).toHaveLength(2);

    api.DfirTimelineView.setSearch(""); // clears it again, before "foo" comes back
    api.loadSearchedTimeline();

    pending[1].resolve(answer(["e2"])); // the abandoned answer lands
    await settle();

    expect(rendered).toHaveLength(1); // and must NOT have repainted
  });

  it("re-asks when the case changes even though the term did not", async () => {
    const { api, caseEl, urls, pending } = harness();
    api.DfirTimelineView.setSearch("certutil");
    api.loadSearchedTimeline();
    pending[0].resolve(answer(["e1"]));
    await settle();

    caseEl.value = "INC-2"; // a different investigation
    api.loadSearchedTimeline();
    expect(urls).toEqual(["/cases/INC-1/state?q=certutil", "/cases/INC-2/state?q=certutil"]);
  });

  it("lets a failed request be retried rather than latching the question as answered", async () => {
    const { api, urls, pending } = harness();
    api.DfirTimelineView.setSearch("certutil");
    api.loadSearchedTimeline();
    pending[0].reject(new Error("offline"));
    await settle();
    expect(api.DfirTimelineSearch.paintedKey()).toBeNull();
    api.loadSearchedTimeline();
    expect(urls).toHaveLength(2);
  });
});

// Reaching the rest of a truncated search, and not repainting over a case that was reconnected
// underneath an in-flight one.
describe("reaching the rest of a truncated search", () => {
  const truncated = (ids: string[], cursor: number) => ({
    caseId: "INC-1",
    forensicTimeline: ids.map((id) => ({ id })),
    forensicTimelineNextCursor: cursor,
    forensicTimelineTotalIsLowerBound: true,
  });
  const complete = (ids: string[]) => ({
    caseId: "INC-1",
    forensicTimeline: ids.map((id) => ({ id })),
    forensicTimelineNextCursor: null,
  });

  it("offers more only when the server actually held matches back", async () => {
    const { api, pending } = harness();
    api.DfirTimelineView.setSearch("svchost");
    api.loadSearchedTimeline();
    expect(api.hasMoreMatches()).toBe(false);

    pending[0].resolve(complete(["e1"]));
    await settle();
    expect(api.hasMoreMatches()).toBe(false);
  });

  it("appends the next batch rather than replacing what is on screen", async () => {
    const { api, urls, pending, rendered } = harness();
    api.DfirTimelineView.setSearch("svchost");
    api.loadSearchedTimeline();
    pending[0].resolve(truncated(["e1", "e2"], 4242));
    await settle();
    expect(api.hasMoreMatches()).toBe(true);

    api.loadMoreMatches();
    expect(urls[1]).toBe("/cases/INC-1/state?q=svchost&timelineCursor=4242");

    pending[1].resolve(complete(["e3", "e4"]));
    await settle();

    const last = rendered[rendered.length - 1] as { forensicTimeline: { id: string }[] };
    expect(last.forensicTimeline.map((e) => e.id)).toEqual(["e1", "e2", "e3", "e4"]);
    expect(api.hasMoreMatches()).toBe(false); // the case ran out of matches
  });

  it("lets the analyst retry when a follow-up batch fails", async () => {
    const { api, pending } = harness();
    api.DfirTimelineView.setSearch("svchost");
    api.loadSearchedTimeline();
    pending[0].resolve(truncated(["e1"], 99));
    await settle();

    api.loadMoreMatches();
    pending[1].reject(new Error("offline"));
    await settle();
    expect(api.hasMoreMatches()).toBe(true); // the cursor is handed back, not lost
  });

  // The case-connect path renders an unfiltered timeline WITHOUT going through this module. An
  // in-flight search must not land on top of it, and the module must not go on believing its own
  // answer is what the analyst is looking at.
  it("drops an in-flight search when the case is reconnected underneath it", async () => {
    const { api, pending, rendered } = harness();
    api.DfirTimelineView.setSearch("svchost");
    api.loadSearchedTimeline();
    expect(pending).toHaveLength(1);

    // Reconnecting the SAME case: someone else writes the state snapshot.
    api.DfirState.setLastState({ caseId: "INC-1", forensicTimeline: [{ id: "a" }, { id: "b" }] });
    expect(api.DfirTimelineSearch.paintedKey()).toBeNull();

    pending[0].resolve(truncated(["e1"], 7));
    await settle();
    expect(rendered).toHaveLength(0); // the abandoned search never painted
    expect(api.hasMoreMatches()).toBe(false);
  });

  it("re-asks after a reconnect even though the term never changed", async () => {
    const { api, urls, pending } = harness();
    api.DfirTimelineView.setSearch("svchost");
    api.loadSearchedTimeline();
    pending[0].resolve(complete(["e1"]));
    await settle();
    expect(urls).toHaveLength(1);

    api.DfirState.setLastState({ caseId: "INC-1", forensicTimeline: [{ id: "a" }] });
    api.loadSearchedTimeline();
    expect(urls).toHaveLength(2);
  });
});

// THE PAGE'S OWN SEQUENCE, not this module called on its own.
//
// setSearch() refreshes `serverSearch` and then `all`, and the `all` painter re-renders the CURRENT
// snapshot — which writes the state cell. Every test above drove the loader directly and so never
// saw that write land in the middle of its own request. Wiring the painters the way dashboard.html
// wires them is the only arrangement that does.
describe("a search driven the way the page drives it", () => {
  function wiredHarness() {
    const h = harness();
    h.api.DfirTimelineView.wire({
      serverSearch: () => h.api.loadSearchedTimeline(),
      // dashboard.html: `all: () => { if (DfirState.lastState()) render(DfirState.lastState()); }`
      all: () => {
        const current = h.api.DfirState.lastState();
        if (current) (globalThis as unknown as { __render?: (s: unknown) => void }).__render?.(current);
      },
    });
    return h;
  }

  it("paints the answer to a term the analyst typed", async () => {
    const h = wiredHarness();
    (globalThis as unknown as { __render?: (s: unknown) => void }).__render = (s) =>
      h.api.DfirState.setLastState(s);

    // A case is already open and painted, exactly as it would be after a connect.
    h.api.DfirState.setLastState({ caseId: "INC-1", forensicTimeline: [{ id: "a" }, { id: "b" }] });

    h.api.DfirTimelineView.setSearch("certutil");
    expect(h.urls).toEqual(["/cases/INC-1/state?q=certutil"]);

    h.pending[0].resolve({ caseId: "INC-1", forensicTimeline: [{ id: "b" }] });
    await settle();

    // The whole point of #928. Before this guard the `all` repaint retired the token first and the
    // answer was thrown away, so the analyst got the locally-filtered page and no server search.
    expect(h.rendered).toHaveLength(1);
    expect(
      (h.rendered[0] as { forensicTimeline: { id: string }[] }).forensicTimeline.map((e) => e.id),
    ).toEqual(["b"]);
  });

  it("still drops a search when the case really is replaced mid-flight", async () => {
    const h = wiredHarness();
    (globalThis as unknown as { __render?: (s: unknown) => void }).__render = (s) =>
      h.api.DfirState.setLastState(s);
    h.api.DfirState.setLastState({ caseId: "INC-1", forensicTimeline: [{ id: "a" }] });

    h.api.DfirTimelineView.setSearch("certutil");
    h.api.DfirState.setLastState({ caseId: "INC-1", forensicTimeline: [{ id: "z" }] }); // a reconnect
    h.pending[0].resolve({ caseId: "INC-1", forensicTimeline: [{ id: "b" }] });
    await settle();

    expect(h.rendered).toHaveLength(0);
  });
});

// Cancelling is only half an answer. When the state really is replaced — a reconnect, a live
// update — the unfiltered timeline is painted while the search box still holds a term, so the
// analyst is shown rows their own filter excludes and is given no sign the search stopped applying.
// The search has to be re-asked, not merely abandoned.
describe("a state replacement under an active search", () => {
  it("re-asks for the term instead of leaving an unfiltered timeline under it", async () => {
    const h = harness();
    h.api.DfirTimelineView.setSearch("certutil");
    h.api.loadSearchedTimeline();
    h.pending[0].resolve({ caseId: "INC-1", forensicTimeline: [{ id: "b" }] });
    await settle();
    expect(h.urls).toHaveLength(1);

    // A reconnect repaints the whole case, unfiltered, without going through this module.
    h.api.DfirState.setLastState({ caseId: "INC-1", forensicTimeline: [{ id: "a" }, { id: "b" }] });

    // The term is still in the box, so the question is still being asked.
    expect(h.urls).toEqual(["/cases/INC-1/state?q=certutil", "/cases/INC-1/state?q=certutil"]);

    h.pending[1].resolve({ caseId: "INC-1", forensicTimeline: [{ id: "b" }] });
    await settle();
    const last = h.rendered[h.rendered.length - 1] as { forensicTimeline: { id: string }[] };
    expect(last.forensicTimeline.map((e) => e.id)).toEqual(["b"]);
  });

  it("does not re-ask when no term is set", async () => {
    const h = harness();
    h.api.DfirState.setLastState({ caseId: "INC-1", forensicTimeline: [{ id: "a" }] });
    expect(h.urls).toEqual([]);
  });
});

// A live case does not replace its state once. Each replacement retiring the in-flight request AND
// starting another turns a burst of updates into a pile of concurrent whole-case scans — the one
// query in this feature expensive enough that stacking it is felt. Bursts must COALESCE: hold the
// slot while a request is out, and ask once more, for the current question, when it comes back.
describe("a burst of live state replacements", () => {
  it("does not stack a case scan per replacement", async () => {
    const h = harness();
    h.api.DfirTimelineView.setSearch("certutil");
    h.api.loadSearchedTimeline();
    expect(h.urls).toHaveLength(1);

    h.api.DfirState.setLastState({ caseId: "INC-1", forensicTimeline: [{ id: "a" }] });
    h.api.DfirState.setLastState({ caseId: "INC-1", forensicTimeline: [{ id: "b" }] });
    h.api.DfirState.setLastState({ caseId: "INC-1", forensicTimeline: [{ id: "c" }] });

    // Still one request out, not four.
    expect(h.urls).toHaveLength(1);

    // It lands superseded, so it must not paint — and must ask once for the current question.
    h.pending[0].resolve({ caseId: "INC-1", forensicTimeline: [{ id: "stale" }] });
    await settle();
    expect(h.rendered).toHaveLength(0);
    expect(h.urls).toHaveLength(2);

    h.pending[1].resolve({ caseId: "INC-1", forensicTimeline: [{ id: "fresh" }] });
    await settle();
    const last = h.rendered[h.rendered.length - 1] as { forensicTimeline: { id: string }[] };
    expect(last.forensicTimeline.map((e) => e.id)).toEqual(["fresh"]);
  });

  // A superseded request that FAILS still owes the current question. Releasing its slot and
  // stopping there leaves the unfiltered case on screen under a term that is still set — rule 4,
  // broken on the error path only, where the earlier version of this test did not look.
  it("still re-asks when a superseded request fails", async () => {
    const h = harness();
    h.api.DfirTimelineView.setSearch("certutil");
    h.api.loadSearchedTimeline();
    h.api.DfirState.setLastState({ caseId: "INC-1", forensicTimeline: [{ id: "a" }] });

    h.pending[0].reject(new Error("offline"));
    await settle();
    expect(h.urls).toHaveLength(2); // asked again on its own, not merely unwedged

    h.pending[1].resolve({ caseId: "INC-1", forensicTimeline: [{ id: "b" }] });
    await settle();
    const last = h.rendered[h.rendered.length - 1] as { forensicTimeline: { id: string }[] };
    expect(last.forensicTimeline.map((e) => e.id)).toEqual(["b"]);
  });

  it("does not retry forever when the request was never superseded", async () => {
    const h = harness();
    h.api.DfirTimelineView.setSearch("certutil");
    h.api.loadSearchedTimeline();
    h.pending[0].reject(new Error("offline"));
    await settle();
    expect(h.urls).toHaveLength(1); // a plain failure is left for the next refresh to retry
  });
});
