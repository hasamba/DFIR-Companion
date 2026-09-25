import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// #1663. While a server-side search answer is painted, the timeline holds only the matches. The
// jump used to count the target's page in that subset, clear the search, and keep the page — and
// clearing the search re-asks the server for the whole timeline ASYNCHRONOUSLY. When the whole list
// landed, the pager kept the subset's page on the longer list, so the analyst saw unrelated events.
// A target outside the subset was worse: the jump did nothing at all.
//
// These tests drive the real search loader, timeline view and jump together, with the server's
// answers held back until the test releases them — the same order of events a slow case scan makes.

interface Ev {
  id: string;
  severity: string;
}

interface Sandbox {
  jumpToEvent(id: string): void;
  loadSearchedTimeline(): void;
  tlPage: number;
  _tlKeepPage: boolean;
  _tlFilterKey: string | null;
  DfirTimelineView: {
    wire(p: Record<string, () => void>): void;
    setSearch(term: string): void;
    showOnlyStarred(on: boolean): void;
    search(): string;
    starredOnly(): boolean;
  };
  DfirState: {
    lastState(): { caseId?: string; forensicTimeline?: Ev[] } | null;
    setLastState(s: unknown): void;
    setLastFt(ft: unknown): void;
    lastFt(): Ev[] | null;
  };
}

const PAGE = 2;
const ev = (id: string): Ev => ({ id, severity: "High" });
const FULL = ["a", "b", "c", "d", "e", "f"].map(ev);
const state = (ids: string[], caseId = "INC-1") => ({ caseId, forensicTimeline: ids.map(ev) });

function harness() {
  const caseEl = { value: "INC-1" };
  const pending: { url: string; resolve: (b: unknown) => void; reject: (e: Error) => void }[] = [];
  const renders: { page: number; ids: string[] }[] = [];
  const toasts: string[] = [];
  const noop = () => {};
  const facet = { showAll: noop, matcher: () => ({ has: () => false }) };
  const globals: Record<string, unknown> = {
    document: {
      getElementById: (id: string) => (id === "caseId" ? caseEl : null),
      addEventListener: noop,
      createElement: () => ({}),
      // The rows on the current page, as renderTimelineEvents would have drawn them.
      querySelectorAll: () =>
        (renders.at(-1)?.ids ?? []).map((id) => ({
          getAttribute: () => id,
          scrollIntoView: noop,
          classList: { add: noop, remove: noop },
          offsetWidth: 0,
        })),
    },
    localStorage: { getItem: () => null, setItem: noop },
    location: { hash: "" },
    setTimeout: (fn: () => void) => fn(),
    tlPage: 0,
    tlPageSize: PAGE,
    _tlKeepPage: false,
    _tlFilterKey: null,
    _srcMenuSig: "",
    _originMenuSig: "",
    _hostMenuSig: "",
    DfirFacets: { sources: facet, origins: facet, hosts: facet },
    sortTimelineEvents: (list: Ev[]) => list,
    viewMeetsMinSev: () => true,
    showToast: (text: string) => toasts.push(text),
    fetch: (url: string) =>
      new Promise((resolve, reject) => {
        pending.push({
          url,
          resolve: (body) => resolve({ ok: true, status: 200, json: () => Promise.resolve(body) }),
          reject,
        });
      }),
    // The page's render(): the single writer of the snapshot, then the timeline's own paint.
    render: (s: { forensicTimeline?: Ev[] }) => {
      sb.DfirState.setLastState(s);
      sb.DfirState.setLastFt(s.forensicTimeline || []);
      renderTimeline();
    },
  };
  // The pager rule from #1660: the page resets when the filter key changes, unless a jump asked
  // to keep it; a background refresh under the same key keeps it.
  function renderTimeline() {
    const v = sb.DfirTimelineView;
    const key = [caseEl.value, v.search(), v.starredOnly()].join("|");
    if (!sb._tlKeepPage && key !== sb._tlFilterKey) sb.tlPage = 0;
    sb._tlFilterKey = key;
    sb._tlKeepPage = false;
    const ft = sb.DfirState.lastFt() || [];
    const ids = ft.slice(sb.tlPage * PAGE, sb.tlPage * PAGE + PAGE).map((e) => e.id);
    renders.push({ page: sb.tlPage, ids });
  }
  globals.renderTimelineEvents = renderTimeline;
  const sb = loadDashboardModule<Sandbox>(
    "dashboard-hunts-jumps.js",
    [
      "dashboard-state.js",
      "dashboard-time.js",
      "dashboard-timeline-view.js",
      "dashboard-timeline-search.js",
      "dashboard-filters.js",
      "dashboard-timeline-display.js",
    ],
    globals,
  );
  sb.DfirTimelineView.wire({
    serverSearch: () => sb.loadSearchedTimeline(),
    all: () => {
      const s = sb.DfirState.lastState();
      if (s) (globals.render as (s: unknown) => void)(s);
    },
  });
  const settle = () => new Promise((r) => setTimeout(r, 0));
  const answer = async (body: unknown) => {
    const p = pending.shift();
    if (!p) throw new Error("no request in flight");
    p.resolve(body);
    await settle();
    await settle();
  };
  const shown = () => renders.at(-1)?.ids ?? [];
  return { sb, caseEl, pending, renders, toasts, answer, shown, settle };
}

// The whole case is painted, then the analyst searches and the server answers with a subset.
async function searched(subset: string[]) {
  const h = harness();
  h.sb.loadSearchedTimeline();
  await h.answer(state(FULL.map((e) => e.id)));
  h.sb.DfirTimelineView.setSearch("x");
  await h.answer(state(subset));
  return h;
}

describe("jumpToEvent while a server-side search is painted (#1663)", () => {
  it("lands on the target's page in the WHOLE timeline once the search clear is answered", async () => {
    const h = await searched(["a", "c", "e", "f"]);
    expect(h.shown()).toEqual(["a", "c"]);
    h.sb.jumpToEvent("f");
    expect(h.pending.map((p) => p.url)).toEqual(["/cases/INC-1/state"]); // the clear re-asks the case
    await h.answer(state(FULL.map((e) => e.id)));
    expect(h.shown()).toContain("f"); // page 2 of the whole list: e, f
    expect(h.sb.tlPage).toBe(2);
    expect(h.toasts).toEqual([]);
  });

  it("reaches a target that is not in the searched subset", async () => {
    const h = await searched(["a", "c", "e", "f"]);
    h.sb.jumpToEvent("d");
    expect(h.sb.DfirTimelineView.search()).toBe(""); // the search that hid it is cleared
    await h.answer(state(FULL.map((e) => e.id)));
    expect(h.shown()).toContain("d");
    expect(h.toasts).toEqual([]);
  });

  it("goes to the LAST target when the analyst jumps twice before the clear is answered", async () => {
    const h = await searched(["a", "c", "e", "f"]);
    h.sb.jumpToEvent("f");
    h.sb.jumpToEvent("b");
    expect(h.pending).toHaveLength(1); // one scan, not two
    await h.answer(state(FULL.map((e) => e.id)));
    expect(h.shown()).toContain("b");
  });

  it("does not jump once the analyst has typed a new search", async () => {
    const h = await searched(["a", "c", "e", "f"]);
    h.sb.jumpToEvent("f");
    h.sb.DfirTimelineView.setSearch("y");
    await h.answer(state(FULL.map((e) => e.id))); // the abandoned clear
    await h.answer(state(["b", "c", "d"])); // the new term's answer
    expect(h.shown()).toEqual(["b", "c"]);
    expect(h.sb.DfirTimelineView.search()).toBe("y");
    expect(h.toasts).toEqual([]);
  });

  it("does not undo a filter the analyst set while the clear was in flight", async () => {
    const h = await searched(["a", "c", "e", "f"]);
    h.sb.jumpToEvent("f");
    h.sb.DfirTimelineView.showOnlyStarred(true);
    await h.answer(state(FULL.map((e) => e.id)));
    expect(h.sb.DfirTimelineView.starredOnly()).toBe(true);
    expect(h.sb.tlPage).toBe(0);
  });

  it("drops the jump when a different case replaces the timeline", async () => {
    const h = await searched(["a", "c", "e", "f"]);
    h.sb.jumpToEvent("f");
    h.caseEl.value = "INC-2";
    (h.sb as unknown as { render: (s: unknown) => void }).render(state(["a", "b"], "INC-2"));
    // The abandoned INC-1 clear lands and re-asks for INC-2, which answers with an f of its own.
    await h.answer(state(FULL.map((e) => e.id)));
    await h.answer(
      state(
        FULL.map((e) => e.id),
        "INC-2",
      ),
    );
    expect(h.sb.tlPage).toBe(0);
    expect(h.toasts).toEqual([]);
  });

  it("says so when the clear request fails, rather than doing nothing", async () => {
    const h = await searched(["a", "c", "e", "f"]);
    h.sb.jumpToEvent("f");
    h.pending.shift()!.reject(new Error("offline"));
    await h.settle();
    await h.settle();
    expect(h.toasts).toHaveLength(1);
    expect(h.toasts[0]).toMatch(/could not/i);
  });

  it("says the event is past the loaded timeline when only the search could reach it", async () => {
    // The unfiltered payload is capped; a search scans the whole case and can return rows past it.
    const h = await searched(["a", "c", "e", "z"]);
    h.sb.jumpToEvent("z");
    await h.answer(state(FULL.map((e) => e.id)));
    expect(h.toasts).toHaveLength(1);
    expect(h.toasts[0]).toMatch(/past the part of the timeline/i);
  });

  it("jumps at once, with no refetch, when no search is painted", async () => {
    const h = harness();
    h.sb.loadSearchedTimeline();
    await h.answer(state(FULL.map((e) => e.id)));
    h.sb.jumpToEvent("f");
    expect(h.pending).toHaveLength(0);
    expect(h.shown()).toContain("f");
  });
});
