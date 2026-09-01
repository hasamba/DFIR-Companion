// The super-timeline panel must say it is working, and a stale answer must never win.
//
// Reported as "the filter does not filter the super-timeline": the analyst typed a term into the
// dashboard's Filter box, the forensic timeline narrowed to 15 of 253 events, and the super-timeline
// went on showing all 100000. The filter was wired end to end the whole time — superQueryString()
// sends the term as `q`, and the server drops every row eventMatchesSearch() rejects — so both
// halves of the failure were in this one load path:
//
//   1. loadSuperTimeline drew NOTHING while the fetch was in flight. The store scans every row in
//      JavaScript, so on a full case the query takes seconds, and for those seconds the panel still
//      shows the previous unfiltered rows. That is indistinguishable from "the filter did nothing".
//   2. There was no request token, so the last RESPONSE won rather than the last REQUEST. The
//      unfiltered load still running when the analyst typed could land second and repaint all
//      100000 rows over the filtered answer — permanently, until something else reloaded the panel.
//
// Both are asserted here against the real module, loaded the way the browser loads it.
import { describe, it, expect } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface SuperTimelineApi {
  loadSuperTimeline: (caseId?: string) => void;
  refreshSuperTimelineFilters: () => void;
  DfirState: { lastSuperData: () => { total: number } | null };
}

const PRELOAD = ["dashboard-state.js", "dashboard-time.js", "dashboard-timeline-view.js"];

/** One super-timeline answer, as the route returns it. No rows — the guard is about WHICH answer paints. */
const answer = (total: number) => ({ events: [], total, origins: [], hosts: [], labelsAvailable: [] });

/** A fetch whose every call hands the test the resolve/reject of that request. */
function harness() {
  const msg = { textContent: "", style: { color: "" } };
  const list = { innerHTML: "" };
  const badge = { textContent: "" };
  const pager = { textContent: "" };
  const elements: Record<string, unknown> = {
    caseId: { value: "INC-1" },
    superTimelineMsg: msg,
    superTimelineList: list,
    superTimelineBadge: badge,
    stPager: pager,
    stPrev: { disabled: false },
    stNext: { disabled: false },
  };
  const pending: { resolve: (body: unknown) => void; reject: (e: Error) => void }[] = [];
  const globals = {
    URLSearchParams, // superQueryString() builds the query with it; the sandbox has no web globals
    document: { getElementById: (id: string) => elements[id] ?? null, addEventListener: () => {} },
    fetch: () =>
      new Promise((resolve, reject) => {
        pending.push({
          resolve: (body) => resolve({ ok: true, status: 200, json: () => Promise.resolve(body) }),
          reject,
        });
      }),
  };
  return {
    msg,
    list,
    badge,
    pager,
    pending,
    api: loadDashboardModule<SuperTimelineApi>("dashboard-super-timeline.js", PRELOAD, globals),
  };
}

/** Let the fetch chain's .then handlers run. */
const settle = () => new Promise((r) => setTimeout(r, 0));

describe("the super-timeline load path", () => {
  it("says it is loading while the query runs, and stops saying it when the rows arrive", async () => {
    const { api, msg, pending } = harness();

    api.loadSuperTimeline();
    expect(msg.textContent).toBe("Loading super-timeline…"); // NOT the stale rows in silence
    expect(msg.style.color).toBe("var(--text-muted)"); // a status line, not an error

    pending[0].resolve(answer(3));
    await settle();
    expect(msg.textContent).toBe("");
  });

  it("keeps the newest answer when an older, slower one lands after it", async () => {
    const { api, badge, pending } = harness();

    api.loadSuperTimeline(); // the unfiltered load the case-open kicked off
    api.loadSuperTimeline(); // the analyst typed "lynx" while that was still running
    expect(pending).toHaveLength(2);

    pending[1].resolve(answer(3)); // the filtered answer comes back first…
    await settle();
    expect(badge.textContent).toBe(" (3 events — page 1 of 1)");

    pending[0].resolve(answer(100000)); // …and the older unfiltered one lands after it
    await settle();
    expect(badge.textContent).toBe(" (3 events — page 1 of 1)"); // still the filtered view
    expect(api.DfirState.lastSuperData()?.total).toBe(3);
  });

  it("re-queries when a filter changes during the FIRST load, and drops that load's answer", async () => {
    const { api, pending } = harness();

    api.loadSuperTimeline(); // the case-open load: unfiltered, and slow
    expect(pending).toHaveLength(1);

    api.refreshSuperTimelineFilters(); // the analyst typed while it was still running
    expect(pending).toHaveLength(2); // it re-queries instead of waiting for an answer to exist

    pending[0].resolve(answer(100000)); // the unfiltered answer lands first…
    await settle();
    expect(api.DfirState.lastSuperData()).toBeNull(); // …and paints nothing

    pending[1].resolve(answer(3));
    await settle();
    expect(api.DfirState.lastSuperData()?.total).toBe(3);
  });

  it("stays quiet for a panel the analyst never opened", () => {
    const { api, pending } = harness();

    api.refreshSuperTimelineFilters();
    expect(pending).toHaveLength(0); // a filter change must not load a panel nobody asked for
  });

  it("goes quiet again when a load ends without an answer", async () => {
    const { api, pending } = harness();

    api.loadSuperTimeline(); // the case-open load…
    pending[0].reject(new Error("aborted")); // …which the analyst then cancelled
    await settle();

    api.refreshSuperTimelineFilters();
    expect(pending).toHaveLength(1); // no fresh full-store scan for a case they walked away from
  });

  it("does not let a stale failure overwrite a newer answer with an error", async () => {
    const { api, msg, pending } = harness();

    api.loadSuperTimeline();
    api.loadSuperTimeline();

    pending[1].resolve(answer(3));
    await settle();
    expect(msg.textContent).toBe("");

    pending[0].reject(new Error("socket hang up"));
    await settle();
    expect(msg.textContent).toBe(""); // the newer request succeeded; the panel is not broken
  });

  it("reports a failure of the newest request", async () => {
    const { api, msg, pending } = harness();

    api.loadSuperTimeline();
    pending[0].reject(new Error("socket hang up"));
    await settle();
    expect(msg.textContent).toContain("failed to load super-timeline: socket hang up");
    expect(msg.style.color).toBe("var(--badge-danger-text)");
  });
});
