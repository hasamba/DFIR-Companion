// The super-timeline panel must say it is working, and a stale answer must never win.
//
// Reported as "the filter does not filter the super-timeline": the analyst typed a term into the
// dashboard's Filter box, the forensic timeline narrowed to 15 of 253 events, and the super-timeline
// went on showing all 100000. The filter was wired end to end the whole time — superQueryString()
// sends the term as `q`, and the server drops every row eventMatchesSearch() rejects — so the whole
// failure was in this one load path:
//
//   1. loadSuperTimeline drew NOTHING while the fetch was in flight. The store scans every row in
//      JavaScript, so on a full case the query takes seconds, and for those seconds the panel still
//      shows the previous unfiltered rows. That is indistinguishable from "the filter did nothing".
//   2. There was no request token, so the last RESPONSE won rather than the last REQUEST. The
//      unfiltered load still running when the analyst typed could land second and repaint all
//      100000 rows over the filtered answer.
//   3. The page's refresh could only re-query a panel that already HAD data (`lastSuperData()`), so
//      a filter typed during the FIRST load fired no request at all. That load then painted every
//      event, and nothing reloaded it.
//
// The third is fixed here rather than in the page, and deliberately without an "a load is running"
// flag: runPanelLoaders hands an aborted loader a promise that NEVER SETTLES (its own comment calls
// that "the honest shape for this request was abandoned"), so such a flag would be stuck on for the
// rest of the session after one cancelled case load — and a panel that is permanently "live"
// re-queries a case the analyst walked away from. The request carries the question it asked
// instead, and re-asks only when an answer lands against a question that has since changed.
import { describe, it, expect } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface SuperTimelineApi {
  loadSuperTimeline: (caseId?: string) => void;
  DfirState: { lastSuperData: () => { total: number } | null };
  DfirTimelineView: { setSearch: (term: string) => void };
}

const PRELOAD = ["dashboard-state.js", "dashboard-time.js", "dashboard-timeline-view.js"];

/** One super-timeline answer, as the route returns it. No rows — these tests are about WHICH answer paints. */
const answer = (total: number) => ({ events: [], total, origins: [], hosts: [], labelsAvailable: [] });

/** A fetch that records every URL and hands the test the resolve/reject of that request. */
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
  const urls: string[] = [];
  const pending: { resolve: (body: unknown) => void; reject: (e: Error) => void }[] = [];
  const globals = {
    URLSearchParams, // superQueryString() builds the query with it; the sandbox has no web globals
    document: { getElementById: (id: string) => elements[id] ?? null, addEventListener: () => {} },
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
  return {
    msg,
    badge,
    urls,
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
    api.loadSuperTimeline(); // a second query while that one was still running
    expect(pending).toHaveLength(2);

    pending[1].resolve(answer(3)); // the newer answer comes back first…
    await settle();
    expect(badge.textContent).toBe(" (3 events — page 1 of 1)");

    pending[0].resolve(answer(100000)); // …and the older one lands after it
    await settle();
    expect(badge.textContent).toBe(" (3 events — page 1 of 1)"); // still the newer view
    expect(api.DfirState.lastSuperData()?.total).toBe(3);
  });

  it("asks again when the filter moved while the first load was in flight, without drawing the stale answer", async () => {
    const { api, msg, urls, pending } = harness();

    api.loadSuperTimeline(); // the case-open load: unfiltered, and slow
    expect(urls[0]).not.toContain("q=");

    api.DfirTimelineView.setSearch("lynx"); // the analyst types while it is still running
    pending[0].resolve(answer(100000)); // the unfiltered answer lands
    await settle();

    expect(urls).toHaveLength(2); // the panel sees that it answered the wrong question
    expect(urls[1]).toContain("q=lynx");
    // And it does NOT draw the answer it just discarded. Painting 100000 events under a filter that
    // is set — even for the seconds the second query takes — is the bug being fixed, not a step
    // on the way to fixing it.
    expect(api.DfirState.lastSuperData()).toBeNull();
    expect(msg.textContent).toBe("Loading super-timeline…");

    pending[1].resolve(answer(3));
    await settle();
    expect(api.DfirState.lastSuperData()?.total).toBe(3); // the filtered answer is the first to paint
  });

  it("stays silent when an abandoned load never lands", async () => {
    const { api, urls, pending } = harness();

    api.loadSuperTimeline(); // a case-open load the analyst then cancelled
    api.DfirTimelineView.setSearch("lynx");
    await settle(); // its promise never settles — runPanelLoaders drops aborted loaders that way

    expect(urls).toHaveLength(1); // no fresh full-store scan for a case they walked away from
    expect(pending).toHaveLength(1);
    expect(api.DfirState.lastSuperData()).toBeNull();
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
