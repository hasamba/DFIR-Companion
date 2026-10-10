// A broad super-timeline search reports a floor, not a count (#2069).
//
// The route asks the store to stop counting once the page is full and the count has passed the
// forensic search's 10,000 ceiling, so a term that matches every row answers in under a second
// instead of ~6. The answer then carries totalIsLowerBound, and the panel must not print the floor
// as a total ("10000 events — page 1 of 100") or disable Next at a last page it cannot know. It
// shows "10,000+" — the forensic timeline's convention — and keeps Next live while pages come back
// full.
import { describe, it, expect } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface SuperTimelineApi {
  renderSuperTimeline: (data: unknown, caseId?: string) => void;
}

const PRELOAD = ["dashboard-state.js", "dashboard-time.js", "dashboard-timeline-view.js"];
const PAGE = 100; // ST_PAGE in dashboard-super-timeline.js

function harness() {
  const badge = { textContent: "", title: "" };
  const pager = { textContent: "" };
  const prev = { disabled: false };
  const next = { disabled: true };
  // No superTimelineList: the row markup is not under test, and render stops before drawing it.
  const elements: Record<string, unknown> = {
    caseId: { value: "INC-1" },
    superTimelineBadge: badge,
    stPager: pager,
    stPrev: prev,
    stNext: next,
  };
  const globals = {
    URLSearchParams,
    document: { getElementById: (id: string) => elements[id] ?? null, addEventListener: () => {} },
    fetch: () => new Promise(() => {}),
  };
  const api = loadDashboardModule<SuperTimelineApi>("dashboard-super-timeline.js", PRELOAD, globals);
  return { api, badge, pager, next };
}

const rows = (n: number) =>
  Array.from({ length: n }, (_, i) => ({ id: `e${i}`, timestamp: "2026-01-01T00:00:00Z", description: "d" }));

const answer = (total: number, n: number, floor: boolean) => ({
  events: rows(n),
  total,
  ...(floor ? { totalIsLowerBound: true } : {}),
  origins: [],
  hosts: [],
  labelsAvailable: [],
});

describe("super-timeline count floor (#2069)", () => {
  it("shows 10,000+ and keeps Next enabled while the page comes back full", () => {
    const { api, badge, pager, next } = harness();
    api.renderSuperTimeline(answer(10_000, PAGE, true), "INC-1");
    expect(badge.textContent).toBe(" (10,000+ events — page 1)");
    expect(badge.title).toMatch(/narrow the term/i);
    expect(pager.textContent).toBe("1–100 of 10,000+");
    expect(next.disabled).toBe(false);
  });

  it("disables Next under a floor once a page comes back short", () => {
    const { api, next } = harness();
    api.renderSuperTimeline(answer(10_000, 40, true), "INC-1");
    expect(next.disabled).toBe(true);
  });

  it("an exact total keeps the page-of-pages wording and its last-page rule", () => {
    const { api, badge, pager, next } = harness();
    api.renderSuperTimeline(answer(100, PAGE, false), "INC-1");
    expect(badge.textContent).toBe(" (100 events — page 1 of 1)");
    expect(badge.title).toBe("");
    expect(pager.textContent).toBe("1–100 of 100");
    expect(next.disabled).toBe(true);
  });
});
