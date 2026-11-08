// #2401: super-timeline state belongs to ONE case.
//
// Rows ticked in case A stayed selected in case B, so Promote, bulk Star and bulk Tag sent case A's
// event ids to case B. Case B also opened on case A's page number and under its Tagged-only,
// Starred-only and tag filters — a filtered or past-the-end page reads as "this case has nothing".
// And Promote had no guard against a double click, so one ticked set could be sent twice.
import { describe, it, expect } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface SuperTimelineApi {
  loadSuperTimeline: (caseId?: string) => void;
  initSuperTimeline: () => void;
  superPage: (delta: number) => void;
  toggleSuperPromote: (id: string, checked: boolean) => void;
  toggleSuperTaggedOnly: () => void;
  toggleSuperStarredOnly: () => void;
  setSuperLabelFilter: (label: string) => void;
  promoteSuperSelected: () => void;
  toggleSuperSelectAll: (checked: boolean) => void;
}

const PRELOAD = [
  "dashboard-state.js",
  "dashboard-escape.js",
  "dashboard-time.js",
  "dashboard-timeline-view.js",
];

const page = (total = 500, ids: string[] = []) => ({
  events: ids.map((id) => ({ id, timestamp: "2026-01-01T00:00:00Z", description: id, sources: ["s"] })),
  total,
  origins: [],
  hosts: [],
  labelsAvailable: ["x"],
});

interface Call {
  url: string;
  body?: string;
  resolve: (v: unknown) => void;
}

function harness() {
  const button = () => ({ textContent: "", classList: { toggle: () => {} } });
  const elements: Record<string, unknown> = {
    caseId: { value: "A" },
    superTimelineMsg: { textContent: "", style: { color: "" } },
    stFrom: { value: "" },
    stTo: { value: "" },
    stTaggedOnly: button(),
    superTimelineList: { innerHTML: "", querySelectorAll: () => [] },
    stStarredOnly: button(),
  };
  const calls: Call[] = [];
  const api = loadDashboardModule<SuperTimelineApi>("dashboard-super-timeline.js", PRELOAD, {
    URLSearchParams,
    document: {
      getElementById: (id: string) => elements[id] ?? null,
      addEventListener: () => {},
      querySelectorAll: () => [],
    },
    fetch: (url: string, init?: { body?: string }) =>
      new Promise((resolve) => calls.push({ url, body: init?.body, resolve })),
  });
  api.initSuperTimeline();
  const answer = (c: Call, body: unknown) =>
    c.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) });
  const reads = () => calls.filter((c) => c.url.includes("/super-timeline?"));
  const promotes = () => calls.filter((c) => c.url.endsWith("/super-timeline/promote"));
  return { api, elements, calls, answer, reads, promotes };
}

const settle = () => new Promise((r) => setTimeout(r, 0));
const params = (url: string) => new URLSearchParams(url.split("?")[1]);

describe("super-timeline across a case switch (#2401)", () => {
  it("does not carry the selection into the next case", async () => {
    const h = harness();
    h.api.loadSuperTimeline("A");
    h.answer(h.reads()[0], page());
    await settle();
    h.api.toggleSuperPromote("evt-from-A", true);

    (h.elements.caseId as { value: string }).value = "B";
    h.api.loadSuperTimeline("B");
    h.api.promoteSuperSelected();
    expect(h.promotes()).toHaveLength(0); // nothing ticked in B — A's ids must not reach B
  });

  it("opens the next case on its first page with no filters carried over", async () => {
    const h = harness();
    h.api.loadSuperTimeline("A");
    h.answer(h.reads()[0], page());
    await settle();
    h.api.toggleSuperTaggedOnly();
    h.api.toggleSuperStarredOnly();
    h.api.setSuperLabelFilter("x");
    h.api.superPage(3); // page 4 of A (a filter toggle resets to page 1, so page last)
    expect(params(h.reads()[h.reads().length - 1].url).get("offset")).toBe("300");

    (h.elements.caseId as { value: string }).value = "B";
    h.api.loadSuperTimeline("B");
    const q = params(h.reads()[h.reads().length - 1].url);
    expect(h.reads()[h.reads().length - 1].url).toContain("/cases/B/");
    expect(q.get("offset") ?? "0").toBe("0");
    expect(q.get("tagged")).toBeNull();
    expect(q.get("starred")).toBeNull();
    expect(q.get("labels")).toBeNull();
    expect((h.elements.stTaggedOnly as { textContent: string }).textContent).toBe("☐ Tagged only");
    expect((h.elements.stStarredOnly as { textContent: string }).textContent).toBe("☆ Starred only");
  });

  it("keeps page and filters while the analyst stays in the same case", async () => {
    const h = harness();
    h.api.loadSuperTimeline("A");
    h.api.toggleSuperTaggedOnly();
    h.api.loadSuperTimeline("A"); // e.g. a super_timeline_changed push
    expect(params(h.reads()[h.reads().length - 1].url).get("tagged")).toBe("1");
  });

  it("sends Promote once however many times it is clicked while in flight", async () => {
    const h = harness();
    h.api.loadSuperTimeline("A");
    h.answer(h.reads()[0], page());
    await settle();
    h.api.toggleSuperPromote("e1", true);
    h.api.promoteSuperSelected();
    h.api.promoteSuperSelected();
    expect(h.promotes()).toHaveLength(1);
    h.answer(h.promotes()[0], { promoted: 1 });
    await settle();
    h.api.toggleSuperPromote("e2", true);
    h.api.promoteSuperSelected();
    expect(h.promotes()).toHaveLength(2); // the guard lifts once the first answer lands
  });

  it("a promote that finishes after a case switch leaves the new case's selection alone", async () => {
    const h = harness();
    h.api.loadSuperTimeline("A");
    h.answer(h.reads()[0], page());
    await settle();
    h.api.toggleSuperPromote("e1", true);
    h.api.promoteSuperSelected();

    (h.elements.caseId as { value: string }).value = "B";
    h.api.loadSuperTimeline("B");
    h.api.toggleSuperPromote("b1", true);
    const readsBefore = h.reads().length;
    h.answer(h.promotes()[0], { promoted: 1 }); // A's promote lands while B is on screen
    await settle();
    expect(
      h
        .reads()
        .slice(readsBefore)
        .some((c) => c.url.includes("/cases/A/")),
    ).toBe(false);
    h.api.promoteSuperSelected();
    expect(h.promotes()).toHaveLength(2);
    expect(JSON.parse(h.promotes()[1].body ?? "{}")).toEqual({ eventIds: ["b1"] });
  });

  it("Select-all during the switch cannot tick the old case's rows into the new case", async () => {
    const h = harness();
    h.api.loadSuperTimeline("A");
    h.answer(h.reads()[0], page(1, ["A-event"]));
    await settle();
    (h.elements.caseId as { value: string }).value = "B";
    h.api.loadSuperTimeline("B"); // B's answer has not landed: A's rows are still cached
    h.api.toggleSuperSelectAll(true);
    h.api.promoteSuperSelected();
    expect(h.promotes()).toHaveLength(0);
  });

  it("an answer from an earlier visit is ignored after A -> B -> A", async () => {
    const h = harness();
    h.api.loadSuperTimeline("A");
    h.answer(h.reads()[0], page(1, ["e1"]));
    await settle();
    h.api.toggleSuperPromote("e1", true);
    h.api.promoteSuperSelected();
    const caseEl = h.elements.caseId as { value: string };
    caseEl.value = "B";
    h.api.loadSuperTimeline("B");
    caseEl.value = "A";
    h.api.loadSuperTimeline("A");
    h.api.toggleSuperPromote("e1", true); // ticked again in the new visit
    h.answer(h.promotes()[0], { promoted: 1 }); // the first visit's promote lands
    await settle();
    h.api.promoteSuperSelected(); // the new visit's tick survives, and the new visit is not locked
    expect(h.promotes()).toHaveLength(2);
    expect(JSON.parse(h.promotes()[1].body ?? "{}")).toEqual({ eventIds: ["e1"] });
  });

  it("the guard lifts after a failed or rejected promote", async () => {
    const h = harness();
    h.api.loadSuperTimeline("A");
    h.answer(h.reads()[0], page());
    await settle();
    h.api.toggleSuperPromote("e1", true);
    h.api.promoteSuperSelected();
    h.promotes()[0].resolve({ ok: false, status: 500, json: () => Promise.resolve({ error: "boom" }) });
    await settle();
    h.api.promoteSuperSelected();
    expect(h.promotes()).toHaveLength(2);
    h.promotes()[1].resolve(Promise.reject(new Error("network down")));
    await settle();
    h.api.promoteSuperSelected();
    expect(h.promotes()).toHaveLength(3); // still ticked after a failure, and sendable again
  });
});
