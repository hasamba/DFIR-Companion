import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// #2468: on an empty case the Ask panel showed only its text box, and the swimlane drew a blank
// chart. Each now says, in a sentence, that there is nothing to work from yet.

interface El {
  innerHTML: string;
  textContent: string;
  value: string;
  hidden: boolean;
  dataset: Record<string, string>;
}
const el = (value = ""): El => ({ innerHTML: "", textContent: "", value, hidden: false, dataset: {} });
const settle = () => new Promise((r) => setTimeout(r, 10));
const html = readFileSync(new URL("../../../public/dashboard.html", import.meta.url), "utf8");

describe("swimlane on an empty case (#2468)", () => {
  function load(lanes: unknown[], ok = true) {
    const all: Record<string, El> = {
      swimlaneGroupBy: el("asset"),
      swimlaneEmpty: { ...el(), hidden: true },
      swimlaneWrap: el(),
    };
    const api = loadDashboardModule<{ loadSwimlane: (c: string) => void }>("dashboard-swimlane.js", [], {
      document: { getElementById: (id: string) => all[id] ?? null },
      fetch: () =>
        Promise.resolve({
          ok,
          status: ok ? 200 : 503,
          json: () => Promise.resolve({ lanes, minTime: null, maxTime: null }),
        }),
      DfirSelection: { events: { count: () => 0 } },
    });
    api.loadSwimlane("INC-1");
    return all;
  }

  it("shows the empty sentence and hides the chart when there are no lanes", async () => {
    const all = load([]);
    await settle();
    expect(all.swimlaneEmpty.hidden).toBe(false);
    expect(all.swimlaneWrap.hidden).toBe(true);
  });

  it("shows the chart and hides the sentence when lanes arrive", async () => {
    const all = load([{ id: "h1", label: "HOST-1", type: "host", events: [] }]);
    await settle();
    expect(all.swimlaneEmpty.hidden).toBe(true);
    expect(all.swimlaneWrap.hidden).toBe(false);
  });

  it("leaves both alone when the load fails (an error is not 'no events')", async () => {
    const all = load([], false);
    await settle();
    expect(all.swimlaneEmpty.hidden).toBe(true);
    expect(all.swimlaneWrap.hidden).toBe(false);
  });

  it("has the sentence in the panel markup, hidden until a load says so", () => {
    expect(html).toMatch(
      /<div id="swimlaneEmpty"[^>]*hidden[^>]*>No forensic-timeline events to chart yet\./,
    );
  });
});

describe("Ask panel on an empty case (#2468)", () => {
  // Reached only through the state subscription — the module publishes no new global for it.
  function load() {
    const all: Record<string, El> = { askAnswer: el() };
    let subscriber: ((s: unknown) => void) | null = null;
    loadDashboardModule("dashboard-import-changes.js", ["dashboard-escape.js"], {
      document: { getElementById: (id: string) => all[id] ?? null, addEventListener: () => {} },
      DfirState: {
        lastState: () => null,
        onLastStateChange: (fn: (s: unknown) => void) => {
          subscriber = fn;
          return () => {};
        },
      },
    });
    return { all, push: (s: unknown) => subscriber?.(s) };
  }
  const EMPTY = { caseId: "INC-1", forensicTimeline: [], forensicTimelineTotal: 0, findings: [] };
  const FULL = { caseId: "INC-1", forensicTimeline: [{ id: "e1" }], forensicTimelineTotal: 1, findings: [] };

  it("says there is nothing to answer from when the case has no events and no findings", () => {
    const { all, push } = load();
    push(EMPTY);
    expect(all.askAnswer.innerHTML).toContain("No forensic-timeline events or findings yet");
  });

  it("clears its own sentence once evidence arrives", () => {
    const { all, push } = load();
    push(EMPTY);
    push(FULL);
    expect(all.askAnswer.innerHTML).toBe("");
  });

  it("never overwrites an answer already on screen", () => {
    const { all, push } = load();
    all.askAnswer.innerHTML = "<div class='info-card'>an answer</div>";
    push(EMPTY);
    expect(all.askAnswer.innerHTML).toBe("<div class='info-card'>an answer</div>");
  });

  it("does not call a case with findings but no events empty", () => {
    const { all, push } = load();
    push({ ...EMPTY, findings: [{ id: "f1" }] });
    expect(all.askAnswer.innerHTML).toBe("");
  });

  it("does nothing for an unknown (null) state", () => {
    const { all, push } = load();
    push(null);
    expect(all.askAnswer.innerHTML).toBe("");
    push(EMPTY);
    push(null); // a case switch clears the state: the stale sentence goes with it
    expect(all.askAnswer.innerHTML).toBe("");
  });
});
