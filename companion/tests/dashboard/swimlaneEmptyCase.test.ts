import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// #2468: on an empty case the swimlane drew a blank chart. It now says, in a sentence, that there is
// nothing to chart yet. (The Ask panel's half of #2468 moved to Watson's log with Ask's retirement —
// see tests/dashboard/watsonPanel.test.ts.)

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
