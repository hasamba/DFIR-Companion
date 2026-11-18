// The full-screen board's filters: Key questions by status, Next steps by priority. One chip row on
// top of each column, with counts; the choice is saved per browser. Runs the real modules in a vm.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

type Item = Record<string, string>;
type Api = {
  watsonNextStepsHtml(steps: unknown[]): string;
  watsonBoardFilterBar(kind: string, items: Item[]): string;
  watsonBoardFiltered(kind: string, items: Item[]): Item[];
  watsonBoardCountText(kind: string, items: Item[]): string;
  watsonSetBoardFilter(btn: { dataset: Record<string, string> }): void;
};
type View = { watsonBoardHtml(questions: unknown[]): string };

function setup(stored: Record<string, string> = {}) {
  const written: Record<string, string> = { ...stored };
  let renders = 0;
  const api = loadDashboardModule<Api>("dashboard-watson-layout.js", ["dashboard-escape.js"], {
    document: {
      documentElement: { style: { setProperty: () => {} } },
      querySelector: () => null,
      querySelectorAll: () => [],
      addEventListener: () => {},
    },
    addEventListener: () => {},
    innerWidth: 1600,
    localStorage: {
      getItem: (k: string) => written[k] ?? null,
      setItem: (k: string, v: string) => (written[k] = v),
    },
    DfirState: { onLastStateChange: () => {} },
    renderWatson: () => (renders += 1),
  });
  return { api, written, renders: () => renders };
}

const STEPS = [
  { priority: "critical", action: "Confirm the emulation" },
  { priority: "medium", action: "Collect Sysmon" },
  { priority: "high", action: "Collect tasks" },
  { priority: "medium", action: "Collect Defender" },
];
const QUESTIONS = [
  { status: "partial", question: "First entry?" },
  { status: "answered", question: "Initial access?" },
  { status: "weird", question: "Odd status" },
];

describe("Next steps filter (priority)", () => {
  it("shows every step and an All chip by default, with a count on each chip", () => {
    const { api } = setup();
    const bar = api.watsonBoardFilterBar("steps", STEPS);
    expect(bar).toContain('data-w-filter-val="all" aria-pressed="true"');
    expect(bar).toContain("All 4");
    expect(bar).toContain("Critical 1");
    expect(bar).toContain("High 1");
    expect(bar).toContain("Medium 2");
    expect(bar).toContain("Low 0");
    expect(api.watsonBoardFiltered("steps", STEPS)).toHaveLength(4);
    expect(api.watsonBoardCountText("steps", STEPS)).toBe(" (4)");
  });

  it("keeps only the chosen priority, saves it, and repaints", () => {
    const { api, written, renders } = setup();
    api.watsonSetBoardFilter({ dataset: { wFilterKind: "steps", wFilterVal: "medium" } });
    expect(written["dfir.watson.filter.steps"]).toBe("medium");
    expect(renders()).toBe(1);
    const html = api.watsonNextStepsHtml(STEPS);
    expect(html).toContain("Collect Sysmon");
    expect(html).toContain("Collect Defender");
    expect(html).not.toContain("Confirm the emulation");
    expect(html).toContain('data-w-filter-val="medium" aria-pressed="true"');
    expect(api.watsonBoardCountText("steps", STEPS)).toBe(" (2 of 4)");
  });

  it("says so when no step matches, and keeps the chip row so the analyst can go back", () => {
    const { api } = setup({ "dfir.watson.filter.steps": "low" });
    const html = api.watsonNextStepsHtml(STEPS);
    expect(html).toContain("No next steps match this filter.");
    expect(html).toContain('data-w-filter-val="all"');
  });

  it("ignores a saved or clicked value that is not a priority", () => {
    const { api } = setup({ "dfir.watson.filter.steps": "<script>" });
    expect(api.watsonBoardFiltered("steps", STEPS)).toHaveLength(4);
    api.watsonSetBoardFilter({ dataset: { wFilterKind: "steps", wFilterVal: "bogus" } });
    expect(api.watsonBoardFiltered("steps", STEPS)).toHaveLength(4);
  });

  it("shows no chip row when there are no steps", () => {
    const { api } = setup();
    const html = api.watsonNextStepsHtml([]);
    expect(html).toContain("There are no next steps.");
    expect(html).not.toContain("watson-filter");
  });
});

describe("Key questions filter (status)", () => {
  it("counts an unrecognised status as Unknown, the same as its badge", () => {
    const { api } = setup();
    const bar = api.watsonBoardFilterBar("questions", QUESTIONS);
    expect(bar).toContain("Answered 1");
    expect(bar).toContain("Partial 1");
    expect(bar).toContain("Unknown 1");
    expect(bar).toContain("Not answerable 0");
    api.watsonSetBoardFilter({ dataset: { wFilterKind: "questions", wFilterVal: "unknown" } });
    expect(api.watsonBoardFiltered("questions", QUESTIONS).map((q) => q.question)).toEqual(["Odd status"]);
    expect(api.watsonBoardCountText("questions", QUESTIONS)).toBe(" (1 of 3)");
  });

  it("the questions column renders the chip row and only the matching questions", () => {
    const { api } = setup({ "dfir.watson.filter.questions": "answered" });
    const view = loadDashboardModule<View>("dashboard-watson-view.js", ["dashboard-escape.js"], {
      watsonBoardFilterBar: api.watsonBoardFilterBar,
      watsonBoardFiltered: api.watsonBoardFiltered,
    });
    const html = view.watsonBoardHtml(QUESTIONS);
    expect(html).toContain("Initial access?");
    expect(html).not.toContain("First entry?");
    expect(html).toContain('data-w-filter-kind="questions"');
  });

  it("the chips are wired to the click dispatcher", () => {
    const act = readFileSync(new URL("../../../public/js/dashboard-data-act.js", import.meta.url), "utf8");
    expect(act).toContain("watsonBoardFilter: (el) => watsonSetBoardFilter(el)");
  });
});
