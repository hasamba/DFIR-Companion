import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// #2468: on an empty case, Re-synthesize first asked "Conclusions are already up to date… run again
// anyway?" and then answered "nothing to synthesize". With nothing in the forensic timeline the
// question is wrong, so it is not asked — the request still goes to the server, which stays the
// authority and answers "nothing to synthesize".

interface ScopeApi {
  resynthesize: () => void;
}

function press(state: unknown) {
  const calls: string[] = [];
  const els: Record<string, unknown> = {
    caseId: { value: "INC-1" },
    status: { textContent: "" },
    deepReasoning: { checked: false },
    synthesize: { disabled: false },
    aiStatus: { className: "ai-idle" },
  };
  const api = loadDashboardModule<ScopeApi>("dashboard-search-scope.js", [], {
    document: { getElementById: (id: string) => els[id] ?? null },
    DfirState: { lastState: () => state },
    confirm: () => {
      calls.push("confirm");
      return false;
    },
    setAi: () => {},
    refreshAiState: () => {},
    fetch: (url: string) => {
      calls.push(`fetch ${url}`);
      return new Promise(() => {});
    },
    render: () => {},
    loadSynthMeta: () => {},
  });
  api.resynthesize();
  return calls;
}

describe("Re-synthesize on an empty case (#2468)", () => {
  it("does not ask the up-to-date question when the forensic timeline is empty", () => {
    expect(press({ caseId: "INC-1", forensicTimeline: [], forensicTimelineTotal: 0 })).toEqual([
      "fetch /cases/INC-1/synthesize",
    ]);
  });

  it("reads an empty timeline array when the server sent no total", () => {
    expect(press({ caseId: "INC-1", forensicTimeline: [] })).toEqual(["fetch /cases/INC-1/synthesize"]);
  });

  it("still asks when the timeline has events", () => {
    expect(press({ caseId: "INC-1", forensicTimeline: [{ id: "e1" }], forensicTimelineTotal: 1 })).toEqual([
      "confirm",
    ]);
  });

  it("still asks when the total says events exist beyond the loaded batch", () => {
    expect(press({ caseId: "INC-1", forensicTimeline: [], forensicTimelineTotal: 40 })).toEqual(["confirm"]);
  });

  it("still asks when no state is loaded yet (unknown is not empty)", () => {
    expect(press(null)).toEqual(["confirm"]);
  });
});
