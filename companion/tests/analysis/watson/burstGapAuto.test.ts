import { describe, expect, it } from "vitest";
import { applyBurstGapQuestions } from "../../../src/analysis/burstGapQuestions.js";
import { openItems } from "../../../src/analysis/ai/watson/autoProgress.js";
import { buildWatsonUserPrompt } from "../../../src/analysis/ai/watson/promptBuilder.js";
import { emptyWatsonChat } from "../../../src/analysis/ai/watson/types.js";
import { emptyState, type ForensicEvent } from "../../../src/analysis/stateTypes.js";

// #2681: Watson Auto works unanswered Key Questions. The burst-gap question must be one of them, and
// Watson's prompt must carry the hidden event ids, because it never sees a question's pointer otherwise.

const burst: ForensicEvent[] = Array.from({ length: 20 }, (_, i) => ({
  id: `9e${100 + i}`,
  timestamp: new Date(Date.UTC(2026, 10, 1, 10, 0, i)).toISOString(),
  description: `Sigma: Renamed cmd - CommandLine=… /c echo step${i}`,
  severity: "High",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
  asset: "WS-07",
  path: "C:\\ProgramData\\svc\\winupd.exe",
  commandLine: `"C:\\ProgramData\\svc\\winupd.exe" /c echo step${i}`,
}));

function stateWithGap() {
  const keyQuestions = applyBurstGapQuestions([], {
    membersOf: new Map([[burst[0].id, burst.map((e) => e.id)]]),
    events: burst,
    findings: [],
  });
  return { ...emptyState("c1"), forensicTimeline: burst, keyQuestions };
}

describe("Watson Auto picks up the burst-gap question (#2681)", () => {
  it("is an open item Auto works", () => {
    const state = stateWithGap();
    const [gap] = state.keyQuestions;
    const items = openItems(state);
    expect(items.map((i) => i.id)).toContain(gap.id);
    expect(items.find((i) => i.id === gap.id)?.needs).toContain("9e119");
  });

  it("Watson's prompt names every hidden event id for a lookup", () => {
    const prompt = buildWatsonUserPrompt({
      state: stateWithGap(),
      chat: emptyWatsonChat(),
      analystText: "",
      caseContext: "",
      mainLanguages: [],
    });
    const hidden = burst.slice(13).map((e) => e.id);
    for (const id of hidden) expect(prompt).toContain(id);
    expect(prompt).toMatch(/system coverage check/i);
  });

  it("an answered gap question is no longer an open item", () => {
    const state = stateWithGap();
    const answered = {
      ...state,
      keyQuestions: state.keyQuestions.map((q) => ({ ...q, status: "answered" as const, answer: "read" })),
    };
    expect(openItems(answered)).toEqual([]);
  });
});
