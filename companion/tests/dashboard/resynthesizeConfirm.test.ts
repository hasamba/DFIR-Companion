import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// #4: Re-synthesize always forces a full provider run. When the pill already reads "up to date"
// (class ai-idle — painted by both the pushed idle event and the derived ai-state), a press asks
// first. Out of date, analyzing, error or no pill: it runs straight away, as before.

interface ScopeApi {
  resynthesize: () => void;
}

function press(pillClass: string | null, answer: boolean) {
  const calls: string[] = [];
  const els: Record<string, unknown> = {
    caseId: { value: "INC-1" },
    status: { textContent: "" },
    deepReasoning: { checked: false },
    synthesize: { disabled: false },
    ...(pillClass === null ? {} : { aiStatus: { className: pillClass } }),
  };
  const api = loadDashboardModule<ScopeApi>("dashboard-search-scope.js", [], {
    document: { getElementById: (id: string) => els[id] ?? null },
    confirm: (text: string) => {
      calls.push(`confirm ${text}`);
      return answer;
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

const QUESTION = "Conclusions are already up to date. Run synthesis again anyway? This spends provider time.";

describe("Re-synthesize on up-to-date conclusions (#4)", () => {
  it("asks first, and does nothing when the analyst declines", () => {
    expect(press("ai-idle", false)).toEqual([`confirm ${QUESTION}`]);
  });

  it("runs when the analyst accepts", () => {
    expect(press("ai-idle", true)).toEqual([`confirm ${QUESTION}`, "fetch /cases/INC-1/synthesize"]);
  });

  it("does not ask when the conclusions are out of date", () => {
    expect(press("ai-stale", false)).toEqual(["fetch /cases/INC-1/synthesize"]);
  });

  it("does not ask on an error or with no pill", () => {
    expect(press("ai-error", false)).toEqual(["fetch /cases/INC-1/synthesize"]);
    expect(press(null, false)).toEqual(["fetch /cases/INC-1/synthesize"]);
  });
});
