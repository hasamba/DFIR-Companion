// #1771 — the 2nd-opinion button on an empty case: the server answers 200 { skipped, message }.
// The status line says the run did not happen, in a neutral sentence — never "second opinion
// failed:" and never "0 disagreements" — and the panel is not painted from a non-record.
import { describe, it, expect } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface Api {
  runSecondOpinion(): void;
}

function harness(status: number, body: unknown) {
  const els = new Map<
    string,
    {
      value: string;
      textContent: string;
      innerHTML: string;
      disabled: boolean;
      checked: boolean;
      style: Record<string, string>;
    }
  >();
  const el = (id: string) => {
    if (!els.has(id))
      els.set(id, { value: "", textContent: "", innerHTML: "", disabled: false, checked: false, style: {} });
    return els.get(id)!;
  };
  const globals = {
    document: { getElementById: (id: string) => el(id) },
    localStorage: { getItem: () => null, setItem: () => {} },
    fetch: () => Promise.resolve({ status, ok: status < 400, json: () => Promise.resolve(body) }),
  };
  const api = loadDashboardModule<Api>(
    "dashboard-second-opinion.js",
    ["dashboard-escape.js", "dashboard-time.js"],
    globals,
  );
  el("caseId").value = "case-1";
  return { api, el };
}

const settle = () => new Promise((resolve) => setTimeout(resolve, 10));

describe("a skipped second opinion (#1771)", () => {
  it("says the run did not happen, neutrally", async () => {
    const { api, el } = harness(200, {
      skipped: "empty-timeline",
      message: "nothing to review — import evidence and synthesize the case first",
    });
    api.runSecondOpinion();
    await settle();
    const text = el("status").textContent;
    expect(text).toBe(
      "second opinion not run: nothing to review — import evidence and synthesize the case first",
    );
    expect(text).not.toMatch(/failed|disagreement/);
    expect(el("secondOpinionPanel").innerHTML).toBe("");
    expect(el("secondOpinion").disabled).toBe(false);
  });

  it("still reports a real failure as a failure", async () => {
    const { api, el } = harness(500, { error: "model B down" });
    api.runSecondOpinion();
    await settle();
    expect(el("status").textContent).toBe("second opinion failed: model B down");
  });
});
