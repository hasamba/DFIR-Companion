// The reason line under a decomposed grade (#1924): the answers the grade was decided from, in words
// an analyst reads, never the raw field names.
import { describe, it, expect } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface Api {
  jevSignalsText(row: Record<string, unknown>): string;
}
const api = () => loadDashboardModule<Api>("dashboard-jev-review-format.js", ["dashboard-escape.js"]);
const signals = (over: Record<string, unknown> = {}) => ({
  shape: "decomposed",
  rule: "d1",
  malicious: 0.92,
  explained: null,
  strength: 2.6,
  strengthConfidence: 0.8,
  impact: 2.2,
  decision: "graded",
  ...over,
});

describe("the decomposed grade's reason line", () => {
  it("says what the grade rests on", () => {
    const t = api().jevSignalsText({ signals: signals() });
    expect(t).toContain("attacker activity 92%");
    expect(t).toContain("evidence: confirmed");
    expect(t).toContain("impact: credentials, privilege or persistence");
    expect(t).not.toContain("malicious");
  });

  it("names an analyst record that explains the row, and a conflict as needing a look", () => {
    expect(
      api().jevSignalsText({ signals: signals({ malicious: 0.1, explained: 0.9, decision: "explained" }) }),
    ).toContain("an analyst record explains it (90%)");
    expect(api().jevSignalsText({ signals: signals({ explained: 0.9, decision: "conflict" }) })).toContain(
      "conflicts with an analyst record — check it",
    );
  });

  it("is empty for a single-question grade or a malformed record", () => {
    expect(api().jevSignalsText({})).toBe("");
    expect(api().jevSignalsText({ signals: { malicious: "x" } })).toBe("");
  });

  it("names the evidence level by the rule's own cut points", () => {
    expect(api().jevSignalsText({ signals: signals({ strength: 0.7 }) })).toContain("evidence: speculative");
    expect(api().jevSignalsText({ signals: signals({ strength: 1.2 }) })).toContain(
      "evidence: circumstantial",
    );
    expect(api().jevSignalsText({ signals: signals({ strength: 2.4 }) })).toContain("evidence: strong");
    expect(api().jevSignalsText({ signals: signals({ strength: 2.5 }) })).toContain("evidence: confirmed");
  });
});
