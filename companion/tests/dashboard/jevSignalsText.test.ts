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

describe("the caption names the grading style (DFIR_JEV_GRADING)", () => {
  interface CaptionApi {
    jevCaptionHtml(
      result: Record<string, unknown>,
      counts: { shown: number; kept: number; drawn: number },
    ): string;
  }
  const caption = (shape?: string) =>
    loadDashboardModule<CaptionApi>("dashboard-jev-review-format.js", ["dashboard-escape.js"]).jevCaptionHtml(
      { matched: 2, read: 2, graded: 2, rows: [], ...(shape ? { shape } : {}) },
      { shown: 0, kept: 0, drawn: 0 },
    );

  it("says when the narrow questions graded the rows", () => {
    expect(caption("decomposed")).toContain("narrow questions (experimental)");
  });

  it("says nothing extra for the default single-question grade, or an older server", () => {
    expect(caption("single")).not.toContain("narrow questions");
    expect(caption()).not.toContain("narrow questions");
  });
});

describe("the Settings field for the grading style", () => {
  it("offers both styles, defaults to single, and explains the trade-off", async () => {
    const { readFile } = await import("node:fs/promises");
    const html = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    const field = html.slice(
      html.indexOf('for="env-DFIR_JEV_GRADING"') - 40,
      html.indexOf("</select>", html.indexOf('id="env-DFIR_JEV_GRADING"')),
    );
    expect(field).toContain('<select id="env-DFIR_JEV_GRADING">');
    expect(field).toMatch(/<option value="">[^<]*single[^<]*<\/option>/);
    expect(field).toContain('<option value="narrow">');
    expect(field).toMatch(/miss/i); // the narrow style's cost is stated, not just its benefit
    expect(field).toMatch(/false alarm/i);
  });
});
