// F13: anything graded Info never reaches the forensic timeline (CLAUDE.md §7), so a Watson finding
// draft graded Info is dropped when the reply's writes are sanitized; every other grade stays.
import { describe, expect, it } from "vitest";
import { sanitizeWrites, type WatsonFindingDraft } from "../../../src/analysis/ai/watson/writesSchema.js";

const draft = (severity: WatsonFindingDraft["severity"]): WatsonFindingDraft => ({
  severity,
  title: `A ${severity} finding`,
  description: "Cites a forensic event.",
  mitreTechniques: [],
  eventIds: ["e1"],
  pasteLines: [],
});

describe("sanitizeWrites", () => {
  it("drops a finding draft graded Info and keeps the other grades", () => {
    const out = sanitizeWrites(
      { findings: [draft("Info"), draft("Low"), draft("High")], nextSteps: [], report: [] },
      new Set(["e1"]),
    );
    expect(out.findings.map((f) => f.severity)).toEqual(["Low", "High"]);
  });
});
