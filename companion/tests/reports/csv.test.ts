import { describe, it, expect } from "vitest";
import { findingsCsv, iocsCsv, timelineCsv } from "../../src/reports/csv.js";
import { emptyState } from "../../src/analysis/stateTypes.js";

describe("CSV renderers", () => {
  it("findingsCsv has a header and one row per finding, escaping commas/quotes", () => {
    const state = emptyState("c1");
    state.findings.push({ id: "f1", severity: "High", title: 'PS, "encoded"', description: "d",
      relatedIocs: ["i1"], mitreTechniques: ["T1059"], sourceScreenshots: ["a.webp"],
      firstSeen: "t0", lastUpdated: "t1", status: "open" });
    const csv = findingsCsv(state);
    const rows = csv.trim().split("\n");
    expect(rows[0]).toContain("id,severity,title");
    expect(rows[1]).toContain('"PS, ""encoded"""'); // escaped
  });

  it("iocsCsv guards formula-injection values with a leading single quote", () => {
    const state = emptyState("c1");
    state.iocs.push({ id: "i1", type: "url", value: "=cmd|'/C calc'!A0", firstSeen: "t0" });
    const csv = iocsCsv(state);
    expect(csv).toContain(`"'=cmd|'/C calc'!A0"`);
  });

  it("iocsCsv and timelineCsv produce headers even when empty", () => {
    const state = emptyState("c1");
    expect(iocsCsv(state).trim()).toBe("id,type,value,firstSeen");
    expect(timelineCsv(state).trim()).toBe("timestamp,windowSequence,description,sourceScreenshots");
  });
});
