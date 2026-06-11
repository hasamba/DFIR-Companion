import { describe, it, expect } from "vitest";
import { findingsCsv, iocsCsv, timelineCsv, forensicTimelineCsv } from "../../src/reports/csv.js";
import { emptyState } from "../../src/analysis/stateTypes.js";

describe("CSV renderers", () => {
  it("findingsCsv has a header and one row per finding, escaping commas/quotes", () => {
    const state = emptyState("c1");
    state.findings.push({ id: "f1", severity: "High", title: 'PS, "encoded"', description: "d",
      relatedIocs: ["i1"], mitreTechniques: ["T1059"], sourceScreenshots: ["a.webp"],
      firstSeen: "t0", lastUpdated: "t1", status: "open" });
    const csv = findingsCsv(state);
    const rows = csv.trim().split("\n");
    expect(rows[0]).toContain("id,severity,confidence,title");
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
    expect(iocsCsv(state).trim()).toBe("id,type,value,firstSeen,sources,sourceCount,enrichment");
    expect(timelineCsv(state).trim()).toBe("timestamp,windowSequence,description,sourceScreenshots");
  });

  it("forensicTimelineCsv emits a header and rows ordered by event time", () => {
    const state = emptyState("c1");
    expect(forensicTimelineCsv(state).trim()).toBe(
      "timestamp,endTimestamp,count,severity,description,mitreTechniques,sources,relatedFindingIds,sourceScreenshots",
    );
    state.forensicTimeline.push(
      { id: "e2", timestamp: "2026-05-20T15:00:00Z", endTimestamp: "2026-05-20T15:30:00Z", count: 12,
        description: "later", severity: "Critical",
        mitreTechniques: ["T1486"], relatedFindingIds: ["f1"], sourceScreenshots: ["s2.webp"] },
      { id: "e1", timestamp: "2026-05-20T09:00:00Z", description: "earlier", severity: "High",
        mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [] },
    );
    const rows = forensicTimelineCsv(state).trim().split("\n");
    expect(rows[1]).toContain("earlier"); // 09:00 sorts before 15:00
    expect(rows[1]).toContain(`,"1",`);   // default count = 1 when absent
    expect(rows[2]).toContain("later");
    expect(rows[2]).toContain(`,"12",`);  // aggregated count surfaced
  });
});
