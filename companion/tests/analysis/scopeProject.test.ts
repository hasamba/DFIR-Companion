import { describe, it, expect } from "vitest";
import { projectScope } from "../../src/analysis/scopeProject.js";
import { emptyState, type InvestigationState } from "../../src/analysis/stateTypes.js";
import { NO_SCOPE } from "../../src/analysis/scope.js";

function stateWith(): InvestigationState {
  return {
    ...emptyState("c1"),
    forensicTimeline: [
      { id: "e1", timestamp: "2026-05-20T09:00:00Z", description: "early phish", severity: "High",
        mitreTechniques: ["T1566"], relatedFindingIds: ["f1"], sourceScreenshots: [] },
      { id: "e2", timestamp: "2026-05-25T12:00:00Z", description: "in-window exec", severity: "Critical",
        mitreTechniques: ["T1059"], relatedFindingIds: ["f2"], sourceScreenshots: [] },
    ],
    findings: [
      { id: "f1", severity: "High", title: "phishing", description: "out of window",
        relatedIocs: ["i001"], mitreTechniques: ["T1566"], sourceScreenshots: [], firstSeen: "", lastUpdated: "", status: "open" },
      { id: "f2", severity: "Critical", title: "execution", description: "in window",
        relatedIocs: ["i002"], mitreTechniques: ["T1059"], sourceScreenshots: [], firstSeen: "", lastUpdated: "", status: "confirmed" },
    ],
    iocs: [
      { id: "i001", type: "file", value: "phish.docx", firstSeen: "" },
      { id: "i002", type: "process", value: "powershell.exe", firstSeen: "" },
      { id: "i003", type: "ip", value: "10.0.0.9", firstSeen: "" }, // cited by nobody → always kept
    ],
    mitreTechniques: [
      { id: "T1566", name: "Phishing", findingIds: ["f1"] },
      { id: "T1059", name: "Command and Scripting Interpreter", findingIds: ["f2"] },
    ],
  };
}

describe("projectScope", () => {
  it("returns the state untouched when there is no scope", () => {
    const s = stateWith();
    expect(projectScope(s, NO_SCOPE)).toBe(s);
  });

  it("drops events, findings, IOCs and MITRE supported only by out-of-scope evidence", () => {
    const s = stateWith();
    // Window starts after e1 (09:00 on the 20th), so only e2 (the 25th) is in scope.
    const out = projectScope(s, { start: "2026-05-22T00:00:00Z", end: null });

    expect(out.forensicTimeline.map((e) => e.id)).toEqual(["e2"]);
    expect(out.findings.map((f) => f.id)).toEqual(["f2"]);     // f1 dropped (only e1 backed it)
    expect(out.iocs.map((i) => i.id)).toEqual(["i002", "i003"]); // i001 dropped, i003 kept (uncited)
    expect(out.mitreTechniques.map((t) => t.id)).toEqual(["T1059"]); // T1566 dropped
  });

  it("keeps a finding still backed by at least one in-scope event", () => {
    const s = stateWith();
    // Make e2 also back f1 — now f1 has in-scope support and must survive.
    s.forensicTimeline[1].relatedFindingIds = ["f1", "f2"];
    const out = projectScope(s, { start: "2026-05-22T00:00:00Z", end: null });
    expect(out.findings.map((f) => f.id).sort()).toEqual(["f1", "f2"]);
  });

  it("does not mutate the input state", () => {
    const s = stateWith();
    projectScope(s, { start: "2026-05-22T00:00:00Z", end: null });
    expect(s.findings).toHaveLength(2);
    expect(s.iocs).toHaveLength(3);
    expect(s.mitreTechniques[0].findingIds).toEqual(["f1"]);
  });
});
