import { describe, it, expect } from "vitest";
import { selectSynthesisEvents, buildSynthesisContext } from "../../src/analysis/synthSelect.js";
import { emptyState, type ForensicEvent, type Severity } from "../../src/analysis/stateTypes.js";

function ev(id: string, t: string, sev: Severity): ForensicEvent {
  return { id, timestamp: t, description: id, severity: sev, mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [] };
}

describe("selectSynthesisEvents", () => {
  it("returns everything (chronological) when under the budget", () => {
    const events = [ev("b", "2026-05-20T11:00:00Z", "Low"), ev("a", "2026-05-20T09:00:00Z", "Low")];
    expect(selectSynthesisEvents(events, 300).map((e) => e.id)).toEqual(["a", "b"]);
  });

  it("keeps all Critical/High, the earliest events, and a time-spread sample — chronologically", () => {
    const events: ForensicEvent[] = [];
    // 100 Low events across a day, plus two High/Critical buried in the middle, plus an early Low.
    for (let i = 0; i < 100; i++) {
      const hh = String(i % 24).padStart(2, "0");
      events.push(ev(`low${i}`, `2026-05-20T${hh}:00:00Z`, "Low"));
    }
    events.push(ev("crit", "2026-05-20T12:30:00Z", "Critical"));
    events.push(ev("high", "2026-05-20T13:30:00Z", "High"));

    const picked = selectSynthesisEvents(events, 30);
    const ids = picked.map((e) => e.id);
    expect(picked.length).toBeLessThanOrEqual(30);
    expect(ids).toContain("crit");                 // all Critical/High kept
    expect(ids).toContain("high");
    expect(ids).toContain("low0");                 // earliest (initial-access) kept
    // chronological order
    const times = picked.map((e) => e.timestamp);
    expect(times).toEqual([...times].sort());
  });

  it("keeps the severest when Critical/High alone exceed the budget", () => {
    const events = Array.from({ length: 50 }, (_, i) => ev(`c${i}`, `2026-05-20T${String(i % 24).padStart(2, "0")}:00:00Z`, "Critical"));
    expect(selectSynthesisEvents(events, 10).length).toBe(10);
  });
});

describe("buildSynthesisContext", () => {
  it("summarizes compromised assets and threat-intel verdicts", () => {
    const s = emptyState("c1");
    s.iocs.push({ id: "i1", type: "process", value: "evil.exe", firstSeen: "",
      enrichments: [{ source: "VirusTotal", verdict: "malicious", score: "52/73", fetchedAt: "" }] });
    s.forensicTimeline.push({ id: "e1", timestamp: "2026-05-20T09:00:00Z", description: "evil.exe run", severity: "Critical",
      mitreTechniques: [], relatedFindingIds: ["f1"], sourceScreenshots: [], asset: "WIN-01" });
    s.findings.push({ id: "f1", severity: "Critical", title: "RW", description: "", relatedIocs: ["i1"],
      mitreTechniques: [], sourceScreenshots: [], firstSeen: "", lastUpdated: "", status: "confirmed" });

    const ctx = buildSynthesisContext(s, s.forensicTimeline);
    expect(ctx).toContain("COMPROMISED ASSETS");
    expect(ctx).toContain("WIN-01 (host)");
    expect(ctx).toContain("evil.exe");
    expect(ctx).toContain("THREAT-INTEL VERDICTS");
    expect(ctx).toContain("evil.exe = malicious (VirusTotal 52/73)");
  });

  it("returns an empty string when there's nothing to add", () => {
    expect(buildSynthesisContext(emptyState("c1"), [])).toBe("");
  });
});
