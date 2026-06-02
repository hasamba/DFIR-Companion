import { describe, it, expect } from "vitest";
import { backfillHighSeverityFindings, shortTitle } from "../../src/analysis/highSeverityFindings.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";

function ev(over: Partial<ForensicEvent> & { id: string }): ForensicEvent {
  return {
    id: over.id, timestamp: "2026-05-26T12:25:36Z", description: "desc", severity: "Info",
    mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], ...over,
  };
}

describe("shortTitle", () => {
  it("takes the first sentence and caps the length", () => {
    expect(shortTitle("Defender flagged Rubeus.exe. More detail here.")).toBe("Defender flagged Rubeus.exe.");
    expect(shortTitle("x".repeat(200)).length).toBeLessThanOrEqual(90);
    expect(shortTitle("x".repeat(200)).endsWith("…")).toBe(true);
  });
});

describe("backfillHighSeverityFindings", () => {
  it("auto-creates a finding for an uncovered Critical/High event", () => {
    const state = emptyState("c1");
    state.forensicTimeline.push(
      ev({ id: "e1", severity: "Critical", description: "Microsoft Defender flagged Rubeus.exe", mitreTechniques: ["T1003"], sourceScreenshots: ["s1.webp"] }),
    );
    const out = backfillHighSeverityFindings(state, new Set(["e1"]), "2026-05-26T13:00:00Z");
    expect(out.findings).toHaveLength(1);
    expect(out.findings[0]).toMatchObject({ id: "f-auto-e1", severity: "Critical", status: "open", mitreTechniques: ["T1003"], sourceScreenshots: ["s1.webp"] });
    expect(out.findings[0].title).toBe("Microsoft Defender flagged Rubeus.exe");
    // The event is linked back to the new finding.
    expect(out.forensicTimeline[0].relatedFindingIds).toEqual(["f-auto-e1"]);
  });

  it("does NOT touch events already covered by a synthesis finding", () => {
    const state = emptyState("c1");
    state.forensicTimeline.push(ev({ id: "e1", severity: "High", relatedFindingIds: ["f1"] }));
    const out = backfillHighSeverityFindings(state, new Set(["e1"]), "t");
    expect(out.findings).toHaveLength(0);
    expect(out).toBe(state); // no change → same reference
  });

  it("ignores Medium/Low/Info events", () => {
    const state = emptyState("c1");
    state.forensicTimeline.push(ev({ id: "e1", severity: "Medium" }), ev({ id: "e2", severity: "Info" }));
    const out = backfillHighSeverityFindings(state, new Set(["e1", "e2"]), "t");
    expect(out.findings).toHaveLength(0);
  });

  it("respects eligibility (scope / legitimate excluded events are not backfilled)", () => {
    const state = emptyState("c1");
    state.forensicTimeline.push(
      ev({ id: "in", severity: "High" }),
      ev({ id: "out", severity: "Critical" }), // out of scope / legit → not eligible
    );
    const out = backfillHighSeverityFindings(state, new Set(["in"]), "t");
    expect(out.findings.map((f) => f.id)).toEqual(["f-auto-in"]);
  });

  it("is idempotent — re-running does not duplicate", () => {
    const state = emptyState("c1");
    state.forensicTimeline.push(ev({ id: "e1", severity: "Critical" }));
    const once = backfillHighSeverityFindings(state, new Set(["e1"]), "t");
    const twice = backfillHighSeverityFindings(once, new Set(["e1"]), "t");
    expect(twice.findings).toHaveLength(1);
    expect(twice).toBe(once); // already linked → no-op
  });
});
