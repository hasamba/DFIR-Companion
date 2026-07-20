import { describe, it, expect } from "vitest";
import { scoreEventRelevance, isLowRelevance } from "../../src/analysis/eventRelevance.js";
import { selectSynthesisEventsAnnotated } from "../../src/analysis/synthSelect.js";
import type { ForensicEvent, Severity } from "../../src/analysis/stateTypes.js";

function ev(id: string, sev: Severity, extra: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id,
    timestamp: "2026-05-20T09:00:00Z",
    description: id,
    severity: sev,
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...extra,
  };
}

describe("scoreEventRelevance", () => {
  it("scores Critical/High as high regardless of other signals", () => {
    expect(scoreEventRelevance(ev("a", "Critical")).tier).toBe("high");
    expect(scoreEventRelevance(ev("b", "High")).tier).toBe("high");
  });

  it("scores a finding-linked event as high even at low severity", () => {
    const e = ev("c", "Info", { relatedFindingIds: ["f1"] });
    expect(scoreEventRelevance(e).tier).toBe("high");
  });

  it("scores a structured hash/path/process-chain event as medium", () => {
    expect(scoreEventRelevance(ev("d", "Low", { sha256: "abc123" })).tier).toBe("medium");
    expect(scoreEventRelevance(ev("e", "Info", { path: "c:\\windows\\temp\\x.exe" })).tier).toBe("medium");
    expect(scoreEventRelevance(ev("f", "Info", { processName: "powershell.exe" })).tier).toBe("medium");
    expect(scoreEventRelevance(ev("g", "Info", { chainSignature: "sig1" })).tier).toBe("medium");
  });

  it("scores an ATT&CK-technique-tagged event as medium", () => {
    const e = ev("h", "Info", { mitreTechniques: ["T1059"] });
    expect(scoreEventRelevance(e).tier).toBe("medium");
  });

  it("scores a cross-source-corroborated event as medium", () => {
    const e = ev("i", "Info", { sources: ["ToolA", "ToolB"] });
    expect(scoreEventRelevance(e).tier).toBe("medium");
  });

  // Corroboration is counted in DISTINCT REAL tools, the same unit correlate.ts/sourceTrust.ts/
  // iocCorroboration.ts and the dashboard's realSourceCount() use. A placeholder or a repeated name
  // must not fake a second tool — otherwise a pure Info hunt row gets promoted out of "low" and the
  // dashboard chip (which does filter/dedup) disagrees with this module it claims to mirror.
  it("does not count the 'unknown source' placeholder as corroboration", () => {
    const e = ev("i-placeholder", "Info", { sources: ["unknown source", "ToolA"] });
    expect(scoreEventRelevance(e).tier).toBe("low");
    expect(isLowRelevance(e)).toBe(true);
  });

  it("does not count a repeated source name as corroboration", () => {
    const e = ev("i-dupe", "Info", { sources: ["ToolA", "ToolA"] });
    expect(scoreEventRelevance(e).tier).toBe("low");
  });

  it("scores a rare event (via rarityOf) as medium, and ignores rarityOf when omitted", () => {
    const e = ev("j", "Info");
    expect(scoreEventRelevance(e, () => 0.9).tier).toBe("medium");
    expect(scoreEventRelevance(e, () => 0.1).tier).toBe("low");
    expect(scoreEventRelevance(e).tier).toBe("low");
  });

  it("scores a pure Info hunt row with no structured id, technique, or corroboration as low", () => {
    const e = ev("k", "Info");
    expect(scoreEventRelevance(e).tier).toBe("low");
    expect(isLowRelevance(e)).toBe(true);
  });

  it("scores an uncorroborated Medium/Low-severity graded detection as medium, not low", () => {
    expect(scoreEventRelevance(ev("l", "Medium")).tier).toBe("medium");
    expect(scoreEventRelevance(ev("m", "Low")).tier).toBe("medium");
  });

  it("never returns low for a non-Info severity event", () => {
    const sevs: Severity[] = ["Critical", "High", "Medium", "Low"];
    for (const sev of sevs) {
      expect(scoreEventRelevance(ev(`n-${sev}`, sev)).tier).not.toBe("low");
    }
  });
});

// Consistency check against the existing budgeted selector (issue #75's acceptance criteria: this
// scorer must not regress selection coverage). It doesn't feed selectSynthesisEvents at all — these
// assertions just confirm the two independent signals agree on what matters, so a future caller could
// safely use the score as a display hint without it contradicting what synthesis actually reads.
describe("scoreEventRelevance vs. the budgeted selector's classes", () => {
  it("agrees with every class the selector already reserves budget for", () => {
    const events: ForensicEvent[] = [
      ev("anchor1", "Critical"),
      ev("corrob1", "Low", { sources: ["ToolA", "ToolB"] }),
      ev("tech1", "Low", { mitreTechniques: ["T1059"] }),
      ev("chain1", "Low", { sha256: "deadbeef" }),
    ];
    // Add enough Info noise so the selector actually has to budget rather than keep everything.
    for (let i = 0; i < 50; i++) {
      events.push(ev(`noise${i}`, "Info", { timestamp: `2026-05-20T${String(i % 24).padStart(2, "0")}:30:00Z` }));
    }

    const { classOf } = selectSynthesisEventsAnnotated(events, 10);

    expect(classOf.get("anchor1")).toBe("anchor");
    expect(scoreEventRelevance(events.find((e) => e.id === "anchor1")!).tier).toBe("high");

    for (const id of ["corrob1", "tech1", "chain1"]) {
      const e = events.find((x) => x.id === id)!;
      expect(scoreEventRelevance(e).tier).toBe("medium");
    }

    // Plain Info noise the selector didn't guarantee a seat for scores low — the two systems point
    // at the same rows as least valuable, without this module changing which rows are actually chosen.
    const noiseSample = events.find((e) => e.id === "noise0")!;
    expect(isLowRelevance(noiseSample)).toBe(true);
  });
});
