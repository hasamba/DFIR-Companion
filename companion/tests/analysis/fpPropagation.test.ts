import { describe, it, expect } from "vitest";
import { matchFpPropagation } from "../../src/analysis/fpPropagation.js";
import { patternKey } from "../../src/analysis/prevalence.js";
import type { FalsePositiveMarker } from "../../src/analysis/falsePositive.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

function ev(partial: Partial<ForensicEvent> & { id: string }): ForensicEvent {
  return { timestamp: "2026-01-02T10:00:00.000Z", description: "", severity: "Info", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], ...partial };
}
function marker(partial: Partial<FalsePositiveMarker> & { ref: string }): FalsePositiveMarker {
  return { id: `event:${partial.ref}`, kind: "event", reason: "duplicate", note: "", markedAt: "2026-01-01T00:00:00Z", markedBy: "a", ...partial };
}

describe("matchFpPropagation (#15b)", () => {
  it("surfaces a pattern reproduced by ≥minMatches new events, sorted most-matched first", () => {
    // The FP marker's fingerprint is the anchor's pattern key.
    const anchor = ev({ id: "old1", processName: "robocopy.exe", description: "robocopy C:\\data\\1 \\\\srv\\bak /mir" });
    const m = marker({ ref: "old1", note: "nightly robocopy backup", patternFingerprint: patternKey(anchor) });

    const newEvents = [
      ev({ id: "n1", processName: "robocopy.exe", description: "robocopy C:\\data\\2 \\\\srv\\bak /mir" }),
      ev({ id: "n2", processName: "robocopy.exe", description: "robocopy C:\\data\\3 \\\\srv2\\bak /mir" }),
      ev({ id: "n3", processName: "robocopy.exe", description: "robocopy C:\\data\\4 \\\\srv3\\bak /mir" }),
      ev({ id: "n4", processName: "powershell.exe", description: "iex (new-object net.webclient)" }), // unrelated
    ];
    const [s, ...rest] = matchFpPropagation(newEvents, [m], { minMatches: 3 });
    expect(rest).toHaveLength(0);
    expect(s.count).toBe(3);
    expect(s.matchedEventIds.sort()).toEqual(["n1", "n2", "n3"]);
    expect(s.note).toBe("nightly robocopy backup");
    expect(s.ref).toBe("old1");
  });

  it("stays silent below the match threshold", () => {
    const anchor = ev({ id: "old1", description: "some benign scan pattern" });
    const m = marker({ ref: "old1", patternFingerprint: patternKey(anchor) });
    const newEvents = [ev({ id: "n1", description: "some benign scan pattern" })]; // only 1 match, min 3
    expect(matchFpPropagation(newEvents, [m], { minMatches: 3 })).toEqual([]);
  });

  it("ignores markers without a fingerprint and non-event markers", () => {
    const newEvents = [ev({ id: "n1", description: "x pattern" }), ev({ id: "n2", description: "x pattern" }), ev({ id: "n3", description: "x pattern" })];
    const noFp = marker({ ref: "old1" });                                   // event marker, no fingerprint
    const findingM = marker({ ref: "some finding", kind: "finding", patternFingerprint: "desc:x pattern" }); // wrong kind
    expect(matchFpPropagation(newEvents, [noFp, findingM], { minMatches: 1 })).toEqual([]);
  });

  it("caps matched ids per pattern", () => {
    const anchor = ev({ id: "old1", description: "repeated line" });
    const m = marker({ ref: "old1", patternFingerprint: patternKey(anchor) });
    const many = Array.from({ length: 10 }, (_, i) => ev({ id: `n${i}`, description: "repeated line" }));
    const [s] = matchFpPropagation(many, [m], { minMatches: 1, maxIdsPerPattern: 4 });
    expect(s.count).toBe(4);
    expect(s.matchedEventIds).toHaveLength(4);
  });
});
