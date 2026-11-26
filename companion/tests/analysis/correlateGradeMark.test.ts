// #2891: a row still waiting for the content tagger keeps the grade mark through a correlation merge,
// even when an already-graded row of the same fact wins primary — otherwise the merged row would read
// as graded and the next case-wide demote could move it out untagged.
import { describe, it, expect } from "vitest";
import { correlateEvents } from "../../src/analysis/correlate.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

const ev = (p: Partial<ForensicEvent> & { id: string }): ForensicEvent => ({
  timestamp: "2026-05-02T10:00:00Z",
  description: `row ${p.id}`,
  severity: "Info",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
  asset: "WS01",
  sha256: "a".repeat(64),
  path: "c:\\windows\\temp\\x.ps1",
  ...p,
});

describe("correlation keeps the grade mark (#2891)", () => {
  it("a waiting member folded under a graded primary leaves the merged row waiting", () => {
    const graded = ev({ id: "old", severity: "High", description: "a long detection description of x.ps1" });
    const waiting = ev({ id: "new", gradePending: true });
    const out = correlateEvents([graded, waiting]);
    expect(out).toHaveLength(1);
    expect(out[0].id).toBe("old");
    expect(out[0].gradePending).toBe(true);
  });

  it("no member waiting → no mark", () => {
    const out = correlateEvents([ev({ id: "a", severity: "High" }), ev({ id: "b" })]);
    expect(out).toHaveLength(1);
    expect(out[0].gradePending).toBeUndefined();
  });
});
