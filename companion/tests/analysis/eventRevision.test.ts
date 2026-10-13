import { describe, it, expect } from "vitest";
import {
  MAX_EVENT_REVISIONS,
  REVISION_DESC_MAX,
  nextRevisions,
  revisionSource,
  revisionSummary,
  type EventRevision,
} from "../../src/analysis/eventRevision.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";
import { readBack } from "../../src/analysis/incrementalMergeRows.js";

// #2141: a merge that overwrites a held row's description or severity keeps a short, capped record
// of what the row said before — the overwrite still happens.

function ev(over: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id: "e1",
    timestamp: "2026-07-01T10:00:00.000Z",
    description: "text A",
    severity: "High",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...over,
  };
}

const AT = "2026-10-13T09:00:00.000Z";

describe("nextRevisions", () => {
  it("records nothing when the description and severity are unchanged", () => {
    expect(nextRevisions(ev(), ev(), AT, "fileB.csv")).toBeUndefined();
  });

  it("records a description change with the prior text only", () => {
    const out = nextRevisions(ev(), ev({ description: "text B" }), AT, "fileB.csv");
    expect(out?.revisions).toEqual([{ at: AT, source: "fileB.csv", description: { from: "text A" } }]);
    expect(out?.revisionsDropped).toBeUndefined();
  });

  it("records a severity change as from → to", () => {
    const out = nextRevisions(ev(), ev({ severity: "Medium" }), AT, "fileB.csv");
    expect(out?.revisions).toEqual([
      { at: AT, source: "fileB.csv", severity: { from: "High", to: "Medium" } },
    ]);
  });

  it("records both changes in one entry", () => {
    const out = nextRevisions(ev(), ev({ description: "text B", severity: "Low" }), AT, "s");
    expect(out?.revisions).toEqual([
      { at: AT, source: "s", description: { from: "text A" }, severity: { from: "High", to: "Low" } },
    ]);
  });

  it("cuts a long prior description at the limit with an ellipsis", () => {
    const long = "x".repeat(REVISION_DESC_MAX + 50);
    const out = nextRevisions(ev({ description: long }), ev({ description: "short" }), AT, "s");
    const from = out?.revisions?.[0].description?.from ?? "";
    expect(from.length).toBe(REVISION_DESC_MAX);
    expect(from.endsWith("…")).toBe(true);
  });

  it("keeps the first entry pinned and the newest four, counting what it dropped", () => {
    let row = ev({ description: "v0" });
    for (let i = 1; i <= 7; i++) {
      const incoming = ev({ description: `v${i}` });
      const out = nextRevisions(row, incoming, `t${i}`, `import-${i}`);
      row = { ...incoming, ...out };
    }
    expect(row.revisions).toHaveLength(MAX_EVENT_REVISIONS);
    expect(row.revisions?.[0]).toEqual({ at: "t1", source: "import-1", description: { from: "v0" } });
    expect(row.revisions?.at(-1)).toEqual({ at: "t7", source: "import-7", description: { from: "v6" } });
    expect(row.revisions?.map((r) => r.at)).toEqual(["t1", "t4", "t5", "t6", "t7"]);
    expect(row.revisionsDropped).toBe(2);
  });

  it("never mutates the held row's revision list", () => {
    const prior: EventRevision[] = Object.freeze([
      Object.freeze({ at: "t0", source: "s", description: Object.freeze({ from: "v" }) }),
    ]) as EventRevision[];
    const held = ev({ revisions: prior });
    const out = nextRevisions(held, ev({ description: "text B" }), AT, "s");
    expect(out?.revisions).toHaveLength(2);
    expect(held.revisions).toBe(prior);
    expect(prior).toHaveLength(1);
  });

  it("compares severity against the grade before a build-time cap, not the capped one", () => {
    const capped = ev({
      severity: "Low",
      buildTime: { marker: "m", window: "a/b", cappedFrom: "High" },
    });
    expect(nextRevisions(capped, ev({ severity: "High" }), AT, "s")).toBeUndefined();
    const raised = nextRevisions(capped, ev({ severity: "Critical" }), AT, "s");
    expect(raised?.revisions?.[0].severity).toEqual({ from: "High", to: "Critical" });
  });

  it("compares severity against the grade before a lab-setup cap", () => {
    const capped = {
      ...ev({ severity: "Medium" }),
      labSetup: { tag: "lab-setup", folder: "\\vmwarednd\\", cappedFrom: "High" },
    } as ForensicEvent;
    expect(nextRevisions(capped, ev({ severity: "High" }), AT, "s")).toBeUndefined();
  });

  it("does not read a raw restatement of a row a correlation pass annotated as a change", () => {
    // The pass appended its note and raised the grade after the first import. A re-import of the
    // same file restates the raw text and grade; the pass re-applies after the merge.
    const annotated = ev({
      description: "Ran payload.exe [initial access: host contacted email-delivered domain example.com]",
      severity: "Medium",
    });
    const raw = ev({ description: "Ran payload.exe", severity: "Low" });
    expect(nextRevisions(annotated, raw, AT, "s")).toBeUndefined();
    // A real change of the base text on that row is still recorded.
    const changed = nextRevisions(annotated, ev({ description: "Ran other.exe", severity: "Low" }), AT, "s");
    expect(changed?.revisions?.[0].description?.from).toBe(annotated.description);
  });
});

describe("revisionSource", () => {
  const incoming = ev({ sources: ["Sysmon", "EVTX"] });
  it("prefers the merge's named change source", () => {
    expect(revisionSource({ changeSource: "MCP agent: vt", sourceScreenshots: ["a.csv"] }, incoming)).toBe(
      "MCP agent: vt",
    );
  });
  it("falls back to the import label, then the row's sources, then a placeholder", () => {
    expect(revisionSource({ sourceScreenshots: ["a.csv"] }, incoming)).toBe("a.csv");
    expect(revisionSource({ sourceScreenshots: [] }, incoming)).toBe("Sysmon, EVTX");
    expect(revisionSource({ sourceScreenshots: [] }, ev({ sources: [] }))).toBe("unknown source");
  });
});

describe("revisionSummary", () => {
  it("is empty for a row that was never revised", () => {
    expect(revisionSummary(ev())).toBe("");
  });

  it("names the change count, the latest change and the first-recorded text and grade", () => {
    const row = ev({
      description: "text C",
      severity: "Low",
      revisions: [
        {
          at: "t1",
          source: "fileB.csv",
          description: { from: "text A" },
          severity: { from: "High", to: "Medium" },
        },
        { at: "t2", source: "fileC.csv", description: { from: "text B" } },
      ],
    });
    const s = revisionSummary(row);
    expect(s).toContain("changed after first recorded");
    expect(s).toContain("2 changes");
    expect(s).toContain("t2");
    expect(s).toContain("fileC.csv");
    expect(s).toContain('"text A"');
    expect(s).toContain("High");
  });

  it("states how many middle changes the cap dropped", () => {
    const row = ev({
      revisions: [{ at: "t1", source: "s", severity: { from: "High", to: "Low" } }],
      revisionsDropped: 3,
    });
    expect(revisionSummary(row)).toContain("4 changes");
  });
});

describe("persistence", () => {
  it("keeps revisions and the dropped count through the stored form", () => {
    const row = ev({
      revisions: [
        { at: "t1", source: "s", description: { from: "text A" }, severity: { from: "High", to: "Low" } },
      ],
      revisionsDropped: 2,
    });
    const back = readBack(row);
    expect(back.revisions).toEqual(row.revisions);
    expect(back.revisionsDropped).toBe(2);
  });
});
