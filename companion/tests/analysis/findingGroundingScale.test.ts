import { describe, it, expect } from "vitest";
import { groundAndScoreFindings } from "../../src/analysis/findingGrounding.js";
import type { Finding, ForensicEvent } from "../../src/analysis/stateTypes.js";

// #2058: grounding scanned the whole scoped timeline once per finding to collect the events that
// name it (reverse links). An importer that makes one finding per distinct rule turns that into
// findings × events, which blocked the server for minutes after the model call on a 70k-event case.
// The reverse links are now indexed once; the supporting set and its order must not change.

function f(id: string, relatedEventIds: string[] = []): Finding {
  return {
    id,
    severity: "High",
    title: `Finding ${id}`,
    description: "",
    relatedIocs: [],
    relatedEventIds,
    sourceScreenshots: [],
    mitreTechniques: [],
    firstSeen: "",
    lastUpdated: "",
    status: "open",
  };
}

function ev(id: string, relatedFindingIds: string[], over: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id,
    timestamp: "2026-01-01T00:00:00Z",
    description: `event ${id}`,
    severity: "High",
    mitreTechniques: [],
    relatedFindingIds,
    sourceScreenshots: [],
    asset: "WS01",
    sources: ["Hayabusa"],
    ...over,
  };
}

// The straightforward reading of the supporting-set rule: forward links in scope first (in the
// finding's own order, de-duped), then every scoped event that names the finding, in scoped order.
function referenceSupporting(finding: Finding, scoped: readonly ForensicEvent[]): string[] {
  const inScope = new Set(scoped.map((e) => e.id));
  const out: string[] = [];
  const seen = new Set<string>();
  const push = (id: string): void => {
    if (seen.has(id) || !inScope.has(id)) return;
    seen.add(id);
    out.push(id);
  };
  for (const id of finding.relatedEventIds ?? []) push(id);
  for (const e of scoped) if ((e.relatedFindingIds ?? []).includes(finding.id)) push(e.id);
  return out;
}

describe("groundAndScoreFindings at scale (#2058)", () => {
  it("grounds 20k findings against 20k reverse-linked events quickly", () => {
    const n = 20_000;
    const findings = Array.from({ length: n }, (_, i) => f(`f${i}`));
    const scopedEvents = Array.from({ length: n }, (_, i) => ev(`e${i}`, [`f${i}`]));
    const t = performance.now();
    const out = groundAndScoreFindings({ findings, scopedEvents, iocs: [], graphLinkedEventIds: new Set() });
    const ms = performance.now() - t;
    expect(out).toHaveLength(n);
    expect(out[123].relatedEventIds).toEqual(["e123"]);
    // Generous for a slow CI runner; the per-finding scan took tens of seconds here.
    expect(ms).toBeLessThan(2500);
  });

  it("keeps the supporting events, their order and the corroboration exactly as before", () => {
    const scopedEvents = [
      ev("e1", ["fA", "fB"], { sources: ["Chainsaw"] }),
      ev("e2", ["fB", "fB"], { asset: "WS02" }), // a duplicate fid inside one event
      ev("e3", []),
      ev("e4", ["fA", "fGone"], { sources: ["Hayabusa", "THOR"], severity: "Info" }),
      ev("e5", ["fC"], { asset: "ws01" }),
      ev("e6", ["fA"]),
    ];
    const findings = [
      f("fA", ["e6", "e3", "missing", "e6"]), // forward links, one out of scope, one repeated
      f("fB", ["e2"]), // forward link that is also a reverse link
      f("fC"),
      f("fD", ["e5"]), // forward only
      f("fNone"),
    ];
    const out = groundAndScoreFindings({
      findings,
      scopedEvents,
      iocs: [],
      graphLinkedEventIds: new Set(["e4"]),
    });
    for (const [i, finding] of findings.entries()) {
      expect(out[i].relatedEventIds).toEqual(referenceSupporting(finding, scopedEvents));
    }
    expect(out[0].relatedEventIds).toEqual(["e6", "e3", "e1", "e4"]);
    expect(out[0].corroboration).toMatchObject({ distinctTools: 3, graphLinked: true });
    expect(out[1].relatedEventIds).toEqual(["e2", "e1"]);
    expect(out[1].corroboration?.distinctHosts).toBe(2);
    expect(out[4].relatedEventIds).toEqual([]);
  });
});
