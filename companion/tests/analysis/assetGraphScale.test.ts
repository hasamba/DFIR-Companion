import { describe, it, expect } from "vitest";
import { buildAssetGraph } from "../../src/analysis/assetGraph.js";
import { emptyState, type ForensicEvent, type IOC } from "../../src/analysis/stateTypes.js";

// Every IoC value used to be scanned against every event description one at a time — events × IoCs
// `includes`/regex calls. A real case (tens of thousands of events, thousands of IoCs) pinned the
// server CPU, and a dozen callers (reports, synthesis selection, host ranking, known-unknowns)
// each rebuild the graph. The description scan is now one pass per description.

function event(i: number, description: string): ForensicEvent {
  return {
    id: `e${i}`,
    timestamp: "2026-05-20T09:00:00Z",
    description,
    severity: "High",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset: `WIN-${i % 40}`,
  };
}

function ioc(i: number, value: string, aliasValues?: string[]): IOC {
  return { id: `i${i}`, type: "domain", value, firstSeen: "", ...(aliasValues ? { aliasValues } : {}) };
}

describe("buildAssetGraph — description matching at scale", () => {
  it("builds a 20k-event, 3k-IoC graph quickly", () => {
    const s = emptyState("c1");
    for (let i = 0; i < 3000; i++) s.iocs.push(ioc(i, `host${i}.evil-example.net`));
    for (let i = 0; i < 20000; i++) {
      const mention = i % 7 === 0 ? ` resolved host${i % 3000}.evil-example.net` : "";
      s.forensicTimeline.push(
        event(i, `Process C:\\Windows\\System32\\svchost.exe -k netsvcs spawned child pid ${i}${mention} ok`),
      );
    }
    const t = performance.now();
    const g = buildAssetGraph(s);
    const ms = performance.now() - t;
    expect(g.edges.length).toBeGreaterThan(0);
    // Generous for a slow CI runner; the single-pass scan is far under it.
    expect(ms).toBeLessThan(2500);
  });

  it("links exactly the IoCs a per-value substring/boundary scan would, in the same order", () => {
    const s = emptyState("c1");
    s.iocs.push(
      ioc(0, "zeta.example.org"),
      ioc(1, "10.0.0.5"), // IP: boundary-aware, must not match inside 10.0.0.50 or 110.0.0.5
      ioc(2, "abc"), // under 4 chars: never matched from a description
      ioc(3, "Payload.EXE"), // case-insensitive
      ioc(4, "canonical.example.org", ["Old-Dup.example.org"]), // alias value links to the canonical IoC
      ioc(5, "example.org"), // a value nested inside other values
      ioc(6, "192.168.1.1"),
    );
    s.forensicTimeline.push(
      event(1, "dns example.org then zeta.example.org then 10.0.0.5:443"),
      event(2, "conn 10.0.0.50 and 110.0.0.5 and 10.0.0.5.1 — none are the IoC"),
      event(3, "ran payload.exe from abc"),
      event(4, "lookup OLD-DUP.EXAMPLE.ORG"),
      event(5, "peer 192.168.1.10, gw 192.168.1.1"),
      event(6, "nothing here"),
    );
    const g = buildAssetGraph(s);
    const linked = (asset: string) => g.assets.find((a) => a.name === asset)?.iocIds ?? [];
    // IoC order, not position-in-text order — matches the old per-IoC loop.
    expect(linked("WIN-1")).toEqual(["i0", "i1", "i5"]);
    expect(linked("WIN-2")).toEqual([]);
    expect(linked("WIN-3")).toEqual(["i3"]);
    expect(linked("WIN-4")).toEqual(["i4", "i5"]);
    expect(linked("WIN-5")).toEqual(["i6"]);
    expect(linked("WIN-6")).toEqual([]);
  });
});
