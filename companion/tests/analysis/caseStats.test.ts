import { describe, it, expect } from "vitest";
import { emptyState } from "../../src/analysis/stateTypes.js";
import { computeCaseStats } from "../../src/analysis/caseStats.js";
import type { ImportMetadata } from "../../src/types.js";

function ev(id: string, asset: string, sources: string[]): any {
  return {
    id,
    timestamp: "2024-03-18T15:24:38Z",
    description: "d",
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset,
    sources,
  };
}

function imp(caseId: string, seq: number, importedAt: string, rows: number): ImportMetadata {
  return { caseId, sequenceNumber: seq, importedAt, filename: `f${seq}.csv`, originalName: `f${seq}.csv`, rows, bytes: rows * 100 };
}

describe("computeCaseStats (#241)", () => {
  it("totals events, findings, IOCs, and distinct assets", () => {
    const s = emptyState("c1");
    s.forensicTimeline.push(ev("a1", "WS-01", ["Sysmon"]), ev("a2", "WS-02", ["Zeek"]));
    s.findings.push({
      id: "f1", severity: "High", title: "t", description: "d", relatedIocs: [], sourceScreenshots: [],
      mitreTechniques: [], firstSeen: "2024-03-18T15:24:38Z", lastUpdated: "2024-03-18T15:24:38Z", status: "open",
    });
    s.iocs.push({ id: "i1", type: "ip", value: "1.2.3.4", firstSeen: "2024-03-18T15:24:38Z" });

    const stats = computeCaseStats(s, []);
    expect(stats.totals.events).toBe(2);
    expect(stats.totals.findings).toBe(1);
    expect(stats.totals.iocs).toBe(1);
    expect(stats.totals.assets).toBe(2);
  });

  it("groups events by source, counting an event once per source it carries", () => {
    const s = emptyState("c1");
    s.forensicTimeline.push(ev("a1", "WS-01", ["Sysmon"]), ev("a2", "WS-01", ["Sysmon", "Zeek"]), ev("a3", "WS-01", ["Zeek"]));

    const stats = computeCaseStats(s, []);
    expect(stats.bySource).toEqual([
      { source: "Sysmon", count: 2 },
      { source: "Zeek", count: 2 },
    ]);
  });

  it("buckets import history into daily import/row counts, sorted ascending", () => {
    const s = emptyState("c1");
    const log = [
      imp("c1", 1, "2024-03-18T09:00:00Z", 100),
      imp("c1", 2, "2024-03-18T14:00:00Z", 50),
      imp("c1", 3, "2024-03-19T09:00:00Z", 20),
    ];

    const stats = computeCaseStats(s, log);
    expect(stats.importVelocity).toEqual([
      { date: "2024-03-18", imports: 2, rows: 150 },
      { date: "2024-03-19", imports: 1, rows: 20 },
    ]);
  });

  it("returns empty structures for a case with no data", () => {
    const stats = computeCaseStats(emptyState("empty"), []);
    expect(stats.totals).toEqual({ events: 0, findings: 0, iocs: 0, assets: 0 });
    expect(stats.bySource).toEqual([]);
    expect(stats.importVelocity).toEqual([]);
  });
});
