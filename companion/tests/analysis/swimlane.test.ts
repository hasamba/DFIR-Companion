import { describe, it, expect } from "vitest";
import { buildSwimlaneData } from "../../src/analysis/swimlane.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

function ev(id: string, timestamp: string, extra: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id,
    timestamp,
    description: extra.description ?? "",
    severity: extra.severity ?? "Info",
    mitreTechniques: extra.mitreTechniques ?? [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...extra,
  };
}

describe("buildSwimlaneData", () => {
  it("returns empty result for an empty timeline", () => {
    const r = buildSwimlaneData([]);
    expect(r.lanes).toEqual([]);
    expect(r.minTime).toBeNull();
    expect(r.maxTime).toBeNull();
    expect(r.totalEvents).toBe(0);
  });

  it("excludes undated events", () => {
    const r = buildSwimlaneData([ev("e1", ""), ev("e2", "not-a-date")]);
    expect(r.lanes).toEqual([]);
    expect(r.totalEvents).toBe(0);
  });

  describe("groupBy asset (default)", () => {
    it("places events with an asset field into a host lane", () => {
      const r = buildSwimlaneData([
        ev("e1", "2026-05-01T10:00:00Z", { asset: "WIN-01" }),
        ev("e2", "2026-05-01T10:01:00Z", { asset: "WIN-01" }),
        ev("e3", "2026-05-01T10:02:00Z", { asset: "SRV-02" }),
      ]);
      expect(r.lanes).toHaveLength(2);
      expect(r.lanes[0].type).toBe("host");
      expect(r.lanes[0].label).toBe("SRV-02");    // alphabetical: SRV before WIN
      expect(r.lanes[0].events).toHaveLength(1);
      expect(r.lanes[1].label).toBe("WIN-01");
      expect(r.lanes[1].events).toHaveLength(2);
      expect(r.totalEvents).toBe(3);
    });

    it("extracts accounts from description when no asset field is set", () => {
      const r = buildSwimlaneData([
        ev("e1", "2026-05-01T10:00:00Z", { description: "Logon CORP\\alice" }),
      ]);
      expect(r.lanes).toHaveLength(1);
      expect(r.lanes[0].type).toBe("account");
      expect(r.lanes[0].label).toBe("CORP\\alice");
    });

    it("puts events with no asset and no account into the Unassigned lane", () => {
      const r = buildSwimlaneData([
        ev("e1", "2026-05-01T10:00:00Z"),
      ]);
      expect(r.lanes).toHaveLength(1);
      expect(r.lanes[0].id).toBe("unassigned");
      expect(r.lanes[0].type).toBe("unassigned");
    });

    it("places Unassigned lane last, hosts before accounts, both alphabetical", () => {
      const r = buildSwimlaneData([
        ev("e1", "2026-05-01T10:00:00Z", { asset: "ZZZ-HOST" }),
        ev("e2", "2026-05-01T10:01:00Z", { asset: "AAA-HOST" }),
        ev("e3", "2026-05-01T10:02:00Z", { description: "CORP\\bob" }),
        ev("e4", "2026-05-01T10:03:00Z"),   // unassigned
      ]);
      const ids = r.lanes.map((l) => l.type);
      expect(ids[0]).toBe("host");
      expect(ids[1]).toBe("host");
      expect(r.lanes[0].label).toBe("AAA-HOST");
      expect(r.lanes[1].label).toBe("ZZZ-HOST");
      expect(ids[2]).toBe("account");
      expect(ids[3]).toBe("unassigned");
    });
  });

  describe("groupBy severity", () => {
    it("groups events by severity in canonical order", () => {
      const r = buildSwimlaneData(
        [
          ev("e1", "2026-05-01T10:00:00Z", { severity: "Low" }),
          ev("e2", "2026-05-01T10:01:00Z", { severity: "Critical" }),
          ev("e3", "2026-05-01T10:02:00Z", { severity: "High" }),
        ],
        "severity",
      );
      expect(r.lanes.map((l) => l.label)).toEqual(["Critical", "High", "Low"]);
      expect(r.lanes[0].events).toHaveLength(1);
    });

    it("omits empty severity lanes", () => {
      const r = buildSwimlaneData(
        [ev("e1", "2026-05-01T10:00:00Z", { severity: "Info" })],
        "severity",
      );
      expect(r.lanes).toHaveLength(1);
      expect(r.lanes[0].label).toBe("Info");
    });
  });

  describe("groupBy tactic", () => {
    it("groups events by ATT&CK tactic in kill-chain order", () => {
      const r = buildSwimlaneData(
        [
          ev("e1", "2026-05-01T10:00:00Z", { mitreTechniques: ["T1059"] }), // Execution
          ev("e2", "2026-05-01T10:01:00Z", { mitreTechniques: ["T1566"] }), // Initial Access
        ],
        "tactic",
      );
      // Initial Access comes before Execution in kill-chain order
      expect(r.lanes[0].label).toBe("Initial Access");
      expect(r.lanes[1].label).toBe("Execution");
    });

    it("places events with unknown technique into Uncategorized last", () => {
      const r = buildSwimlaneData(
        [
          ev("e1", "2026-05-01T10:00:00Z", { mitreTechniques: ["T1059"] }),  // Execution
          ev("e2", "2026-05-01T10:01:00Z", { mitreTechniques: [] }),         // Uncategorized
        ],
        "tactic",
      );
      expect(r.lanes[r.lanes.length - 1].label).toBe("Uncategorized");
    });
  });

  describe("time bounds", () => {
    it("computes minTime and maxTime across all dated events", () => {
      const r = buildSwimlaneData([
        ev("e1", "2026-05-01T10:00:00Z"),
        ev("e2", "2026-05-01T12:00:00Z"),
        ev("e3", "2026-05-01T08:00:00Z"),
      ]);
      expect(r.minTime).toBe("2026-05-01T08:00:00.000Z");
      expect(r.maxTime).toBe("2026-05-01T12:00:00.000Z");
    });

    it("extends maxTime to endTimestamp when present and later", () => {
      const r = buildSwimlaneData([
        ev("e1", "2026-05-01T10:00:00Z", { endTimestamp: "2026-05-01T11:30:00Z" }),
      ]);
      expect(r.maxTime).toBe("2026-05-01T11:30:00.000Z");
    });
  });
});
