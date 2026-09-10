import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  findPrecursorGroups,
  markRansomwarePrecursors,
  MIN_CLASSES,
  DEFAULT_WINDOW_MS,
} from "../../src/analysis/ransomwarePrecursor.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

let seq = 0;
const ev = (techniques: string[], over: Partial<ForensicEvent> = {}): ForensicEvent => ({
  id: `e${++seq}`,
  timestamp: "2026-01-01T10:00:00Z",
  description: "something happened",
  severity: "Medium",
  mitreTechniques: techniques,
  relatedFindingIds: [],
  sourceScreenshots: [],
  asset: "WS-01",
  ...over,
});

const at = (min: number) => new Date(Date.parse("2026-01-01T10:00:00Z") + min * 60000).toISOString();

describe("findPrecursorGroups — several distinct behaviours, one host, one window", () => {
  it("reports three distinct classes clustered together", () => {
    const g = findPrecursorGroups([
      ev(["T1562.001"], {
        timestamp: at(0),
        commandLine: "Set-MpPreference -DisableRealtimeMonitoring $true",
      }),
      ev(["T1070.001"], { timestamp: at(2), commandLine: "wevtutil cl Security" }),
      ev(["T1490"], { timestamp: at(4), commandLine: "vssadmin delete shadows /all /quiet" }),
    ]);
    expect(g).toHaveLength(1);
    expect(g[0].classes).toHaveLength(3);
    expect(g[0].severity).toBe("High");
    expect(g[0].host).toBe("WS-01");
  });

  it("names which behaviours contributed and links their events", () => {
    const a = ev(["T1562.001"], {
      timestamp: at(0),
      commandLine: "netsh advfirewall set allprofiles state off",
    });
    const b = ev(["T1070.001"], { timestamp: at(1), commandLine: "wevtutil cl System" });
    const c = ev(["T1490"], { timestamp: at(2), commandLine: "wbadmin delete catalog -quiet" });
    const [g] = findPrecursorGroups([a, b, c]);
    expect(g.note).toContain("security tooling disabled");
    expect(g.note).toContain("event logs cleared");
    expect(g.note).toContain("backups or shadow copies removed");
    expect(g.eventIds).toEqual([a.id, b.id, c.id]);
    expect(g.note).toContain(a.id);
  });

  // The issue's central constraint.
  it("says nothing about a single maintenance command", () => {
    expect(findPrecursorGroups([ev(["T1490"], { commandLine: "vssadmin delete shadows" })])).toEqual([]);
  });

  it("says nothing about two classes, which is a plausible maintenance window", () => {
    expect(
      findPrecursorGroups([
        ev(["T1562.001"], { timestamp: at(0), commandLine: "sc stop WinDefend" }),
        ev(["T1070.001"], { timestamp: at(1), commandLine: "wevtutil cl Application" }),
      ]),
    ).toEqual([]);
  });

  // Ten vssadmin lines from one loop are ONE behaviour.
  it("counts one behaviour repeated many times once", () => {
    const many = Array.from({ length: 10 }, (_v, i) =>
      ev(["T1490"], { timestamp: at(i), commandLine: "vssadmin delete shadows /all /quiet" }),
    );
    expect(findPrecursorGroups(many)).toEqual([]);
  });

  // Overlapping telemetry is normal in a case that imported both EDR and event logs.
  it("counts one command reported by two tools once", () => {
    const cmd = "vssadmin delete shadows /all /quiet";
    const g = findPrecursorGroups([
      ev(["T1562.001"], { timestamp: at(0), commandLine: "sc stop WinDefend" }),
      ev(["T1490"], { timestamp: at(1), commandLine: cmd, sources: ["Sysmon"] }),
      ev(["T1490"], { timestamp: at(1), commandLine: cmd, sources: ["CrowdStrike"] }),
    ]);
    // Two distinct classes only — the duplicate does not become a third.
    expect(g).toEqual([]);
  });

  it("does not join behaviours on two different hosts", () => {
    expect(
      findPrecursorGroups([
        ev(["T1562.001"], { timestamp: at(0), asset: "WS-01", commandLine: "a" }),
        ev(["T1070.001"], { timestamp: at(1), asset: "WS-02", commandLine: "b" }),
        ev(["T1490"], { timestamp: at(2), asset: "WS-03", commandLine: "c" }),
      ]),
    ).toEqual([]);
  });

  it("does not join behaviours spread far beyond the window", () => {
    const far = DEFAULT_WINDOW_MS / 60000 + 10;
    expect(
      findPrecursorGroups([
        ev(["T1562.001"], { timestamp: at(0), commandLine: "a" }),
        ev(["T1070.001"], { timestamp: at(far), commandLine: "b" }),
        ev(["T1490"], { timestamp: at(far * 2), commandLine: "c" }),
      ]),
    ).toEqual([]);
  });

  it("ignores an event with no host or no usable time", () => {
    expect(
      findPrecursorGroups([
        ev(["T1562.001"], { asset: undefined, commandLine: "a" }),
        ev(["T1070.001"], { timestamp: "", commandLine: "b" }),
        ev(["T1490"], { timestamp: "not a date", commandLine: "c" }),
      ]),
    ).toEqual([]);
  });

  it("respects a caller-supplied threshold", () => {
    const g = findPrecursorGroups(
      [
        ev(["T1562.001"], { timestamp: at(0), commandLine: "a" }),
        ev(["T1070.001"], { timestamp: at(1), commandLine: "b" }),
      ],
      { minClasses: 2 },
    );
    expect(g).toHaveLength(1);
    expect(MIN_CLASSES).toBe(3);
  });
});

describe("markRansomwarePrecursors — the timeline pass", () => {
  const cluster = () => [
    ev(["T1562.001"], { timestamp: at(0), commandLine: "sc stop WinDefend", severity: "Medium" }),
    ev(["T1070.001"], { timestamp: at(1), commandLine: "wevtutil cl Security", severity: "Medium" }),
    ev(["T1490"], { timestamp: at(2), commandLine: "vssadmin delete shadows", severity: "Medium" }),
  ];

  it("raises every contributing event and explains why", () => {
    const out = markRansomwarePrecursors(cluster());
    for (const e of out) {
      expect(e.severity).toBe("High");
      expect(e.description).toContain("[ransomware precursors:");
      expect(e.mitreTechniques).toContain("T1486");
    }
  });

  it("states that this is not proof encryption happened", () => {
    const [e] = markRansomwarePrecursors(cluster());
    expect(e.description).toContain("does not establish that encryption occurred");
    expect(e.description).toContain("approved maintenance window");
  });

  it("is idempotent", () => {
    const once = markRansomwarePrecursors(cluster());
    const twice = markRansomwarePrecursors(once);
    expect(twice[0].description).toBe(once[0].description);
  });

  it("never lowers a severity the event already had", () => {
    const raised = cluster().map((e) => ({ ...e, severity: "Critical" as const }));
    expect(markRansomwarePrecursors(raised)[0].severity).toBe("Critical");
  });

  it("returns the input untouched when there is no cluster", () => {
    const plain = [ev(["T1490"], { commandLine: "vssadmin delete shadows" })];
    expect(markRansomwarePrecursors(plain)).toBe(plain);
  });
});

// Reachability: the pass only matters if the merge runs it.
describe("reachability", () => {
  it("runs from the merge", () => {
    const merge = readFileSync(join(process.cwd(), "src/analysis/stateMerge.ts"), "utf8");
    expect(merge).toContain("markRansomwarePrecursors");
  });

  // Appending to a description breaks exact-duplicate re-import matching unless it is stripped
  // before the key is taken. This codebase has hit that bug twice.
  it("has its marker stripped before correlation keys a duplicate", () => {
    const corr = readFileSync(join(process.cwd(), "src/analysis/correlate.ts"), "utf8");
    expect(corr).toContain("ransomware precursors");
  });
});
