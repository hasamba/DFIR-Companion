import { describe, it, expect } from "vitest";
import { renderStructuredTags, buildBeaconDigest, buildAttackPhaseDigest } from "../../src/analysis/synthEvidence.js";
import type { ForensicEvent, Severity } from "../../src/analysis/stateTypes.js";
import type { BeaconCandidate } from "../../src/analysis/beaconDetect.js";
import type { AttackPhase } from "../../src/analysis/burstDetect.js";

function ev(p: Partial<ForensicEvent>): ForensicEvent {
  return {
    id: p.id ?? "e1", timestamp: p.timestamp ?? "2026-01-01T00:00:00Z", description: p.description ?? "x",
    severity: p.severity ?? "Info", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], ...p,
  };
}

describe("renderStructuredTags", () => {
  it("emits host/proc/net/src tags only for set fields", () => {
    const t = renderStructuredTags(ev({ asset: "WS07", processName: "powershell.exe", parentName: "excel.exe", srcIp: "10.1.2.3", dstIp: "52.1.1.1", port: 443, sources: ["a", "b", "c"] }));
    expect(t).toContain("<host:WS07>");
    expect(t).toContain("<proc:powershell.exe←excel.exe>");
    expect(t).toContain("<net:10.1.2.3→52.1.1.1:443>");
    expect(t).toContain("<src:3>");
  });

  it("returns '' for a bare event (no structured fields)", () => {
    expect(renderStructuredTags(ev({ description: "just prose" }))).toBe("");
  });

  it("omits <src:N> when fewer than 2 sources (no corroboration to flag)", () => {
    expect(renderStructuredTags(ev({ sources: ["only-one"] }))).toBe("");
  });

  it("handles a process with no parent and a dst-only connection", () => {
    const t = renderStructuredTags(ev({ processName: "cmd.exe", dstIp: "8.8.8.8" }));
    expect(t).toContain("<proc:cmd.exe>");
    expect(t).not.toContain("←");
    expect(t).toContain("<net:?→8.8.8.8>");
  });
});

function beacon(p: Partial<BeaconCandidate>): BeaconCandidate {
  return {
    id: p.id ?? "beacon-1", source: p.source ?? "WS04", destIp: p.destIp ?? "203.0.113.7", destPort: p.destPort,
    eventCount: p.eventCount ?? 214, intervalSeconds: p.intervalSeconds ?? 62, jitterSeconds: p.jitterSeconds ?? 1,
    jitterPct: p.jitterPct ?? 3, firstSeen: "", lastSeen: "", severity: p.severity ?? "High",
    external: p.external ?? true, eventIds: p.eventIds ?? ["e1", "e2"],
  };
}

describe("buildBeaconDigest", () => {
  it("renders a candidate line with the verify caveat", () => {
    const out = buildBeaconDigest([beacon({ destPort: 443 })]);
    expect(out).toContain("PERIODIC BEACON CANDIDATES");
    expect(out).toContain("WS04 → 203.0.113.7:443 every ~62s");
    expect(out).toMatch(/LEAD to verify/i);
    expect(out).toMatch(/not a verdict|not confirmed C2/i);
  });

  it("returns '' when there are no beacons", () => {
    expect(buildBeaconDigest([])).toBe("");
  });
});

function phase(p: Partial<AttackPhase>): AttackPhase {
  return {
    id: p.id ?? "phase-1", label: p.label ?? "Discovery", startTimestamp: p.startTimestamp ?? "2026-05-20T09:02:00Z",
    endTimestamp: p.endTimestamp ?? "2026-05-20T09:15:00Z", eventIds: p.eventIds ?? ["e1", "e2"],
    inferredTechniques: p.inferredTechniques ?? ["T1087"], eventCount: p.eventCount ?? 41, maxSeverity: p.maxSeverity ?? "Medium",
  };
}

describe("buildAttackPhaseDigest", () => {
  it("renders a phase line with window, label, count and techniques", () => {
    const out = buildAttackPhaseDigest([phase({})]);
    expect(out).toContain("ATTACK PHASES");
    expect(out).toContain("09:02–09:15 Discovery (41 ev, Medium)");
    expect(out).toContain("T1087");
  });

  it("skips single-event phases and empty input", () => {
    expect(buildAttackPhaseDigest([phase({ eventCount: 1 })])).toBe("");
    expect(buildAttackPhaseDigest([])).toBe("");
  });
});
