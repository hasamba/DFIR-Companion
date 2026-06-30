import { describe, it, expect } from "vitest";
import { emptyState } from "../../src/analysis/stateTypes.js";
import { rankHosts, buildSignalConcentrationDigest } from "../../src/analysis/hostRanking.js";

function ev(id: string, asset: string, severity: string, ts: string, mitre: string[], description: string): any {
  return { id, timestamp: ts, description, severity, mitreTechniques: mitre, relatedFindingIds: [], sourceScreenshots: [], asset, sources: ["Sysmon"] };
}

function caseState(): ReturnType<typeof emptyState> {
  const s = emptyState("veridia");
  // WS-DEV-01 — the real workstation: Critical/High + techniques.
  s.forensicTimeline.push(
    ev("a1", "WS-DEV-01", "Critical", "2024-03-18T15:24:38Z", ["T1003.001"], "LSASS dump by wdi-svc.exe (marcus.chen)"),
    ev("a2", "WS-DEV-01", "High", "2024-03-18T14:17:07Z", ["T1204.002"], "dropper brsvc.exe by DOMAIN\\marcus.chen"),
    ev("a3", "WS-DEV-01", "Medium", "2024-03-18T14:24:41Z", ["T1069.002"], "net group Domain Admins /domain"),
  );
  // DB-01 — the DB server: Medium collection/exfil.
  s.forensicTimeline.push(
    ev("b1", "DB-01", "Medium", "2024-03-18T16:25:02Z", ["T1005"], "mysqldump payment_methods"),
    ev("b2", "DB-01", "Medium", "2024-03-18T16:50:22Z", ["T1041"], "curl POST exfil"),
  );
  // WS-HR-01 — pure benign noise: many Info events, no techniques.
  for (let i = 0; i < 40; i++) s.forensicTimeline.push(ev(`n${i}`, "WS-HR-01", "Info", "2024-03-18T12:00:00Z", [], "benign telemetry"));
  return s;
}

describe("rankHosts (#202)", () => {
  it("ranks the high-signal host first and excludes the benign-but-chatty host", () => {
    const { ranks } = rankHosts(caseState());
    expect(ranks[0].name).toBe("WS-DEV-01");
    expect(ranks.find((r) => r.name === "DB-01")).toBeDefined();
    expect(ranks.find((r) => r.name === "WS-HR-01")).toBeUndefined(); // 40 Info events → score 0 → dropped
  });

  it("scores by signal not volume (WS-DEV-01 > DB-01 despite similar event counts)", () => {
    const { ranks } = rankHosts(caseState());
    const dev = ranks.find((r) => r.name === "WS-DEV-01")!;
    const db = ranks.find((r) => r.name === "DB-01")!;
    expect(dev.score).toBeGreaterThan(db.score);
    expect(dev.critical).toBe(1);
    expect(dev.high).toBe(1);
  });

  it("extracts the compromised account as a ranked entity", () => {
    const { ranks } = rankHosts(caseState());
    expect(ranks.some((r) => r.type === "account" && /marcus\.chen/i.test(r.name))).toBe(true);
  });

  it("suggests a scope window covering the top hosts' activity", () => {
    const { suggestedWindow, topHosts } = rankHosts(caseState());
    expect(topHosts).toContain("WS-DEV-01");
    expect(suggestedWindow.start).toBe("2024-03-18T14:17:07Z");
    expect(suggestedWindow.end).toBeTruthy();
  });

  it("builds a signal-concentration digest naming the top hosts", () => {
    const digest = buildSignalConcentrationDigest(rankHosts(caseState()));
    expect(digest).toContain("SIGNAL CONCENTRATION");
    expect(digest).toContain("WS-DEV-01");
  });

  it("returns empty ranking when nothing carries signal", () => {
    const s = emptyState("c");
    s.forensicTimeline.push(ev("x", "H1", "Info", "2024-03-18T12:00:00Z", [], "benign"));
    const { ranks, topHosts } = rankHosts(s);
    expect(ranks).toHaveLength(0);
    expect(topHosts).toHaveLength(0);
  });
});
