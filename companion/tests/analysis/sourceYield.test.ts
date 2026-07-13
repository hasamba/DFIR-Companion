import { describe, it, expect } from "vitest";
import { classifyImportYield, ZERO_YIELD_MIN_LINES_DEFAULT, type ImportMeta } from "../../src/analysis/importMeta.js";
import { buildKnownUnknownItems, networkTelemetryWithoutDetector } from "../../src/analysis/knownUnknowns.js";
import { emptyState, type Finding, type ForensicEvent, type InvestigationState } from "../../src/analysis/stateTypes.js";

function meta(p: Partial<ImportMeta>): ImportMeta {
  return {
    lastImportedAt: "2026-05-20T00:00:00Z", lastImportKind: p.lastImportKind ?? "log", lastImportFile: p.lastImportFile ?? "proxy_access.log",
    addedCount: p.addedCount ?? 0, removedCount: 0, lastDiff: null,
    iocsAddedCount: 0, iocsRemovedCount: 0, iocsDiff: null,
    linesIn: p.linesIn ?? 0, path: p.path ?? "ai",
    ...(p.truncation !== undefined ? { truncation: p.truncation } : {}),
  };
}
function finding(sev: Finding["severity"]): Finding {
  return { id: "f1", severity: sev, title: "x", description: "", relatedIocs: [], sourceScreenshots: [], mitreTechniques: ["T1486"],
    firstSeen: "", lastUpdated: "", status: "open" };
}
function ev(p: Partial<ForensicEvent>): ForensicEvent {
  return { id: p.id ?? "e1", timestamp: "2026-05-20T09:00:00Z", description: p.description ?? "", severity: p.severity ?? "Info",
    mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], ...p };
}

describe("classifyImportYield (trigger a — zero-yield AI import)", () => {
  it("flags a large AI-triage import that produced zero events (the northpeak proxy-log case)", () => {
    const w = classifyImportYield(meta({ lastImportFile: "proxy_access.log", linesIn: 27290, path: "ai", addedCount: 0 }));
    expect(w).not.toBeNull();
    expect(w!.reason).toBe("zero_yield_ai");
    expect(w!.linesIn).toBe(27290);
    expect(w!.message).toMatch(/27,290 lines → 0 events/);
    expect(w!.inferredPhases).toContain("Command and Control"); // proxy → C2/Exfil/Discovery
  });
  it("does NOT flag a deterministic import (only the AI path can silently drop everything)", () => {
    expect(classifyImportYield(meta({ path: "deterministic", linesIn: 99999, addedCount: 0 }))).toBeNull();
  });
  it("does NOT flag an AI import that produced events", () => {
    expect(classifyImportYield(meta({ path: "ai", linesIn: 5000, addedCount: 12 }))).toBeNull();
  });
  it("does NOT flag a tiny AI import below the line threshold", () => {
    expect(classifyImportYield(meta({ path: "ai", linesIn: ZERO_YIELD_MIN_LINES_DEFAULT - 1, addedCount: 0 }))).toBeNull();
  });
});

describe("classifyImportYield (trigger b — cap-hit template truncation, #10 deferred)", () => {
  it("flags an import whose log-aggregation cap dropped distinct patterns, even when events WERE produced", () => {
    const w = classifyImportYield(meta({ lastImportFile: "huge.log", path: "ai", addedCount: 120, linesIn: 90000, truncation: { distinctTemplates: 950, keptTemplates: 400 } }));
    expect(w).not.toBeNull();
    expect(w!.reason).toBe("cap_hit");
    expect(w!.message).toMatch(/550 of 950 distinct log patterns/);
    expect(w!.message).toMatch(/DFIR_LOG_MAX_TEMPLATES/);
  });
  it("does NOT flag when nothing was truncated (kept >= distinct)", () => {
    expect(classifyImportYield(meta({ path: "ai", addedCount: 50, truncation: { distinctTemplates: 120, keptTemplates: 400 } }))).toBeNull();
    expect(classifyImportYield(meta({ path: "ai", addedCount: 50, truncation: null }))).toBeNull();
  });
  it("zero-yield (trigger a) takes precedence when both could apply", () => {
    const w = classifyImportYield(meta({ path: "ai", addedCount: 0, linesIn: 27290, truncation: { distinctTemplates: 950, keptTemplates: 400 } }));
    expect(w!.reason).toBe("zero_yield_ai");
  });
});

describe("networkTelemetryWithoutDetector (trigger c)", () => {
  const serious = (): InvestigationState => { const s = emptyState("c"); s.findings = [finding("Critical")]; return s; };
  it("flags network telemetry with no endpoint detector", () => {
    const s = serious();
    s.forensicTimeline = [ev({ id: "e1", sources: ["Zeek"], description: "conn.log flow" })];
    expect(networkTelemetryWithoutDetector(s)).toMatch(/NO endpoint-detector feed/);
  });
  it("returns null when a detector feed IS present", () => {
    const s = serious();
    s.forensicTimeline = [ev({ id: "e1", sources: ["Zeek"] }), ev({ id: "e2", sources: ["Sysmon"] })];
    expect(networkTelemetryWithoutDetector(s)).toBeNull();
  });
  it("returns null for a non-serious case (no Critical/High finding)", () => {
    const s = emptyState("c"); s.forensicTimeline = [ev({ id: "e1", sources: ["proxy"] })];
    expect(networkTelemetryWithoutDetector(s)).toBeNull();
  });
});

describe("buildKnownUnknownItems — yield_gap items (#10)", () => {
  it("emits a yield_gap from a supplied zero-yield warning", () => {
    const warning = classifyImportYield(meta({ lastImportFile: "proxy.log", linesIn: 10000, path: "ai", addedCount: 0 }))!;
    const items = buildKnownUnknownItems(emptyState("c"), [], { yieldWarning: warning });
    const yg = items.filter((i) => i.kind === "yield_gap");
    expect(yg.length).toBe(1);
    expect(yg[0].label).toMatch(/0 events via AI triage/);
    expect(yg[0].collect).toEqual([]);
  });
  it("emits a yield_gap for network-telemetry-without-detector", () => {
    const s = emptyState("c"); s.findings = [finding("High")];
    s.forensicTimeline = [ev({ id: "e1", sources: ["proxy"], description: "web access" })];
    const items = buildKnownUnknownItems(s, s.forensicTimeline);
    expect(items.some((i) => i.kind === "yield_gap")).toBe(true);
  });
});
