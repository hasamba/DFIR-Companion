import { describe, it, expect } from "vitest";
import { buildHostAliasIndex } from "../../src/analysis/hostAlias.js";
import { groundAndScoreFindings } from "../../src/analysis/findingGrounding.js";
import type { Finding, ForensicEvent } from "../../src/analysis/stateTypes.js";

const ALIAS = buildHostAliasIndex([], { win11: "win11.windomain.local" });

function ev(id: string, asset: string): ForensicEvent {
  return {
    id,
    timestamp: "2026-04-22T11:41:00Z",
    description: "logon",
    severity: "High",
    mitreTechniques: [],
    relatedFindingIds: ["f1"],
    sourceScreenshots: [],
    asset,
    sources: ["Sysmon"], // ONE tool, so `corroborated` hinges on distinctHosts alone
  };
}

// Required by Finding but absent from the plan's snippet — the interface has no optional escape
// hatch for these, so an `as Finding` cast alone doesn't satisfy tsc without them (see
// task-7-report.md). Adding them makes the literal a fully valid Finding on its own, which in turn
// makes a trailing `as Finding` a no-op that @typescript-eslint/no-unnecessary-type-assertion flags —
// so the cast is dropped rather than kept as dead code.
const finding: Finding = {
  id: "f1",
  title: "Suspicious logon",
  description: "d",
  severity: "High",
  confidence: 90,
  relatedEventIds: ["a", "b"],
  relatedIocs: [],
  mitreTechniques: [],
  sourceScreenshots: [],
  firstSeen: "2026-04-22T11:41:00Z",
  lastUpdated: "2026-04-22T11:41:00Z",
  status: "open",
};

function ground(aliasIndex?: ReturnType<typeof buildHostAliasIndex>) {
  return groundAndScoreFindings({
    findings: [finding],
    scopedEvents: [ev("a", "WIN11"), ev("b", "WIN11.windomain.local")],
    iocs: [],
    graphLinkedEventIds: new Set<string>(),
    ...(aliasIndex ? { aliasIndex } : {}),
  })[0];
}

describe("groundAndScoreFindings host aliasing", () => {
  it("counts a split host as two without an alias index", () => {
    expect(ground().corroboration?.distinctHosts).toBe(2);
  });

  it("counts it as one with an alias index", () => {
    expect(ground(ALIAS).corroboration?.distinctHosts).toBe(1);
  });

  it("applies the single-source confidence cap once the hosts collapse", () => {
    const capped = ground(ALIAS);
    expect(capped.confidence).toBeLessThan(90);
    expect(capped.confidenceReason).toContain("single-source");
  });

  it("without the index the finding wrongly escapes the cap", () => {
    expect(ground().confidence).toBe(90);
  });
});
