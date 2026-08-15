import { describe, it, expect } from "vitest";
import { buildHostAliasIndex } from "../../src/analysis/hostAlias.js";
import { buildSynthesisContext } from "../../src/analysis/synthSelect.js";
import { rankConnectiveIocs } from "../../src/analysis/iocAnchors.js";
import { emptyState, type ForensicEvent, type InvestigationState } from "../../src/analysis/stateTypes.js";

const ALIAS = buildHostAliasIndex([], { win11: "win11.windomain.local" });

function ev(id: string, asset: string, description: string): ForensicEvent {
  return {
    id,
    timestamp: "2026-04-22T11:41:00Z",
    description,
    severity: "Critical",
    mitreTechniques: ["T1003.001"],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset,
    sources: ["Sysmon"],
  };
}

function splitState(): InvestigationState {
  const s = emptyState("c1");
  s.forensicTimeline.push(
    ev("a", "WIN11", "beacon to evil.example 10.0.0.9"),
    ev("b", "WIN11.windomain.local", "beacon to evil.example 10.0.0.9"),
  );
  s.iocs.push({ id: "i1", type: "domain", value: "evil.example", firstSeen: "2026-04-22T11:41:00Z" });
  return s;
}

describe("buildSynthesisContext host resolution", () => {
  it("names both spellings when no alias index is given", () => {
    const block = buildSynthesisContext(splitState(), splitState().forensicTimeline);
    // No aliasIndex → raw event.asset casing is preserved verbatim (assetGraph.ts only lowercases
    // when an aliasIndex is supplied), so the FQDN spelling appears exactly as seeded: "WIN11...".
    expect(block).toContain("WIN11.windomain.local");
    expect(/\bWIN11\b(?!\.)/i.test(block)).toBe(true);
  });

  it("collapses the pair to the canonical name in COMPROMISED ASSETS", () => {
    const s = splitState();
    const block = buildSynthesisContext(s, s.forensicTimeline, undefined, ALIAS);
    const assetLines = block.slice(block.indexOf("COMPROMISED ASSETS"));
    expect(assetLines).toContain("win11.windomain.local");
    expect(/^- WIN11 \(host\)/im.test(assetLines)).toBe(false);
  });

  it("reports one host, not two, in SIGNAL CONCENTRATION", () => {
    const s = splitState();
    const block = buildSynthesisContext(s, s.forensicTimeline, undefined, ALIAS);
    const line = block.split("\n").find((l) => l.startsWith("SIGNAL CONCENTRATION")) ?? "";
    expect(line).toContain("win11.windomain.local");
    expect(line.split("win11").length - 1).toBe(1);
  });
});

describe("rankConnectiveIocs host resolution", () => {
  it("counts a split host twice without an alias index", () => {
    const s = splitState();
    const [anchor] = rankConnectiveIocs(s, s.forensicTimeline);
    expect(anchor.hosts).toHaveLength(2);
  });

  it("counts it once with an alias index, so cross-host reach is not inflated", () => {
    const s = splitState();
    // Once honestly merged this IOC touches exactly ONE host via ONE tool with no malicious/
    // suspicious verdict — it never had real connective reach; only the un-merged spelling faked
    // a 2-host count past the (pre-existing, unchanged) `hosts.size >= minHosts` gate. The anchor
    // correctly disappears instead of surviving with an inflated host list.
    const anchors = rankConnectiveIocs(s, s.forensicTimeline, { aliasIndex: ALIAS });
    expect(anchors).toEqual([]);
  });
});
