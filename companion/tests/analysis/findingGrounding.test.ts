import { describe, it, expect } from "vitest";
import {
  groundAndScoreFindings,
  corroborationLabel,
  UNGROUNDED_CONFIDENCE_CAP,
  SINGLE_SOURCE_CONFIDENCE_CAP,
} from "../../src/analysis/findingGrounding.js";
import type { Finding, ForensicEvent, IOC, Severity } from "../../src/analysis/stateTypes.js";

function f(p: Partial<Finding>): Finding {
  return {
    id: p.id ?? "f1", severity: p.severity ?? "High", title: p.title ?? "A finding", description: "",
    relatedIocs: p.relatedIocs ?? [], sourceScreenshots: [], mitreTechniques: [], firstSeen: "", lastUpdated: "",
    status: "open", ...p,
  };
}
function ev(p: Partial<ForensicEvent>): ForensicEvent {
  return {
    id: p.id ?? "e1", timestamp: "2026-01-01T00:00:00Z", description: "x", severity: p.severity ?? "High" as Severity,
    mitreTechniques: [], relatedFindingIds: p.relatedFindingIds ?? [], sourceScreenshots: [], ...p,
  };
}
function ioc(p: Partial<IOC>): IOC {
  return { id: p.id ?? "i1", type: p.type ?? "ip", value: p.value ?? "1.2.3.4", firstSeen: "", ...p };
}

describe("groundAndScoreFindings", () => {
  it("flags a finding with no cited in-scope evidence as ungrounded and caps confidence", () => {
    const out = groundAndScoreFindings({
      findings: [f({ id: "f1", confidence: 95, relatedEventIds: ["missing"] })],
      scopedEvents: [ev({ id: "e1" })],
      iocs: [],
      graphLinkedEventIds: new Set(),
    });
    expect(out[0].ungrounded).toBe(true);
    expect(out[0].confidence).toBe(UNGROUNDED_CONFIDENCE_CAP);
    expect(out[0].confidenceReason).toMatch(/no cited evidence/i);
    expect(out[0].relatedEventIds).toEqual([]);
  });

  it("grounds a deterministic backfill finding via the REVERSE link (event.relatedFindingIds)", () => {
    // backfillHighSeverityFindings sets no forward relatedEventIds — only the event points back.
    const out = groundAndScoreFindings({
      findings: [f({ id: "f-auto-e1", confidence: 100, relatedEventIds: [] })],
      scopedEvents: [ev({ id: "e1", relatedFindingIds: ["f-auto-e1"], sources: ["Velociraptor", "THOR"], asset: "H1" })],
      iocs: [],
      graphLinkedEventIds: new Set(),
    });
    expect(out[0].ungrounded).toBeUndefined();
    expect(out[0].relatedEventIds).toEqual(["e1"]);
    expect(out[0].corroboration).toEqual({ distinctTools: 2, distinctHosts: 1, intelSources: 0, graphLinked: false });
    expect(out[0].confidence).toBe(100); // corroborated by 2 tools → not capped
  });

  it("caps a grounded but single-tool/single-host/uncorroborated finding at 65", () => {
    const out = groundAndScoreFindings({
      findings: [f({ id: "f1", confidence: 90, relatedEventIds: ["e1"] })],
      scopedEvents: [ev({ id: "e1", sources: ["OneTool"], asset: "H1" })],
      iocs: [],
      graphLinkedEventIds: new Set(),
    });
    expect(out[0].confidence).toBe(SINGLE_SOURCE_CONFIDENCE_CAP);
    expect(out[0].confidenceReason).toMatch(/single-source/i);
  });

  it("does not cap a single-tool finding that IS graph-linked", () => {
    const out = groundAndScoreFindings({
      findings: [f({ id: "f1", confidence: 90, relatedEventIds: ["e1"] })],
      scopedEvents: [ev({ id: "e1", sources: ["OneTool"], asset: "H1" })],
      iocs: [],
      graphLinkedEventIds: new Set(["e1"]),
    });
    expect(out[0].confidence).toBe(90);
    expect(out[0].corroboration?.graphLinked).toBe(true);
  });

  it("counts intel-flagged related IOCs and does not cap when intel backs a single-tool finding", () => {
    const out = groundAndScoreFindings({
      findings: [f({ id: "f1", confidence: 88, relatedEventIds: ["e1"], relatedIocs: ["i1"] })],
      scopedEvents: [ev({ id: "e1", sources: ["OneTool"], asset: "H1" })],
      iocs: [ioc({ id: "i1", enrichments: [{ source: "VT", verdict: "malicious", fetchedAt: "" }] })],
      graphLinkedEventIds: new Set(),
    });
    expect(out[0].corroboration?.intelSources).toBe(1);
    expect(out[0].confidence).toBe(88); // intel corroboration → not capped
  });

  it("never RAISES confidence and is idempotent", () => {
    const once = groundAndScoreFindings({
      findings: [f({ id: "f1", confidence: 30, relatedEventIds: ["e1"] })],
      scopedEvents: [ev({ id: "e1", sources: ["OneTool"], asset: "H1" })],
      iocs: [], graphLinkedEventIds: new Set(),
    });
    expect(once[0].confidence).toBe(30); // already below the cap — unchanged
    const twice = groundAndScoreFindings({ findings: once, scopedEvents: [ev({ id: "e1", sources: ["OneTool"], asset: "H1" })], iocs: [], graphLinkedEventIds: new Set() });
    expect(twice[0].confidence).toBe(30);
    expect(twice[0].corroboration).toEqual(once[0].corroboration);
  });
});

describe("corroborationLabel", () => {
  it("labels an ungrounded finding", () => {
    expect(corroborationLabel(f({ ungrounded: true }))).toMatch(/no cited evidence/i);
  });
  it("labels a multi-tool finding as corroborated (no warning)", () => {
    const label = corroborationLabel(f({ corroboration: { distinctTools: 2, distinctHosts: 3, intelSources: 1, graphLinked: false } }));
    expect(label).toContain("2 tools / 3 hosts / intel ✓");
    expect(label).not.toMatch(/uncorroborated/);
  });
  it("marks a single-tool finding uncorroborated", () => {
    expect(corroborationLabel(f({ corroboration: { distinctTools: 1, distinctHosts: 1, intelSources: 0, graphLinked: false } }))).toMatch(/uncorroborated/);
  });
});
