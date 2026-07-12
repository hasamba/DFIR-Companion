import { describe, it, expect } from "vitest";
import { classifyVerdict, iocHasBehavioralEvent, isInternalAddress } from "../../src/analysis/iocAnchors.js";
import { capIntelOnlyFindings } from "../../src/analysis/findingGrounding.js";
import type { Finding, ForensicEvent, IOC, Severity } from "../../src/analysis/stateTypes.js";

const hostNames = new Set(["db-01"]);

function ioc(p: Partial<IOC>): IOC {
  return { id: p.id ?? "i1", type: p.type ?? "domain", value: p.value ?? "evil.example", firstSeen: "", ...p };
}
function ev(p: Partial<ForensicEvent>): ForensicEvent {
  return { id: p.id ?? "e1", timestamp: "2026-01-01T00:00:00Z", description: p.description ?? "x", severity: p.severity ?? "High" as Severity,
    mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], ...p };
}
function f(p: Partial<Finding>): Finding {
  return { id: p.id ?? "f1", severity: p.severity ?? "Critical", title: p.title ?? "C2 via malicious domain", description: "",
    relatedIocs: p.relatedIocs ?? [], sourceScreenshots: [], mitreTechniques: [], firstSeen: "", lastUpdated: "", status: "open", ...p };
}

describe("isInternalAddress", () => {
  it("recognizes RFC1918 / loopback / CGNAT", () => {
    expect(isInternalAddress("10.1.2.3")).toBe(true);
    expect(isInternalAddress("192.168.0.5")).toBe(true);
    expect(isInternalAddress("172.16.9.9")).toBe(true);
    expect(isInternalAddress("127.0.0.1")).toBe(true);
    expect(isInternalAddress("100.64.0.1")).toBe(true);
    expect(isInternalAddress("8.8.8.8")).toBe(false);
    expect(isInternalAddress("172.32.0.1")).toBe(false);
  });
});

describe("classifyVerdict", () => {
  const vt = { source: "VirusTotal", verdict: "malicious" };
  it("flags a verdict on the case's own host asset as conflicted", () => {
    const c = classifyVerdict(ioc({ value: "db-01.corp.local", enrichments: [{ source: "OpenCTI", verdict: "suspicious" }] }), { hasBehavioralEvent: false, hostNames });
    expect(c).toBe("conflicted");
  });
  it("flags a verdict on an internal IP as conflicted", () => {
    expect(classifyVerdict(ioc({ value: "10.0.0.5", enrichments: [{ source: "X", verdict: "malicious" }] }), { hasBehavioralEvent: true, hostNames })).toBe("conflicted");
  });
  it("is corroborated with two distinct providers", () => {
    expect(classifyVerdict(ioc({ enrichments: [{ provider: "A", verdict: "malicious" }, { provider: "B", verdict: "suspicious" }] }), { hasBehavioralEvent: false, hostNames })).toBe("corroborated");
  });
  it("is corroborated with one provider PLUS a behavioral event", () => {
    expect(classifyVerdict(ioc({ enrichments: [vt] }), { hasBehavioralEvent: true, hostNames })).toBe("corroborated");
  });
  it("is lone-intel with one provider and no behavioral event", () => {
    expect(classifyVerdict(ioc({ enrichments: [vt] }), { hasBehavioralEvent: false, hostNames })).toBe("lone-intel");
  });
  it("is none with no malicious/suspicious verdict", () => {
    expect(classifyVerdict(ioc({ enrichments: [{ source: "X", verdict: "harmless" }] }), { hasBehavioralEvent: false, hostNames })).toBe("none");
  });
});

describe("iocHasBehavioralEvent", () => {
  it("matches a value in a High-severity event's structured field or description", () => {
    expect(iocHasBehavioralEvent("evil.exe", [ev({ severity: "Critical", description: "ran evil.exe" })])).toBe(true);
    expect(iocHasBehavioralEvent("1.2.3.4", [ev({ severity: "Medium", dstIp: "1.2.3.4" })])).toBe(true);
  });
  it("ignores Low/Info events (not behavioral corroboration)", () => {
    expect(iocHasBehavioralEvent("1.2.3.4", [ev({ severity: "Info", dstIp: "1.2.3.4" })])).toBe(false);
  });
});

describe("capIntelOnlyFindings — northpeak class", () => {
  it("floors a Critical finding driven only by a conflicted (own-server) verdict", () => {
    const events = [ev({ id: "e1", severity: "Info", description: "connection to db-01.corp.local", asset: "db-01.corp.local", dstIp: "db-01.corp.local" })];
    const finding = f({ id: "f1", severity: "Critical", confidence: 92, relatedIocs: ["i1"], corroboration: { distinctTools: 1, distinctHosts: 1, intelSources: 1, graphLinked: false } });
    const out = capIntelOnlyFindings({
      findings: [finding],
      iocs: [ioc({ id: "i1", value: "db-01.corp.local", enrichments: [{ source: "OpenCTI", verdict: "suspicious" }] })],
      scopedEvents: events, hostNames,
    });
    expect(out[0].severity).toBe("Medium");
    expect(out[0].confidence).toBe(60);
    expect(out[0].confidenceReason).toMatch(/OWN infrastructure/i);
  });

  it("does NOT floor a finding with behavioral corroboration (2 tools)", () => {
    const finding = f({ id: "f1", severity: "Critical", confidence: 95, relatedIocs: ["i1"], corroboration: { distinctTools: 2, distinctHosts: 1, intelSources: 1, graphLinked: false } });
    const out = capIntelOnlyFindings({
      findings: [finding],
      iocs: [ioc({ id: "i1", value: "evil.example", enrichments: [{ source: "VT", verdict: "malicious" }] })],
      scopedEvents: [], hostNames,
    });
    expect(out[0].severity).toBe("Critical");
    expect(out[0].confidence).toBe(95);
  });

  it("does NOT floor a finding not driven by intel at all", () => {
    const finding = f({ id: "f1", severity: "High", confidence: 88, relatedIocs: ["i1"], corroboration: { distinctTools: 1, distinctHosts: 1, intelSources: 0, graphLinked: false } });
    const out = capIntelOnlyFindings({
      findings: [finding],
      iocs: [ioc({ id: "i1", value: "plain.example", enrichments: [] })],
      scopedEvents: [], hostNames,
    });
    expect(out[0].severity).toBe("High");
  });

  it("floors a lone-intel-only High finding to Medium/60", () => {
    const finding = f({ id: "f1", severity: "High", confidence: 80, relatedIocs: ["i1"], corroboration: { distinctTools: 1, distinctHosts: 1, intelSources: 1, graphLinked: false } });
    const out = capIntelOnlyFindings({
      findings: [finding],
      iocs: [ioc({ id: "i1", value: "lone.example", enrichments: [{ source: "VT", verdict: "malicious" }] })],
      scopedEvents: [], hostNames,
    });
    expect(out[0].severity).toBe("Medium");
    expect(out[0].confidence).toBe(60);
    expect(out[0].confidenceReason).toMatch(/single-provider threat-intel/i);
  });
});
