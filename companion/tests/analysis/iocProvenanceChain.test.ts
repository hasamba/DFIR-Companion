import { describe, it, expect } from "vitest";
import { buildIocProvenanceChains } from "../../src/analysis/iocProvenanceChain.js";
import type { Finding, ForensicEvent, IOC } from "../../src/analysis/stateTypes.js";

function ev(p: Partial<ForensicEvent> & { id: string; severity: ForensicEvent["severity"] }): ForensicEvent {
  return { timestamp: "t", description: "", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], ...p };
}
const ioc = (p: Partial<IOC> & { id: string; type: IOC["type"]; value: string }): IOC => ({ firstSeen: "t", ...p });
function finding(p: Partial<Finding> & { id: string }): Finding {
  return {
    severity: "Medium", title: "f", description: "", relatedIocs: [], sourceScreenshots: [], mitreTechniques: [],
    firstSeen: "t", lastUpdated: "t", status: "open", ...p,
  };
}

describe("buildIocProvenanceChains", () => {
  it("returns empty map for no IOCs", () => {
    expect(buildIocProvenanceChains([], [], [])).toEqual({});
  });

  it("matches an extraction event via a structured field", () => {
    const events = [ev({ id: "e1", severity: "High", dstIp: "8.8.8.8", timestamp: "2026-01-01T00:00:00Z" })];
    const chains = buildIocProvenanceChains([ioc({ id: "i1", type: "ip", value: "8.8.8.8" })], events, []);
    expect(chains.i1.extraction).toEqual([
      { eventId: "e1", timestamp: "2026-01-01T00:00:00Z", description: "", severity: "High", sources: undefined },
    ]);
    expect(chains.i1.extractionTruncated).toBe(0);
  });

  it("matches an extraction event via a token in the description", () => {
    const events = [ev({ id: "e1", severity: "Medium", description: "connection to evil.example.com observed" })];
    const chains = buildIocProvenanceChains([ioc({ id: "i1", type: "domain", value: "evil.example.com" })], events, []);
    expect(chains.i1.extraction.map((x) => x.eventId)).toEqual(["e1"]);
  });

  it("is boundary-safe (10.0.0.1 does not match 10.0.0.10)", () => {
    const events = [ev({ id: "e1", severity: "High", dstIp: "10.0.0.10" })];
    const chains = buildIocProvenanceChains([ioc({ id: "i1", type: "ip", value: "10.0.0.1" })], events, []);
    expect(chains.i1.extraction).toEqual([]);
  });

  it("carries the event's artifactName (finer-grained than sources) when set", () => {
    const events = [ev({ id: "e1", severity: "High", dstIp: "8.8.8.8", sources: ["Velociraptor"], artifactName: "Windows.Network.DNS" })];
    const chains = buildIocProvenanceChains([ioc({ id: "i1", type: "ip", value: "8.8.8.8" })], events, []);
    expect(chains.i1.extraction[0].artifactName).toBe("Windows.Network.DNS");
    expect(chains.i1.extraction[0].sources).toEqual(["Velociraptor"]);
  });

  it("dedupes an event matching on multiple fields and sorts extraction chronologically", () => {
    const events = [
      ev({ id: "e2", severity: "High", dstIp: "1.2.3.4", timestamp: "2026-01-02T00:00:00Z" }),
      ev({ id: "e1", severity: "High", dstIp: "1.2.3.4", description: "seen 1.2.3.4 again", timestamp: "2026-01-01T00:00:00Z" }),
    ];
    const chains = buildIocProvenanceChains([ioc({ id: "i1", type: "ip", value: "1.2.3.4" })], events, []);
    expect(chains.i1.extraction.map((x) => x.eventId)).toEqual(["e1", "e2"]);
  });

  it("caps extraction events and reports the truncated count", () => {
    const events = Array.from({ length: 30 }, (_, n) =>
      ev({ id: `e${n}`, severity: "Low", dstIp: "1.1.1.1", timestamp: `2026-01-01T00:00:${String(n).padStart(2, "0")}Z` }));
    const chains = buildIocProvenanceChains([ioc({ id: "i1", type: "ip", value: "1.1.1.1" })], events, []);
    expect(chains.i1.extraction.length).toBe(25);
    expect(chains.i1.extractionTruncated).toBe(5);
    expect(chains.i1.extraction[0].eventId).toBe("e0");   // earliest-first, not dropped from the front
  });

  it("carries enrichment lookups sorted by fetchedAt with their timestamp", () => {
    const i = ioc({
      id: "i1", type: "hash", value: "deadbeef",
      enrichments: [
        { source: "AbuseIPDB", verdict: "malicious", fetchedAt: "2026-01-02T00:00:00Z" },
        { source: "VirusTotal", verdict: "suspicious", fetchedAt: "2026-01-01T00:00:00Z", link: "https://vt/x" },
      ],
    });
    const chains = buildIocProvenanceChains([i], [], []);
    expect(chains.i1.enrichment).toEqual([
      { source: "VirusTotal", verdict: "suspicious", score: undefined, fetchedAt: "2026-01-01T00:00:00Z", link: "https://vt/x" },
      { source: "AbuseIPDB", verdict: "malicious", score: undefined, fetchedAt: "2026-01-02T00:00:00Z", link: undefined },
    ]);
  });

  it("links findings that reference the IOC via relatedIocs, sorted by firstSeen", () => {
    const findings = [
      finding({ id: "f2", title: "second", relatedIocs: ["i1"], firstSeen: "2026-01-02T00:00:00Z" }),
      finding({ id: "f1", title: "first", relatedIocs: ["i1"], firstSeen: "2026-01-01T00:00:00Z" }),
      finding({ id: "f3", title: "unrelated", relatedIocs: ["i2"], firstSeen: "2026-01-01T00:00:00Z" }),
    ];
    const chains = buildIocProvenanceChains([ioc({ id: "i1", type: "ip", value: "9.9.9.9" })], [], findings);
    expect(chains.i1.findings.map((f) => f.findingId)).toEqual(["f1", "f2"]);
  });

  it("returns empty arrays for an IOC with no matches", () => {
    const chains = buildIocProvenanceChains([ioc({ id: "i1", type: "ip", value: "1.2.3.4" })], [], []);
    expect(chains.i1).toEqual({
      iocId: "i1", value: "1.2.3.4", type: "ip", extraction: [], extractionTruncated: 0,
      extractionAuthoritative: false, enrichment: [], findings: [],
    });
  });

  it("uses extractedFrom directly when present, ignoring the value-match index", () => {
    const events = [
      ev({ id: "e1", severity: "High", timestamp: "2026-01-01T00:00:00Z", description: "unrelated text" }),
      ev({ id: "e2", severity: "Low", timestamp: "2026-01-02T00:00:00Z", description: "also unrelated" }),
    ];
    const i = ioc({ id: "i1", type: "domain", value: "evil.example.com", extractedFrom: ["e2", "e1"] });
    const chains = buildIocProvenanceChains([i], events, []);
    expect(chains.i1.extraction.map((x) => x.eventId)).toEqual(["e1", "e2"]); // sorted chronologically
    expect(chains.i1.extractionAuthoritative).toBe(true);
  });

  it("falls back to approximate matching when extractedFrom points at no existing event", () => {
    const events = [ev({ id: "e1", severity: "High", description: "connection to evil.example.com observed" })];
    const i = ioc({ id: "i1", type: "domain", value: "evil.example.com", extractedFrom: ["e999"] });
    const chains = buildIocProvenanceChains([i], events, []);
    expect(chains.i1.extraction.map((x) => x.eventId)).toEqual(["e1"]);
    expect(chains.i1.extractionAuthoritative).toBe(false);
  });

  it("falls back to approximate matching when extractedFrom is empty", () => {
    const events = [ev({ id: "e1", severity: "High", dstIp: "8.8.8.8" })];
    const i = ioc({ id: "i1", type: "ip", value: "8.8.8.8" });
    const chains = buildIocProvenanceChains([i], events, []);
    expect(chains.i1.extractionAuthoritative).toBe(false);
  });
});
