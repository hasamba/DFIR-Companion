import { describe, it, expect } from "vitest";
import { buildGeoMap } from "../../src/analysis/geoMap.js";
import type { InvestigationState, IOC, ForensicEvent } from "../../src/analysis/stateTypes.js";

function ip(id: string, value: string, enr: Partial<IOC["enrichments"][number]> = {}): IOC {
  return {
    id, type: "ip", value, firstSeen: "2026-01-01T00:00:00Z",
    enrichments: [{ source: "GeoIP", verdict: "unknown", fetchedAt: "2026-01-01T00:00:00Z", ...enr }],
  };
}
function ev(e: Partial<ForensicEvent>): ForensicEvent {
  return { id: e.id ?? "e1", timestamp: e.timestamp ?? "2026-01-02T10:00:00Z", description: e.description ?? "", severity: e.severity ?? "Info", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], ...e };
}
function state(iocs: IOC[], events: ForensicEvent[] = [], findings: InvestigationState["findings"] = []): InvestigationState {
  return { caseId: "c", timeline: [], forensicTimeline: events, findings, iocs, threads: [], mitreTechniques: [], keyQuestions: [], summary: "", attackerPath: [], nextSteps: [] } as unknown as InvestigationState;
}

describe("buildGeoMap (#133)", () => {
  it("builds a severity-colored marker from a geo enrichment + referencing event", () => {
    const s = state(
      [ip("i1", "8.8.8.8", { lat: 37.4, lon: -122.1, country: "US", city: "Mountain View", tags: ["US", "AS15169"] })],
      [ev({ id: "e1", dstIp: "8.8.8.8", severity: "High", sources: ["Suricata"] })],
    );
    const g = buildGeoMap(s);
    expect(g.markers).toHaveLength(1);
    const m = g.markers[0];
    expect(m.ip).toBe("8.8.8.8");
    expect(m.severity).toBe("High");
    expect(m.color).toBe("red");
    expect(m.asn).toBe("AS15169");
    expect(m.eventCount).toBe(1);
    expect(m.sources).toEqual(["Suricata"]);
    expect(m.internal).toBe(false);
  });

  it("drops IP IOCs with no coordinates but counts them as unresolved", () => {
    const s = state([
      ip("i1", "8.8.8.8", { lat: 1, lon: 1 }),
      ip("i2", "1.1.1.1"), // no coords
    ]);
    const g = buildGeoMap(s);
    expect(g.markers).toHaveLength(1);
    expect(g.stats.totalIps).toBe(2);
    expect(g.stats.resolved).toBe(1);
    expect(g.stats.unresolved).toBe(1);
  });

  it("colors legitimate IPs gray regardless of severity", () => {
    const s = state(
      [ip("i1", "8.8.8.8", { lat: 1, lon: 1 })],
      [ev({ dstIp: "8.8.8.8", severity: "Critical" })],
    );
    const g = buildGeoMap(s, { legitimateValues: ["8.8.8.8"] });
    expect(g.markers[0].falsePositive).toBe(true);
    expect(g.markers[0].color).toBe("gray");
  });

  it("takes worst severity from findings too", () => {
    const s = state(
      [ip("i1", "8.8.8.8", { lat: 1, lon: 1 })],
      [],
      [{ id: "f1", severity: "Critical", title: "t", description: "", relatedIocs: ["i1"], sourceScreenshots: [], mitreTechniques: [], firstSeen: "x", lastUpdated: "x", status: "open" }],
    );
    expect(buildGeoMap(s).markers[0].severity).toBe("Critical");
  });

  it("derives a flow between two geo-resolved endpoints with direction", () => {
    const s = state(
      [
        ip("i1", "10.0.0.5", { lat: 40, lon: -70 }),  // internal (RFC1918)
        ip("i2", "8.8.8.8", { lat: 37, lon: -122 }),  // external
      ],
      [ev({ srcIp: "10.0.0.5", dstIp: "8.8.8.8", severity: "High", count: 3 })],
    );
    const g = buildGeoMap(s);
    expect(g.flows).toHaveLength(1);
    expect(g.flows[0].direction).toBe("outgoing");
    expect(g.flows[0].count).toBe(3);
  });

  it("excludes a flow when an endpoint has no coordinates", () => {
    const s = state(
      [ip("i2", "8.8.8.8", { lat: 37, lon: -122 })],   // dst resolved, src 10.0.0.5 not an IOC
      [ev({ srcIp: "10.0.0.5", dstIp: "8.8.8.8" })],
    );
    expect(buildGeoMap(s).flows).toHaveLength(0);
  });

  it("aggregates top countries by count and worst severity", () => {
    const s = state(
      [
        ip("i1", "8.8.8.8", { lat: 1, lon: 1, country: "US" }),
        ip("i2", "8.8.4.4", { lat: 2, lon: 2, country: "US" }),
        ip("i3", "1.1.1.1", { lat: 3, lon: 3, country: "AU" }),
      ],
      [ev({ dstIp: "8.8.8.8", severity: "Critical" })],
    );
    const g = buildGeoMap(s);
    expect(g.countries[0]).toEqual({ country: "US", count: 2, severity: "Critical" });
    expect(g.stats.distinctCountries).toBe(2);
  });

  it("caps markers and reports the cap", () => {
    const iocs = Array.from({ length: 5 }, (_, n) => ip(`i${n}`, `9.9.9.${n}`, { lat: n, lon: n }));
    const g = buildGeoMap(state(iocs), { maxMarkers: 2 });
    expect(g.markers).toHaveLength(2);
    expect(g.stats.markerCap).toBe(2);
    expect(g.stats.resolved).toBe(5);
  });

  it("returns an empty map for a case with no geo IPs", () => {
    const g = buildGeoMap(state([]));
    expect(g.markers).toHaveLength(0);
    expect(g.stats.totalIps).toBe(0);
  });

  it("matches an IP referenced only in the event description", () => {
    const s = state(
      [ip("i1", "203.0.113.7", { lat: 5, lon: 5 })],
      [ev({ id: "e1", description: "outbound to 203.0.113.7 detected", severity: "High" })],
    );
    const m = buildGeoMap(s).markers[0];
    expect(m.eventCount).toBe(1);
    expect(m.severity).toBe("High");
  });

  it("does not substring-match a different IP with a shared prefix", () => {
    const s = state(
      [ip("i1", "192.168.1.1", { lat: 5, lon: 5 })],
      [ev({ id: "e1", description: "alert on 192.168.1.10", severity: "Critical" })], // different host
    );
    const m = buildGeoMap(s).markers[0];
    expect(m.eventCount).toBe(0);     // 192.168.1.1 was NOT referenced
    expect(m.severity).toBe("Info");
  });

  // ── F1.2: country-centroid fallback ──────────────────────────────────────────────────────────

  it("F1.2: IOC with country:'DE' and no lat/lon → approximate marker at Germany centroid", () => {
    // source:"GeoIP" so enrichmentCountry picks it up as a GeoIP signal
    const s = state([ip("i1", "1.2.3.4", { country: "DE" })]);
    const g = buildGeoMap(s);
    expect(g.markers).toHaveLength(1);
    const m = g.markers[0];
    expect(m.approximate).toBe(true);
    expect(m.lat).toBeCloseTo(51.17, 0);   // Germany centroid ~51.165691
    expect(m.lon).toBeCloseTo(10.45, 0);   // Germany centroid ~10.451526
    expect(m.country).toBe("Germany");     // resolved to full name via centroid
  });

  it("F1.2: IOC with tags:['IL'] (no country, no lat/lon) → approximate marker at Israel centroid", () => {
    const s = state([ip("i1", "1.2.3.5", { tags: ["IL"] })]);
    const g = buildGeoMap(s);
    expect(g.markers).toHaveLength(1);
    const m = g.markers[0];
    expect(m.approximate).toBe(true);
    // Israel centroid: lat ~31.5, lon ~34.75
    expect(m.lat).toBeGreaterThan(29);
    expect(m.lat).toBeLessThan(34);
    expect(m.lon).toBeGreaterThan(33);
    expect(m.lon).toBeLessThan(36);
  });

  it("F1.2: IOC with precise lat/lon → approximate:false (precise wins even with country present)", () => {
    const s = state([ip("i1", "5.6.7.8", { lat: 5, lon: 6, country: "US" })]);
    const g = buildGeoMap(s);
    expect(g.markers).toHaveLength(1);
    const m = g.markers[0];
    expect(m.approximate).toBe(false);
    expect(m.lat).toBe(5);
    expect(m.lon).toBe(6);
  });

  it("F1.2: IOC with neither coords nor resolvable country → no marker", () => {
    // score only, no country, no lat/lon — enrichmentCountry should return undefined
    const s = state([ip("i1", "9.9.9.9", { score: "no country here" })]);
    const g = buildGeoMap(s);
    expect(g.markers).toHaveLength(0);
  });

  it("resolves country from the GeoIP score leading token when no field/tags/coords", () => {
    const s = state([ip("i1", "203.0.113.9", { score: "DE · AS60729 Example" })]);
    const m = buildGeoMap(s).markers[0];
    expect(m).toBeTruthy();
    expect(m.approximate).toBe(true);
    expect(m.lat).toBeCloseTo(51.17, 1);   // Germany centroid
  });
});
