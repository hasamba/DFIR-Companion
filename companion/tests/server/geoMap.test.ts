import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ReportWriter } from "../../src/reports/reportWriter.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import { createApp } from "../../src/server.js";

// Mirrors the pattern used in redactedExportRoute.test.ts and reportTemplateRoutes.test.ts:
// build a minimal app with a ReportWriter wired in, seed a case with a geo-enriched IP IOC,
// and assert the geo-map routes return the expected shapes.

let app: ReturnType<typeof createApp>;
let cases: CaseStore;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-geomap-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "Geo Test", investigator: "analyst", aiProvider: null });

  const stateStore = new StateStore(cases);

  // Seed an IP IOC with GeoIP coordinates + a High-severity forensic event referencing it.
  await stateStore.save({
    ...emptyState("c1"),
    iocs: [
      {
        id: "i1",
        type: "ip",
        value: "8.8.8.8",
        firstSeen: "2026-01-01T00:00:00Z",
        enrichments: [
          {
            source: "GeoIP",
            verdict: "unknown",
            fetchedAt: "2026-01-01T00:00:00Z",
            lat: 37.4,
            lon: -122.1,
            country: "US",
            city: "Mountain View",
            tags: ["US", "AS15169"],
          },
        ],
      },
    ],
    forensicTimeline: [
      {
        id: "e1",
        timestamp: "2026-01-02T10:00:00Z",
        description: "Connection to 8.8.8.8",
        severity: "High",
        dstIp: "8.8.8.8",
        mitreTechniques: [],
        relatedFindingIds: [],
        sourceScreenshots: [],
        sources: ["Suricata"],
      },
    ],
  });

  app = createApp(cases, {
    stateStore,
    reportWriter: new ReportWriter(cases, stateStore),
  });
});

describe("GET /cases/:id/geo-map (#133)", () => {
  it("returns geo map data with a marker for the enriched IP IOC", async () => {
    const res = await request(app).get("/cases/c1/geo-map");
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.markers)).toBe(true);
    expect(res.body.markers).toHaveLength(1);
    expect(res.body.markers[0].ip).toBe("8.8.8.8");
    expect(res.body.stats.resolved).toBe(1);
  });

  it("returns 501 when the report writer is not configured", async () => {
    const bare = createApp(cases, {});
    const res = await request(bare).get("/cases/c1/geo-map");
    expect(res.status).toBe(501);
  });
});

describe("GET /cases/:id/geo-map.csv (#133)", () => {
  it("serves the geo-map CSV with the correct header", async () => {
    const res = await request(app).get("/cases/c1/geo-map.csv");
    expect(res.status).toBe(200);
    expect(res.headers["content-type"]).toContain("text/csv");
    expect(res.text.split("\n")[0]).toBe(
      "ip,country,city,lat,lon,asn,severity,verdict,internal,eventCount",
    );
  });
});

describe("GET /vendor/leaflet/leaflet.js (#133)", () => {
  it("serves the vendored Leaflet JS with a 200", async () => {
    const res = await request(app).get("/vendor/leaflet/leaflet.js");
    expect(res.status).toBe(200);
  });
});
