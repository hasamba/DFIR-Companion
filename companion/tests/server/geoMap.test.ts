import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { FalsePositiveStore } from "../../src/analysis/falsePositive.js";
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
    expect(res.body.markers[0].severity).toBe("High");
    expect(res.body.markers[0].color).toBe("red");
    expect(res.body.markers[0].eventCount).toBe(1);
    expect(res.body.stats.resolved).toBe(1);
  });

  it("renders a legitimate IOC as gray with eventCount 0", async () => {
    // Build a new root with the same case but wired with a FalsePositiveStore that marks
    // 8.8.8.8 as a false-positive IOC. The marker should make the IP render gray, and the
    // marked event should no longer count toward eventCount.
    const root2 = await mkdtemp(join(tmpdir(), "dfir-geomap-legit-"));
    const cases2 = new CaseStore(root2);
    await cases2.createCase({ caseId: "c1", name: "Geo Legit Test", investigator: "analyst", aiProvider: null });
    const stateStore2 = new StateStore(cases2);
    await stateStore2.save({
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
    const legitStore2 = new FalsePositiveStore(cases2);
    await legitStore2.save("c1", [
      {
        id: "ioc:8.8.8.8",
        kind: "ioc",
        ref: "8.8.8.8",
        reason: "known-good-tool",
        note: "Google DNS — confirmed legitimate",
        markedAt: "2026-01-01T00:00:00Z",
        markedBy: "anonymous",
      },
    ]);
    const app2 = createApp(cases2, {
      stateStore: stateStore2,
      reportWriter: new ReportWriter(cases2, stateStore2, undefined, legitStore2),
    });

    const res = await request(app2).get("/cases/c1/geo-map");
    expect(res.status).toBe(200);
    expect(res.body.markers).toHaveLength(1);
    expect(res.body.markers[0].ip).toBe("8.8.8.8");
    expect(res.body.markers[0].legitimate).toBe(true);
    expect(res.body.markers[0].color).toBe("gray");
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
      "ip,country,city,lat,lon,asn,severity,verdict,internal,eventCount,approximate",
    );
  });
});

describe("GET /vendor/leaflet/leaflet.js (#133)", () => {
  it("serves the vendored Leaflet JS with a 200", async () => {
    const res = await request(app).get("/vendor/leaflet/leaflet.js");
    expect(res.status).toBe(200);
  });
});
