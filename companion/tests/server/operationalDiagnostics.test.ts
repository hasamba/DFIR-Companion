import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { OperationalMetricsStore } from "../../src/analysis/operationalMetrics.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";

describe("operational diagnostics and support bundle", () => {
  it("returns long-term metrics and a separately redacted preview", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-operational-diagnostics-"));
    const cases = new CaseStore(root);
    await cases.createCase({
      caseId: "customer-secret-id",
      name: "Customer Secret Name",
      investigator: "Sensitive Person",
      aiProvider: null,
    });
    const metrics = new OperationalMetricsStore(join(root, "diagnostics", "metrics.json"));
    await metrics.record({
      type: "import",
      importer: "siem",
      durationMs: 800,
      rowsRead: 100,
      accepted: 25,
      rejected: 75,
      promoted: 4,
      rejectionReason: "filtered",
    });
    await metrics.record({
      type: "query",
      operation: "forensic_timeline",
      index: "host",
      durationMs: 200,
      rows: 25,
    });

    const app = createApp(cases, {
      operationalMetrics: metrics,
      appVersion: "0.35.0",
      liveConnectionCount: () => 3,
    });
    const response = await request(app).get("/diagnostics");

    expect(response.status).toBe(200);
    expect(response.body.report.operational.imports).toMatchObject({
      runs: 1,
      rowsRead: 100,
      accepted: 25,
      rejected: 75,
      promoted: 4,
    });
    expect(response.body.report.operational.websocket.active).toBe(3);
    expect(response.body.report.operational.slowest.importer.name).toBe("siem");
    expect(response.body.supportPreview).toContain('"caseEvidence": "excluded"');
    expect(response.body.supportFilename).toMatch(/^dfir-companion-support-\d{4}-\d{2}-\d{2}\.json$/);
    expect(response.body.supportPreview).not.toContain("customer-secret-id");
    expect(response.body.supportPreview).not.toContain("Customer Secret Name");
    expect(response.body.supportPreview).not.toContain("Sensitive Person");
  });
});
