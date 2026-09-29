import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ScopeStore } from "../../src/analysis/scope.js";
import { FalsePositiveStore } from "../../src/analysis/falsePositive.js";
import { ReportWriter } from "../../src/reports/reportWriter.js";
import { emptyState, type IOC } from "../../src/analysis/stateTypes.js";

// #1807: GET /cases/:id/export/ioc-blocklist?format=summary returns the match count and the
// reason each IOC was left out, so the dialog can say why an export would be empty.

const live = (verdict: "malicious" | "suspicious") => ({
  source: "VT",
  verdict,
  fetchedAt: "2026-06-13T09:00:00Z",
  status: "live" as const,
});

async function harness(iocs: IOC[]) {
  const root = await mkdtemp(join(tmpdir(), "dfir-blocklist-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const reportWriter = new ReportWriter(store, stateStore, {
    scope: new ScopeStore(store),
    falsePositives: new FalsePositiveStore(store),
  });
  const app = createApp(store, { stateStore, reportWriter });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  await stateStore.save({ ...emptyState("c1"), iocs });
  return app;
}

const IOCS: IOC[] = [
  {
    id: "i1",
    type: "ip",
    value: "203.0.113.10",
    firstSeen: "2026-06-13T09:00:00Z",
    enrichments: [live("malicious")],
  },
  { id: "i2", type: "ip", value: "192.0.2.5", firstSeen: "2026-06-13T09:00:00Z" },
  { id: "i3", type: "file", value: "x.exe", firstSeen: "2026-06-13T09:00:00Z" },
];

describe("GET /cases/:id/export/ioc-blocklist?format=summary (#1807)", () => {
  it("returns the match count and per-reason exclusions as JSON, not a download", async () => {
    const app = await harness(IOCS);
    const res = await request(app).get("/cases/c1/export/ioc-blocklist?format=summary&minSeverity=Medium");
    expect(res.status).toBe(200);
    expect(res.headers["content-type"]).toMatch(/application\/json/);
    expect(res.headers["content-disposition"]).toBeUndefined();
    expect(res.body).toEqual({
      total: 3,
      matched: 1,
      excluded: {
        retired: 0,
        "client-reported": 0,
        "ineligible-type": 1,
        "no-actionable-intel": 1,
        "below-min-severity": 0,
        "not-verdict-confirmed": 0,
      },
    });
  });

  it("applies the same filter arguments as the download", async () => {
    const app = await harness(IOCS);
    const res = await request(app).get(
      "/cases/c1/export/ioc-blocklist?format=summary&minSeverity=Info&types=domain&verdictOnly=true",
    );
    expect(res.body.matched).toBe(0);
    expect(res.body.excluded["ineligible-type"]).toBe(3);
  });

  it("an empty types= (every type unticked) matches nothing instead of falling back to the defaults", async () => {
    const app = await harness(IOCS);
    const res = await request(app).get(
      "/cases/c1/export/ioc-blocklist?format=summary&minSeverity=Info&types=",
    );
    expect(res.body.matched).toBe(0);
    expect(res.body.excluded["ineligible-type"]).toBe(res.body.total);
  });

  it("still serves the file formats, and the TXT header carries the count", async () => {
    const app = await harness(IOCS);
    const txt = await request(app).get("/cases/c1/export/ioc-blocklist?format=txt");
    expect(txt.status).toBe(200);
    expect(txt.headers["content-type"]).toMatch(/text\/plain/);
    expect(txt.headers["content-disposition"]).toContain("ioc-blocklist-c1.txt");
    expect(txt.text).toContain("# Matched 1 of 3 IOCs");
    const csv = await request(app).get("/cases/c1/export/ioc-blocklist?format=csv");
    expect(csv.headers["content-type"]).toMatch(/text\/csv/);
    expect(csv.headers["content-disposition"]).toContain("ioc-blocklist-c1.csv");
    expect(csv.text).not.toContain("Matched");
    const stix = await request(app).get("/cases/c1/export/ioc-blocklist?format=stix");
    expect(stix.headers["content-type"]).toMatch(/application\/json/);
    expect(stix.headers["content-disposition"]).toContain("ioc-blocklist-c1.stix.json");
    expect(JSON.parse(stix.text).type).toBe("bundle");
  });

  it("rejects an unknown format", async () => {
    const app = await harness(IOCS);
    const res = await request(app).get("/cases/c1/export/ioc-blocklist?format=pdf");
    expect(res.status).toBe(400);
    expect(res.body.error).toContain("summary");
  });
});
