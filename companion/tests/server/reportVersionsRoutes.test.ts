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
import { ReportMetaStore } from "../../src/reports/reportMeta.js";
import { ReportVersionStore } from "../../src/reports/reportVersionStore.js";
import { ReportWriter } from "../../src/reports/reportWriter.js";

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "dfir-rv-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const reportMetaStore = new ReportMetaStore(store);
  const reportVersionStore = new ReportVersionStore(store);
  // NOTE the argument count: reportVersions is the LAST constructor parameter, and master's
  // lateralPathDismissals sits immediately before it. These are positional, so an off-by-one here
  // silently lands the store in the wrong slot and leaves `reportVersions` undefined — the version
  // list then stays empty and every test in this file fails with "expected [] to have a length of 1".
  const reportWriter = new ReportWriter(
    store, stateStore, new ScopeStore(store), new FalsePositiveStore(store), reportMetaStore,
    undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined,
    undefined,            // lateralPathDismissals — not exercised here
    reportVersionStore,
  );
  const app = createApp(store, { stateStore, reportWriter, reportMetaStore, reportVersionStore });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, store };
}

describe("report-versions routes", () => {
  it("returns [] before any report has been generated", async () => {
    const { app } = await harness();
    const res = await request(app).get("/cases/c1/report-versions");
    expect(res.status).toBe(200);
    expect(res.body).toEqual([]);
  });

  it("records a version on each distinct report generation", async () => {
    const { app } = await harness();
    await request(app).put("/cases/c1/report-meta").send({ organization: "ExampleCorp" });
    expect((await request(app).post("/cases/c1/report")).status).toBe(200);

    const afterFirst = await request(app).get("/cases/c1/report-versions");
    expect(afterFirst.body).toHaveLength(1);
    expect(afterFirst.body[0].version).toBe("v1");

    // Regenerating with nothing changed must not add a second version.
    expect((await request(app).post("/cases/c1/report")).status).toBe(200);
    expect((await request(app).get("/cases/c1/report-versions")).body).toHaveLength(1);

    // A change to report-meta changes the rendered markdown, so it adds v2.
    await request(app).put("/cases/c1/report-meta").send({ organization: "NewCorp Inc" });
    expect((await request(app).post("/cases/c1/report")).status).toBe(200);
    const afterSecond = await request(app).get("/cases/c1/report-versions");
    expect(afterSecond.body).toHaveLength(2);
    expect(afterSecond.body[0].version).toBe("v2"); // newest first
  });

  it("diffs findings/IOCs/timeline between two versions", async () => {
    const { app, store } = await harness();
    const { StateStore: SS } = await import("../../src/analysis/stateStore.js");
    const stateStore = new SS(store);
    const { emptyState } = await import("../../src/analysis/stateTypes.js");

    const s1 = emptyState("c1");
    s1.findings.push({ id: "f1", severity: "Low", title: "Suspicious login", description: "d", relatedIocs: [], sourceScreenshots: [], mitreTechniques: [], firstSeen: "t0", lastUpdated: "t1", status: "open" });
    await stateStore.save(s1);
    await request(app).post("/cases/c1/report");
    const v1 = (await request(app).get("/cases/c1/report-versions")).body[0];

    const s2 = emptyState("c1");
    s2.findings.push({ id: "f1", severity: "Critical", title: "Suspicious login", description: "d", relatedIocs: [], sourceScreenshots: [], mitreTechniques: [], firstSeen: "t0", lastUpdated: "t1", status: "open" });
    s2.findings.push({ id: "f2", severity: "High", title: "Ransomware deployed", description: "d", relatedIocs: [], sourceScreenshots: [], mitreTechniques: [], firstSeen: "t0", lastUpdated: "t1", status: "open" });
    await stateStore.save(s2);
    await request(app).post("/cases/c1/report");
    const v2 = (await request(app).get("/cases/c1/report-versions")).body[0];

    const diff = await request(app).get(`/cases/c1/report-versions/diff?from=${v1.id}&to=${v2.id}`);
    expect(diff.status).toBe(200);
    expect(diff.body.findings.added).toEqual(["Ransomware deployed"]);
    expect(diff.body.findings.severityChanged).toEqual([{ title: "Suspicious login", from: "Low", to: "Critical" }]);
  });

  it("restores a prior version's editable report-meta", async () => {
    const { app } = await harness();
    await request(app).put("/cases/c1/report-meta").send({ organization: "OriginalCorp" });
    await request(app).post("/cases/c1/report");
    const v1 = (await request(app).get("/cases/c1/report-versions")).body[0];

    await request(app).put("/cases/c1/report-meta").send({ organization: "OverwrittenCorp" });
    expect((await request(app).get("/cases/c1/report-meta")).body.organization).toBe("OverwrittenCorp");

    const restore = await request(app).post(`/cases/c1/report-versions/${v1.id}/restore`);
    expect(restore.status).toBe(200);
    expect(restore.body.organization).toBe("OriginalCorp");
    expect((await request(app).get("/cases/c1/report-meta")).body.organization).toBe("OriginalCorp");
  });

  it("404s a diff/restore against an unknown version id", async () => {
    const { app } = await harness();
    expect((await request(app).get("/cases/c1/report-versions/diff?from=ghost&to=ghost2")).status).toBe(404);
    expect((await request(app).post("/cases/c1/report-versions/ghost/restore")).status).toBe(404);
  });

  it("rejects a path-traversal version id instead of reading an arbitrary file (404, not 200/500)", async () => {
    const { app } = await harness();
    // Generate one real version so a valid `to` exists and can't be the reason for a 404.
    await request(app).post("/cases/c1/report");
    const real = (await request(app).get("/cases/c1/report-versions")).body[0];
    const traversal = encodeURIComponent("../../../../../../../../etc/hostname");

    const diffFrom = await request(app).get(`/cases/c1/report-versions/diff?from=${traversal}&to=${real.id}`);
    expect(diffFrom.status).toBe(404);

    const diffTo = await request(app).get(`/cases/c1/report-versions/diff?from=${real.id}&to=${traversal}`);
    expect(diffTo.status).toBe(404);

    const restore = await request(app).post(`/cases/c1/report-versions/${traversal}/restore`);
    expect(restore.status).toBe(404);
  });
});
