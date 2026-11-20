import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { IncidentTypeStore } from "../../src/analysis/incidentTypeStore.js";
import { ActivityLogStore } from "../../src/analysis/activityLog.js";
import { SynthMetaStore } from "../../src/analysis/synthMeta.js";
import { ReportTemplateControlStore } from "../../src/reports/reportTemplateControl.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import { pollFor } from "../helpers/poll.js";

// Hunt-case routes (#2670): status, Convert to incident, and the hunt case's default report.
async function makeApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-huntcase-"));
  const store = new CaseStore(join(root, "cases"));
  const stateStore = new StateStore(store);
  const incidentTypeStore = new IncidentTypeStore(store, join(root, "incident-types"));
  const synthMetaStore = new SynthMetaStore(store);
  const activityLogStore = new ActivityLogStore(store);
  const reportTemplateControlStore = new ReportTemplateControlStore(store);
  const app = createApp(store, {
    stateStore,
    aiConfigured: false,
    activityLogStore,
    incidentTypeStore,
    synthMetaStore,
    reportTemplateControlStore,
  });
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, stateStore, incidentTypeStore, synthMetaStore, activityLogStore, reportTemplateControlStore };
}

const ev = (id: string, severity: ForensicEvent["severity"]): ForensicEvent => ({
  id,
  timestamp: "2026-01-01T00:00:00Z",
  description: `row ${id}`,
  severity,
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
});

describe("hunt case routes (#2670)", () => {
  it("picking the Threat hunt type switches the report to the Threat hunt summary", async () => {
    const { app, reportTemplateControlStore } = await makeApp();
    const res = await request(app).post("/cases/c1/incident-type").send({ typeId: "threat-hunt" });
    expect(res.status).toBe(200);
    expect((await reportTemplateControlStore.load("c1")).templateId).toBe("threat-hunt-summary");
  });

  it("never overrides a report template the analyst already picked", async () => {
    const { app, reportTemplateControlStore } = await makeApp();
    await reportTemplateControlStore.set("c1", { templateId: "executive-brief" });
    await request(app).post("/cases/c1/incident-type").send({ typeId: "threat-hunt" });
    expect((await reportTemplateControlStore.load("c1")).templateId).toBe("executive-brief");
  });

  it("status: hunt mode with coverage unknown, and no Convert offer on a clean hunt", async () => {
    const { app, incidentTypeStore, stateStore } = await makeApp();
    await incidentTypeStore.saveRecord("c1", "threat-hunt");
    await stateStore.save({ ...emptyState("c1"), forensicTimeline: [ev("m", "Medium")] });
    const res = await request(app).get("/cases/c1/hunt/status");
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ hunt: true, convertOffered: false, coverage: { known: false } });
  });

  it("status: offers Convert as soon as the hunt holds a High finding", async () => {
    const { app, incidentTypeStore, stateStore } = await makeApp();
    await incidentTypeStore.saveRecord("c1", "threat-hunt");
    await stateStore.save({ ...emptyState("c1"), forensicTimeline: [ev("h", "High")] });
    expect((await request(app).get("/cases/c1/hunt/status")).body.convertOffered).toBe(true);
  });

  it("status: an incident case is not a hunt", async () => {
    const { app, incidentTypeStore } = await makeApp();
    await incidentTypeStore.saveRecord("c1", "ransomware");
    expect((await request(app).get("/cases/c1/hunt/status")).body).toMatchObject({ hunt: false });
  });

  it("convert keeps every row, switches the type, records where it came from and marks AI stale", async () => {
    const { app, incidentTypeStore, stateStore, synthMetaStore, activityLogStore } = await makeApp();
    await incidentTypeStore.saveRecord("c1", "threat-hunt");
    const rows = [ev("h", "High"), ev("i", "Info")];
    await stateStore.save({ ...emptyState("c1"), forensicTimeline: rows, lastSummary: "hunt summary" });
    await synthMetaStore
      .record("c1", { lastSynthesizedAt: "2026-01-01T00:00:00Z" } as never)
      .catch(() => undefined);

    const res = await request(app).post("/cases/c1/hunt/convert-to-incident").send({});
    expect(res.status).toBe(200);
    expect(res.body.record).toMatchObject({ typeId: "intrusion", convertedFrom: "threat-hunt" });
    expect(res.body.hunt).toBe(false);

    const after = await stateStore.load("c1");
    expect(after.forensicTimeline.map((e) => e.id).sort()).toEqual(["h", "i"]);
    expect(after.lastSummary).toBe("hunt summary");
    expect((await synthMetaStore.load("c1")).outOfDate?.reason).toMatch(/Converted from a threat hunt/);
    await pollFor("the convert audit line", async () =>
      (await activityLogStore.load("c1")).find((e) => e.action === "hunt-convert-to-incident"),
    );
    expect((await request(app).get("/cases/c1/hunt/status")).body).toMatchObject({
      hunt: false,
      convertedFrom: "threat-hunt",
    });
  });

  it("refuses to convert a case that is not a hunt, or into another hunt type", async () => {
    const { app, incidentTypeStore } = await makeApp();
    await incidentTypeStore.saveRecord("c1", "ransomware");
    expect((await request(app).post("/cases/c1/hunt/convert-to-incident").send({})).status).toBe(409);
    await incidentTypeStore.saveRecord("c1", "threat-hunt");
    const res = await request(app).post("/cases/c1/hunt/convert-to-incident").send({ typeId: "threat-hunt" });
    expect(res.status).toBe(400);
    const bad = await request(app).post("/cases/c1/hunt/convert-to-incident").send({ typeId: 7 });
    expect(bad.status).toBe(400);
  });
});

describe("POST /cases/:id/hunt/regrade (#2670)", () => {
  async function regradeApp() {
    const { HuntInventoryStore } = await import("../../src/analysis/huntInventoryStore.js");
    const root = await mkdtemp(join(tmpdir(), "dfir-huntregrade-"));
    const store = new CaseStore(join(root, "cases"));
    const stateStore = new StateStore(store);
    const incidentTypeStore = new IncidentTypeStore(store, join(root, "incident-types"));
    const activityLogStore = new ActivityLogStore(store);
    const huntGradingDeps = {
      stateStore,
      inventoryStore: new HuntInventoryStore(store),
      incidentTypeStore,
      veloHuntStore: { list: async () => [] },
    };
    const app = createApp(store, {
      stateStore,
      aiConfigured: false,
      activityLogStore,
      incidentTypeStore,
      huntGradingDeps,
    });
    await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    return { app, incidentTypeStore, activityLogStore };
  }

  it("refuses a case that is not a hunt", async () => {
    const { app, incidentTypeStore } = await regradeApp();
    await incidentTypeStore.saveRecord("c1", "ransomware");
    expect((await request(app).post("/cases/c1/hunt/regrade").send({})).status).toBe(409);
  });

  it("re-grades a hunt case, discloses evicted observations, and is audit-logged", async () => {
    const { app, incidentTypeStore, activityLogStore } = await regradeApp();
    await incidentTypeStore.saveRecord("c1", "threat-hunt");
    const res = await request(app).post("/cases/c1/hunt/regrade").send({});
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ rowsRead: 0, evicted: 0, entries: 0 });
    const entry = await pollFor("the re-grade audit line", async () =>
      (await activityLogStore.load("c1")).find((e) => e.action === "hunt-regrade"),
    );
    expect(entry.detail).toMatch(/no longer in the raw record/);
  });
});
