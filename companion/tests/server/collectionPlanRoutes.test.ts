import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { IncidentTypeStore } from "../../src/analysis/incidentTypeStore.js";
import { CollectionPlanStore } from "../../src/analysis/collectionPlanStore.js";
import { ActivityLogStore } from "../../src/analysis/activityLog.js";
import type { ForensicEvent, InvestigationState } from "../../src/analysis/stateTypes.js";

function ev(sources: string[]): ForensicEvent {
  return {
    id: `e-${sources[0]}`, timestamp: "2026-01-01T00:00:00Z", description: "", severity: "Info",
    mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], sources,
  };
}

async function makeApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-cplanroute-"));
  const casesRoot = join(root, "cases");
  const store = new CaseStore(casesRoot);
  const stateStore = new StateStore(store);
  const app = createApp(store, {
    stateStore, aiConfigured: false,
    activityLogStore: new ActivityLogStore(store),
    incidentTypeStore: new IncidentTypeStore(store, join(root, "incident-types")),
    collectionPlanStore: new CollectionPlanStore(store),
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const withEvents = async (events: ForensicEvent[]) => {
    const s = await stateStore.load("c1");
    await stateStore.save({ ...s, forensicTimeline: events } as InvestigationState);
  };
  return { app, stateStore, withEvents };
}

describe("GET /cases/:id/collection-plan", () => {
  it("returns no plan for a case with no incident type", async () => {
    const { app } = await makeApp();
    const res = await request(app).get("/cases/c1/collection-plan");
    expect(res.status).toBe(200);
    expect(res.body.typeId).toBe("");
    expect(res.body.plan).toBeNull();
  });

  it("returns the type's ordered plan, ticking what the case already holds", async () => {
    const { app, withEvents } = await makeApp();
    await request(app).post("/cases/c1/incident-type").send({ typeId: "ransomware" });
    await withEvents([ev(["EDR (ECAR)"])]);

    const res = await request(app).get("/cases/c1/collection-plan");
    expect(res.status).toBe(200);
    expect(res.body.typeId).toBe("ransomware");
    expect(res.body.plan.steps.map((s: { id: string }) => s.id))
      .toEqual(["edr", "memory", "windows-event-logs", "endpoint-triage", "network", "siem"]);
    expect(res.body.plan.steps[0].state).toBe("collected");
    expect(res.body.plan.nextStepId).toBe("memory");
  });
});

describe("PUT/DELETE /cases/:id/collection-plan/:stepId", () => {
  it("sets an override that beats the derived state", async () => {
    const { app } = await makeApp();
    await request(app).post("/cases/c1/incident-type").send({ typeId: "ransomware" });

    const res = await request(app).put("/cases/c1/collection-plan/edr").send({ state: "na", reason: "no EDR here" });
    expect(res.status).toBe(200);
    const step = res.body.plan.steps.find((s: { id: string }) => s.id === "edr");
    expect(step.state).toBe("override-na");
    expect(step.reason).toBe("no EDR here");
    expect(res.body.plan.nextStepId).toBe("memory");
  });

  it("clears an override, returning the step to automatic", async () => {
    const { app, withEvents } = await makeApp();
    await request(app).post("/cases/c1/incident-type").send({ typeId: "ransomware" });
    await withEvents([ev(["EDR (ECAR)"])]);
    await request(app).put("/cases/c1/collection-plan/edr").send({ state: "na", reason: "x" });

    const res = await request(app).delete("/cases/c1/collection-plan/edr");
    expect(res.status).toBe(200);
    expect(res.body.plan.steps.find((s: { id: string }) => s.id === "edr").state).toBe("collected");
  });

  it("rejects an unknown step id and an invalid state", async () => {
    const { app } = await makeApp();
    await request(app).post("/cases/c1/incident-type").send({ typeId: "ransomware" });
    expect((await request(app).put("/cases/c1/collection-plan/nope").send({ state: "na" })).status).toBe(404);
    expect((await request(app).put("/cases/c1/collection-plan/edr").send({ state: "banana" })).status).toBe(400);
    expect((await request(app).put("/cases/c1/collection-plan/edr").send({})).status).toBe(400);
  });
});
