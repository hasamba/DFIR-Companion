import { describe, expect, it } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { createApp } from "../../src/server.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { HypothesisStore } from "../../src/analysis/hypothesisStore.js";
import { FindingWorkflowStore } from "../../src/analysis/findingWorkflow.js";
import { PinnedFindingsStore } from "../../src/analysis/pinnedFindings.js";
import { ActivityLogStore } from "../../src/analysis/activityLog.js";
import { emptyState } from "../../src/analysis/stateTypes.js";

async function makeApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-cockpit-routes-"));
  const cases = new CaseStore(root);
  const stateStore = new StateStore(cases);
  const hypothesisStore = new HypothesisStore(cases);
  const findingWorkflowStore = new FindingWorkflowStore(cases);
  const pinnedFindingsStore = new PinnedFindingsStore(cases);
  const activityLogStore = new ActivityLogStore(cases);
  const app = createApp(cases, {
    stateStore,
    hypothesisStore,
    findingWorkflowStore,
    pinnedFindingsStore,
    activityLogStore,
  });
  await request(app)
    .post("/cases")
    .send({ caseId: "c1", name: "Case", investigator: "Case Owner", aiProvider: null });
  await stateStore.save({
    ...emptyState("c1"),
    findings: [
      {
        id: "f1",
        severity: "Critical",
        confidence: 95,
        title: "Credential theft",
        description: "LSASS access",
        relatedIocs: [],
        sourceScreenshots: [],
        mitreTechniques: ["T1003"],
        relatedEventIds: ["e1"],
        firstSeen: "2026-07-30T09:00:00.000Z",
        lastUpdated: "2026-07-30T10:00:00.000Z",
        status: "open",
      },
    ],
    forensicTimeline: [
      {
        id: "e1",
        timestamp: "2026-07-30T09:00:00.000Z",
        description: "LSASS access",
        severity: "Critical",
        mitreTechniques: ["T1003"],
        relatedFindingIds: ["f1"],
        sourceScreenshots: [],
      },
    ],
    updatedAt: "2026-07-30T10:00:00.000Z",
  });
  return { app, findingWorkflowStore, pinnedFindingsStore, activityLogStore };
}

describe("cockpit routes", () => {
  it("returns a deterministic cockpit and falls back to the case investigator identity", async () => {
    const { app } = await makeApp();
    const response = await request(app).get("/cases/c1/cockpit");

    expect(response.status).toBe(200);
    expect(response.body.investigator).toBe("Case Owner");
    expect(response.body.sections.leads[0]).toMatchObject({
      id: "lead:finding:f1",
      evidenceIds: ["e1"],
    });
  });

  it("returns 404 for an unknown case without creating cockpit state", async () => {
    const { app } = await makeApp();
    expect((await request(app).get("/cases/missing/cockpit")).status).toBe(404);
    expect(
      (await request(app).post("/cases/missing/cockpit/review").send({ investigator: "Alice" })).status,
    ).toBe(404);
  });

  it("pins and assigns a finding through its owning stores while preserving cockpit audit history", async () => {
    const { app, findingWorkflowStore, pinnedFindingsStore, activityLogStore } = await makeApp();

    expect(
      (
        await request(app)
          .patch("/cases/c1/cockpit/cards/lead%3Afinding%3Af1")
          .send({ action: "pin", actor: "Alice" })
      ).status,
    ).toBe(200);
    expect(
      (
        await request(app)
          .patch("/cases/c1/cockpit/cards/lead%3Afinding%3Af1")
          .send({ action: "assign", actor: "Alice", value: "Bob" })
      ).status,
    ).toBe(200);

    expect(await pinnedFindingsStore.load("c1")).toEqual([
      expect.objectContaining({ findingId: "f1", pinnedBy: "Alice" }),
    ]);
    expect(await findingWorkflowStore.load("c1")).toEqual([
      expect.objectContaining({ findingId: "f1", assignee: "Bob" }),
    ]);

    const history = await request(app).get("/cases/c1/cockpit/history");
    expect(history.status).toBe(200);
    expect(history.body.history.map((entry: { action: string }) => entry.action)).toEqual(["pin", "assign"]);
    expect((await activityLogStore.load("c1")).map((entry) => entry.action)).toEqual([
      "cockpit-assign",
      "cockpit-pin",
    ]);
  });

  it("dismisses, defers, restores, and marks review per investigator", async () => {
    const { app } = await makeApp();
    const path = "/cases/c1/cockpit/cards/lead%3Afinding%3Af1";

    expect((await request(app).patch(path).send({ action: "dismiss", actor: "Alice" })).status).toBe(200);
    let cockpit = await request(app).get("/cases/c1/cockpit?investigator=Alice");
    expect(cockpit.body.sections.leads).toEqual([]);
    expect(cockpit.body.parked[0].id).toBe("lead:finding:f1");

    expect((await request(app).patch(path).send({ action: "restore", actor: "Alice" })).status).toBe(200);
    expect(
      (
        await request(app).patch(path).send({
          action: "defer",
          actor: "Alice",
          value: "2099-01-01T00:00:00.000Z",
        })
      ).status,
    ).toBe(200);
    cockpit = await request(app).get("/cases/c1/cockpit?investigator=Alice");
    expect(cockpit.body.parked[0]).toMatchObject({
      id: "lead:finding:f1",
      deferredUntil: "2099-01-01T00:00:00.000Z",
    });

    const reviewed = await request(app).post("/cases/c1/cockpit/review").send({ investigator: "Alice" });
    expect(reviewed.status).toBe(200);
    expect(reviewed.body.review.investigatorKey).toBe("alice");
    cockpit = await request(app).get("/cases/c1/cockpit?investigator=Alice");
    expect(cockpit.body.lastReviewedAt).toBeTruthy();
  });

  it("uses the case investigator for omitted actors and rejects incomplete action values", async () => {
    const { app, pinnedFindingsStore, activityLogStore } = await makeApp();
    const path = "/cases/c1/cockpit/cards/lead%3Afinding%3Af1";

    expect((await request(app).patch(path).send({ action: "assign" })).status).toBe(400);
    expect((await request(app).patch(path).send({ action: "defer", value: "tomorrow" })).status).toBe(400);
    expect((await request(app).patch(path).send({ action: "pin" })).status).toBe(200);

    expect(await pinnedFindingsStore.load("c1")).toEqual([
      expect.objectContaining({ findingId: "f1", pinnedBy: "Case Owner" }),
    ]);
    expect((await activityLogStore.load("c1"))[0]).toMatchObject({
      action: "cockpit-pin",
      actor: "Case Owner",
    });
  });

  it("rejects unknown cards and invalid actions", async () => {
    const { app } = await makeApp();
    expect(
      (await request(app).patch("/cases/c1/cockpit/cards/not-real").send({ action: "pin", actor: "Alice" }))
        .status,
    ).toBe(404);
    expect(
      (
        await request(app)
          .patch("/cases/c1/cockpit/cards/lead%3Afinding%3Af1")
          .send({ action: "explode", actor: "Alice" })
      ).status,
    ).toBe(400);
  });
});
