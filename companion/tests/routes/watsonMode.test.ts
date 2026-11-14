import { mkdir, mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { ActivityLogStore } from "../../src/analysis/activityLog.js";
import { WatsonChatStore } from "../../src/analysis/ai/watson/chatStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import { createApp } from "../../src/server.js";
import { CaseStore } from "../../src/storage/caseStore.js";

// POST /cases/:id/watson/mode: the per-case Approve / Auto switch, its audit entry, and the
// runMode / veloConnected fields on GET /watson.

const CASE = "c1";

async function harness() {
  const store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-watson-mode-")));
  await store.createCase({ caseId: CASE, name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(store);
  await stateStore.save(emptyState(CASE));
  const activity = new ActivityLogStore(store);
  const app = createApp(store, {
    stateStore,
    activityLogStore: activity,
    watsonChatStore: new WatsonChatStore(store),
  });
  return { app, store, activity };
}

describe("Watson run mode route", () => {
  it("reports approve by default and no Velociraptor server", async () => {
    const { app } = await harness();
    const res = await request(app).get(`/cases/${CASE}/watson`);
    expect(res.status).toBe(200);
    expect(res.body.runMode).toBe("approve");
    expect(res.body.veloConnected).toBe(false);
  });

  it("switches to auto and back, each switch audited with the analyst", async () => {
    const { app, activity } = await harness();
    const on = await request(app).post(`/cases/${CASE}/watson/mode`).send({ mode: "auto" });
    expect(on.status).toBe(200);
    expect(on.body).toEqual({ mode: "auto" });
    expect((await request(app).get(`/cases/${CASE}/watson`)).body.runMode).toBe("auto");
    const off = await request(app).post(`/cases/${CASE}/watson/mode`).send({ mode: "approve" });
    expect(off.body).toEqual({ mode: "approve" });
    expect((await request(app).get(`/cases/${CASE}/watson`)).body.runMode).toBe("approve");
    const entries = (await activity.load(CASE)).filter((e) => e.action === "watson.mode");
    expect(entries.map((e) => e.detail)).toEqual(["Switched Watson to Approve", "Switched Watson to Auto"]);
    for (const e of entries) {
      expect(e.category).toBe("ai");
      expect(e.actor).toBeTruthy();
    }
  });

  it("does not log or rewrite provenance when the mode is already set", async () => {
    const { app, activity } = await harness();
    await request(app).post(`/cases/${CASE}/watson/mode`).send({ mode: "auto" });
    await request(app).post(`/cases/${CASE}/watson/mode`).send({ mode: "auto" });
    expect((await activity.load(CASE)).filter((e) => e.action === "watson.mode")).toHaveLength(1);
  });

  it("answers 400 for a bad mode and 404 for an unknown case", async () => {
    const { app } = await harness();
    expect((await request(app).post(`/cases/${CASE}/watson/mode`).send({ mode: "fleet" })).status).toBe(400);
    expect((await request(app).post(`/cases/${CASE}/watson/mode`).send({})).status).toBe(400);
    expect((await request(app).post("/cases/nope/watson/mode").send({ mode: "auto" })).status).toBe(404);
  });

  it("refuses the switch on a frozen case", async () => {
    const { app, store } = await harness();
    await store.updateCaseMeta(CASE, { status: "closed" });
    const res = await request(app).post(`/cases/${CASE}/watson/mode`).send({ mode: "auto" });
    expect(res.status).toBe(423);
  });
});

describe("the mode switch audit comes first (final review G15)", () => {
  it("a switch whose save fails is still audited, and audited as failed", async () => {
    const { app, store, activity } = await harness();
    await request(app).get(`/cases/${CASE}/watson`); // the control is cached: only the save fails
    // Make the ai-control save fail: a directory where the file goes.
    await mkdir(join(store.stateDir(CASE), "ai-control.json"), { recursive: true });
    const res = await request(app).post(`/cases/${CASE}/watson/mode`).send({ mode: "auto" });
    expect(res.status).toBeGreaterThanOrEqual(400);
    const entries = (await activity.load(CASE)).filter((e) => e.action === "watson.mode");
    expect(entries.map((e) => e.detail)).toEqual([
      "Switched Watson to Auto (the switch failed)",
      "Switched Watson to Auto",
    ]);
    expect(entries[0].outcome).toBe("error");
  });
});

describe("an audit that cannot be written refuses the switch (final review G15)", () => {
  it("leaves the mode unchanged", async () => {
    const store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-watson-mode-noaudit-")));
    await store.createCase({ caseId: CASE, name: "n", investigator: "i", aiProvider: null });
    const stateStore = new StateStore(store);
    await stateStore.save(emptyState(CASE));
    const activity = new ActivityLogStore(store);
    activity.add = async () => {
      throw new Error("EROFS: read-only file system");
    };
    const app = createApp(store, {
      stateStore,
      activityLogStore: activity,
      watsonChatStore: new WatsonChatStore(store),
    });
    const res = await request(app).post(`/cases/${CASE}/watson/mode`).send({ mode: "auto" });
    expect(res.status).toBe(503);
    expect(res.body.error).toMatch(/not changed/);
    expect((await request(app).get(`/cases/${CASE}/watson`)).body.runMode).toBe("approve");
  });
});
