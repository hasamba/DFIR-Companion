import { mkdtemp } from "node:fs/promises";
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

// POST /cases/:id/watson/auto-chain {max} and /auto-chain/stop: the per-case Auto chain limit
// (0 = no limit) and Stop chain, each audited; GET /watson returns both on the chat.

const CASE = "c1";

async function harness() {
  const store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-watson-chain-")));
  await store.createCase({ caseId: CASE, name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(store);
  await stateStore.save(emptyState(CASE));
  const activity = new ActivityLogStore(store);
  const chats = new WatsonChatStore(store);
  const app = createApp(store, { stateStore, activityLogStore: activity, watsonChatStore: chats });
  return { app, activity, chats };
}

const audits = async (activity: ActivityLogStore) =>
  (await activity.load(CASE))
    .filter((e) => e.action === "watson.autoChain")
    .map((e) => e.detail)
    .sort();

describe("Watson Auto chain routes", () => {
  it("sets the case's chain limit, 0 meaning no limit, and audits each change", async () => {
    const { app, activity } = await harness();
    const five = await request(app).post(`/cases/${CASE}/watson/auto-chain`).send({ max: 5 });
    expect(five.status).toBe(200);
    expect(five.body.autoChainMax).toBe(5);
    const none = await request(app).post(`/cases/${CASE}/watson/auto-chain`).send({ max: "0" });
    expect(none.body.autoChainMax).toBe(0);
    expect((await request(app).get(`/cases/${CASE}/watson`)).body.autoChainMax).toBe(0);
    expect(await audits(activity)).toEqual([
      "Set the Auto chain limit to 5",
      "Set the Auto chain limit to no limit",
    ]);
  });

  it("refuses a limit that is not a whole number from 0 to 50", async () => {
    const { app } = await harness();
    for (const max of [-1, 51, 2.5, "abc", "", null]) {
      const res = await request(app).post(`/cases/${CASE}/watson/auto-chain`).send({ max });
      expect(res.status).toBe(400);
    }
    expect((await request(app).post("/cases/nope/watson/auto-chain").send({ max: 3 })).status).toBe(404);
  });

  it("stops the chain until the analyst's next message, audited", async () => {
    const { app, activity, chats } = await harness();
    const res = await request(app).post(`/cases/${CASE}/watson/auto-chain/stop`).send({});
    expect(res.status).toBe(200);
    expect(res.body.autoChainStopped).toBe(true);
    expect((await chats.load(CASE)).autoChainStopped).toBe(true);
    expect(await audits(activity)).toEqual(["Stopped the Auto chain until the next analyst message"]);
  });
});
