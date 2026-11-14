import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { ActivityLogStore } from "../../src/analysis/activityLog.js";
import { WatsonChatStore } from "../../src/analysis/ai/watson/chatStore.js";
import type { WatsonVeloLaunchProposal } from "../../src/analysis/ai/watson/types.js";
import { launchFingerprints } from "../../src/analysis/ai/watson/velo/fingerprintIndex.js";
import { HuntOutcomeStore } from "../../src/analysis/huntOutcomeStore.js";
import { StateLock } from "../../src/analysis/stateLock.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import { VeloHuntStore } from "../../src/analysis/veloHuntStore.js";
import {
  VelociraptorClient,
  type VelociraptorApiConfig,
  type VqlRunner,
} from "../../src/integrations/velociraptor/velociraptorApi.js";
import { createApp } from "../../src/server.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import { veloServerClients } from "../helpers/serverClientsStub.js";

// Watson phase 3, Task 4: an approved velo_launch proposal launches through the same deploy path
// as the analyst's Deploy button (routes/veloDeploy.ts), exactly once, with source "watson".

const CASE = "c1";
const PSLIST = "SELECT * FROM pslist()";
const HOST = "web01.example.com";
const CLIENT = "C.webserver1";
const CLIENTS = [{ clientId: CLIENT, hostname: HOST, fqdn: HOST }];

const veloCfg: VelociraptorApiConfig = {
  apiConfigPath: "/x/api.yaml",
  binary: "velociraptor",
  timeoutMs: 5000,
  maxRows: 1000,
  maxOutputBytes: 1024 * 1024,
};

async function harness(opts: { failLaunch?: boolean } = {}) {
  const store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-velo-deploy-")));
  await store.createCase({ caseId: CASE, name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(store);
  await stateStore.save(emptyState(CASE));
  const launches: string[] = [];
  const runner: VqlRunner = async (statements) => {
    const p = statements[0];
    if (p.includes("hunt(") && p.includes("artifacts=")) {
      launches.push("hunt");
      if (opts.failLaunch) throw new Error("Velociraptor timed out");
      return { rows: [{ Hunt: { HuntId: "H.SAMPLE1", state: "RUNNING" } }], raw: "" };
    }
    if (p.includes("collect_client(")) {
      launches.push("collection");
      return { rows: [{ Flow: { flow_id: "F.SAMPLE1" } }], raw: "" };
    }
    return { rows: [], raw: "" };
  };
  const chatStore = new WatsonChatStore(store);
  const activity = new ActivityLogStore(store);
  const outcomes = new HuntOutcomeStore(store);
  const inventory = { load: async () => ({ updatedAt: "", clients: CLIENTS }) };
  const app = createApp(store, {
    stateStore,
    stateLock: new StateLock(),
    activityLogStore: activity,
    watsonChatStore: chatStore,
    huntOutcomeStore: outcomes,
    veloHuntStore: new VeloHuntStore(store),
    serverClients: veloServerClients(new VelociraptorClient(veloCfg, runner)),
    velociraptorClientStore: inventory,
    clientInventoryFor: (() => inventory) as never,
  });
  return { app, store, chatStore, activity, outcomes, launches };
}

function proposal(over: Partial<WatsonVeloLaunchProposal> = {}): WatsonVeloLaunchProposal {
  const host = over.mode === "collection" ? HOST : undefined;
  const keys = launchFingerprints(over.vql ?? PSLIST, host);
  return {
    id: "wp-1",
    turnId: "t1",
    kind: "velo_launch",
    status: "pending",
    targetId: keys[0],
    mode: "hunt",
    title: "Process listing",
    vql: PSLIST,
    fingerprint: keys[0],
    fingerprints: keys,
    ...(host ? { hostname: host } : {}),
    ...over,
  };
}

async function seed(chatStore: WatsonChatStore, p: WatsonVeloLaunchProposal) {
  await chatStore.update(CASE, (c) => ({ ...c, proposals: [...c.proposals, p] }));
}

const apply = (app: Parameters<typeof request>[0], pid = "wp-1") =>
  request(app).post(`/cases/${CASE}/watson/proposals/${pid}/apply`).send({});

describe("Watson velo_launch through the deploy path", () => {
  it("launches one fleet hunt with source watson and stores the hunt id", async () => {
    const h = await harness();
    await seed(h.chatStore, proposal());
    const res = await apply(h.app);
    expect(res.status).toBe(200);
    expect(h.launches).toEqual(["hunt"]);
    const p = res.body.chat.proposals[0];
    expect(p.status).toBe("applied");
    expect(p.launched.huntId).toBe("H.SAMPLE1");
    const [outcome] = await h.outcomes.load(CASE);
    expect(outcome).toMatchObject({ source: "watson", huntId: "H.SAMPLE1", title: "Process listing" });
    const actions = (await h.activity.load(CASE)).map((e) => e.action);
    expect(actions).toEqual(expect.arrayContaining(["deploy-hunt", "watson.apply"]));
  });

  it("answers 409 to a second apply and launches nothing more", async () => {
    const h = await harness();
    await seed(h.chatStore, proposal());
    await apply(h.app);
    expect((await apply(h.app)).status).toBe(409);
    expect(h.launches).toHaveLength(1);
  });

  it("launches a single-host collection and records its flow, client and server set", async () => {
    const h = await harness();
    await seed(h.chatStore, proposal({ mode: "collection" }));
    const res = await apply(h.app);
    expect(res.status).toBe(200);
    expect(h.launches).toEqual(["collection"]);
    expect(res.body.chat.proposals[0].launched).toMatchObject({ flowId: "F.SAMPLE1", clientId: CLIENT });
    const [outcome] = await h.outcomes.load(CASE);
    expect(outcome).toMatchObject({
      source: "watson",
      flowId: "F.SAMPLE1",
      clientId: CLIENT,
      serverSetId: "stub",
    });
  });

  it("refuses a stored proposal whose VQL now fails the risk check, launching nothing", async () => {
    const h = await harness();
    await seed(h.chatStore, proposal({ vql: "SELECT * FROM execve(argv=['whoami'])" }));
    expect((await apply(h.app)).status).toBe(409);
    expect(h.launches).toHaveLength(0);
  });

  it("refuses apply and resolve on a frozen case", async () => {
    const h = await harness();
    await seed(h.chatStore, proposal({ status: "uncertain" }));
    await h.store.updateCaseMeta(CASE, { status: "closed" });
    expect((await apply(h.app)).status).toBe(423);
    const resolve = await request(h.app)
      .post(`/cases/${CASE}/watson/proposals/wp-1/resolve`)
      .send({ outcome: "launched" });
    expect(resolve.status).toBe(423);
    expect(h.launches).toHaveLength(0);
  });

  it("leaves a failed launch uncertain; the analyst can retry it", async () => {
    const h = await harness({ failLaunch: true });
    await seed(h.chatStore, proposal());
    const res = await apply(h.app);
    expect(res.status).toBe(409);
    expect(res.body.error).toMatch(/could not confirm/);
    expect((await h.chatStore.load(CASE)).proposals[0].status).toBe("uncertain");
    expect((await apply(h.app)).status).toBe(409); // never relaunched on its own
    expect(h.launches).toHaveLength(1);
    const bad = await request(h.app)
      .post(`/cases/${CASE}/watson/proposals/wp-1/resolve`)
      .send({ outcome: "x" });
    expect(bad.status).toBe(400);
    const retry = await request(h.app)
      .post(`/cases/${CASE}/watson/proposals/wp-1/resolve`)
      .send({ outcome: "retry" });
    expect(retry.status).toBe(200);
    expect(retry.body.chat.proposals[0].status).toBe("pending");
  });

  it("the analyst's own deploy-hunt collection now records its flow and client", async () => {
    const h = await harness();
    const res = await request(h.app)
      .post(`/cases/${CASE}/velociraptor/deploy-hunt`)
      .send({ vql: PSLIST, title: "ps", mode: "collection", hostname: HOST });
    expect(res.status).toBe(200);
    const [outcome] = await h.outcomes.load(CASE);
    expect(outcome).toMatchObject({ source: "fleet", flowId: "F.SAMPLE1", clientId: CLIENT });
  });
});
