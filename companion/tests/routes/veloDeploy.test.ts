import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { ActivityLogStore } from "../../src/analysis/activityLog.js";
import { AiControlStore } from "../../src/analysis/aiControl.js";
import { AiCostStore } from "../../src/analysis/aiCost.js";
import { AnonControlStore } from "../../src/analysis/anonControl.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import type { AIProvider, AnalyzeResult } from "../../src/providers/provider.js";
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

/** Watson's one reply: a collection on HOST (Auto mode tests). */
class CollectReply implements AIProvider {
  readonly name = "fake";
  readonly model = "fake-model";
  async analyze(): Promise<AnalyzeResult> {
    const request = {
      kind: "velociraptor",
      mode: "collection",
      hostname: HOST,
      title: "Process list",
      vql: PSLIST,
      why: "w",
    };
    const reply = {
      message: "Collecting.",
      workingOn: "",
      learned: "",
      questionUpdates: [],
      newQuestions: [],
    };
    return {
      rawText: JSON.stringify({ ...reply, request, search: null, memory: "" }),
      usage: { costUSD: 0.01 },
    };
  }
}

async function harness(opts: { failLaunch?: boolean; watson?: boolean } = {}) {
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
  const stateLock = new StateLock();
  const aiCostStore = new AiCostStore(store);
  const fake = new CollectReply();
  const watson = opts.watson
    ? {
        aiCostStore,
        watsonProvider: () => fake,
        pipeline: new AnalysisPipeline({
          provider: fake,
          synthesisProvider: fake,
          stateStore,
          stateLock,
          aiCostStore,
          anonStore: new AnonControlStore(store),
          retries: 0,
          velociraptorClientStore: inventory,
          imageLoader: async () => ({ base64: "", mimeType: "image/webp" }),
        }),
      }
    : {};
  const app = createApp(store, {
    ...watson,
    stateStore,
    stateLock,
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
  it("Auto mode launches Watson's collection; both audit entries name Watson (Auto) and who switched Auto on", async () => {
    const h = await harness({ watson: true });
    const control = new AiControlStore(h.store);
    await control.save(CASE, {
      ...(await control.load(CASE)),
      enabled: true,
      watsonRunMode: "auto",
      watsonAutoSince: "2026-11-14T07:30:00.000Z",
      watsonAutoBy: { name: "Robin Lead" },
    });
    const res = await request(h.app)
      .post(`/cases/${CASE}/watson/message`)
      .send({ text: "what runs on web01?" });
    expect(res.status).toBe(200);
    expect(h.launches).toEqual(["collection"]);
    const entries = await h.activity.load(CASE);
    const suffix = "Auto mode on since 2026-11-14T07:30:00.000Z, switched on by Robin Lead";
    const hunt = entries.filter((e) => e.category === "hunt");
    expect(hunt.length).toBeGreaterThan(0);
    for (const e of hunt) {
      expect(e.actor).toBe("Watson (Auto)");
      expect(e.detail).toContain(suffix);
    }
    const applied = entries.find((e) => e.action === "watson.apply");
    expect(applied).toMatchObject({ actor: "Watson (Auto)" });
    expect(applied?.detail).toContain(suffix);
  });

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

  it("refuses an analyst deploy-hunt that claims source watson", async () => {
    const h = await harness();
    const res = await request(h.app)
      .post(`/cases/${CASE}/velociraptor/deploy-hunt`)
      .send({ vql: PSLIST, title: "ps", source: "watson" });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("source watson is reserved for Watson");
    expect(h.launches).toHaveLength(0);
  });

  it("a Watson collection outcome is a live-state snapshot", async () => {
    const h = await harness();
    await seed(h.chatStore, proposal({ mode: "collection" }));
    expect((await apply(h.app)).status).toBe(200);
    const [outcome] = await h.outcomes.load(CASE);
    expect(outcome.coverage).toBe("snapshot");
  });

  it("resolving an uncertain launch as launched records a source watson outcome", async () => {
    const h = await harness({ failLaunch: true });
    await seed(h.chatStore, proposal());
    await apply(h.app);
    const res = await request(h.app)
      .post(`/cases/${CASE}/watson/proposals/wp-1/resolve`)
      .send({ outcome: "launched" });
    expect(res.status).toBe(200);
    const [outcome] = await h.outcomes.load(CASE);
    expect(outcome).toMatchObject({ source: "watson", title: "Process listing", status: "deployed" });
    expect(outcome.huntId).toBeUndefined();
    expect(outcome.vqlFingerprint).toBeTruthy();
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
