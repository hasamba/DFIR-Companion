import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtemp, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { StateLock } from "../../src/analysis/stateLock.js";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { ActivityLogStore } from "../../src/analysis/activityLog.js";
import { JobManager } from "../../src/analysis/jobManager.js";
import { ForensicGateControlStore } from "../../src/analysis/forensicGateControl.js";
import { WatsonChatStore } from "../../src/analysis/ai/watson/chatStore.js";
import { csSearchKey } from "../../src/analysis/ai/watson/crowdstrike/csLaunchCheck.js";
import type { WatsonCsSearchProposal } from "../../src/analysis/ai/watson/types.js";
import { pollFor } from "../helpers/poll.js";

// #2666 Part B: Watson's cs_search card -> Run -> the same siem-search job as the analyst's Run ->
// fake Falcon (injected fetch) -> evidence + CrowdStrike importer -> the card's outcome and one `hunt`
// case event for Watson. Synthetic rows only.

const ENV_KEYS = [
  "DFIR_CROWDSTRIKE_SIEM_CLIENT_ID",
  "DFIR_CROWDSTRIKE_SIEM_CLIENT_SECRET",
  "DFIR_CROWDSTRIKE_SIEM_BASE_URL",
];
const HOUR = 3_600_000;
const Q = `#event_simpleName=ProcessRollup2 | table([@timestamp, ComputerName, CommandLine], limit=100)`;
const ROWS = [
  {
    "@id": "r1",
    "@timestamp": Date.parse("2026-11-16T10:00:00.000Z"),
    ComputerName: "WS-09",
    ImageFileName: "\\Device\\HarddiskVolume3\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    CommandLine: "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AA==",
  },
];

function fakeFalcon() {
  const bodies: unknown[] = [];
  const fetchFn = (async (input: string | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    if (url.pathname === "/oauth2/token")
      return Response.json({ access_token: "tok", expires_in: 1799 }, { status: 201 });
    if (init?.method === "POST") {
      bodies.push(JSON.parse(String(init.body)));
      return Response.json({ id: "job1" });
    }
    if (init?.method === "DELETE") return new Response(null, { status: 204 });
    return Response.json({
      done: true,
      events: ROWS,
      metaData: { isAggregate: true, extraData: { hasMoreEvents: "false" } },
    });
  }) as typeof fetch;
  return { fetchFn, bodies };
}

describe("Watson's CrowdStrike search card end to end (#2666)", () => {
  const saved: Record<string, string | undefined> = {};
  beforeEach(() => {
    for (const k of ENV_KEYS) saved[k] = process.env[k];
    process.env.DFIR_CROWDSTRIKE_SIEM_CLIENT_ID = "siem-id";
    process.env.DFIR_CROWDSTRIKE_SIEM_CLIENT_SECRET = "siem-secret";
    process.env.DFIR_CROWDSTRIKE_SIEM_BASE_URL = "https://falcon.test";
  });
  afterEach(() => {
    for (const k of ENV_KEYS) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  });

  it("Run starts the search with the card's exact query, imports the rows and tells Watson once", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-watson-cs-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const chatStore = new WatsonChatStore(store);
    const jobManager = new JobManager();
    const f = fakeFalcon();
    const pipeline = buildRuntimePipeline({
      provider: undefined,
      synthesisProvider: undefined,
      stateStore,
      store,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });
    const app = createApp(store, {
      pipeline,
      stateStore,
      stateLock: new StateLock(),
      importMetaStore: new ImportMetaStore(store),
      superTimelineStore: new SuperTimelineStore(store),
      activityLogStore: new ActivityLogStore(store),
      forensicGateControlStore: new ForensicGateControlStore(store),
      watsonChatStore: chatStore,
      jobManager,
      crowdstrikeSiemFetch: f.fetchFn,
    });
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });

    const end = new Date(Math.floor((Date.now() - HOUR) / HOUR) * HOUR).toISOString();
    const start = new Date(Date.parse(end) - 2 * 24 * HOUR).toISOString();
    const card: WatsonCsSearchProposal = {
      id: "wp-cs",
      turnId: "wt-1",
      kind: "cs_search",
      status: "pending",
      targetId: csSearchKey(Q, "search-all", start, end),
      title: "Encoded PowerShell on WS-09",
      query: Q,
      start,
      end,
      repository: "search-all",
    };
    await chatStore.update("c1", (c) => ({
      ...c,
      turns: [
        { id: "wt-1", at: start, role: "watson", text: "Let me search Falcon.", proposalIds: ["wp-cs"] },
      ],
      proposals: [card],
    }));

    const res = await request(app).post("/cases/c1/watson/proposals/wp-cs/apply").send({});
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    const applied = res.body.chat.proposals[0] as WatsonCsSearchProposal;
    expect(applied.status).toBe("applied");
    expect(jobManager.get(applied.launched!.jobId)?.kind).toBe("siem-search");

    const done = await pollFor("the card's outcome", async () => {
      const p = (await chatStore.load("c1")).proposals[0] as WatsonCsSearchProposal;
      return p.watch?.notified ? p : undefined;
    });
    expect(f.bodies[0]).toMatchObject({ queryString: Q, start: Date.parse(start), end: Date.parse(end) });
    expect(done.watch).toMatchObject({ state: "finished", rows: 1 });
    const events = (await chatStore.load("c1")).pendingCaseEvents.filter((e) => e.kind === "hunt");
    expect(events).toHaveLength(1);
    expect(events[0].text).toContain(
      "Watson's CrowdStrike NG-SIEM search Encoded PowerShell on WS-09 finished. It found 1 row",
    );
    const files = await readdir(store.importsDir("c1"));
    expect(files.some((n) => n.includes("crowdstrike-ngsiem"))).toBe(true);
    const state = await stateStore.load("c1");
    expect(state.forensicTimeline.some((e) => e.sources?.includes("CrowdStrike NG-SIEM"))).toBe(true);
  });
});
