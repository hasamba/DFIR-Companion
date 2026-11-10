import { mkdtemp, readdir, readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { CustomEntitiesStore } from "../../src/analysis/anonEntities.js";
import { AnonControlStore } from "../../src/analysis/anonControl.js";
import { DiscoveredEntitiesStore } from "../../src/analysis/anonDiscovered.js";
import { PresidioPendingStore } from "../../src/analysis/presidioPending.js";
import { PlaybookStore } from "../../src/analysis/playbookStore.js";
import { PlaybookHuntStore } from "../../src/analysis/playbookHuntStore.js";
import { PlaybookControlStore } from "../../src/analysis/playbookControl.js";
import { VelociraptorClientStore } from "../../src/analysis/velociraptorClientStore.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import type { PresidioClient } from "../../src/analysis/presidio.js";
import { createApp } from "../../src/server.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import {
  VelociraptorClient,
  type VelociraptorApiConfig,
  type VqlRunner,
} from "../../src/integrations/velociraptor/velociraptorApi.js";
import type { AIProvider, AnalyzeRequest, AnalyzeResult } from "../../src/providers/provider.js";
import { veloServerClients } from "../helpers/serverClientsStub.js";
import { storedImportName } from "../../src/routes/importCommit.js";

// #2515 — the AI preview now covers import-time extraction (the chosen file), playbook hunts (built
// from the STORED fleet inventory, no refresh) and the two decision-model (Jev) requests. Each test
// previews first (nothing sent, nothing in the cases root changes), then runs the REAL route and
// compares the first request it sends with what the preview showed.

const HOST = "ACME-WS42";
const USER = "jdoe-secret";

class Recording implements AIProvider {
  readonly name = "rec";
  readonly model = "m";
  readonly sent: AnalyzeRequest[] = [];
  async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
    this.sent.push(req);
    throw new Error("recording provider: stop after the first request");
  }
}

const ev = (id: string, over: Partial<ForensicEvent> = {}): ForensicEvent => ({
  id,
  timestamp: "2026-06-01T00:00:00Z",
  description: `webshell write on ${HOST} by ${USER}`,
  severity: "High",
  mitreTechniques: [],
  relatedFindingIds: ["f1"],
  sourceScreenshots: [],
  asset: HOST,
  ...over,
});

const veloCfg: VelociraptorApiConfig = {
  apiConfigPath: "/x/api.yaml",
  binary: "velociraptor",
  timeoutMs: 5000,
  maxRows: 1000,
  maxOutputBytes: 1024 * 1024,
  guiUrl: "https://velo.example/",
};

interface HarnessOpts {
  readonly velo?: boolean;
  readonly storedInventory?: boolean;
  readonly presidio?: PresidioClient;
}

async function harness(opts: HarnessOpts = {}) {
  const root = await mkdtemp(join(tmpdir(), "dfir-ai-preview-more-"));
  const store = new CaseStore(root);
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(store);
  const state = emptyState("c1");
  state.forensicTimeline = [ev("e1")];
  state.findings = [
    {
      id: "f1",
      severity: "Critical",
      title: `Webshell on ${HOST}`,
      description: `ASPX webshell dropped by ${USER}`,
      relatedEventIds: ["e1"],
      relatedIocs: [],
      mitreTechniques: ["T1505.003"],
      sourceScreenshots: [],
      firstSeen: "",
      lastUpdated: "",
      status: "open",
    },
  ];
  await stateStore.save(state);
  const superTimelineStore = new SuperTimelineStore(store);
  await superTimelineStore.append("c1", [
    ev("raw1", { severity: "Info", description: `certutil -urlcache on ${HOST} by ${USER}` }),
    ev("raw2", { severity: "Info", description: `reg query on ${HOST}` }),
  ]);
  await superTimelineStore.query("c1", {}); // opened once: storage upkeep done
  const customEntitiesStore = new CustomEntitiesStore(store);
  await customEntitiesStore.save("c1", [
    { value: HOST, category: "HOST" },
    { value: USER, category: "USER" },
  ]);
  const presidioPendingStore = new PresidioPendingStore(store);

  const vqlCalls: string[] = [];
  const runner: VqlRunner = async (statements) => {
    vqlCalls.push(statements[0]);
    if (statements[0].includes("FROM clients("))
      return { rows: [{ client_id: "C.ws42", os_info: { hostname: HOST.toLowerCase() } }], raw: "" };
    if (statements[0].includes("artifact_definitions("))
      return { rows: [{ name: "Windows.System.Pslist", type: "client" }], raw: "" };
    return { rows: [], raw: "" };
  };
  const velo = opts.velo ? new VelociraptorClient(veloCfg, runner) : undefined;
  const inventory = new VelociraptorClientStore(join(root, "velociraptor", "clients-stub.json"));
  if (velo && opts.storedInventory) {
    await inventory.save(await velo.listClients(), "2026-11-01T08:00:00.000Z");
    await velo.listClientArtifacts(); // the server already fetched its catalog once
  }
  vqlCalls.length = 0;

  const provider = new Recording();
  const pipeline = new AnalysisPipeline({
    provider,
    synthesisProvider: provider,
    stateStore,
    superTimelineStore,
    anonStore: new AnonControlStore(store),
    customEntitiesStore,
    discoveredStore: new DiscoveredEntitiesStore(store),
    presidioPendingStore,
    velociraptorClientStore: inventory,
    retries: 0,
    backoffMs: 0,
    imageLoader: async () => ({ base64: "", mimeType: "image/webp" }),
    ...(opts.presidio
      ? { presidio: { client: opts.presidio, url: "http://presidio.test", minScore: 0.5 } }
      : {}),
  });
  const app = createApp(store, {
    pipeline,
    stateStore,
    superTimelineStore,
    playbookStore: new PlaybookStore(store),
    playbookHuntStore: new PlaybookHuntStore(store),
    playbookControlStore: new PlaybookControlStore(store),
    velociraptorClientStore: inventory,
    clientInventoryFor: () => inventory,
    ...(velo ? { serverClients: veloServerClients(velo) } : {}),
  });
  return { root, store, app, provider, presidioPendingStore, vqlCalls, pipeline };
}

/** Every file under the cases root by content hash; -shm and an empty -wal are not data. */
async function snapshot(dir: string): Promise<Record<string, string>> {
  const out: Record<string, string> = {};
  for (const entry of await readdir(dir, { withFileTypes: true, recursive: true })) {
    if (!entry.isFile() || entry.name.endsWith("-shm")) continue;
    const path = join(entry.parentPath, entry.name);
    const bytes = await readFile(path);
    if (entry.name.endsWith("-wal") && bytes.length === 0) continue;
    out[path] = createHash("sha256").update(bytes).digest("hex");
  }
  return out;
}

async function preview(h: Awaited<ReturnType<typeof harness>>, action: string, params: object = {}) {
  const before = await snapshot(h.root);
  const res = await request(h.app).post("/cases/c1/ai-preview").send({ action, params });
  expect(await snapshot(h.root)).toEqual(before); // nothing in the cases root changed
  expect(h.provider.sent).toHaveLength(0); // nothing was sent
  expect(await h.presidioPendingStore.load("c1")).toEqual([]);
  return res;
}

/** Every real call below is awaited, so its first request is already recorded. */
async function firstSent(provider: Recording): Promise<AnalyzeRequest> {
  expect(provider.sent.length).toBeGreaterThan(0);
  return provider.sent[0];
}

const CSV = `Time,Host,User,Command\n2026-06-01T00:00:00Z,${HOST},${USER},whoami\n2026-06-01T00:01:00Z,${HOST},${USER},net use\n`;
const LOG = `2026-06-01T00:00:00Z sshd[1]: Failed password for ${USER} from 10.9.8.7 on ${HOST}\n`;

describe("AI preview — import-time extraction of a chosen file (#2515)", () => {
  it("CSV: shows the first batch as the real import would send it, and imports nothing", async () => {
    const h = await harness();
    const res = await preview(h, "extract-csv", { text: CSV, fileName: "edr export.csv" });
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.outcome).toBe("captured");
    const call = res.body.call;
    expect(call.clearPrompt).toContain(HOST);
    expect(call.maskedPrompt).not.toContain(HOST);
    expect(call.maskedPrompt).not.toContain(USER);
    expect(call.notes.join(" ")).toMatch(/would be stored under/);
    expect(res.body.multiRequest).toMatch(/first batch/);

    // The label is the stored name the real import route gives this file: the number it reserves next.
    const label = storedImportName(await h.store.nextImportSeq("c1"), "edr export.csv", "import.csv");
    expect(label).toBe("0001_edr_export.csv");
    expect(call.notes.join(" ")).toContain(label);
    await h.pipeline
      .analyzeCsv("c1", CSV, { label, idPrefix: "m1", importedAt: new Date().toISOString() })
      .catch(() => undefined);
    const sent = await firstSent(h.provider);
    expect(call.maskedPrompt).toBe(sent.userPrompt);
    expect(call.systemPrompt).toBe(sent.systemPrompt);
  });

  it("log: parity with the real import, and no truncation warning is left for the next import", async () => {
    const h = await harness();
    const res = await preview(h, "extract-log", { text: LOG, fileName: "auth.log" });
    expect(res.body.outcome).toBe("captured");
    expect(h.pipeline.consumeImportTruncation("c1")).toBeUndefined();
    const label = storedImportName(await h.store.nextImportSeq("c1"), "auth.log", "import.log");
    await h.pipeline
      .analyzeLog("c1", LOG, { label, idPrefix: "l1", importedAt: new Date().toISOString() })
      .catch(() => undefined);
    const sent = await firstSent(h.provider);
    expect(res.body.call.maskedPrompt).toBe(sent.userPrompt);
  });

  it("an empty CSV is refused with the real route's reason", async () => {
    const h = await harness();
    const res = await request(h.app)
      .post("/cases/c1/ai-preview")
      .send({ action: "extract-csv", params: { text: "a,b\n" } });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/no data rows/);
  });

  it("the whole-import Presidio pre-scan is reported, and no approval is saved", async () => {
    const presidio: PresidioClient = {
      analyze: async () => [{ entityType: "PERSON", score: 0.99, value: "Zed Quill" }],
    };
    const h = await harness({ presidio });
    const res = await preview(h, "extract-csv", { text: CSV, fileName: "x.csv" });
    expect(res.body.call.presidio.state).toBe("would-hold");
    expect(res.body.call.presidio.held.map((e: { value: string }) => e.value)).toContain("Zed Quill");
  });

  it("an unreachable Presidio is the real import's stop, reported — not a crash", async () => {
    const presidio: PresidioClient = {
      analyze: async () => {
        throw new Error("ECONNREFUSED");
      },
    };
    const h = await harness({ presidio });
    const res = await preview(h, "extract-csv", { text: CSV, fileName: "x.csv" });
    expect(res.body.call.presidio.state).toBe("scan-failed");
  });

  it("screenshot: the chosen image, one-image window, as the vision model would get it", async () => {
    const h = await harness();
    const res = await preview(h, "extract-screenshot", {
      imageBase64: "data:image/png;base64,iVBORw0KGgo=",
      mimeType: "image/png",
      fileName: "velo.png",
      tabTitle: `Velociraptor — ${HOST}`,
      url: "https://velo.example/app",
    });
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    const call = res.body.call;
    expect(call.clearPrompt).toContain(`Velociraptor — ${HOST}`);
    expect(call.maskedPrompt).not.toContain(HOST);
    expect(call.images).toEqual([{ index: 0, mimeType: "image/png", handling: "sent-as-is" }]);
    expect(call.notes.join(" ")).toMatch(/Single-image preview/);
  });

  it("screenshot: a non-image file is refused", async () => {
    const h = await harness();
    const res = await request(h.app)
      .post("/cases/c1/ai-preview")
      .send({ action: "extract-screenshot", params: { imageBase64: "AAAA", mimeType: "text/plain" } });
    expect(res.status).toBe(400);
  });
});

describe("AI preview — playbook hunts, built from the stored fleet inventory (#2515)", () => {
  it("makes no Velociraptor call, saves nothing, names the inventory's time — and matches the real run", async () => {
    const h = await harness({ velo: true, storedInventory: true });
    const res = await preview(h, "playbook-hunts");
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.outcome).toBe("captured");
    expect(h.vqlCalls).toEqual([]); // no fleet refresh, no artifact fetch
    const notes = res.body.call.notes.join(" ");
    expect(notes).toMatch(/fleet inventory stored at 2026-11-01 08:00 UTC/);
    expect(notes).toMatch(/artifact list is the one fetched at/);
    expect(res.body.call.maskedPrompt).toContain("Windows.System.Pslist");
    expect(res.body.call.maskedPrompt).not.toContain(HOST);

    await request(h.app).post("/cases/c1/playbook/suggest-hunts").send({});
    const sent = await firstSent(h.provider);
    // Same fleet and catalog as stored: the real run's prompt is the preview's.
    expect(res.body.call.maskedPrompt).toBe(sent.userPrompt);
  });

  it("says plainly when no fleet inventory is stored and no artifact list was fetched", async () => {
    const h = await harness({ velo: true });
    const res = await preview(h, "playbook-hunts");
    const notes = res.body.call.notes.join(" ");
    expect(notes).toMatch(/No Velociraptor fleet inventory is stored for this case yet/);
    expect(notes).toMatch(/No Velociraptor artifact list has been fetched/);
    expect(h.vqlCalls).toEqual([]);
  });

  it("a case with no Velociraptor server says the real run refreshes nothing either", async () => {
    const h = await harness();
    const res = await preview(h, "playbook-hunts");
    expect(res.body.call.notes.join(" ")).toMatch(/no Velociraptor server/);
  });
});

describe("AI preview — the decision-model requests (#2515)", () => {
  const ENV = ["DFIR_JEV_ENABLED", "DFIR_JEV_KEY", "DFIR_JEV_BASE_URL", "DFIR_ANONYMIZE"] as const;
  const saved: Record<string, string | undefined> = {};
  let jev: ReturnType<typeof createServer>;
  let bodies: string[];

  beforeEach(async () => {
    for (const k of ENV) saved[k] = process.env[k];
    delete process.env.DFIR_ANONYMIZE;
    bodies = [];
    jev = createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        bodies.push(body);
        res.writeHead(400, { "content-type": "application/json" });
        res.end("{}");
      });
    });
    await new Promise<void>((resolve) => jev.listen(0, "127.0.0.1", resolve));
    process.env.DFIR_JEV_ENABLED = "1";
    process.env.DFIR_JEV_KEY = "jev-test-credential-NOTAREALKEY";
    process.env.DFIR_JEV_BASE_URL = `http://127.0.0.1:${(jev.address() as AddressInfo).port}/decisions`;
  });

  afterEach(async () => {
    for (const k of ENV) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
    await new Promise<void>((resolve) => jev.close(() => resolve()));
  });

  it("review: the first batch's masked state is the body the real review sends; clear view is the same rows", async () => {
    const h = await harness();
    const res = await preview(h, "jev-review");
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(bodies).toHaveLength(0); // nothing reached the decision model
    const call = res.body.call;
    expect(call.provider).toBe("jev");
    const masked = JSON.parse(call.maskedPrompt);
    const clear = JSON.parse(call.clearPrompt);
    expect(Object.keys(clear.rows)).toEqual(Object.keys(masked.rows));
    expect(call.clearPrompt).toContain(HOST);
    expect(call.maskedPrompt).not.toContain(HOST);

    await request(h.app).post("/cases/c1/jev/review").send({});
    expect(bodies.length).toBeGreaterThan(0);
    const wire = JSON.parse(bodies[0]);
    expect(masked).toEqual(wire.state);
    expect(JSON.parse(call.systemPrompt)).toEqual(wire.questions);
  });

  it("review: honours the same limit the review route reads", async () => {
    const h = await harness();
    const res = await preview(h, "jev-review", { limit: 1 });
    expect(Object.keys(JSON.parse(res.body.call.maskedPrompt).rows)).toHaveLength(1);
    await request(h.app).post("/cases/c1/jev/review").send({ limit: 1 });
    expect(JSON.parse(res.body.call.maskedPrompt)).toEqual(JSON.parse(bodies[0]).state);
  });

  it("containment check: parity with the real check's body, and a missing finding is the real error", async () => {
    const h = await harness();
    const res = await preview(h, "containment-check", { findingId: "f1" });
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(bodies).toHaveLength(0);
    const call = res.body.call;
    expect(call.clearPrompt).toContain(HOST);
    expect(call.maskedPrompt).not.toContain(HOST);
    await request(h.app).post("/cases/c1/findings/f1/containment-check").send({});
    const wire = JSON.parse(bodies[0]);
    expect(JSON.parse(call.maskedPrompt)).toEqual(wire.state);
    expect(Object.keys(JSON.parse(call.clearPrompt).events)).toEqual(Object.keys(wire.state.events));

    const missing = await request(h.app)
      .post("/cases/c1/ai-preview")
      .send({ action: "containment-check", params: { findingId: "nope" } });
    expect(missing.status).toBe(409);
    expect(missing.body.error).toMatch(/not found/);
  });

  it("needs the decision model, not the chat model: unconfigured Jev is a plain 400", async () => {
    delete process.env.DFIR_JEV_ENABLED;
    delete process.env.DFIR_JEV_KEY;
    const h = await harness();
    const res = await request(h.app)
      .post("/cases/c1/ai-preview")
      .send({ action: "containment-check", params: { findingId: "f1" } });
    expect(res.status).toBe(400);
  });
});
