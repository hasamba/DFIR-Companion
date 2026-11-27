import { describe, it, expect } from "vitest";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Buffer } from "node:buffer";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { NotificationConfigStore } from "../../src/analysis/notificationStore.js";
import { createNotifier } from "../../src/integrations/notify/notifyDispatch.js";
import { loadToolConfig, type ToolId, type ToolConfig } from "../../src/integrations/tools/toolConfig.js";
import type { ToolRunner } from "../../src/integrations/tools/toolRunner.js";
import { POLL_TIMEOUT_MS, pollFor } from "../helpers/poll.js";

// #3036 — a dashboard run of a local (spawn) tool sends one "Import finished" / "Import failed"
// message per run, through the same case notifier as every other import. Synthetic data only.

const RAW_EVTX = Buffer.from([0x45, 0x6c, 0x66, 0x46, 0x69, 0x6c, 0x65, 0x00, 0xff, 0xfe]);

const HAYABUSA_CSV = [
  "Timestamp,RuleTitle,Level,Computer,Channel,EventID,RecordID,Details",
  "2026-05-26 12:00:00.000 +00:00,Suspicious Logon,high,WS-EXAMPLE-01,Security,4624,884213,TgtUser: bob",
].join("\n");

function hayabusaCfg(): Map<ToolId, ToolConfig> {
  const cfg = loadToolConfig("hayabusa", { DFIR_TOOL_HAYABUSA_BINARY: "/opt/hayabusa" })!;
  return new Map<ToolId, ToolConfig>([["hayabusa", cfg]]);
}

const okRunner: ToolRunner = async (_binary, args) => {
  if (args.includes("--version")) return { stdout: "Hayabusa v3.2.0", stderr: "", code: 0 };
  await writeFile(args[args.indexOf("-o") + 1], HAYABUSA_CSV, "utf8");
  return { stdout: "", stderr: "", code: 0 };
};

const failingRunner: ToolRunner = async (_binary, args) => {
  if (args.includes("--version")) return { stdout: "Hayabusa v3.2.0", stderr: "", code: 0 };
  return { stdout: "", stderr: "synthetic parser crash", code: 2 };
};

async function harness(runner: ToolRunner) {
  const root = await mkdtemp(join(tmpdir(), "dfir-toolnotify-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const notificationStore = new NotificationConfigStore(join(root, "notifications", "config.json"));
  const bodies: string[] = [];
  const fetchFn = (async (_u: string, init?: { body?: unknown }) => {
    bodies.push(String(init?.body ?? ""));
    return new Response("ok", { status: 200 });
  }) as typeof fetch;
  const app = createApp(store, {
    pipeline: buildRuntimePipeline({
      provider: undefined,
      synthesisProvider: undefined,
      stateStore,
      store,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    }),
    stateStore,
    toolRunner: runner,
    loadToolConfigs: hayabusaCfg,
    notificationStore,
    notifier: createNotifier({ store: notificationStore, fetchFn }),
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  await request(app)
    .post("/notifications")
    .send({ type: "slack", webhookUrl: "https://hooks.slack.com/services/T/B/tools" });
  const importMessages = (): string[] => bodies.filter((b) => /Import (finished|failed)/.test(b));
  return { app, store, importMessages };
}

const settle = (): Promise<void> => new Promise((r) => setTimeout(r, 300));

describe("a dashboard tool run's import message (#3036)", { timeout: POLL_TIMEOUT_MS * 3 }, () => {
  it("an uploaded file run through a local tool sends one Import finished message", async () => {
    const h = await harness(okRunner);
    const r = await request(h.app)
      .post("/cases/c1/tools/hayabusa/run-upload")
      .send({ filename: "Security.evtx", dataBase64: RAW_EVTX.toString("base64") });
    expect(r.status).toBe(200);
    const sent = await pollFor("the import message", async () => {
      const hits = h.importMessages();
      return hits.length ? hits : undefined;
    });
    await settle();
    expect(h.importMessages()).toHaveLength(1);
    expect(sent[0]).toContain("Import finished");
    expect(sent[0]).toContain("Hayabusa");
    expect(sent[0]).toContain("Security.evtx");
    // The settled diff's real counts: the fixture's one High row (#3038), never "not available".
    expect(sent[0]).toContain("Forensic timeline: +1 event (1 High/Critical)");
    expect(sent[0]).not.toContain("Event counts are not available");
  });

  it("a tool run that fails sends one Import failed message with the reason", async () => {
    const h = await harness(failingRunner);
    const r = await request(h.app)
      .post("/cases/c1/tools/hayabusa/run-upload")
      .send({ filename: "Security.evtx", dataBase64: RAW_EVTX.toString("base64") });
    expect(r.status).toBe(400);
    const sent = await pollFor("the import message", async () => {
      const hits = h.importMessages();
      return hits.length ? hits : undefined;
    });
    await settle();
    expect(h.importMessages()).toHaveLength(1);
    expect(sent[0]).toContain("Import failed");
    expect(sent[0]).toContain("Security.evtx");
  });

  it("a run against a file already in the case sends one message", async () => {
    const h = await harness(okRunner);
    const dir = join(h.store.caseDir("c1"), "raw");
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, "System.evtx"), RAW_EVTX);
    const r = await request(h.app).post("/cases/c1/tools/hayabusa/run").send({ path: "raw/System.evtx" });
    expect(r.status).toBe(200);
    await pollFor("the import message", async () => (h.importMessages().length ? true : undefined));
    await settle();
    expect(h.importMessages()).toHaveLength(1);
    expect(h.importMessages()[0]).toContain("System.evtx");
    expect(h.importMessages()[0]).toContain("Forensic timeline: +1 event (1 High/Critical)");
  });

  it("a request refused before any run sends nothing", async () => {
    const h = await harness(okRunner);
    const r = await request(h.app)
      .post("/cases/c1/tools/hayabusa/run-upload")
      .send({ filename: "notes.txt", dataBase64: RAW_EVTX.toString("base64") });
    expect(r.status).toBe(400);
    await settle();
    expect(h.importMessages()).toHaveLength(0);
  });
});
