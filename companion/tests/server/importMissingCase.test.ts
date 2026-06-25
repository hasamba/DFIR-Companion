import { describe, it, expect } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";

// Regression: POST /cases/:id/import — evidence imported into a case that does not exist.
// Found by /qa on 2026-06-25.
// Report: .gstack/qa-reports/qa-report-127-0-0-1-2026-06-25.md
//
// The "Connect" toolbar action attaches to a case id WITHOUT creating it, so a typo'd or
// never-created id loads a blank dashboard. Importing evidence there used to return 202
// "accepted" (parity with the happy path) while silently orphaning the bytes on disk — the
// events never reached a persisted state, the case stayed 404 / invisible in the case list,
// and the analyst saw no error. That is silent loss of forensic evidence. POST /captures and
// GET /state already 404 a missing case; /import must do the same.

// A single Chainsaw hunt detection (Sigma rule matched on an embedded Sysmon process-create).
// Deterministic: the chainsaw importer maps it straight to one forensic event — no AI call.
const CHAINSAW_HUNT = [
  {
    group: "Sigma",
    kind: "individual",
    document: {
      kind: "evtx",
      path: "Sysmon.evtx",
      data: {
        Event: {
          System: {
            Provider: { "#attributes": { Name: "Microsoft-Windows-Sysmon" } },
            EventID: 1,
            Channel: "Microsoft-Windows-Sysmon/Operational",
            Computer: "WIN-DC01.corp.local",
            TimeCreated: { "#attributes": { SystemTime: "2023-01-02T10:00:00.000Z" } },
          },
          EventData: {
            UtcTime: "2023-01-02 10:00:00.000",
            Image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            CommandLine: "powershell.exe -nop -w hidden -enc SQBFAFgA",
            ParentImage: "C:\\Program Files\\Microsoft Office\\winword.exe",
          },
        },
      },
    },
    rule: {
      name: "Suspicious Encoded PowerShell Command Line",
      level: "high",
      tags: ["attack.execution", "attack.t1059.001"],
    },
    timestamp: "2023-01-02T10:00:00.000Z",
  },
];

async function makeApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-import-missing-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  // No-AI pipeline: deterministic importers populate the timeline without any model call.
  const pipeline = buildRuntimePipeline({
    provider: undefined, synthesisProvider: undefined, stateStore, store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, { pipeline, stateStore, importMetaStore: new ImportMetaStore(store) });
  return { app, store, stateStore };
}

async function waitForEvents(stateStore: StateStore, caseId: string): Promise<number> {
  for (let i = 0; i < 100; i++) {
    const s = await stateStore.load(caseId);
    if (s.forensicTimeline.length > 0) return s.forensicTimeline.length;
    await new Promise((r) => setTimeout(r, 20));
  }
  return (await stateStore.load(caseId)).forensicTimeline.length;
}

const body = { filename: "hunt.json", text: JSON.stringify(CHAINSAW_HUNT) };

describe("POST /cases/:id/import — case existence guard", () => {
  it("404s a valid import into a case that does not exist (no silent 202 / orphaned evidence)", async () => {
    const { app, store } = await makeApp();
    const res = await request(app).post("/cases/does-not-exist/import").send(body);
    expect(res.status).toBe(404);
    expect(res.body.error).toMatch(/does not exist/i);
    // And it must not have conjured the case as a side effect.
    expect(await store.caseExists("does-not-exist")).toBe(false);
    expect((await request(app).get("/cases/does-not-exist/state")).status).toBe(404);
  });

  it("still accepts the same import into an existing case (the guard does not break the happy path)", async () => {
    const { app, stateStore } = await makeApp();
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });

    const res = await request(app).post("/cases/c1/import").send(body);
    expect(res.status).toBe(202);
    expect(res.body).toMatchObject({ accepted: true, kind: "chainsaw" });

    // The deterministic import actually lands the event.
    expect(await waitForEvents(stateStore, "c1")).toBeGreaterThan(0);
  });

  it("404s a server-side import-file into a case that does not exist", async () => {
    const { app, store } = await makeApp();
    const dir = await mkdtemp(join(tmpdir(), "dfir-import-file-"));
    const path = join(dir, "hunt.json");
    await writeFile(path, JSON.stringify(CHAINSAW_HUNT), "utf8");

    const res = await request(app).post("/cases/does-not-exist/import-file").send({ path });
    expect(res.status).toBe(404);
    expect(res.body.error).toMatch(/does not exist/i);
    expect(await store.caseExists("does-not-exist")).toBe(false);
  });
});
