import { describe, it, expect } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
import { CustodyStore } from "../../src/analysis/custody.js";

// Regression #2055: POST /cases/:id/import-file copied the server file straight into imports/
// without going through CaseStore, so the stored evidence got no chain-of-custody record (no
// SHA-256 baseline, absent from the signed manifest and the report's custody appendix).

// One Chainsaw hunt detection — deterministic, no AI call.
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
            Computer: "WIN-TEST01",
            TimeCreated: { "#attributes": { SystemTime: "2023-01-02T10:00:00.000Z" } },
          },
          EventData: {
            UtcTime: "2023-01-02 10:00:00.000",
            Image: "C:\\Windows\\System32\\cmd.exe",
            CommandLine: "cmd.exe /c whoami",
            ParentImage: "C:\\Windows\\explorer.exe",
          },
        },
      },
    },
    rule: { name: "Test Rule", level: "high", tags: ["attack.execution"] },
    timestamp: "2023-01-02T10:00:00.000Z",
  },
];

async function makeApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-importfile-custody-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const pipeline = buildRuntimePipeline({
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, {
    pipeline,
    stateStore,
    importMetaStore: new ImportMetaStore(store),
    custodyStore: new CustodyStore(store),
  });
  return { app };
}

describe("POST /cases/:id/import-file — chain of custody (#2055)", () => {
  it("records the stored copy in custody with the source file's sha256", async () => {
    const { app } = await makeApp();
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const text = JSON.stringify(CHAINSAW_HUNT);
    const src = join(await mkdtemp(join(tmpdir(), "dfir-importfile-src-")), "hunt2055.json");
    await writeFile(src, text);

    const res = await request(app).post("/cases/c1/import-file").send({ path: src });
    expect(res.status).toBe(202);

    const custody = await request(app).get("/cases/c1/custody");
    expect(custody.status).toBe(200);
    const records = custody.body.records as Array<{ artifactPath: string; sha256: string }>;
    const stored = records.filter((r) => r.artifactPath.endsWith("0001_hunt2055.json"));
    expect(stored).toHaveLength(1);
    expect(stored[0]?.sha256).toBe(createHash("sha256").update(text).digest("hex"));
  });
});
