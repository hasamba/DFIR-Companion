// #2890 end to end: the Import button (routes/import.ts) and the Velociraptor external import
// (composition/veloExternalIngest.ts) used to swallow a settle that failed after stamping — the rows
// never reached the super-timeline or the tagger, and the next import's case-wide demote moved them
// out untagged. Now each logs a WARN and settles its rows by stored name inside its import section.
// Real importers, so the selector is checked against the stored name the importer really stamps.
import { describe, it, expect, afterEach, vi } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { ForensicGateControlStore } from "../../src/analysis/forensicGateControl.js";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
import { getServerLogger } from "../../src/logging/serverLogger.js";
import type { VelociraptorRunResult } from "../../src/integrations/velociraptor/velociraptorApi.js";
import { veloServerClients } from "../helpers/serverClientsStub.js";
import { pollFor, POLL_TIMEOUT_MS } from "../helpers/poll.js";

const TS = "2023-01-02T10:00:00.000Z";
const HUNT = [
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
            Computer: "WS-01.example.test",
            TimeCreated: { "#attributes": { SystemTime: TS } },
          },
          EventData: {
            UtcTime: TS.replace("T", " ").replace("Z", ""),
            Image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            CommandLine: "powershell.exe -nop -w hidden -enc SQBFAFgA",
            ParentImage: "C:\\Program Files\\Microsoft Office\\winword.exe",
          },
        },
      },
    },
    rule: { name: "Suspicious Encoded PowerShell", level: "high", tags: ["attack.t1059.001"] },
    timestamp: TS,
  },
];
const thor = (file: string) =>
  JSON.stringify({
    time: "2025-03-14T21:18:18Z",
    hostname: "WS-02",
    level: "Alert",
    module: "Filescan",
    message: "Malware file found",
    file,
  });
const UPLOADS = [
  { name: "thor-a.json", clientId: "C.1", content: thor("C:\\Tools\\a.exe") },
  { name: "thor-b.json", clientId: "C.2", content: thor("C:\\Tools\\b.exe") },
];
const MFT_ROW = { OSPath: "C:\\evil.exe", Created0x10: "2026-06-01T00:00:00Z", FileName: "evil.exe" };

afterEach(() => {
  vi.restoreAllMocks();
});

async function makeApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-settle-recovery-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const superTimelineStore = new SuperTimelineStore(store);
  const pipeline = buildRuntimePipeline({
    provider: undefined,
    synthesisProvider: undefined,
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const client = {
    async getHuntArtifacts() {
      return ["Windows.NTFS.MFT"];
    },
    async huntResultsByArtifact() {
      return { results: { "Windows.NTFS.MFT": [MFT_ROW] }, skipped: [] };
    },
    async huntArtifactRows(): Promise<VelociraptorRunResult> {
      return { rows: [MFT_ROW], total: 1, truncated: false };
    },
    async getFlowInfo() {
      return { artifacts: ["Windows.NTFS.MFT"], hostname: "DESKTOP-01" };
    },
    async collectionResults(): Promise<VelociraptorRunResult> {
      return { rows: [MFT_ROW], total: 1, truncated: false };
    },
    huntGuiUrlFor() {
      return undefined;
    },
    flowGuiUrlFor() {
      return undefined;
    },
    async huntUploads() {
      return UPLOADS;
    },
  };
  const app = createApp(store, {
    pipeline,
    stateStore,
    superTimelineStore,
    importMetaStore: new ImportMetaStore(store),
    forensicGateControlStore: new ForensicGateControlStore(store),
    serverClients: veloServerClients(client),
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, stateStore, superTimelineStore };
}

/** Fail the first page read of already-stamped rows: the settle's dual-write, AFTER the stamp. */
function failAfterStamp(stateStore: StateStore): void {
  const real = stateStore.forensicRowsById.bind(stateStore);
  let failed = false;
  vi.spyOn(stateStore, "forensicRowsById").mockImplementation(async (caseId, ids) => {
    const rows = await real(caseId, ids);
    if (!failed && rows.length && rows.every((r) => r.event.importBatchId)) {
      failed = true;
      throw new Error("out of memory");
    }
    return rows;
  });
}

async function superIds(superStore: SuperTimelineStore): Promise<string[]> {
  const ids: string[] = [];
  for await (const b of superStore.eventBatches("c1")) for (const e of b) ids.push(e.id);
  return ids;
}

describe("a settle that fails after stamping is recovered (#2890)", () => {
  it(
    "Import button: the imported row still reaches the super-timeline, stamped",
    async () => {
      const { app, stateStore, superTimelineStore } = await makeApp();
      failAfterStamp(stateStore);
      const warn = vi.spyOn(getServerLogger(), "warn");
      const res = await request(app)
        .post("/cases/c1/import")
        .send({ filename: "hunt.json", text: JSON.stringify(HUNT) });
      expect(res.status).toBe(202);
      const file = String(res.body.file);
      await pollFor(
        () => `the recovery WARN for ${file}`,
        async () =>
          warn.mock.calls.some(([m]) => String(m).includes(`settled 1 row(s) of ${file} whose settle failed`))
            ? true
            : undefined,
      );
      const rows = (await stateStore.load("c1")).forensicTimeline;
      expect(rows).toHaveLength(1);
      expect(rows[0].sourceScreenshots).toContain(file); // what the recovery selects by
      expect(rows[0].importBatchId).toEqual(expect.any(String));
      expect(await superIds(superTimelineStore)).toEqual([rows[0].id]);
    },
    POLL_TIMEOUT_MS * 2,
  );

  it("Velociraptor external import: the map's rows still reach the super-timeline", async () => {
    const { app, stateStore, superTimelineStore } = await makeApp();
    failAfterStamp(stateStore);
    const warn = vi.spyOn(getServerLogger(), "warn");
    const res = await request(app).post("/cases/c1/velociraptor/import-external").send({ ref: "H.ABC" });
    expect(res.status).toBe(200);
    const lines = warn.mock.calls.map(([m]) => String(m));
    expect(lines.some((l) => /\[velociraptor\] c1: settle failed: out of memory/.test(l))).toBe(true);
    expect(lines.some((l) => /settled [1-9]\d* row\(s\) of .* whose settle failed/.test(l))).toBe(true);
    const sup = await superIds(superTimelineStore);
    expect(sup.length).toBeGreaterThan(0);
    for (const e of (await stateStore.load("c1")).forensicTimeline) {
      expect(e.importBatchId).toEqual(expect.any(String));
      expect(sup).toContain(e.id);
    }
  });

  it("Velociraptor uploads-only import: EVERY upload's rows are recovered, not just the last one's", async () => {
    const { app, stateStore, superTimelineStore } = await makeApp();
    failAfterStamp(stateStore);
    const warn = vi.spyOn(getServerLogger(), "warn");
    const res = await request(app)
      .post("/cases/c1/velociraptor/import-external")
      .send({ ref: "https://velo.example/app/index.html?org_id=root#/hunts/H.ABC/uploads" });
    expect(res.status).toBe(200);
    expect(res.body.imported).toEqual(["thor-a.json", "thor-b.json"]);
    const rows = (await stateStore.load("c1")).forensicTimeline;
    const sources = new Set(rows.flatMap((e) => e.sourceScreenshots));
    expect([...sources].filter((s) => /thor-[ab]/.test(s))).toHaveLength(2); // both uploads' rows
    const sup = await superIds(superTimelineStore);
    for (const e of rows) {
      expect(e.importBatchId).toEqual(expect.any(String));
      expect(sup).toContain(e.id);
    }
    expect(warn.mock.calls.some(([m]) => /settled 2 row\(s\) of .*thor-a.*thor-b/.test(String(m)))).toBe(
      true,
    );
  });
});
