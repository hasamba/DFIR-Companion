import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { pollFor, POLL_TIMEOUT_MS } from "../helpers/poll.js";

// #776 — malfind rows must survive the CASE MERGE, not just the parser.
//
// Two layers can fold them and only the second one matters to the analyst. The aggregator keys on a
// region discriminator, so the parser keeps the rows apart. Correlation then unions events sharing a
// timestamp and a description — and malfind rows are undated — so any discriminator the aggregation
// key uses but the DESCRIPTION does not print gets undone at the merge, silently, with the count
// reset to 1 while the import note still reports the true number.
//
// Asserting on parseMemory's output cannot see this. These tests drive the real import route.

async function makeApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-malfind-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const importMetaStore = new ImportMetaStore(store);
  const superTimelineStore = new SuperTimelineStore(store);
  const pipeline = buildRuntimePipeline({
    provider: undefined,
    synthesisProvider: undefined,
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, { pipeline, stateStore, importMetaStore, superTimelineStore });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, stateStore, importMetaStore };
}

async function importRows(
  app: Awaited<ReturnType<typeof makeApp>>["app"],
  importMetaStore: ImportMetaStore,
  rows: object[],
): Promise<void> {
  const res = await request(app)
    .post("/cases/c1/import")
    .send({ filename: "malfind.json", text: JSON.stringify(rows) });
  expect(res.status).toBe(202);
  let seen = "";
  await pollFor(
    () => `import-meta to record '${res.body.file}' (last saw '${seen}')`,
    async () => {
      seen = (await importMetaStore.load("c1")).lastImportFile || "";
      return seen === res.body.file ? true : undefined;
    },
  );
  await new Promise((r) => setTimeout(r, 300));
}

async function malfindRows(stateStore: StateStore) {
  const state = await stateStore.load("c1");
  return state.forensicTimeline.filter((e) => e.description.includes("malfind"));
}

describe("#776 — malfind regions survive the case merge", () => {
  it(
    "keeps three addressed regions in one process as three rows",
    async () => {
      const { app, stateStore, importMetaStore } = await makeApp();
      await importRows(app, importMetaStore, [
        {
          PID: 3120,
          Process: "evil.exe",
          "Start VPN": 33554432,
          Tag: "VadS",
          Protection: "PAGE_EXECUTE_READWRITE",
        },
        {
          PID: 3120,
          Process: "evil.exe",
          "Start VPN": 67108864,
          Tag: "VadS",
          Protection: "PAGE_EXECUTE_READWRITE",
        },
        {
          PID: 3120,
          Process: "evil.exe",
          "Start VPN": 100663296,
          Tag: "VadS",
          Protection: "PAGE_EXECUTE_READWRITE",
        },
      ]);
      expect(await malfindRows(stateStore)).toHaveLength(3);
    },
    POLL_TIMEOUT_MS * 2,
  );

  it(
    "keeps regions a source reports WITHOUT an address as separate rows too",
    async () => {
      const { app, stateStore, importMetaStore } = await makeApp();
      await importRows(app, importMetaStore, [
        {
          PID: 3120,
          Process: "evil.exe",
          Tag: "VadS",
          Protection: "PAGE_EXECUTE_READWRITE",
          CommitCharge: 1,
        },
        {
          PID: 3120,
          Process: "evil.exe",
          Tag: "VadS",
          Protection: "PAGE_EXECUTE_READWRITE",
          CommitCharge: 2,
        },
        {
          PID: 3120,
          Process: "evil.exe",
          Tag: "VadS",
          Protection: "PAGE_EXECUTE_READWRITE",
          CommitCharge: 3,
        },
      ]);
      const rows = await malfindRows(stateStore);
      expect(rows).toHaveLength(3);
      expect(rows.some((e) => e.description.includes("commit charge 2"))).toBe(true);
      expect(rows.every((e) => !/\bat 0x/.test(e.description))).toBe(true); // no address is invented
    },
    POLL_TIMEOUT_MS * 2,
  );

  it(
    "reports a truthful count when the source gives nothing to tell the regions apart",
    async () => {
      const { app, stateStore, importMetaStore } = await makeApp();
      const identical = { PID: 3120, Process: "evil.exe", Tag: "VadS", Protection: "PAGE_EXECUTE_READWRITE" };
      await importRows(app, importMetaStore, [identical, { ...identical }, { ...identical }]);
      const rows = await malfindRows(stateStore);
      // Indistinguishable in the evidence itself, so ONE row — but it must say it stands for three.
      expect(rows).toHaveLength(1);
      expect(rows[0].count).toBe(3);
    },
    POLL_TIMEOUT_MS * 2,
  );
});
