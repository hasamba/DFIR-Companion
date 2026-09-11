import { describe, expect, it } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
import { IMPORT_FILE_HEAD_BYTES } from "../../src/routes/importFileHead.js";

// #953, end to end. The detector contract is pinned in tests/analysis/importDetect.test.ts; this is
// the route that motivated it: Import-from-path sniffs a bounded head, and a Velociraptor GUI export
// — a JSON array, routinely over 256 KB — answered 400 "could not detect the file type" from the
// one route that exists for large files, while the same bytes imported through the dashboard upload.

// Deterministic rows — every one of these imports with no AI call. The filenames carry no tool name
// on purpose: the detector has filename hints, and the CONTENT must be what classifies the head.
const ARRAY_KINDS: Array<[string, object]> = [
  [
    "velociraptor",
    {
      _Source: "Windows.Detection.X",
      Detection: { Name: "Bad" },
      EventTime: "2026-01-01T00:00:00Z",
      EntryPath: "c:\\x.exe",
      ClientId: "C.1",
      Fqdn: "host",
    },
  ],
  [
    "chainsaw",
    {
      group: "Sigma",
      kind: "individual",
      document: {
        kind: "evtx",
        path: "S.evtx",
        data: {
          Event: {
            System: {
              EventID: 1,
              Computer: "H",
              TimeCreated: { "#attributes": { SystemTime: "2023-01-02T10:00:00.000Z" } },
            },
            EventData: { Image: "x" },
          },
        },
      },
      rule: { name: "r", level: "high", tags: [] },
      timestamp: "2023-01-02T10:00:00.000Z",
    },
  ],
  [
    "hayabusa",
    {
      Timestamp: "2023-01-02 10:00:00.000 +00:00",
      Computer: "H",
      Channel: "Sec",
      EventID: 4624,
      Level: "high",
      RuleTitle: "Logon",
      Details: "x",
    },
  ],
];

async function makeApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-import-array-head-"));
  const store = new CaseStore(join(root, "cases"));
  const stateStore = new StateStore(store);
  const pipeline = buildRuntimePipeline({
    provider: undefined,
    synthesisProvider: undefined,
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, { pipeline, stateStore, importMetaStore: new ImportMetaStore(store) });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, root };
}

describe("POST /cases/:id/import-file — a JSON-array export larger than the head sample (#953)", () => {
  for (const [kind, row] of ARRAY_KINDS) {
    it(`classifies a ${kind} array over the sample size and accepts it`, async () => {
      const { app, root } = await makeApp();
      const one = JSON.stringify(row);
      const n = Math.ceil((2 * IMPORT_FILE_HEAD_BYTES) / (one.length + 1)) + 1;
      const path = join(root, "export.json");
      await writeFile(path, `[${Array.from({ length: n }, () => one).join(",")}]`, "utf8");

      const res = await request(app).post("/cases/c1/import-file").send({ path });

      expect(res.status, JSON.stringify(res.body)).toBe(202);
      expect(res.body).toMatchObject({ kind });
    });
  }

  it("still refuses a genuinely malformed WHOLE file through the upload route (review P2)", async () => {
    // One complete Velociraptor row followed by a cut one, sent as the whole body: the detector
    // must not classify it from its one good row and then import nothing. Only the head-sniff
    // path completes a truncated array; the whole-file paths see the bytes as they are.
    const { app } = await makeApp();
    const [, row] = ARRAY_KINDS[0];
    const one = JSON.stringify(row);
    const malformed = `[${one},${one.slice(0, 40)}`;
    const res = await request(app)
      .post("/cases/c1/import")
      .send({ filename: "export.json", text: malformed });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/could not detect/);
  });
});
