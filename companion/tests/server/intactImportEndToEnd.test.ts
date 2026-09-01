import { describe, it, expect } from "vitest";
import type { Express } from "express";
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

// #776 — the two Intact files overlap, and importing both is the obvious thing an analyst does.
//
// The `yara` array inside memory_payload.json is a strict SUBSET of yarascan_results.jsonl, stripped
// of Component and Value. Nothing else in the merge would catch that: forensic events dedupe by ID,
// every other importer numbers its events from a per-import sequence, and correlation's exact
// timestamp+description step cannot help either — the JSON-Lines copy of a hit carries the matched
// string and the payload's copy does not, so the two descriptions differ by construction.
//
// What absorbs the overlap is the Intact adapter minting a CONTENT-derived id from (Offset, Rule).
// This test drives the real HTTP import route for both files and counts the result, so it fails if
// that id stops being stable, if platformImports goes back to overwriting a parser-supplied id, or
// if detection stops routing either file to the memory importer.

const SHARED = [
  { Offset: 0x1000_0000, Rule: "Cobalt_Strike_Beacon" },
  { Offset: 0x2000_0000, Rule: "Mimikatz_Memory" },
];

const PAYLOAD = JSON.stringify({
  plugins: {
    "volatility3.plugins.windows.pstree.PsTree": [
      {
        Cmd: "services.exe",
        PID: 832,
        PPID: 684,
        Path: "C:\\WINDOWS\\system32\\services.exe",
        "Offset(V)": 213901691334784,
        CreateTime: "2026-08-30T15:00:35+00:00",
        ImageFileName: "services.exe",
      },
    ],
  },
  yara: SHARED,
});

// The full set: the two hits the payload also carries, plus one it does not — with the matched
// string and value the payload's copy was stripped of.
const YARA_JSONL = [
  { ...SHARED[0], Component: "$s1", Value: "b'beacon.dll'" },
  { ...SHARED[1], Component: "$s2", Value: "b'sekurlsa'" },
  { Offset: 0x3000_0000, Rule: "Webshell_Generic", Component: "$s0", Value: "b'eval(' " },
]
  .map((r) => JSON.stringify(r))
  .join("\n");

const FILE_PAYLOAD = { filename: "memory_payload.json", text: PAYLOAD };
const FILE_YARA = { filename: "yarascan_results.jsonl", text: YARA_JSONL };

async function makeApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-intact-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const superTimelineStore = new SuperTimelineStore(store);
  const importMetaStore = new ImportMetaStore(store);
  // No-AI pipeline: the Intact import is fully deterministic, so no model call is needed.
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

// Wait for ONE import cycle, identified by the stored filename the 202 returned. import-meta is
// written after the importer's events have merged into the forensic timeline (see
// importReimportIdempotence.test.ts for why the audit log is not usable as the signal).
async function settle(importMetaStore: ImportMetaStore, storedFile: string): Promise<void> {
  let seen = "(nothing)";
  await pollFor(
    () => `import-meta to record the '${storedFile}' import cycle (last saw '${seen}')`,
    async () => {
      seen = (await importMetaStore.load("c1")).lastImportFile || "(nothing)";
      return seen === storedFile ? true : undefined;
    },
  );
  await new Promise((r) => setTimeout(r, 300));
}

async function startImport(app: Express, file: { filename: string; text: string }): Promise<string> {
  const res = await request(app).post("/cases/c1/import").send(file);
  expect(res.status).toBe(202);
  expect(res.body.kind).toBe("memory"); // not "log" — the AI fallback both files used to land in
  return res.body.file as string;
}

async function yaraRows(stateStore: StateStore): Promise<string[]> {
  const state = await stateStore.load("c1");
  return state.forensicTimeline
    .filter((e) => e.description.startsWith("Intact YARA (memory):"))
    .map((e) => e.description);
}

describe("#776 — importing both Intact files", () => {
  it(
    "keeps one timeline row per (offset, rule) instead of double-counting the shared hits",
    async () => {
      const { app, stateStore, importMetaStore } = await makeApp();

      await settle(importMetaStore, await startImport(app, FILE_PAYLOAD));
      const afterPayload = await yaraRows(stateStore);
      expect(afterPayload).toHaveLength(2);

      await settle(importMetaStore, await startImport(app, FILE_YARA));
      const afterBoth = await yaraRows(stateStore);

      // 2 + 3 rows arrived; 2 of them are the same two hits. Three distinct hits remain.
      expect(afterBoth).toHaveLength(3);
      // The richer file merged last, so a shared hit now carries the matched string it was missing.
      expect(afterBoth.find((d) => d.includes("Cobalt_Strike_Beacon"))).toContain("beacon.dll");
    },
    POLL_TIMEOUT_MS * 3,
  );
});
