// A hunt collect imports its artifacts one at a time inside one import section. When a LATER artifact
// failed (the memory guard can refuse a batched artifact partway, #2812), the earlier ones stayed in
// the case while the collect skipped the settle, the import record and the undo checkpoint — and the
// card said "nothing was changed" (#2817). Now the collect stops at the failed artifact, settles and
// records what imported, and the card names both groups. Through the real collect path, on the
// harness of huntPartialCollect.test.ts, with the guard's real refusal text.
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
import { assessImportMemory, ImportMemoryRefusedError } from "../../src/analysis/importMemoryGuard.js";
import { ImportUndoStore } from "../../src/analysis/importUndo.js";
import { registerHuntSettle } from "../../src/analysis/huntSettleHook.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore, type SuperEviction } from "../../src/analysis/superTimelineStore.js";
import { VeloHuntStore, type VeloHuntJob } from "../../src/analysis/veloHuntStore.js";
import { HUNT_REFUSAL_WORDING } from "../../src/composition/veloEvidenceFirst.js";
import { buildRuntimePipeline, createApp } from "../../src/server.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import type { VelociraptorRunResult } from "../../src/integrations/velociraptor/velociraptorApi.js";
import { veloServerClients } from "../helpers/serverClientsStub.js";
import { pollFor, POLL_TIMEOUT_MS } from "../helpers/poll.js";

const FIRST = "Generic.System.Pstree";
const SECOND = "Windows.System.Pslist";
const THIRD = "Custom.Hunt.Processes";
const ARTIFACTS = [FIRST, SECOND, THIRD];
// One graded process row per artifact, each its own event.
const row = (i: number) => ({
  Fqdn: "WS-001",
  ClientId: "C.1",
  Name: "rundll32.exe",
  Pid: 4000 + i,
  CommandLine: `rundll32.exe C:\\Users\\Public\\payload${i}.dll,Start`,
  Timestamp: `2026-06-01T10:0${i}:00Z`,
});

/** The guard's real refusal, as a starved machine words it for a hunt. */
function refusal(): ImportMemoryRefusedError {
  const assessed = assessImportMemory({
    caseEvents: 50_000,
    incomingEvents: 1,
    availableBytes: 0,
    rssBytes: 0,
    heapLimitBytes: 1024 ** 4,
    reservedBytes: 0,
    wording: HUNT_REFUSAL_WORDING,
  });
  if (assessed.ok) throw new Error("the fixture machine must be starved");
  return new ImportMemoryRefusedError(assessed.message);
}

/** `failAt`: the 1-based artifact import that is refused; 0 refuses none. */
async function world(failAt: number, brokenRecord = false, capDropped?: SuperEviction) {
  const root = await mkdtemp(join(tmpdir(), "dfir-hunt-midfail-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const veloHuntStore = new VeloHuntStore(store);
  const importMetaStore = new ImportMetaStore(store);
  const importUndoStore = new ImportUndoStore(store, 5);
  if (brokenRecord)
    importMetaStore.record = async () => {
      throw new Error("disk full");
    };
  const pipeline = buildRuntimePipeline({
    provider: undefined,
    synthesisProvider: undefined,
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const realImport = pipeline.importVelociraptorArtifact.bind(pipeline);
  let imports = 0;
  pipeline.importVelociraptorArtifact = async (...args) => {
    imports += 1;
    if (imports === failAt) throw refusal();
    const state = await realImport(...args);
    // What a batched artifact's run reports once it committed (#2816): the rows the cap dropped.
    if (capDropped) args[2].onSuperEvicted?.(capDropped);
    return state;
  };
  const client = {
    async huntStatus() {
      return { state: "RUNNING", clients: { scheduled: 1, completed: 1, errors: 0 } };
    },
    async huntReachedClients() {
      return [{ clientId: "C.1", hostname: "WS-001", fqdn: "WS-001", os: "windows" }];
    },
    async huntArtifactRows(_h: string, artifact: string): Promise<VelociraptorRunResult> {
      const rows = [row(ARTIFACTS.indexOf(artifact))];
      return { rows, total: rows.length, truncated: false };
    },
    async huntUploads() {
      return [];
    },
    huntGuiUrlFor() {
      return undefined;
    },
  };
  const app = createApp(store, {
    pipeline,
    stateStore,
    veloHuntStore,
    importMetaStore,
    importUndoStore,
    superTimelineStore: new SuperTimelineStore(store),
    serverClients: veloServerClients(client),
  });
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const job: VeloHuntJob = {
    bundleId: "threat-hunt-starter",
    bundleName: "Threat Hunt Starter",
    artifacts: ARTIFACTS,
    huntId: "H.1",
    launchedAt: "2026-01-01T00:00:00Z",
    waitMinutes: 15,
    collectAt: "2026-01-01T00:15:00Z",
    status: "running",
  };
  await veloHuntStore.upsert("c1", job);
  // What the persisted job listed as skipped each time the settle seam ran its hunt hook.
  const seen: { skipped: string[]; status: string }[] = [];
  registerHuntSettle(stateStore, async (caseId) => {
    const cur = await veloHuntStore.get(caseId, "H.1");
    seen.push({ skipped: (cur?.skippedArtifacts ?? []).map((s) => s.name), status: cur?.status ?? "" });
    return 0; // graded nothing
  });
  return { app, stateStore, veloHuntStore, importMetaStore, importUndoStore, seen, imports: () => imports };
}

async function collect(w: Awaited<ReturnType<typeof world>>, end: VeloHuntJob["status"]) {
  const res = await request(w.app).post("/cases/c1/velociraptor/collect").send({ huntId: "H.1" });
  expect(res.status).toBe(202);
  return pollFor(`hunt H.1 ${end}`, async () => {
    const j = await w.veloHuntStore.get("c1", "H.1");
    return j?.status === end ? j : null;
  });
}

const events = async (s: StateStore) => (await s.load("c1")).forensicTimeline.length;

describe("a hunt collect that fails on a later artifact (#2817)", () => {
  it(
    "control: three artifacts import, with one record and one undo checkpoint",
    async () => {
      const w = await world(0);
      const job = await collect(w, "imported");
      expect(job.addedEvents).toBe(3);
      expect((await w.importUndoStore.load("c1")).undo).toHaveLength(1);
    },
    POLL_TIMEOUT_MS * 2,
  );

  it(
    "the third refused: the first two are settled, recorded and undoable, and the card names all three",
    async () => {
      const w = await world(3);
      const job = await collect(w, "error");

      expect(job.error).toContain("Import refused to protect the server");
      expect(job.error).not.toMatch(/nothing was changed/i);
      expect(job.error).toContain(`Imported: ${FIRST}, ${SECOND}.`);
      expect(job.error).toContain(`Not imported: ${THIRD}.`);
      expect(job.error).toContain("Undo is available for what was imported.");
      expect(job.error).toContain("press Collect now on this hunt"); // the retry advice stays

      expect(await events(w.stateStore)).toBe(2);
      expect(job.addedEvents).toBe(2);
      const meta = await w.importMetaStore.load("c1");
      expect(meta.lastImportKind).toBe("velociraptor");
      expect(meta.lastImportFile).toMatch(/Pslist/); // the last artifact that DID import
      expect(meta.addedCount).toBe(2);

      const stack = await w.importUndoStore.load("c1");
      expect(stack.undo).toHaveLength(1);
      const undone = await request(w.app).post("/cases/c1/import/undo").send({});
      expect(undone.status).toBe(200);
      expect(await events(w.stateStore)).toBe(0);

      expect((job.skippedArtifacts ?? []).map((s) => s.name)).toEqual([THIRD]);
      expect(job.skippedArtifacts?.[0]?.error).toContain("Import refused to protect the server");
      expect(job.skippedArtifacts?.[0]?.error).not.toMatch(/nothing was changed/i);
      // Before the settle: the seam's hunt grading already read the failed artifact from the job.
      expect(w.seen[0]).toEqual({ skipped: [THIRD], status: "collecting" });
    },
    POLL_TIMEOUT_MS * 2,
  );

  // #2816 review: a batched artifact's run reports what the super-timeline cap dropped when it
  // committed; the collect adds its artifacts' reports up and its one import record carries them.
  it(
    "the import record carries the rows the cap dropped across the artifacts that imported",
    async () => {
      const one = { count: 5, setAside: 1, from: "2025-02-01T00:00:00Z", to: "2025-02-03T00:00:00Z" };
      const w = await world(3, false, one);
      await collect(w, "error");
      const meta = await w.importMetaStore.load("c1");
      expect(meta.superTimelineEvicted).toEqual({ ...one, count: 10, setAside: 2 }); // two imported
    },
    POLL_TIMEOUT_MS * 2,
  );

  it(
    "the second refused: the artifact never reached is listed as not imported too",
    async () => {
      const w = await world(2);
      const job = await collect(w, "error");
      expect(job.error).toContain(`Imported: ${FIRST}.`);
      expect(job.error).toContain(`Not imported: ${SECOND}, ${THIRD}.`);
      expect(w.imports()).toBe(2); // the collect stopped: the third was never tried
      expect((job.skippedArtifacts ?? []).map((s) => s.name)).toEqual([SECOND, THIRD]);
      expect((await w.importUndoStore.load("c1")).undo).toHaveLength(1);
    },
    POLL_TIMEOUT_MS * 2,
  );

  it(
    "the settle of what imported fails too: the card still leads with the artifact's error",
    async () => {
      const w = await world(3, true);
      const job = await collect(w, "error");
      expect(job.error).toMatch(/^Import refused to protect the server/);
      expect(job.error).toContain(`Not imported: ${THIRD}.`);
      expect(job.error).toContain("Settling or recording what was imported failed");
      expect(job.addedEvents).toBe(2); // the settle returned: its counts stand
      expect(job.error).not.toContain("Undo is available");
      expect(job.error).not.toContain("disk full"); // logged, not on the card
    },
    POLL_TIMEOUT_MS * 2,
  );

  it(
    "the first refused: nothing is settled and the message is the guard's own",
    async () => {
      const w = await world(1);
      const job = await collect(w, "error");
      expect(job.error).toBe(refusal().message);
      expect(job.error).toContain("nothing was changed");
      expect(await events(w.stateStore)).toBe(0);
      expect((await w.importUndoStore.load("c1")).undo).toHaveLength(0);
      expect((await w.importMetaStore.load("c1")).lastImportFile).toBe("");
      expect(w.seen).toEqual([]);
      expect(job.skippedArtifacts).toBeUndefined();
    },
    POLL_TIMEOUT_MS * 2,
  );
});
