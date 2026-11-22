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
import { describe, expect, it, vi } from "vitest";
import {
  buildCollectionInventory,
  emptySettledClasses,
  renderCollectionInventory,
  sanitizeHuntJobs,
} from "../../src/analysis/collectionInventory.js";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
import { assessImportMemory, ImportMemoryRefusedError } from "../../src/analysis/importMemoryGuard.js";
import { ImportUndoStore } from "../../src/analysis/importUndo.js";
import { registerHuntSettle } from "../../src/analysis/huntSettleHook.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SynthMetaStore } from "../../src/analysis/synthMeta.js";
import { SuperTimelineStore, type SuperEviction } from "../../src/analysis/superTimelineStore.js";
import { buildBulkImportSink } from "../../src/composition/bulkImportSink.js";
import { VeloHuntStore, type VeloHuntJob } from "../../src/analysis/veloHuntStore.js";
import { HUNT_REFUSAL_WORDING } from "../../src/composition/veloEvidenceFirst.js";
import { ownOutcome } from "../../src/composition/veloHuntCompleteness.js";
import { getServerLogger } from "../../src/logging/serverLogger.js";
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

/** What the batched-import tests add to the world (#2831). */
interface Batched {
  /** An uploaded Velociraptor report, and what its batched run says the cap dropped. */
  uploadDropped?: SuperEviction;
  /** The real batched importer and a real super-timeline of `cap` rows; `rows` graded rows per artifact. */
  real?: { cap: number; rows: number };
  /**
   * A failure AFTER the collect built its result (#2850): "write" rejects the first write of an
   * imported job; "notify" throws from the dashboard refresh that follows the final job write.
   */
  late?: "write" | "notify";
}

const LATE_WRITE = "EPERM: operation not permitted, rename";
const LATE_NOTIFY = "late notify failure";

// `rows` YARA hits of one artifact — a detection verdict, graded High — each its own event.
const manyRows = (artifact: number, rows: number) =>
  Array.from({ length: rows }, (_, n) => ({
    _Source: "Windows.Detection.Yara",
    Fqdn: "WS-001",
    ClientId: "C.1",
    Rule: `SyntheticRule_${artifact}_${n}`,
    Namespace: "n",
    OSPath: `C:\\Users\\Public\\sample-${artifact}-${n}.dll`,
    Created0x10: new Date(Date.UTC(2026, 5, 1 + artifact, 10, 0, n)).toISOString(),
  }));

/** `failAt`: the 1-based artifact import that is refused; 0 refuses none. */
async function world(
  failAt: number,
  brokenRecord = false,
  capDropped?: SuperEviction,
  batched: Batched = {},
) {
  const root = await mkdtemp(join(tmpdir(), "dfir-hunt-midfail-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const veloHuntStore = new VeloHuntStore(store);
  // #2850: every AI status the collect pushed, each job status it wrote, and where the late failure
  // fired (an index into `statuses`; -1 until it does).
  const late = { statuses: [] as string[], writes: [] as string[], fired: -1, built: false };
  const realUpsert = veloHuntStore.upsert.bind(veloHuntStore);
  veloHuntStore.upsert = async (caseId, written) => {
    late.writes.push(written.status);
    if (batched.late === "write" && written.status === "imported" && late.fired < 0) {
      late.fired = late.statuses.length;
      throw new Error(LATE_WRITE);
    }
    const saved = await realUpsert(caseId, written);
    if (written.status !== "collecting" && written.importedAt) late.built = true; // the final job
    return saved;
  };
  const onVeloHunt = () => {
    if (batched.late !== "notify" || !late.built || late.fired >= 0) return;
    late.fired = late.statuses.length;
    throw new Error(LATE_NOTIFY);
  };
  const importMetaStore = new ImportMetaStore(store);
  const importUndoStore = new ImportUndoStore(store, 5);
  if (brokenRecord)
    importMetaStore.record = async () => {
      throw new Error("disk full");
    };
  const superTimelineStore = new SuperTimelineStore(store, batched.real?.cap);
  const bulkImportSink = batched.real
    ? buildBulkImportSink({
        stateStore,
        superTimelineStore,
        log: () => {},
        env: { DFIR_IMPORT_BULK_MIN_MB: "0", DFIR_IMPORT_BATCH_ROWS: "500" },
      })
    : undefined;
  const bulk = bulkImportSink ? { bulkImportSink } : {};
  const pipeline = buildRuntimePipeline({
    provider: undefined,
    synthesisProvider: undefined,
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    ...bulk,
  });
  const realImport = pipeline.importVelociraptorArtifact.bind(pipeline);
  let imports = 0;
  // What a test changes between two collects of one hunt (#2842).
  const sw = { failAt, poisonRows: false };
  pipeline.importVelociraptorArtifact = async (...args) => {
    imports += 1;
    if (imports === sw.failAt) throw refusal();
    const state = await realImport(...args);
    // What a batched artifact's run hands the collect once it committed (#2831): the rows its cap
    // passes dropped, and the run itself.
    if (capDropped)
      args[2].onRunEvicted?.(capDropped, { importBatchId: `run-${imports}`, fence: 0, mode: "forensic" });
    return state;
  };
  if (batched.uploadDropped) {
    const dropped = batched.uploadDropped;
    const realVelo = pipeline.importVelociraptor.bind(pipeline);
    pipeline.importVelociraptor = async (...args) => {
      const state = await realVelo(...args);
      args[2].onSuperEvicted?.(dropped); // an uploaded report's batched run: its own net report
      return state;
    };
  }
  const client = {
    async huntStatus() {
      return { state: "RUNNING", clients: { scheduled: 1, completed: 1, errors: 0 } };
    },
    async huntReachedClients() {
      return [{ clientId: "C.1", hostname: "WS-001", fqdn: "WS-001", os: "windows" }];
    },
    async huntArtifactRows(_h: string, artifact: string): Promise<VelociraptorRunResult> {
      const index = ARTIFACTS.indexOf(artifact);
      const rows = batched.real ? manyRows(index, batched.real.rows) : [row(index)];
      // A row the collect cannot write to its scratch file: the fetch works, the collect then fails.
      if (sw.poisonRows) return { rows: [{ ...row(index), Size: 1n }], total: 1, truncated: false };
      return { rows, total: rows.length, truncated: false };
    },
    async huntUploads() {
      if (!batched.uploadDropped) return [];
      const content = JSON.stringify([{ ...row(7), _Source: "Windows.System.Pslist" }]);
      return [{ name: "Windows.System.Pslist.json", clientId: "C.1", content }];
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
    superTimelineStore,
    ...bulk,
    serverClients: veloServerClients(client),
    onVeloHunt,
    onAiStatus: (_caseId, e) => void late.statuses.push(`${e.status}: ${e.detail ?? ""}`),
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
  const made = { app, stateStore, veloHuntStore, importMetaStore, importUndoStore, superTimelineStore };
  return { ...made, store, late, seen, sw, imports: () => imports };
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
      expect(job.skippedArtifacts?.[0]?.notImported).toBe("stopped"); // read, not imported (#2835)
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

  // #2831: an uploaded report inside the hunt can be a large Velociraptor export, read in batches too.
  it(
    "the import record carries the rows an uploaded report's batched import pushed out",
    async () => {
      const one = { count: 5, setAside: 1, from: "2025-02-01T00:00:00Z", to: "2025-02-03T00:00:00Z" };
      const up = { count: 7, setAside: 0, from: "2025-03-01T00:00:00Z", to: "2025-03-02T00:00:00Z" };
      const w = await world(0, false, one, { uploadDropped: up });
      await collect(w, "imported");
      const meta = await w.importMetaStore.load("c1");
      // Three artifacts and the upload.
      expect(meta.superTimelineEvicted).toEqual({ count: 22, setAside: 3, from: one.from, to: up.to });
    },
    POLL_TIMEOUT_MS * 2,
  );

  // #2831: each artifact is a batched run of its own and the collect settles once. A later artifact's
  // cap pass drops an earlier artifact's graded rows, the settle offers every graded row again, and
  // the record counted the rows that came back as dropped. The real importer and a real store.
  it(
    "counts each row the cap dropped once across a collect's batched artifacts",
    async () => {
      const CAP = 20;
      const w = await world(0, false, undefined, { real: { cap: CAP, rows: 30 } });
      await collect(w, "imported");
      // Every row is graded: each is in the forensic timeline and was offered to the super-timeline,
      // which started empty. What it does not hold now is what the cap dropped.
      const graded = await events(w.stateStore);
      const held = (await w.superTimelineStore.meta("c1")).rows;
      expect(graded).toBeGreaterThan(CAP * 2);
      expect(held).toBe(CAP);
      expect((await w.importMetaStore.load("c1")).superTimelineEvicted?.count).toBe(graded - held);
    },
    POLL_TIMEOUT_MS * 4,
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
      expect((job.skippedArtifacts ?? []).map((s) => s.notImported)).toEqual(["stopped", "stopped"]);

      // #2838: the AI's collection inventory lists this hunt — the stored job, read as synthesis reads it.
      const inv = buildCollectionInventory({ events: [], hunts: sanitizeHuntJobs([job]) });
      expect(inv.hunts.map((h) => `${h.artifact}=${h.state}`)).toEqual([
        `${THIRD}=not-imported`,
        `${FIRST}=archive-only`,
        `${SECOND}=not-imported`,
      ]);
      const text = renderCollectionInventory(inv);
      expect(text).toContain(`${SECOND} — read but NOT imported by this hunt (the collect stopped part-way)`);
      expect(text).not.toContain("fetch failed");
      expect(text).not.toContain("Import refused"); // the stored reason never reaches the prompt
      expect([...emptySettledClasses(inv, "WS-001")]).toEqual([]);
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
      // #2838: nothing imported, so the inventory says nothing about this hunt.
      expect(buildCollectionInventory({ events: [], hunts: sanitizeHuntJobs([job]) }).hunts).toEqual([]);
    },
    POLL_TIMEOUT_MS * 2,
  );
});

// #2842: a collect that fails before it records its own results leaves an EARLIER collect's lists on
// the job. They stay (they are still true of the case) and the job says whose they are.
describe("a hunt collect that fails after an earlier part-imported collect (#2842)", () => {
  type World = Awaited<ReturnType<typeof world>>;
  /** The second of three refused: one artifact imported, two "stopped" records on the job. */
  async function partCollected() {
    const w = await world(2);
    const first = await collect(w, "error");
    expect((first.skippedArtifacts ?? []).map((s) => s.notImported)).toEqual(["stopped", "stopped"]);
    expect(first.earlierCoverage).toBeUndefined(); // its own results
    return { w, first };
  }
  /** Collect again and wait for a failure that is not the earlier one's. */
  async function collectFailsAgain(w: World, earlier: VeloHuntJob) {
    const res = await request(w.app).post("/cases/c1/velociraptor/collect").send({ huntId: "H.1" });
    expect(res.status).toBe(202);
    return pollFor("hunt H.1 failed again", async () => {
      const j = await w.veloHuntStore.get("c1", "H.1");
      return j?.status === "error" && j.error !== earlier.error ? j : null;
    });
  }

  it(
    "a failure before the collect recorded its own results marks the lists as an earlier collect's",
    async () => {
      const { w, first } = await partCollected();
      w.sw.poisonRows = true;
      const job = await collectFailsAgain(w, first);
      expect(job.error).toMatch(/BigInt/);
      expect(w.imports()).toBe(2); // the second collect imported nothing
      expect(job.skippedArtifacts).toEqual(first.skippedArtifacts);
      expect(job.earlierCoverage).toBe(true);

      // The AI's inventory still reads the hunt as part-collected, never as clean silence (#2838).
      const inv = buildCollectionInventory({ events: [], hunts: sanitizeHuntJobs([job]) });
      expect(inv.hunts.map((h) => `${h.artifact}=${h.state}`)).toEqual([
        `${THIRD}=not-imported`,
        `${FIRST}=archive-only`,
        `${SECOND}=not-imported`,
      ]);
      expect([...emptySettledClasses(inv, "WS-001")]).toEqual([]);

      // A collect that completes writes its own results: the mark is gone.
      w.sw.poisonRows = false;
      const clean = await collect(w, "imported");
      expect(clean.earlierCoverage).toBeUndefined();
      expect(clean.skippedArtifacts).toBeUndefined();
    },
    POLL_TIMEOUT_MS * 4,
  );

  it(
    "control: a failure after the collect recorded its own results is not marked",
    async () => {
      const { w, first } = await partCollected();
      w.sw.failAt = w.imports() + 1; // the second collect's FIRST artifact is refused
      const job = await collectFailsAgain(w, first);
      expect(job.error).toBe(refusal().message);
      expect(job.skippedArtifacts).toBeUndefined(); // its own results: nothing was skipped or held
      expect(job.earlierCoverage).toBeUndefined();
    },
    POLL_TIMEOUT_MS * 4,
  );
});

// #2850: a failure after the collect built its result (in production: the final job write) reached
// the collect's catch, which rewrote a hunt whose rows are all in the case as a failed collect.
describe("a hunt collect that fails after it built its result (#2850)", () => {
  type World = Awaited<ReturnType<typeof world>>;
  /** Collect, and wait until the pass that hit the late failure has said how it ended. */
  async function collectPastLateFailure(w: World) {
    const res = await request(w.app).post("/cases/c1/velociraptor/collect").send({ huntId: "H.1" });
    expect(res.status).toBe(202);
    const said = await pollFor("the collect's last status", async () => {
      if (w.late.fired < 0) return null;
      return w.late.statuses.slice(w.late.fired).find((s) => s.includes("Velociraptor hunt collect")) ?? null;
    });
    const job = await w.veloHuntStore.get("c1", "H.1");
    if (!job) throw new Error("the hunt job is gone");
    return { job, said };
  }

  it(
    "the final job write fails once: the job ends imported, with its import time and counts",
    async () => {
      const w = await world(0, false, undefined, { late: "write" });
      const { job, said } = await collectPastLateFailure(w);
      expect(job.status).toBe("imported");
      expect(job.importedAt).toBeTruthy();
      expect(job.addedEvents).toBe(3);
      expect(job.error).toBeUndefined();
      expect(await events(w.stateStore)).toBe(3);
      expect(w.late.writes.filter((s) => s === "imported")).toHaveLength(2); // refused, then landed
      expect(w.late.writes).not.toContain("error");
      expect(said).toContain("kept its result");
      expect(said).toContain(LATE_WRITE);
      expect(said).not.toContain("collect failed");
      // The steps the throw skipped (re-grade, synthesis start) are flagged, not silently lost.
      expect((await new SynthMetaStore(w.store).load("c1")).outOfDate?.reason).toMatch(/hunt collect/);
    },
    POLL_TIMEOUT_MS * 2,
  );

  it(
    "a late callback throw on a clean collect: the job stays imported and no import failure is logged",
    async () => {
      const warn = vi.spyOn(getServerLogger(), "warn");
      try {
        const w = await world(0, false, undefined, { late: "notify" });
        const { job, said } = await collectPastLateFailure(w);
        expect(job.status).toBe("imported");
        expect(job.addedEvents).toBe(3);
        expect(job.error).toBeUndefined();
        expect(said).toContain("kept its result");
        const warned = warn.mock.calls.map((c) => String(c[0]));
        expect(warned.some((l) => l.includes("hunt H.1") && l.includes(LATE_NOTIFY))).toBe(true);
        expect(warned.some((l) => l.includes("FAILED"))).toBe(false);
      } finally {
        warn.mockRestore();
      }
    },
    POLL_TIMEOUT_MS * 2,
  );

  it(
    "a part-imported collect plus a late throw keeps its own message and its stopped record",
    async () => {
      const w = await world(3, false, undefined, { late: "notify" });
      const { job, said } = await collectPastLateFailure(w);
      expect(job.status).toBe("error");
      expect(job.error).toContain(`Imported: ${FIRST}, ${SECOND}.`);
      expect(job.error).toContain(`Not imported: ${THIRD}.`);
      expect(job.error).not.toContain(LATE_NOTIFY);
      expect(job.addedEvents).toBe(2);
      expect((job.skippedArtifacts ?? []).map((s) => s.notImported)).toEqual(["stopped"]);
      expect(job.earlierCoverage).toBeUndefined();
      expect(said).toContain("kept its result");
    },
    POLL_TIMEOUT_MS * 2,
  );

  it("ownOutcome: only a job the collect itself finished counts", () => {
    const before: VeloHuntJob = {
      bundleId: "b",
      bundleName: "B",
      artifacts: [FIRST],
      huntId: "H.1",
      launchedAt: "2026-01-01T00:00:00Z",
      waitMinutes: 15,
      collectAt: "2026-01-01T00:15:00Z",
      status: "imported", // an EARLIER collect's result
    };
    expect(ownOutcome(before, before)).toBeUndefined(); // nothing written yet
    expect(ownOutcome({ ...before, status: "collecting" }, before)).toBeUndefined();
    const imported: VeloHuntJob = { ...before, addedEvents: 3 };
    expect(ownOutcome(imported, before)).toBe(imported);
    const partFailed: VeloHuntJob = { ...before, status: "error", error: "Imported: a. Not imported: b." };
    expect(ownOutcome(partFailed, before)).toBe(partFailed);
  });
});
