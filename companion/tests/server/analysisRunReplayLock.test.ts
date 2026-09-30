import { describe, expect, it } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { AnalysisRunStore } from "../../src/analysis/analysisRunStore.js";
import type { AnalysisRunManifest, AnalysisRunRecordInput } from "../../src/analysis/analysisRunTypes.js";
import { EXAMPLE_IMPORTER_SPEC } from "../../src/analysis/importerSpec.js";
import { ImporterStore } from "../../src/analysis/importerStore.js";
import { ImportLock } from "../../src/analysis/importLock.js";
import type { ImportAdmission, ImportAdmissionHint } from "../../src/analysis/importMemoryGuard.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { buildRuntimePipeline, createApp } from "../../src/server.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import { pollFor } from "../helpers/poll.js";

// #1890: an import replay imports into the case, so it must hold the case's import section from its
// pre-import snapshot through its child run record, like every other import path. Otherwise a live
// import running at the same time counts the replay's rows as its own (and sweeps them into its undo
// checkpoint), and the replay's receipt claims the other import's rows.

const MDE_CSV =
  "Timestamp,DeviceName,ActionType,FileName,Severity,SHA256,RemoteIP\n" +
  "2026-06-10T12:00:00Z,HOST01,ProcessCreated,evil.exe,High,abc123,192.0.2.9";

/** An import lock that knows whether a section is held for the case. */
class WatchedLock extends ImportLock {
  held = 0;
  override runExclusive<T>(caseId: string, fn: () => Promise<T>, hint?: ImportAdmissionHint): Promise<T> {
    return super.runExclusive(
      caseId,
      async () => {
        this.held++;
        try {
          return await fn();
        } finally {
          this.held--;
        }
      },
      hint,
    );
  }
}

/** A run store that notes, for each child run, whether the case's import section was held. */
class WatchedRunStore extends AnalysisRunStore {
  childRecordedUnderLock: boolean[] = [];
  watchedLock?: WatchedLock;
  override async record(caseId: string, input: AnalysisRunRecordInput): Promise<AnalysisRunManifest> {
    if (input.parentRunId) this.childRecordedUnderLock.push((this.watchedLock?.held ?? 0) > 0);
    return super.record(caseId, input);
  }
}

async function setup(lock: ImportLock) {
  const root = await mkdtemp(join(tmpdir(), "dfir-replay-lock-"));
  const cases = new CaseStore(root);
  const stateStore = new StateStore(cases);
  const runStore = new WatchedRunStore(cases, { appVersion: "0.33.0" });
  if (lock instanceof WatchedLock) runStore.watchedLock = lock;
  const pipeline = buildRuntimePipeline({
    stateStore,
    store: cases,
    analysisRunStore: runStore,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(cases, {
    pipeline,
    stateStore,
    importerStore: new ImporterStore(join(root, "importers")),
    analysisRunStore: runStore,
    appVersion: "0.33.0",
    importLock: lock,
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  await request(app).post("/importers").send({ spec: EXAMPLE_IMPORTER_SPEC });
  const imported = await request(app)
    .post("/cases/c1/import")
    .send({ text: MDE_CSV, filename: "advanced-hunting.csv", minSeverity: "medium" });
  expect(imported.status).toBe(202);
  const run = await pollFor("the import's run record", async () =>
    (await runStore.list("c1")).find((r) => r.kind === "import"),
  );
  return { app, stateStore, runStore, run };
}

const timelineIds = async (stateStore: StateStore) =>
  (await stateStore.load("c1")).forensicTimeline.map((e) => e.id).sort();

describe("import replay takes the case's import section (#1890)", () => {
  it("waits for a held section, and records its child run before releasing it", async () => {
    const lock = new WatchedLock();
    const { app, stateStore, runStore, run } = await setup(lock);
    const before = await timelineIds(stateStore);

    // The replay's pre-import snapshot must be taken inside the section.
    const readsUnderLock: boolean[] = [];
    const load = stateStore.load.bind(stateStore);
    stateStore.load = async (caseId: string) => {
      readsUnderLock.push(lock.held > 0);
      return load(caseId);
    };
    const release = await lock.acquire("c1");
    const replay = request(app)
      .post(`/cases/c1/analysis-runs/${run.id}/replay`)
      .then((r) => r);
    await new Promise((resolve) => setTimeout(resolve, 300));
    // Nothing of the replay has reached the case while another import holds the section, and it has
    // not read the case yet either.
    expect(readsUnderLock).toEqual([]);
    expect(await timelineIds({ load } as unknown as StateStore)).toEqual(before);
    expect((await runStore.list("c1")).filter((r) => r.parentRunId === run.id)).toHaveLength(0);
    release();

    expect((await replay).status).toBe(200);
    const child = (await runStore.list("c1")).find((r) => r.parentRunId === run.id);
    expect(child).toBeDefined();
    expect(runStore.childRecordedUnderLock).toEqual([true]);
    stateStore.load = load;
    // Its first read is the pre-import snapshot (later reads may be background synthesis).
    expect(readsUnderLock[0]).toBe(true);
    // Its receipt names only the replay's own rows.
    const after = await timelineIds(stateStore);
    const added = after.filter((id) => !before.includes(id));
    expect([...(child?.output.entityIds ?? [])].filter((id) => after.includes(id)).sort()).toEqual(added);
  });

  it("releases the section when the replay fails, so the next import runs", async () => {
    const lock = new WatchedLock();
    const { app, runStore, run } = await setup(lock);
    const failing = Object.assign(runStore, {
      record: async () => {
        throw new Error("ledger unavailable");
      },
    });
    expect(failing).toBe(runStore);
    const replay = await request(app).post(`/cases/c1/analysis-runs/${run.id}/replay`);
    expect(replay.status).toBe(500);
    expect(lock.held).toBe(0);
    const next = await Promise.race([
      lock.runExclusive("c1", async () => "granted"),
      new Promise((resolve) => setTimeout(() => resolve("wedged"), 2000)),
    ]);
    expect(next).toBe("granted");
  });

  it("is refused by the memory guard with replay wording, and changes nothing", async () => {
    const hints: ImportAdmissionHint[] = [];
    let refuse = false;
    const admission: ImportAdmission = {
      admit: async (_caseId, hint) => {
        if (hint) hints.push(hint);
        if (refuse)
          throw new Error(`refused: ${hint?.wording?.saved ?? "-"} / ${hint?.wording?.retry ?? "-"}`);
        return () => {};
      },
    };
    const { app, stateStore, runStore, run } = await setup(new ImportLock(admission));
    const before = await timelineIds(stateStore);
    refuse = true;

    const replay = await request(app).post(`/cases/c1/analysis-runs/${run.id}/replay`);
    expect(replay.status).toBe(500);
    const hint = hints.at(-1);
    expect(hint?.incomingBytes).toBe(Buffer.byteLength(MDE_CSV));
    expect(hint?.wording?.retry).toBe("replay the run again");
    expect(replay.body.error).toContain("replay the run again");
    expect(await timelineIds(stateStore)).toEqual(before);
    expect((await runStore.list("c1")).filter((r) => r.parentRunId === run.id)).toHaveLength(0);
  });
});
