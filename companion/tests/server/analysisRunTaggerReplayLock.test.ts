import { afterEach, describe, expect, it } from "vitest";
import { AsyncLocalStorage } from "node:async_hooks";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { AnalysisRunStore } from "../../src/analysis/analysisRunStore.js";
import { StateLock } from "../../src/analysis/stateLock.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import type { ForensicEvent, InvestigationState } from "../../src/analysis/stateTypes.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { TaggerStore } from "../../src/analysis/taggerStore.js";
import { TagsStore } from "../../src/analysis/tags.js";
import { createApp, setServerLogger } from "../../src/server.js";
import { createConsoleLogger } from "../../src/logging/logger.js";
import { CaseStore } from "../../src/storage/caseStore.js";

// #1892: replaying a tagger run reads the case, tags it and saves the whole snapshot back. It must do
// all three inside ONE state-lock section, like the manual "Run tagger" route. Otherwise a write that
// lands between the replay's read and its save (an import merge, an analyst edit) is overwritten.

const RULES = `svc:
  description: Windows service installed
  any:
    - { field: message, contains: ['7045'] }
  tags: ['win-service']
  severity: High
`;

function ev(p: Partial<ForensicEvent> & { id: string }): ForensicEvent {
  return {
    timestamp: "2026-06-01T00:00:00Z",
    description: "d",
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...p,
  };
}

const UNTAGGED = ev({ id: "e1", message: "A new service was installed 7045", severity: "Low" });

/** A state lock that stamps each held section with its own id, visible only to code running in it. */
class WatchedStateLock extends StateLock {
  private readonly section = new AsyncLocalStorage<number>();
  private nextId = 0;
  get current(): number | undefined {
    return this.section.getStore();
  }
  override runExclusive<T>(caseId: string, fn: () => Promise<T>): Promise<T> {
    return super.runExclusive(caseId, () => this.section.run(++this.nextId, fn));
  }
}

type Op = { op: "load" | "save"; section: number | undefined };

const dirs: string[] = [];
afterEach(async () => {
  await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

async function setup() {
  const dir = await mkdtemp(join(tmpdir(), "dfir-tagger-replay-lock-"));
  dirs.push(dir);
  setServerLogger(createConsoleLogger("error"));
  const cases = new CaseStore(dir);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(cases);
  const rulesPath = join(dir, "default-tags.yaml");
  await writeFile(rulesPath, RULES);
  const runStore = new AnalysisRunStore(cases, { appVersion: "0.33.0" });
  const lock = new WatchedStateLock();
  const app = createApp(cases, {
    stateStore,
    tagsStore: new TagsStore(cases),
    taggerStore: new TaggerStore(join(dir, "user-tags.yaml"), [rulesPath]),
    superTimelineStore: new SuperTimelineStore(cases),
    analysisRunStore: runStore,
    appVersion: "0.33.0",
    stateLock: lock,
  });
  const seeded = await stateStore.load("c1");
  await stateStore.save({ ...seeded, forensicTimeline: [UNTAGGED] });
  expect((await request(app).post("/cases/c1/tagger/run")).status).toBe(200);
  const run = (await runStore.list("c1")).find((r) => r.kind === "deterministic");
  expect(run).toBeDefined();
  // Undo the manual run's tagging, so the replay has something to change and must save the case.
  const tagged = await stateStore.load("c1");
  await stateStore.save({ ...tagged, forensicTimeline: [UNTAGGED] });

  // Note every read and write of the case, with the state-lock section it ran in.
  const ops: Op[] = [];
  const load = stateStore.load.bind(stateStore);
  const save = stateStore.save.bind(stateStore);
  stateStore.load = async (caseId: string) => {
    ops.push({ op: "load", section: lock.current });
    return load(caseId);
  };
  stateStore.save = async (state: InvestigationState) => {
    ops.push({ op: "save", section: lock.current });
    return save(state);
  };
  return { app, lock, runStore, run: run!, ops, load, save };
}

describe("tagger replay holds the case's state lock (#1892)", () => {
  it("reads, tags and saves the case inside one state-lock section", async () => {
    const { app, run, ops, load } = await setup();

    const replay = await request(app).post(`/cases/c1/analysis-runs/${run.id}/replay`);
    expect(replay.status).toBe(200);

    const saves = ops.filter((o) => o.op === "save");
    expect(saves).toHaveLength(1);
    const section = saves[0].section;
    expect(section).toBeDefined();
    // The snapshot it saved was read in the SAME section — not an earlier one, not outside any.
    const saveAt = ops.indexOf(saves[0]);
    const lastLoadBeforeSave = ops
      .slice(0, saveAt)
      .filter((o) => o.op === "load")
      .at(-1);
    expect(lastLoadBeforeSave?.section).toBe(section);
    expect((await load("c1")).forensicTimeline[0].severity).toBe("High");
  });

  it("waits for a held section, and keeps an event written meanwhile", async () => {
    const { app, lock, runStore, run, ops, load, save } = await setup();

    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let entered!: () => void;
    const holding = new Promise<void>((resolve) => {
      entered = resolve;
    });
    const held = lock.runExclusive("c1", async () => {
      entered();
      await gate;
      // Another writer adds evidence while it holds the case's section.
      const state = await load("c1");
      await save({ ...state, forensicTimeline: [...state.forensicTimeline, ev({ id: "e-new" })] });
    });
    await holding;
    ops.length = 0;

    const replay = request(app)
      .post(`/cases/c1/analysis-runs/${run.id}/replay`)
      .then((r) => r);
    await new Promise((resolve) => setTimeout(resolve, 300));
    // The replay has not saved the case, and has read it only for its preflight (outside the lock).
    expect(ops.filter((o) => o.op === "save")).toHaveLength(0);
    expect(ops.filter((o) => o.section !== undefined)).toHaveLength(0);
    release();
    await held;

    expect((await replay).status).toBe(200);
    const stored = await load("c1");
    expect(stored.forensicTimeline.map((e) => e.id).sort()).toEqual(["e-new", "e1"]);
    expect(stored.forensicTimeline.find((e) => e.id === "e1")?.severity).toBe("High");
    // The child run describes the state it saved, which includes the event written meanwhile.
    const child = (await runStore.list("c1")).find((r) => r.parentRunId === run.id);
    expect(child?.input.eventIds).toContain("e-new");
  });
});
