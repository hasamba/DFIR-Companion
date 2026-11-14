import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import { WatsonChatStore } from "../../src/analysis/ai/watson/chatStore.js";
import type { WatsonChat, WatsonVeloLaunchProposal } from "../../src/analysis/ai/watson/types.js";
import { WATSON_WATCH_DEFAULT_MS } from "../../src/analysis/ai/watson/velo/launchWatch.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";
import { fileIngestStage } from "../../src/composition/watsonFlowStage.js";
import {
  NO_LAUNCH_SERVER,
  WATSON_WATCH_GRACE_MS,
  WatsonFlowWatcher,
  type WatsonFlowWatcherDeps,
} from "../../src/composition/watsonVeloResults.js";
import { createAppWatsonFlowWatcher } from "../../src/composition/watsonVeloResultsWiring.js";
import type { RouteContext } from "../../src/routes/context.js";
import { CaseStore } from "../../src/storage/caseStore.js";

// Final review G6 (reads go to the server set the collection was launched on), G7 (an ingest whose
// chat save failed is finished from a durable stage, never lost and never re-ingested) and G18
// (a timeout after failed status reads says the results may still be in Velociraptor).

const CASE = "c1";
const HOST = "web01.example.com";
const T0 = Date.parse("2026-11-14T10:00:00.000Z");
const DEADLINE = new Date(T0 + WATSON_WATCH_DEFAULT_MS).toISOString();

let store: CaseStore;
let chatStore: WatsonChatStore;

const collection = (launched: Partial<NonNullable<WatsonVeloLaunchProposal["launched"]>> = {}) =>
  ({
    id: "wp-coll",
    turnId: "t1",
    kind: "velo_launch",
    status: "applied",
    targetId: "fp1",
    mode: "collection",
    hostname: HOST,
    title: "Process listing",
    vql: "SELECT * FROM pslist()",
    fingerprint: "fp1",
    fingerprints: ["fp1"],
    launched: {
      flowId: "F.SAMPLE",
      clientId: "C.webserver1",
      at: new Date(T0).toISOString(),
      by: "Dana",
      ...launched,
    },
    watch: { deadline: DEADLINE, state: "watching" },
  }) as WatsonVeloLaunchProposal;

const seed = (p: WatsonVeloLaunchProposal) =>
  chatStore.update(CASE, (c) => ({ ...c, analystEngaged: true, proposals: [...c.proposals, p] }));
const huntTexts = async () =>
  (await chatStore.load(CASE)).pendingCaseEvents.filter((e) => e.kind === "hunt").map((e) => e.text);
const stored = async () =>
  (await chatStore.load(CASE)).proposals.find((p) => p.id === "wp-coll") as WatsonVeloLaunchProposal;

const heldRow = {
  id: "e1",
  timestamp: "2026-11-14T09:00:00Z",
  host: HOST,
  severity: "High",
  description: "x",
};

beforeEach(async () => {
  store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-watson-results-rec-")));
  await store.createCase({ caseId: CASE, name: "n", investigator: "i", aiProvider: null });
  chatStore = new WatsonChatStore(store);
});

/** A chat store whose save of a FINISHED watch fails `failures` times. */
function failingResultSave(failures: number): WatsonFlowWatcherDeps["chatStore"] {
  let left = failures;
  return {
    load: (id) => chatStore.load(id),
    update: (id, fn) =>
      chatStore.update(id, async (c: WatsonChat) => {
        const next = await fn(c);
        const done = next.proposals.some((p) => p.kind === "velo_launch" && p.watch?.state === "finished");
        if (done && left > 0) {
          left--;
          throw new Error("EIO: disk full");
        }
        return next;
      }),
  };
}

function watcher(over: Partial<WatsonFlowWatcherDeps>, counts: { ingests: number }, now = T0 + 60_000) {
  const queue: (() => void)[] = [];
  const w = new WatsonFlowWatcher({
    chatStore,
    velo: () => ({ flowStatus: async () => ({ state: "FINISHED", error: "", rows: 3 }) }),
    readRows: async () => ({ text: "{}", rows: 3 }),
    ingest: async () => {
      counts.ingests++;
      return {
        paste: { id: "wf-1", storedName: "0003_x.json", filename: "x.json", bytes: 2, lines: 1, at: "x" },
        ingest: { kind: "velociraptor", rows: 3, held: [heldRow as unknown as ForensicEvent], added: 1 },
      };
    },
    fillOutcome: async () => {},
    isFrozen: async () => false,
    wake: () => {},
    now: () => now,
    setTimer: (fn) => {
      queue.push(fn);
      return { unref() {} } as unknown as ReturnType<typeof setTimeout>;
    },
    ...over,
  });
  const runAll = async () => {
    while (queue.length) {
      queue.shift()!();
      await w.settled();
    }
  };
  return { w, runAll, queue };
}

describe("G7 — a failed result save after the ingest", () => {
  it("is finished from the stage on retry: held promotions kept, rows ingested once", async () => {
    await seed(collection());
    const counts = { ingests: 0 };
    const { w, runAll } = watcher({ chatStore: failingResultSave(1), stage: fileIngestStage(store) }, counts);
    w.watch(CASE, "wp-coll");
    await runAll();
    expect(counts.ingests).toBe(1);
    const p = await stored();
    expect(p.watch?.state).toBe("finished");
    expect(p.watch?.proposalIds).toHaveLength(1);
    expect(await huntTexts()).toEqual(["Watson's hunt Process listing finished: 3 rows, 1 new event"]);
  });

  it("is finished from the stage after a restart, once", async () => {
    await seed(collection());
    const counts = { ingests: 0 };
    const first = watcher({ chatStore: failingResultSave(1), stage: fileIngestStage(store) }, counts);
    first.w.watch(CASE, "wp-coll");
    first.queue.shift()!(); // the tick that ingests, then fails the save
    await first.w.settled();
    first.w.stop(); // the server stops before the retry
    expect((await stored()).watch?.ingesting).toBe(true);
    const second = watcher({ stage: fileIngestStage(store) }, counts);
    await second.w.resume(CASE);
    await second.w.resume(CASE);
    expect(counts.ingests).toBe(1);
    expect((await stored()).watch?.proposalIds).toHaveLength(1);
    expect(await huntTexts()).toHaveLength(1);
  });
});

describe("G18 — a timeout after failed status reads", () => {
  it("says Watson could not read the status and the results may be in Velociraptor", async () => {
    await seed(collection());
    const late = T0 + WATSON_WATCH_DEFAULT_MS + WATSON_WATCH_GRACE_MS + 5;
    const failing = { flowStatus: async () => Promise.reject(new Error("connection refused")) };
    const { w } = watcher({ velo: () => failing }, { ingests: 0 }, late);
    await w.resume(CASE);
    const [text] = await huntTexts();
    expect(text).toMatch(/timed out: Watson could not read the collection's status/);
    expect(text).toMatch(/The results are in Velociraptor and may not have been imported/);
    expect(text).not.toMatch(/failed: Watson could not/);
  });
});

describe("G6 / G20 — the app's watcher (real wiring) reads from the launch's server set", () => {
  const calls: string[] = [];
  const client = (name: string) => ({
    flowStatus: async () => {
      calls.push(name);
      return { state: "RUNNING", error: "", rows: 0 };
    },
  });
  const ok = (setId: string, name: string) => ({
    ok: true as const,
    servers: { setId, setName: setId, velociraptor: client(name) },
  });
  const ctxWith = (sets: Record<string, ReturnType<typeof ok>>) =>
    ({
      store,
      options: { watsonChatStore: chatStore },
      serverClients: {
        forCase: () => ok("set-b", "B"), // the case was MOVED to set-b mid-collection
        forDefault: () => ok("set-b", "B"),
        forSet: (id: string) => sets[id] ?? { ok: false as const, status: 409, error: "no such set" },
        forInput: () => ({ servers: {}, errors: {} }),
        invalidate: () => undefined,
      },
    }) as unknown as RouteContext;

  beforeEach(() => {
    calls.length = 0;
  });

  it("polls the set the collection was launched on, not the case's current set", async () => {
    await seed(collection({ serverSetId: "set-a" }));
    await chatStore.update(CASE, (c) => ({
      ...c,
      proposals: c.proposals.map((p) =>
        p.kind === "velo_launch"
          ? { ...p, watch: { deadline: new Date(0).toISOString(), state: "watching" as const } }
          : p,
      ),
    }));
    const w = createAppWatsonFlowWatcher(ctxWith({ "set-a": ok("set-a", "A") }), () => {})!;
    await w.resume(CASE);
    w.stop();
    expect(calls).toEqual(["A"]);
  });

  it("fails with the Velociraptor pointer when the launch's set no longer exists", async () => {
    await seed(collection({ serverSetId: "set-gone" }));
    await chatStore.update(CASE, (c) => ({
      ...c,
      proposals: c.proposals.map((p) =>
        p.kind === "velo_launch"
          ? { ...p, watch: { deadline: new Date(0).toISOString(), state: "watching" as const } }
          : p,
      ),
    }));
    const w = createAppWatsonFlowWatcher(ctxWith({}), () => {})!;
    await w.resume(CASE);
    w.stop();
    expect(calls).toEqual([]);
    const [text] = await huntTexts();
    expect(text).toContain(NO_LAUNCH_SERVER);
    expect(text).toContain("The results are in Velociraptor");
  });
});
