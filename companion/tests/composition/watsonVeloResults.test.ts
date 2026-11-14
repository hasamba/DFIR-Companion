import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import { WatsonChatStore } from "../../src/analysis/ai/watson/chatStore.js";
import type { WatsonRoundInput } from "../../src/analysis/ai/watson/round.js";
import { WatsonReactor } from "../../src/analysis/ai/watson/reactor.js";
import type { WatsonChat, WatsonVeloLaunchProposal } from "../../src/analysis/ai/watson/types.js";
import { WATSON_WATCH_DEFAULT_MS } from "../../src/analysis/ai/watson/velo/launchWatch.js";
import { fillOutcomeByFlow, type HuntOutcome } from "../../src/analysis/huntOutcomes.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";
import { createWatsonCaseEvents } from "../../src/composition/watsonCaseEvents.js";
import {
  noteWatsonFleetResult,
  WatsonFlowWatcher,
  type WatsonFlowWatcherDeps,
} from "../../src/composition/watsonVeloResults.js";
import { readWatsonFlowRows } from "../../src/composition/watsonVeloResultsWiring.js";
import { CaseStore } from "../../src/storage/caseStore.js";

// Task 5: results of Watson's own launches come back as a `hunt` case event — a fleet hunt from the
// existing collect, a single-host collection from a durable watch that survives a restart and never
// ingests or notifies twice.

const CASE = "c1";
const HOST = "web01.example.com";
const T0 = Date.parse("2026-11-14T10:00:00.000Z");

let store: CaseStore;
let chatStore: WatsonChatStore;

function launch(over: Partial<WatsonVeloLaunchProposal>): WatsonVeloLaunchProposal {
  return {
    id: "wp-hunt",
    turnId: "t1",
    kind: "velo_launch",
    status: "applied",
    targetId: "fp1",
    mode: "hunt",
    title: "Process listing",
    vql: "SELECT * FROM pslist()",
    fingerprint: "fp1",
    fingerprints: ["fp1"],
    launched: { huntId: "H.SAMPLE1", at: new Date(T0).toISOString(), by: "Dana Analyst" },
    ...over,
  };
}

const collection = (over: Partial<WatsonVeloLaunchProposal> = {}): WatsonVeloLaunchProposal =>
  launch({
    id: "wp-coll",
    mode: "collection",
    hostname: HOST,
    launched: { flowId: "F.SAMPLE", clientId: "C.webserver1", at: new Date(T0).toISOString(), by: "Dana" },
    watch: { deadline: new Date(T0 + WATSON_WATCH_DEFAULT_MS).toISOString(), state: "watching" },
    ...over,
  });

async function seed(...proposals: WatsonVeloLaunchProposal[]): Promise<void> {
  await chatStore.update(CASE, (c) => ({
    ...c,
    analystEngaged: true,
    proposals: [...c.proposals, ...proposals],
  }));
}

const chat = (): Promise<WatsonChat> => chatStore.load(CASE);
const huntEvents = async () => (await chat()).pendingCaseEvents.filter((e) => e.kind === "hunt");
const stored = async (id: string) =>
  (await chat()).proposals.find((p) => p.id === id) as WatsonVeloLaunchProposal;

const heldRow = (id: string): ForensicEvent =>
  ({
    id,
    timestamp: "2026-11-14T09:00:00Z",
    host: HOST,
    severity: "High",
    description: "lsass dump",
  }) as unknown as ForensicEvent;

/** A manual timer queue: tests run the next poll themselves. */
function timers() {
  const queue: (() => void)[] = [];
  return {
    queue,
    set: (fn: () => void) => {
      queue.push(fn);
      return { unref() {} } as unknown as ReturnType<typeof setTimeout>;
    },
    async runOne(w: WatsonFlowWatcher) {
      queue.shift()?.();
      await w.settled();
    },
    async runAll(w: WatsonFlowWatcher) {
      while (queue.length) {
        queue.shift()!();
        await w.settled();
      }
    },
  };
}

interface Harness {
  deps: WatsonFlowWatcherDeps;
  watcher: WatsonFlowWatcher;
  ingests: number;
  fills: { flowId: string; resultRows?: number }[];
  wakes: number;
  states: string[];
  clock: { now: number };
  t: ReturnType<typeof timers>;
}

function harness(over: Partial<WatsonFlowWatcherDeps> = {}, states = ["RUNNING", "FINISHED"]): Harness {
  const h = {
    ingests: 0,
    fills: [],
    wakes: 0,
    states: [...states],
    clock: { now: T0 + 60_000 },
    t: timers(),
  } as unknown as Harness;
  h.deps = {
    chatStore,
    velo: () => ({
      flowStatus: async () => ({ state: h.states.shift() ?? "FINISHED", error: "bad plugin arg", rows: 0 }),
    }),
    readRows: async () => ({ text: '{"Custom.Collect.Companion.X/Pivot0":[]}', rows: 3 }),
    ingest: async () => {
      h.ingests++;
      return {
        paste: {
          id: "wf-1",
          storedName: "0003_velo-flow_F.SAMPLE.json",
          filename: "velo-flow_F.SAMPLE.json",
          bytes: 40,
          lines: 1,
          at: "x",
        },
        ingest: { kind: "velociraptor", rows: 3, held: [heldRow("e1")], added: 1 },
      };
    },
    fillOutcome: async (_c, ref, r) => {
      h.fills.push({ flowId: ref.flowId, resultRows: r.resultRows });
    },
    isFrozen: async () => false,
    wake: () => {
      h.wakes++;
    },
    now: () => h.clock.now,
    setTimer: h.t.set,
    ...over,
  };
  h.watcher = new WatsonFlowWatcher(h.deps);
  return h;
}

function reactorFor(rounds: WatsonRoundInput[]) {
  const fires: (() => void)[] = [];
  const reactor = new WatsonReactor({
    chatStore,
    runRound: async (_c, input) => {
      rounds.push(input);
      return chat();
    },
    isAiEnabled: async () => true,
    isSynthesisBusy: () => false,
    isFrozen: async () => false,
    delayMs: () => 60_000,
    setTimer: ((fn: () => void) => {
      fires.push(fn);
      return { unref() {} };
    }) as unknown as typeof setTimeout,
  });
  return {
    reactor,
    async fire() {
      await chatStore.update(CASE, (c) => c); // queued after every note already written
      fires.splice(0).at(-1)?.();
      await reactor.settled();
    },
  };
}

beforeEach(async () => {
  store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-watson-results-")));
  await store.createCase({ caseId: CASE, name: "n", investigator: "i", aiProvider: null });
  chatStore = new WatsonChatStore(store);
});

describe("a Watson fleet hunt's collect", () => {
  it("with rows: one hunt event after the import event, and the reaction writes nothing", async () => {
    await seed(launch({}));
    const rounds: WatsonRoundInput[] = [];
    const r = reactorFor(rounds);
    const events = createWatsonCaseEvents(chatStore);
    events.attach(r.reactor);
    events.importChanged(CASE); // the collect's onImportMeta comes first
    await noteWatsonFleetResult(chatStore, events.wake, CASE, { huntId: "H.SAMPLE1", rows: 3, added: 2 });
    expect((await huntEvents()).map((e) => e.text)).toEqual([
      "Watson's hunt Process listing finished: 3 rows, 2 new events",
    ]);
    await r.fire();
    expect(rounds).toHaveLength(1);
    expect(rounds[0]).toMatchObject({ reaction: true, allowWrites: false });
  });

  it("that found nothing still wakes Watson, and its reaction may propose writes", async () => {
    await seed(launch({}));
    const rounds: WatsonRoundInput[] = [];
    const r = reactorFor(rounds);
    await noteWatsonFleetResult(chatStore, (id) => r.reactor.wake(id), CASE, {
      huntId: "H.SAMPLE1",
      rows: 0,
      added: 0,
    });
    expect((await huntEvents()).map((e) => e.text)).toEqual(["Watson's hunt Process listing found nothing"]);
    await r.fire();
    expect(rounds[0]).toMatchObject({ reaction: true, allowWrites: true });
  });

  it("notes nothing for a hunt Watson did not launch", async () => {
    await seed(launch({}));
    let wakes = 0;
    await noteWatsonFleetResult(chatStore, () => wakes++, CASE, { huntId: "H.OTHER9", rows: 5, added: 5 });
    expect(await huntEvents()).toEqual([]);
    expect(wakes).toBe(0);
  });

  it("notes a straggler re-collect of the same hunt only once", async () => {
    await seed(launch({}));
    const note = (rows: number) =>
      noteWatsonFleetResult(chatStore, () => {}, CASE, { huntId: "H.SAMPLE1", rows, added: 0 });
    await note(2);
    await note(4);
    expect(await huntEvents()).toHaveLength(1);
    expect((await stored("wp-hunt")).watch).toMatchObject({ state: "finished", notified: true, rows: 2 });
  });
});

describe("a Watson single-host collection", () => {
  it("finishing: rows ingested once with held promotions, outcome filled, one hunt event", async () => {
    await seed(collection());
    const h = harness();
    h.watcher.watch(CASE, "wp-coll");
    await h.t.runAll(h.watcher); // RUNNING, then FINISHED
    expect(h.ingests).toBe(1);
    expect(h.fills).toEqual([{ flowId: "F.SAMPLE", resultRows: 3 }]);
    const c = await chat();
    const promote = c.proposals.filter((p) => p.kind === "event_promote");
    expect(promote).toHaveLength(1);
    expect(promote[0].status).toBe("pending");
    expect(c.pastes.map((p) => p.id)).toEqual(["wf-1"]);
    const events = await huntEvents();
    expect(events.map((e) => e.text)).toEqual([
      "Watson's hunt Process listing finished: 3 rows, 1 new event",
    ]);
    expect(events[0].proposalIds).toEqual([promote[0].id]);
    expect((await stored("wp-coll")).watch).toMatchObject({
      state: "finished",
      ingested: true,
      notified: true,
    });
    expect(h.wakes).toBe(1);
  });

  it("its reaction may propose writes and carries the held proposals", async () => {
    await seed(collection());
    const rounds: WatsonRoundInput[] = [];
    const r = reactorFor(rounds);
    const h = harness({ wake: (id) => r.reactor.wake(id) }, ["FINISHED"]);
    h.watcher.watch(CASE, "wp-coll");
    await h.t.runAll(h.watcher);
    await r.fire();
    const ids = (await chat()).proposals.filter((p) => p.kind === "event_promote").map((p) => p.id);
    expect(rounds[0]).toMatchObject({ reaction: true, allowWrites: true, heldProposalIds: ids });
  });

  it("that returns no rows ingests nothing and says it found nothing", async () => {
    await seed(collection());
    const h = harness({ readRows: async () => ({ text: "{}", rows: 0 }) }, ["FINISHED"]);
    h.watcher.watch(CASE, "wp-coll");
    await h.t.runAll(h.watcher);
    expect(h.ingests).toBe(0);
    expect((await huntEvents()).map((e) => e.text)).toEqual(["Watson's hunt Process listing found nothing"]);
  });

  it("timing out says so, once", async () => {
    await seed(collection());
    const h = harness({}, ["RUNNING", "RUNNING", "RUNNING"]);
    h.watcher.watch(CASE, "wp-coll");
    await h.t.runOne(h.watcher); // still RUNNING: polled again later
    expect(h.t.queue).toHaveLength(1);
    h.clock.now = T0 + WATSON_WATCH_DEFAULT_MS + 1;
    await h.t.runAll(h.watcher);
    await harness().watcher.resume(CASE); // a later restart sends nothing more
    expect((await huntEvents()).map((e) => e.text)).toEqual([
      "Watson's hunt Process listing timed out: no result within 30 minutes",
    ]);
    expect((await stored("wp-coll")).watch?.state).toBe("timeout");
    expect(h.ingests).toBe(0);
  });

  it("a flow that errors on the endpoint says so", async () => {
    await seed(collection());
    const h = harness({}, ["ERROR"]);
    h.watcher.watch(CASE, "wp-coll");
    await h.t.runAll(h.watcher);
    expect((await huntEvents()).map((e) => e.text)).toEqual([
      "Watson's hunt Process listing failed: bad plugin arg",
    ]);
  });

  it("a restart mid-watch resumes the watch and ingests once", async () => {
    await seed(collection());
    const first = harness({}, ["RUNNING"]);
    first.watcher.watch(CASE, "wp-coll");
    await first.t.runOne(first.watcher); // one RUNNING poll, then the server stops
    first.watcher.stop();
    const second = harness({}, ["FINISHED"]);
    await second.watcher.resume(CASE);
    expect(second.t.queue).toHaveLength(1);
    await second.t.runAll(second.watcher);
    expect(first.ingests + second.ingests).toBe(1);
    expect(await huntEvents()).toHaveLength(1);
  });

  it("a restart after the deadline sends one timeout event", async () => {
    await seed(collection());
    const late = () => {
      const h = harness();
      h.clock.now = T0 + WATSON_WATCH_DEFAULT_MS + 5;
      return h;
    };
    await late().watcher.resume(CASE);
    await late().watcher.resume(CASE);
    expect((await huntEvents()).map((e) => e.text)).toEqual([
      "Watson's hunt Process listing timed out: no result within 30 minutes",
    ]);
  });

  it("a crash after the ingest but before the event notifies once and never ingests again", async () => {
    await seed(collection());
    const crashed = harness(
      {
        fillOutcome: async () => {
          throw new Error("server stopped");
        },
      },
      ["FINISHED"],
    );
    crashed.watcher.watch(CASE, "wp-coll");
    await crashed.t.runAll(crashed.watcher);
    expect(crashed.ingests).toBe(1);
    expect(await huntEvents()).toEqual([]);
    const after = harness();
    await after.watcher.resume(CASE);
    await after.watcher.resume(CASE);
    expect(after.ingests).toBe(0);
    expect(after.fills).toEqual([{ flowId: "F.SAMPLE", resultRows: 3 }]);
    expect(await huntEvents()).toHaveLength(1);
  });

  it("a claim with no saved result is reported failed once, never re-read", async () => {
    await seed(
      collection({
        watch: {
          deadline: new Date(T0 + WATSON_WATCH_DEFAULT_MS).toISOString(),
          state: "watching",
          ingested: true,
        },
      }),
    );
    const h = harness();
    await h.watcher.resume(CASE);
    await h.watcher.resume(CASE);
    expect(h.ingests).toBe(0);
    const events = await huntEvents();
    expect(events).toHaveLength(1);
    expect(events[0].text).toMatch(/^Watson's hunt Process listing failed: Watson was interrupted/);
  });

  it("refuses to ingest into a closed case", async () => {
    await seed(collection());
    const h = harness({ isFrozen: async () => true }, ["FINISHED"]);
    h.watcher.watch(CASE, "wp-coll");
    await h.t.runAll(h.watcher);
    expect(h.ingests).toBe(0);
    expect((await huntEvents())[0].text).toBe("Watson's hunt Process listing failed: the case is closed");
  });
});

describe("reading a collection's rows", () => {
  it("reads every Pivot source of an unqualified artifact and stamps the host", async () => {
    const reads: { artifact: string; sources: string[] }[] = [];
    const client = {
      getFlowInfo: async () => ({ artifacts: ["Custom.Collect.Companion.X"], hostname: "" }),
      collectionResults: async (_c: string, _f: string, artifact: string, sources: string[] = []) => {
        reads.push({ artifact, sources });
        return {
          rows: [{ Name: "lsass.exe" }, { Name: "cmd.exe", Fqdn: "db01.example.com" }],
          total: 2,
          truncated: false,
        };
      },
    };
    const p = collection({ vql: "SELECT * FROM pslist()\n\nSELECT * FROM netstat()" });
    const out = await readWatsonFlowRows(client, p);
    expect(reads).toEqual([{ artifact: "Custom.Collect.Companion.X", sources: ["Pivot0", "Pivot1"] }]);
    expect(out.rows).toBe(2);
    expect(JSON.parse(out.text)).toEqual({
      "Custom.Collect.Companion.X": [
        { Name: "lsass.exe", Fqdn: HOST },
        { Name: "cmd.exe", Fqdn: "db01.example.com" },
      ],
    });
  });
});

describe("fillOutcomeByFlow", () => {
  const base: HuntOutcome = {
    id: "o1",
    title: "Process listing",
    status: "deployed",
    flowId: "F.SAMPLE",
    clientId: "C.webserver1",
  } as HuntOutcome;
  const result = { resultRows: 3, addedEvents: 2, addedIocs: 0, collectedAt: "2026-11-14T10:05:00Z" };

  it("fills the matching collection and leaves a collected one alone", () => {
    const [filled] = fillOutcomeByFlow([base], { flowId: "F.SAMPLE", clientId: "C.webserver1" }, result);
    expect(filled).toMatchObject({ status: "collected", foundEvidence: true, resultRows: 3, addedEvents: 2 });
    expect(filled.huntId).toBeUndefined();
    const again = fillOutcomeByFlow([filled], { flowId: "F.SAMPLE", clientId: "C.webserver1" }, result);
    expect(again[0].addedEvents).toBe(2);
    expect(fillOutcomeByFlow([base], { flowId: "F.SAMPLE", clientId: "C.other1" }, result)[0]).toBe(base);
  });
});
