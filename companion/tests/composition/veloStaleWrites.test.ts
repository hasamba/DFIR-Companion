import { describe, it, expect, beforeEach, vi } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { VeloMonitorStore, type VeloMonitor } from "../../src/analysis/veloMonitorStore.js";
import { VeloHuntStore, type VeloHuntJob } from "../../src/analysis/veloHuntStore.js";
import { createVeloMonitors } from "../../src/composition/veloMonitors.js";
import {
  createVeloHuntStatusTimers,
  INTERRUPTED_COLLECT_MESSAGE,
} from "../../src/composition/veloHuntStatusTimers.js";
import { veloServerClients } from "../helpers/serverClientsStub.js";
import { pollFor, pollBudget, POLL_TIMEOUT_MS } from "../helpers/poll.js";
import type { AppOptions } from "../../src/composition/appOptions.js";

// #2403: a background poll waits on the network, then used to save the whole copy it read before the
// wait — undoing a Stop pressed meanwhile (the monitor came back after a restart) and wiping a
// collect's status. These drive the real composition modules with a Velociraptor client whose answers
// the test releases by hand, so the analyst action lands exactly while the poll is in flight.

function gate<T>() {
  let release!: (v: T) => void;
  const promise = new Promise<T>((r) => (release = r));
  return { promise, release };
}

let store: CaseStore;
beforeEach(async () => {
  store = new CaseStore(await mkdtemp(join(tmpdir(), "velo-stale-")));
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
});

const MON: VeloMonitor = {
  id: "C.1__Windows.Events.ProcessCreation",
  clientId: "C.1",
  artifact: "Windows.Events.ProcessCreation",
  pollSeconds: 30,
  cursor: 1_000,
  status: "active",
  createdAt: "2026-11-08T00:00:00.000Z",
  addedEvents: 5,
  polls: 2,
};

function monitorsWith(read: () => Promise<unknown[]>, monStore: VeloMonitorStore) {
  let reads = 0;
  const client = {
    monitorResults: async () => {
      reads++;
      return { rows: await read() };
    },
  };
  const options = {
    veloMonitorStore: monStore,
    serverClients: veloServerClients(client),
  } as unknown as AppOptions;
  const m = createVeloMonitors({
    store,
    options,
    ingestStreamed: async () => ({ storedName: "x", addedEvents: 1, addedIocs: 0, analyzed: false }),
  });
  return { m, reads: () => reads };
}

describe("live monitor poll vs. analyst actions (#2403)", () => {
  it("a Stop pressed while a poll is in flight stays stopped, and the poll's progress is kept", async () => {
    const monStore = new VeloMonitorStore(store);
    await monStore.upsert("c1", MON);
    const g = gate<unknown[]>();
    const { m } = monitorsWith(() => g.promise, monStore);
    const polling = m.pollVeloMonitor("c1", MON.id);
    await new Promise((r) => setTimeout(r, 20));
    m.stopVeloMonitorTimer("c1", MON.id);
    await monStore.update("c1", MON.id, (cur) => ({ ...cur, status: "stopped" }));
    g.release([{ Time: 2_000 }]);
    await polling;
    const after = await monStore.get("c1", MON.id);
    expect(after?.status).toBe("stopped");
    expect(after!.cursor).toBeGreaterThan(MON.cursor);
    expect(after?.addedEvents).toBe(6);
    expect(after?.polls).toBe(3);
  });

  it("a monitor deleted while a poll is in flight is not written back", async () => {
    const monStore = new VeloMonitorStore(store);
    await monStore.upsert("c1", MON);
    const g = gate<unknown[]>();
    const { m } = monitorsWith(() => g.promise, monStore);
    const polling = m.pollVeloMonitor("c1", MON.id);
    await new Promise((r) => setTimeout(r, 20));
    await monStore.remove("c1", MON.id);
    g.release([]);
    await polling;
    expect(await monStore.get("c1", MON.id)).toBeNull();
  });

  it("Poll now during a running poll joins it instead of reading the same window twice", async () => {
    const monStore = new VeloMonitorStore(store);
    await monStore.upsert("c1", MON);
    const g = gate<unknown[]>();
    const { m, reads } = monitorsWith(() => g.promise, monStore);
    const a = m.pollVeloMonitor("c1", MON.id);
    await new Promise((r) => setTimeout(r, 20));
    const b = m.pollVeloMonitor("c1", MON.id);
    g.release([]);
    await Promise.all([a, b]);
    expect(reads()).toBe(1);
    expect((await monStore.get("c1", MON.id))?.polls).toBe(3);
  });
});

const JOB: VeloHuntJob = {
  bundleId: "b",
  bundleName: "B",
  artifacts: ["Windows.System.Pslist"],
  huntId: "H.1",
  launchedAt: "2026-11-08T00:00:00.000Z",
  waitMinutes: 10,
  collectAt: "2026-11-08T00:10:00.000Z",
  status: "running",
};

function huntTimers(
  huntStore: VeloHuntStore,
  huntStatus: () => Promise<unknown>,
  collecting = new Set<string>(),
) {
  const collects: string[] = [];
  const options = {
    veloHuntStore: huntStore,
    serverClients: veloServerClients({ huntStatus }),
  } as unknown as AppOptions;
  const t = createVeloHuntStatusTimers({
    store,
    options,
    startVeloHuntCollect: (_c, h) => collects.push(h),
    isCollecting: (_c, h) => collecting.has(h),
  });
  return { t, collects };
}

describe("hunt status poll vs. a collect (#2403)", () => {
  it("a collect that starts while a status poll is in flight keeps its status and phase", async () => {
    const huntStore = new VeloHuntStore(store);
    await huntStore.upsert("c1", JOB);
    const g = gate<unknown>();
    const { t, collects } = huntTimers(huntStore, () => g.promise);
    const polling = t.pollVeloHuntStatus("c1", JOB.huntId);
    await new Promise((r) => setTimeout(r, 20));
    await huntStore.update("c1", JOB.huntId, (cur) => ({
      ...cur,
      status: "collecting",
      collectPhase: "fetching",
    }));
    g.release(null); // a stale "deleted" answer
    await polling;
    expect(await huntStore.get("c1", JOB.huntId)).toMatchObject({
      status: "collecting",
      collectPhase: "fetching",
    });
    expect(collects).toEqual([]);
  });

  it("a stale terminal answer does not start a second collect while one is live", async () => {
    const huntStore = new VeloHuntStore(store);
    await huntStore.upsert("c1", JOB);
    const live = new Set<string>();
    const g = gate<unknown>();
    const { t, collects } = huntTimers(huntStore, () => g.promise, live);
    const polling = t.pollVeloHuntStatus("c1", JOB.huntId);
    await new Promise((r) => setTimeout(r, 20));
    live.add(JOB.huntId); // "Collect now" claimed it; the first status write has not happened yet
    g.release({ state: "STOPPED" });
    await polling;
    expect(collects).toEqual([]);
  });

  it("a status change with nothing in the way is still recorded", async () => {
    const huntStore = new VeloHuntStore(store);
    await huntStore.upsert("c1", JOB);
    const { t } = huntTimers(huntStore, async () => {
      throw new Error("ECONNREFUSED");
    });
    await t.pollVeloHuntStatus("c1", JOB.huntId);
    expect((await huntStore.get("c1", JOB.huntId))?.status).toBe("unreachable");
    t.stopVeloHuntStatusPollsForCase("c1");
  });
});

describe("hunts left mid-collect by a dead process (#2403)", () => {
  it("startup marks them interrupted, and leaves a live collect and running hunts alone", async () => {
    const huntStore = new VeloHuntStore(store);
    await huntStore.upsert("c1", {
      ...JOB,
      huntId: "H.dead",
      status: "collecting",
      collectPhase: "importing",
      collectRows: 9,
    });
    await huntStore.upsert("c1", {
      ...JOB,
      huntId: "H.live",
      status: "collecting",
      collectPhase: "fetching",
    });
    await huntStore.upsert("c1", { ...JOB, huntId: "H.run", status: "imported" });
    const { t } = huntTimers(huntStore, async () => ({ state: "RUNNING" }), new Set(["H.live"]));
    await t.resumeVeloHuntStatusPolls({ startup: true });
    const dead = await huntStore.get("c1", "H.dead");
    expect(dead).toMatchObject({ status: "error", error: INTERRUPTED_COLLECT_MESSAGE });
    expect(dead?.collectPhase).toBeUndefined();
    expect(dead?.collectRows).toBeUndefined();
    expect(await huntStore.get("c1", "H.live")).toMatchObject({
      status: "collecting",
      collectPhase: "fetching",
    });
    t.stopVeloHuntStatusPollsForCase("c1");
  });

  it("reconnect (no startup flag) never marks a collecting hunt", async () => {
    const huntStore = new VeloHuntStore(store);
    await huntStore.upsert("c1", { ...JOB, status: "collecting", collectPhase: "importing" });
    const { t } = huntTimers(huntStore, async () => ({ state: "RUNNING" }));
    await t.resumeVeloHuntStatusPolls();
    expect((await huntStore.get("c1", JOB.huntId))?.status).toBe("collecting");
  });
});

describe("overlapping hunt status polls (#2403)", () => {
  // #2516: this test used to time out at random in CI. The fake client hands out its gates in the
  // order the polls ARRIVE, and the test released gate 0 and then awaited poll `a` — but each poll
  // first reads the hunt file, and nothing orders two concurrent reads. When `b`'s read won, `b` held
  // gate 0, `a` sat on gate 1 (released only after `await a`) and the test deadlocked. The product
  // code is symmetric — whichever poll records the change owns the re-arm — so the fix is here:
  // start `b` only once `a` is on the network, and wait on wall-clock deadlines, not loop counts.
  it(
    "a stale poll does not cancel the re-arm an overlapping poll just made",
    async () => {
      const huntStore = new VeloHuntStore(store);
      await huntStore.upsert("c1", JOB);
      const gates = [gate<unknown>(), gate<unknown>()];
      let call = 0;
      const { t } = huntTimers(huntStore, async () => {
        const mine = call++;
        if (mine >= 2) return { state: "RUNNING" };
        const answer = await gates[mine].promise;
        if (mine === 0) throw new Error("ECONNREFUSED"); // A: running -> unreachable
        return answer;
      });
      const calls = (n: number) => async () => (call >= n ? true : undefined);
      const budget = { timeoutMs: pollBudget(3_000) };
      // The 300 s ceiling, so the re-arm can never fire by itself inside the test — only when the test
      // fires it. shouldAdvanceTime keeps every OTHER timer working in real time: atomicWrite's retry
      // sleep on a transient Windows lock and pollFor's own interval would otherwise hang forever.
      vi.stubEnv("DFIR_VELO_HUNT_POLL_S", "300");
      vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"], shouldAdvanceTime: true });
      try {
        t.scheduleVeloHuntStatusPoll("c1", JOB.huntId);
        const a = t.pollVeloHuntStatus("c1", JOB.huntId); // the scheduled tick
        await pollFor("poll A asking Velociraptor", calls(1), budget);
        const b = t.pollVeloHuntStatus("c1", JOB.huntId); // "Poll now", also started from "running"
        await pollFor("poll B asking Velociraptor", calls(2), budget);
        gates[0].release(undefined);
        await a; // recorded "unreachable" and re-armed
        gates[1].release({ state: "RUNNING" }); // B is stale now: the row is no longer "running"
        await b;
        expect((await huntStore.get("c1", JOB.huntId))?.status).toBe("unreachable");
        expect(vi.getTimerCount()).toBe(1);
        // The chain must still be alive: the next tick fires, polls, records "running" and re-arms.
        await vi.advanceTimersToNextTimerAsync();
        // After the write no retry sleep can be pending, and the re-arm runs right after the write —
        // so "running" on disk plus exactly one timer means the third poll finished and re-armed.
        await pollFor(
          "the next tick recording running and re-arming",
          async () =>
            (await huntStore.get("c1", JOB.huntId))?.status === "running" && vi.getTimerCount() === 1
              ? true
              : undefined,
          budget,
        );
        expect(call).toBe(3);
      } finally {
        t.stopVeloHuntStatusPollsForCase("c1");
        vi.useRealTimers();
        vi.unstubAllEnvs();
      }
    },
    POLL_TIMEOUT_MS * 2,
  );
});
