/**
 * Timer lifecycle for the three background pollers createApp owns (#416).
 *
 * WHY THIS FILE EXISTS. The safety net around server.ts is good at shape and bad at time:
 * routeInventory.test.ts records every Express layer, check:boundaries records every import edge,
 * and ~6,800 tests cover request/response behaviour — but NONE of them can tell whether a poll is
 * still scheduled. That is exactly the property the createApp decomposition is most likely to
 * break, because a lost `scheduleX()` call, a `clearTimeout` on the wrong key, or a resume sweep
 * that reads the wrong status all fail SILENTLY: monitoring simply stops, and the next thing that
 * notices is an analyst asking why the dashboard went quiet.
 *
 * So each test asserts one of four lifecycle properties, and nothing else:
 *   ARMED     — the poll starts when it should (and does not when it shouldn't)
 *   RE-ARMED  — each tick schedules the next one, so it keeps running
 *   CANCELLED — stop/delete/hand-off actually clears the timer, so no zombie poll survives
 *   RESUMED   — a restart re-arms what was persisted, and only what should be re-armed
 *
 * HOW THE OBSERVATION WORKS. Every assertion is a COUNT OF OUTBOUND WORK — VQL statements issued
 * by the stub runner, or a file the drop sweep moved — never a private timer handle. That keeps
 * the tests valid across the extraction: the timers move to composition/ modules, the counts do
 * not change.
 *
 * FAKE TIMERS, NARROWLY. Only setTimeout/clearTimeout are faked (the pollers use nothing else).
 * Date, setInterval and setImmediate stay real, so cursor arithmetic is honest and `settle()` can
 * still yield to the real event loop for the store's file I/O — which has no timer to advance.
 *
 * NO POLL MAY STILL BE IN FLIGHT WHEN A TEST ENDS (#685). This is the one rule every test here has
 * to keep, and it is not about tidiness. `vi.useFakeTimers()` replaces the GLOBAL setTimeout, so a
 * poll chain that outlives its own test does not die with it: it keeps running on the real event
 * loop, and when it finally re-arms, its `setTimeout` lands in the NEXT test's fake timer queue.
 * That test then counts a timer it never armed. The symptom is a `getTimerCount()` assertion in a
 * LATER test failing by exactly one, at whatever point the stray happened to land — a full run once
 * reported `expected 0, received 1` at the CANCELLED assertion below while the file passed cleanly
 * on its own, because the leak came from the test before it.
 *
 * Keeping the rule is mechanical: end on `tickAndRearm()`, never `tick()`, whenever the poll is
 * still meant to be running. The re-arm is the LAST statement of every poll chain here, so a
 * pending timer is proof the chain finished. The `afterEach` at the bottom of this block checks the
 * rule after every test, so a future leak fails in the test that caused it instead of flaking a
 * later one.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdtemp, mkdir, writeFile, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { VeloMonitorStore, type VeloMonitor } from "../../src/analysis/veloMonitorStore.js";
import { VeloHuntStore, type VeloHuntJob } from "../../src/analysis/veloHuntStore.js";
import { DropStatusStore } from "../../src/analysis/dropStatus.js";
import { pollBudget } from "../helpers/poll.js";
import {
  VelociraptorClient,
  type VqlRunner,
  type VelociraptorApiConfig,
} from "../../src/integrations/velociraptor/velociraptorApi.js";

const veloCfg: VelociraptorApiConfig = {
  apiConfigPath: "/x/api.yaml",
  binary: "velociraptor",
  timeoutMs: 5000,
  maxRows: 1000,
  maxOutputBytes: 1024 * 1024,
};

// Captured BEFORE vi.useFakeTimers() replaces the global, so settle() can still reach real time.
const realSetTimeout = globalThis.setTimeout;

/**
 * Hand the real event loop enough turns for the pollers' file I/O to finish.
 *
 * advanceTimersByTimeAsync drains the FAKE timer queue and the microtask queue, but a poll also
 * does real reads and writes against the case store, and those complete on the libuv thread pool —
 * there is no timer to advance for them. A few real macrotask yields is the only honest way to
 * wait. The count is deliberately generous rather than tuned: over-yielding costs microseconds,
 * under-yielding costs a flaky suite.
 */
async function settle(turns = 40): Promise<void> {
  for (let i = 0; i < turns; i++) await new Promise((r) => realSetTimeout(r, 0));
}

/** Advance the fake clock, then let the I/O each fired timer started actually finish. */
async function tick(ms: number): Promise<void> {
  await vi.advanceTimersByTimeAsync(ms);
  await settle();
}

/**
 * Advance the clock, then wait until the poller has actually RE-ARMED before returning.
 *
 * USE THIS WHENEVER A LATER `tick()` DEPENDS ON THIS SWEEP HAVING SCHEDULED THE NEXT ONE.
 *
 * Every poller here re-arms in a `finally` that runs after its async scan (see
 * composition/dropFolder.ts). `settle()` spends a FIXED number of turns, which is a budget rather
 * than a guarantee: when the scan outlasts it — as it does under the disk contention of a full
 * parallel run — no timer is armed, so the next `advanceTimersByTime` fires nothing and a sweep is
 * silently skipped. The test then sees one fewer sweep than it asked for and reports it as a logic
 * failure. Observed directly at a reduced turn count: pending timers 0 after sweep 1, still 0 after
 * advancing for sweep 2, and 1 only after ~300ms of real time.
 *
 * Waiting for the pending-timer count is that missing guarantee, and it is exact: it consumes no
 * fake time and fires no extra sweeps, so every "polled exactly N times" assertion in this file
 * keeps its original meaning.
 *
 * PASS `pollers` WHEN THE TEST DRIVES MORE THAN ONE. The wait is satisfied by the count, so with
 * two live pollers and a default of 1 the first one to re-arm releases it while the second is still
 * mid-poll — and that second chain then runs on past the end of the test (#685).
 *
 * Deliberately NOT used by the CANCELLED/DISARMED tests: for those, zero pending timers is the
 * property under test, so waiting for one would be waiting for the bug.
 */
const REARM_TIMEOUT_MS = pollBudget(10_000);

/**
 * The timeout a test must carry PER WAIT — every `tickAndRearm()` or `tickUntil()` call — plus room
 * for its own work.
 *
 * Derived, not written down twice. A caller that waits up to REARM_TIMEOUT_MS twice can legitimately
 * spend 2x that before doing anything wrong, and the suite's 15s default would kill it partway
 * through the second wait — each wait inside its own budget, the pair outside the test's. That is
 * the arithmetic tests/helpers/poll.ts warns about ("keep the caller's test timeout above the SUM
 * of its poll budgets"), and this patch's own reviewer caught it here. Computing it means adjusting
 * REARM_TIMEOUT_MS can never silently outgrow the timeout again.
 *
 * PLATFORM-SCALED, VIA pollBudget, FOR THE REASON THAT FILE GIVES. An explicit `it()` timeout
 * REPLACES vitest.config.ts's, and that config already triples its default to 45s on Windows — so
 * an unscaled 20s or 30s written here would be a Windows REGRESSION for every test that carries it,
 * on tests that do real file I/O. Scaling both the inner wait and the headroom by the one shared
 * factor keeps every ratio the same on both platforms, which is what pollBudget exists to enforce.
 */
const rearmBudget = (calls: number) => REARM_TIMEOUT_MS * calls + pollBudget(10_000);

/**
 * Advance the fake clock once, then yield real turns until `ready()` holds.
 *
 * The engine under `tickAndRearm`, exposed on its own for the one test whose poller is not supposed
 * to re-arm — a STOPPED hunt hands off and stops, so "a timer is pending" is the wrong signal there
 * and only the outbound-work count can say the poll actually ran. `what` names the wait, so a
 * timeout reads as a missing guarantee rather than an anonymous 10s hang.
 */
async function tickUntil(ms: number, ready: () => boolean, what: string): Promise<void> {
  await vi.advanceTimersByTimeAsync(ms);
  const deadline = Date.now() + REARM_TIMEOUT_MS;
  for (;;) {
    await settle(2);
    if (ready()) return;
    if (Date.now() >= deadline) {
      throw new Error(`timed out after ${REARM_TIMEOUT_MS}ms waiting for: ${what}`);
    }
  }
}

async function tickAndRearm(ms: number, pollers = 1): Promise<void> {
  await tickUntil(ms, () => vi.getTimerCount() >= pollers, `all ${pollers} poller(s) to re-arm`);
}

/** A Velociraptor runner that answers everything emptily and records what it was asked. */
function countingRunner(overrides: { huntState?: string } = {}): { runner: VqlRunner; vql: string[] } {
  const vql: string[] = [];
  const runner: VqlRunner = async (statements) => {
    const program = statements.join("\n");
    vql.push(program);
    if (program.includes("FROM hunts()")) {
      // `expires` far in the future, so a STOPPED answer is not misread as "stopped early".
      return {
        rows: [{ state: overrides.huntState ?? "RUNNING", expires: (Date.now() + 86_400_000) * 1000 }],
        raw: "",
      };
    }
    return { rows: [], raw: "" };
  };
  return { runner, vql };
}

/** How many monitor-result reads were issued for `artifact`. */
const monitorPolls = (vql: string[], artifact: string): number =>
  vql.filter((p) => p.includes("source(") && p.includes(artifact)).length;

/** How many hunt-state reads were issued for `huntId`. */
const statusPolls = (vql: string[], huntId: string): number =>
  vql.filter((p) => p.includes("FROM hunts()") && p.includes(huntId)).length;

function monitor(
  patch: Partial<VeloMonitor> & Pick<VeloMonitor, "id" | "clientId" | "artifact">,
): VeloMonitor {
  return {
    pollSeconds: 30,
    cursor: 0,
    status: "active",
    createdAt: new Date().toISOString(),
    ...patch,
  };
}

function huntJob(huntId: string, status: VeloHuntJob["status"]): VeloHuntJob {
  return {
    bundleId: "b1",
    bundleName: "bundle",
    artifacts: ["Windows.System.Pslist"],
    huntId,
    launchedAt: new Date().toISOString(),
    waitMinutes: 5,
    collectAt: new Date(Date.now() + 300_000).toISOString(),
    status,
  };
}

async function freshRoot(prefix: string): Promise<{ root: string; store: CaseStore }> {
  const root = await mkdtemp(join(tmpdir(), prefix));
  const store = new CaseStore(root);
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { root, store };
}

/** A provider-less pipeline. The monitor routes require one wired; no AI call is ever made here. */
function offlinePipeline(store: CaseStore) {
  return buildRuntimePipeline({
    provider: undefined,
    synthesisProvider: undefined,
    stateStore: new StateStore(store),
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
}

beforeEach(() => {
  // Only what the pollers use. Faking Date would break the monitor cursor arithmetic (epoch
  // seconds) and faking setInterval would freeze the unrelated flush/health sweeps for no gain.
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
});

/**
 * How long the teardown guard watches for a straggling poll chain to betray itself by re-arming.
 * Paid once per test, so it is sized against the file I/O of a single poll, not the worst case.
 */
const LEAK_CHECK_TURNS = 80;

afterEach(async () => {
  // Everything a test armed on purpose is already pending by now, so nothing new should appear.
  // A timer that shows up here came from a poll chain that outlived its test — see NO POLL MAY
  // STILL BE IN FLIGHT at the top of this file.
  //
  // A BACKSTOP, NOT THE FIX. It can only see a stray that surfaces inside its own window, so a
  // slow enough chain still lands in a later test — and then this fails in THAT test rather than
  // the one that leaked. Either way the run fails loudly and points at the right cause, which is
  // the whole gain over a bare `expected 0, received 1` somewhere downstream. What actually keeps
  // the queue clean is every test ending on tickAndRearm().
  const armed = vi.getTimerCount();
  await settle(LEAK_CHECK_TURNS);
  const stray = vi.getTimerCount() - armed;
  vi.useRealTimers();
  expect(
    stray,
    "a poll chain was still in flight and re-armed after a test finished — this test's, or an " +
      "earlier one's. End every test on tickAndRearm() rather than tick() while its poller is " +
      "still meant to be running, or stop the poller first.",
  ).toBe(0);
});

describe("Velociraptor live monitors — timer lifecycle", () => {
  // rearmBudget(2): two tickAndRearm calls, so the test must survive two full waits.
  it(
    "ARMED + RE-ARMED: a started monitor keeps polling on its own interval",
    { timeout: rearmBudget(2) },
    async () => {
      const { store } = await freshRoot("dfir-timer-mon-");
      const { runner, vql } = countingRunner();
      const app = createApp(store, {
        pipeline: offlinePipeline(store),
        velociraptorClient: new VelociraptorClient(veloCfg, runner),
        veloMonitorStore: new VeloMonitorStore(store),
      });
      await settle();

      const start = await request(app)
        .post("/cases/c1/velociraptor/monitors")
        .send({ clientId: "C.abc123", artifact: "Windows.Events.ProcessCreation", pollSeconds: 30 });
      expect(start.status).toBe(202);
      expect(monitorPolls(vql, "Windows.Events.ProcessCreation")).toBe(0); // armed, not yet fired

      await tickAndRearm(30_000);
      expect(monitorPolls(vql, "Windows.Events.ProcessCreation")).toBe(1);

      // The property that matters: the poll that just ran scheduled the next one. A monitor that
      // polls exactly once and then goes quiet is the silent failure this test exists to catch.
      await tickAndRearm(30_000);
      expect(monitorPolls(vql, "Windows.Events.ProcessCreation")).toBe(2);
    },
  );

  // rearmBudget(1): one tickAndRearm call. The last tick must stay a plain tick — after the stop,
  // no timer is meant to appear, and waiting for one would be waiting for the bug.
  it(
    "CANCELLED: stopping a monitor clears its timer — no zombie polls",
    { timeout: rearmBudget(1) },
    async () => {
      const { store } = await freshRoot("dfir-timer-monstop-");
      const { runner, vql } = countingRunner();
      const app = createApp(store, {
        pipeline: offlinePipeline(store),
        velociraptorClient: new VelociraptorClient(veloCfg, runner),
        veloMonitorStore: new VeloMonitorStore(store),
      });
      await settle();

      // Counting PENDING TIMERS, not just outbound traffic. pollVeloMonitor re-reads the monitor and
      // bails when it is stopped, so a leaked timer ingests nothing and is invisible to a VQL count —
      // it just wakes the process up forever. Only the timer count can see it, and with fake timers
      // narrowed to setTimeout the queue holds exactly this app's pending polls.
      const idle = vi.getTimerCount();
      await request(app)
        .post("/cases/c1/velociraptor/monitors")
        .send({ clientId: "C.abc123", artifact: "Windows.Events.ProcessCreation", pollSeconds: 30 });
      expect(vi.getTimerCount()).toBe(idle + 1); // ARMED: exactly one new timer

      // tickAndRearm, not tick: the count below is only meaningful once this poll has finished and
      // scheduled its successor. A plain tick can return mid-poll, and then the re-arm lands after
      // the stop — or after the whole test — and the count is read at a moment nobody chose.
      await tickAndRearm(30_000);
      expect(monitorPolls(vql, "Windows.Events.ProcessCreation")).toBe(1);
      expect(vi.getTimerCount()).toBe(idle + 1); // RE-ARMED: replaced, not stacked

      const stop = await request(app)
        .post("/cases/c1/velociraptor/monitors/C.abc123__Windows.Events.ProcessCreation/stop")
        .send({});
      expect(stop.status).toBe(200);
      expect(vi.getTimerCount()).toBe(idle); // CANCELLED: the timer is gone

      await tick(30_000 * 5);
      expect(monitorPolls(vql, "Windows.Events.ProcessCreation")).toBe(1);
    },
  );

  // rearmBudget(1): the closing tickAndRearm below.
  it(
    "RESUMED: a restart re-arms persisted active monitors and leaves stopped ones alone",
    { timeout: rearmBudget(1) },
    async () => {
      const { store } = await freshRoot("dfir-timer-monresume-");
      const monitors = new VeloMonitorStore(store);
      await monitors.upsert(
        "c1",
        monitor({ id: "C.a__Live.Artifact", clientId: "C.aaaaaa", artifact: "Live.Artifact" }),
      );
      await monitors.upsert(
        "c1",
        monitor({
          id: "C.b__Stopped.Artifact",
          clientId: "C.bbbbbb",
          artifact: "Stopped.Artifact",
          status: "stopped",
        }),
      );

      const { runner, vql } = countingRunner();
      // Constructing the app IS the restart: createApp fires resumeVeloMonitors() on the way out.
      createApp(store, {
        velociraptorClient: new VelociraptorClient(veloCfg, runner),
        veloMonitorStore: monitors,
      });
      await settle();

      // One armed poll, not two: a stopped monitor whose timer is armed anyway would wake up, re-read
      // itself, and bail — costing a file read every 30s forever while looking perfectly healthy.
      expect(vi.getTimerCount()).toBe(1);

      // tickAndRearm, not tick: this monitor is still meant to be running when the test ends, so
      // the test must not walk away while its poll is mid-flight.
      await tickAndRearm(30_000);
      expect(monitorPolls(vql, "Live.Artifact")).toBe(1);
      expect(monitorPolls(vql, "Stopped.Artifact")).toBe(0);
    },
  );
});

describe("Velociraptor hunt status polls — timer lifecycle", () => {
  // rearmBudget(2): two tickAndRearm calls, so the test must survive two full waits.
  it(
    "RESUMED + RE-ARMED: a restart re-polls running and unreachable hunts, and only those",
    { timeout: rearmBudget(2) },
    async () => {
      const { store } = await freshRoot("dfir-timer-hunt-");
      const hunts = new VeloHuntStore(store);
      await hunts.upsert("c1", huntJob("H.RUNNING1", "running"));
      await hunts.upsert("c1", huntJob("H.UNREACH1", "unreachable"));
      await hunts.upsert("c1", huntJob("H.IMPORTED", "imported")); // terminal — nothing left to check

      const { runner, vql } = countingRunner();
      createApp(store, {
        velociraptorClient: new VelociraptorClient(veloCfg, runner),
        veloHuntStore: hunts,
      });
      await settle();

      // Two pollers, so wait for two re-arms: stopping at the first would walk away from the other.
      await tickAndRearm(30_000, 2); // DFIR_VELO_HUNT_POLL_S default
      expect(statusPolls(vql, "H.RUNNING1")).toBe(1);
      expect(statusPolls(vql, "H.UNREACH1")).toBe(1);
      expect(statusPolls(vql, "H.IMPORTED")).toBe(0);

      // Still RUNNING → reschedule. The next tick must find a timer waiting.
      await tickAndRearm(30_000, 2);
      expect(statusPolls(vql, "H.RUNNING1")).toBe(2);
    },
  );

  // rearmBudget(1): one tickUntil wait below.
  it(
    "CANCELLED: a hunt Velociraptor reports STOPPED hands off to the collect and stops polling",
    { timeout: rearmBudget(1) },
    async () => {
      const { store } = await freshRoot("dfir-timer-huntstop-");
      const hunts = new VeloHuntStore(store);
      await hunts.upsert("c1", huntJob("H.DONE1", "running"));

      const { runner, vql } = countingRunner({ huntState: "STOPPED" });
      createApp(store, {
        velociraptorClient: new VelociraptorClient(veloCfg, runner),
        veloHuntStore: hunts,
      });
      await settle();

      // tickUntil, not tickAndRearm: this poller is supposed to STOP, so a pending timer is the
      // wrong thing to wait for. The poll itself is still the guarantee the assertion needs.
      await tickUntil(30_000, () => statusPolls(vql, "H.DONE1") === 1, "the STOPPED hunt to be polled");
      expect(statusPolls(vql, "H.DONE1")).toBe(1);

      // The status poller's job is over: it handed the hunt to the collect path, which owns the
      // job from here. A poller that kept its timer would re-collect the same hunt every 30s.
      //
      // The hand-off is fire-and-forget, so the extra settle turns are what keep it from running on
      // past the end of the test and re-arming into the next one.
      await tick(30_000 * 5);
      await settle();
      expect(statusPolls(vql, "H.DONE1")).toBe(1);
    },
  );
});

describe("Evidence drop-folder watcher — timer lifecycle", () => {
  const ENV_KEYS = ["DFIR_DROP_ENABLED", "DFIR_DROP_POLL_S"] as const;
  let saved: Record<string, string | undefined>;

  beforeEach(() => {
    saved = Object.fromEntries(ENV_KEYS.map((k) => [k, process.env[k]]));
    process.env.DFIR_DROP_POLL_S = "2"; // clamped floor; createApp reads it once at construction
  });

  afterEach(() => {
    for (const k of ENV_KEYS) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  });

  /** Put an unimportable file in the drop folder. Unrecognized → the sweep moves it to _failed/. */
  async function dropJunk(store: CaseStore, name: string): Promise<void> {
    const dropDir = join(store.caseDir("c1"), "drop");
    await mkdir(dropDir, { recursive: true });
    await writeFile(join(dropDir, name), "not a recognizable evidence format\n", "utf8");
  }

  const failedNames = async (store: CaseStore): Promise<string[]> =>
    readdir(join(store.caseDir("c1"), "drop", "_failed")).catch(() => [] as string[]);

  // rearmBudget(2): this test calls tickAndRearm twice, so it must survive two full waits.
  it(
    "ARMED + RE-ARMED: the watcher sweeps, and sweeps again, so a settled file is processed",
    { timeout: rearmBudget(2) },
    async () => {
      const { store } = await freshRoot("dfir-timer-drop-");
      createApp(store, { dropStatusStore: new DropStatusStore(store) });
      await settle();
      await dropJunk(store, "junk.txt");

      // A file must be seen unchanged by TWO sweeps before it is read (selectReadyFiles waits for
      // size+mtime to settle, so a half-copied file is never imported). That makes this assertion
      // a re-arm test by construction: one sweep alone can never move the file.
      // tickAndRearm, not tick: the assertion below depends on a SECOND sweep firing, which can only
      // happen if this first one finished and scheduled it.
      await tickAndRearm(2_000);
      expect(await failedNames(store)).toEqual([]);

      await tickAndRearm(2_000);
      expect(await failedNames(store)).toEqual(["junk.txt"]);
    },
  );

  it("DISARMED: no dropStatusStore means no filesystem poller at all", async () => {
    const { store } = await freshRoot("dfir-timer-dropoff-");
    createApp(store, {}); // the createApp-only unit-test shape
    await settle();
    await dropJunk(store, "junk.txt");

    // One interval per tick, exactly as the armed test does: a single big advance would not give
    // the sweep's file I/O time to finish and re-arm, so it would pass even with a live watcher.
    for (let i = 0; i < 4; i++) await tick(2_000);
    expect(await failedNames(store)).toEqual([]);
  });

  it("DISARMED: DFIR_DROP_ENABLED=off keeps the watcher down even with the store wired", async () => {
    process.env.DFIR_DROP_ENABLED = "off";
    const { store } = await freshRoot("dfir-timer-dropenvoff-");
    createApp(store, { dropStatusStore: new DropStatusStore(store) });
    await settle();
    await dropJunk(store, "junk.txt");

    for (let i = 0; i < 4; i++) await tick(2_000);
    expect(await failedNames(store)).toEqual([]);
  });
});
