import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import { ActivityLogStore } from "../../../../src/analysis/activityLog.js";
import { WatsonChatStore } from "../../../../src/analysis/ai/watson/chatStore.js";
import {
  applyWatsonProposal,
  WatsonProposalConflict,
  WatsonProposalStateError,
  type WriterDeps,
} from "../../../../src/analysis/ai/watson/proposals.js";
import { WatsonLaunchUncertain } from "../../../../src/analysis/ai/watson/proposalErrors.js";
import type { WatsonChat, WatsonVeloLaunchProposal } from "../../../../src/analysis/ai/watson/types.js";
import {
  fingerprintStoreFor,
  launchFingerprints,
} from "../../../../src/analysis/ai/watson/velo/fingerprintIndex.js";
import type { HuntFingerprintStore } from "../../../../src/analysis/ai/watson/velo/huntFingerprintStore.js";
import {
  markStrandedLaunches,
  resolveVeloLaunch,
} from "../../../../src/analysis/ai/watson/velo/launchResolve.js";
import type {
  VeloLaunchOutcome,
  VeloLaunchRequest,
} from "../../../../src/analysis/ai/watson/velo/launchTypes.js";
import { UNDO_REFUSED } from "../../../../src/analysis/ai/watson/writers/veloLaunchWriter.js";
import { StateLock } from "../../../../src/analysis/stateLock.js";
import { StateStore } from "../../../../src/analysis/stateStore.js";
import { matchClient } from "../../../../src/integrations/velociraptor/clientInventory.js";
import { CaseStore } from "../../../../src/storage/caseStore.js";

// Applying a velo_launch proposal: one launch, intent saved before the call, ids after it, and a
// failure at each boundary lands in the right state (pending + released, or uncertain + kept).

const CASE = "c1";
const PSLIST = "SELECT * FROM pslist()";
const HOST = "web01.example.com";
const CLIENTS = [{ clientId: "C.webserver1", hostname: HOST, fqdn: HOST }];

/** A chat store whose Nth save (1-based) fails once. */
class FlakyChatStore extends WatsonChatStore {
  saves = 0;
  failOn = 0;
  loads = 0;
  failLoadsAfter = Infinity;
  override async load(caseId: string): Promise<WatsonChat> {
    this.loads++;
    if (this.loads > this.failLoadsAfter) throw new Error("EIO: read failed");
    return super.load(caseId);
  }
  override async save(caseId: string, chat: WatsonChat): Promise<void> {
    this.saves++;
    if (this.saves === this.failOn) throw new Error("EIO: disk gone");
    return super.save(caseId, chat);
  }
}

type Launch = (req: VeloLaunchRequest) => Promise<VeloLaunchOutcome>;

let store: CaseStore;
let chatStore: FlakyChatStore;
let activity: ActivityLogStore;
let fps: HuntFingerprintStore;
let calls: VeloLaunchRequest[];

function deps(
  launch: Launch = async () => ({ phase: "launched", launched: { huntId: "H.SAMPLE1" } }),
  fingerprints: Pick<HuntFingerprintStore, "load" | "reserve" | "release"> = fps,
): WriterDeps {
  return {
    stateStore: new StateStore(store),
    stateLock: new StateLock(),
    chatStore,
    activity,
    markConclusionsOutOfDate: async () => {},
    veloLaunch: {
      launch: async (_caseId, req) => {
        calls.push(req);
        return launch(req);
      },
      fleet: {
        veloConnected: () => true,
        velociraptorClientStore: { load: async () => ({ updatedAt: "", clients: CLIENTS }) },
      },
      matchClient,
      fingerprints,
    },
  };
}

function huntProposal(id = "wp-hunt", vql = PSLIST): WatsonVeloLaunchProposal {
  const keys = launchFingerprints(vql);
  return {
    id,
    turnId: "t1",
    kind: "velo_launch",
    status: "pending",
    targetId: keys[0],
    mode: "hunt",
    title: "Process listing",
    vql,
    fingerprint: keys[0],
    fingerprints: keys,
  };
}

function collectionProposal(id = "wp-coll"): WatsonVeloLaunchProposal {
  const keys = launchFingerprints(PSLIST, HOST);
  return {
    ...huntProposal(id),
    mode: "collection",
    hostname: HOST,
    targetId: keys[0],
    fingerprint: keys[0],
    fingerprints: keys,
  };
}

async function seed(...proposals: WatsonVeloLaunchProposal[]): Promise<void> {
  await chatStore.update(CASE, (c) => ({ ...c, proposals: [...c.proposals, ...proposals] }));
}

const stored = async (id: string) =>
  (await chatStore.load(CASE)).proposals.find((p) => p.id === id) as WatsonVeloLaunchProposal;

beforeEach(async () => {
  store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-velo-launch-")));
  await store.createCase({ caseId: CASE, name: "n", investigator: "i", aiProvider: null });
  chatStore = new FlakyChatStore(store);
  activity = new ActivityLogStore(store);
  fps = fingerprintStoreFor(store);
  calls = [];
});

describe("applying a velo_launch proposal", () => {
  it("launches once, stores the ids and audits watson.apply", async () => {
    await seed(huntProposal());
    await applyWatsonProposal(deps(), CASE, "wp-hunt", "apply", "Dana Analyst");
    expect(calls).toEqual([{ mode: "hunt", vql: PSLIST, title: "Process listing" }]);
    const p = await stored("wp-hunt");
    expect(p.status).toBe("applied");
    expect(p.launched).toMatchObject({ huntId: "H.SAMPLE1", by: "Dana Analyst" });
    expect(p.appliedBy).toBe("Dana Analyst");
    expect([...(await fps.load(CASE))]).toEqual(expect.arrayContaining(p.fingerprints));
    const entry = (await activity.load(CASE)).find((e) => e.action === "watson.apply");
    expect(entry).toMatchObject({ category: "ai", targetType: "hunt", targetId: p.targetId });
  });

  it("passes a collection's host and records its flow and client", async () => {
    await seed(collectionProposal());
    const launch: Launch = async () => ({
      phase: "launched",
      launched: { flowId: "F.SAMPLE", clientId: CLIENTS[0].clientId },
    });
    await applyWatsonProposal(deps(launch), CASE, "wp-coll", "apply");
    expect(calls[0]).toMatchObject({ mode: "collection", hostname: HOST });
    expect((await stored("wp-coll")).launched).toMatchObject({
      flowId: "F.SAMPLE",
      clientId: CLIENTS[0].clientId,
    });
  });

  it("saves a collection's result watch with its ids and starts it; a fleet hunt gets none", async () => {
    await seed(collectionProposal(), huntProposal());
    const started: string[] = [];
    const launch: Launch = async (req) =>
      req.mode === "collection"
        ? { phase: "launched", launched: { flowId: "F.SAMPLE", clientId: CLIENTS[0].clientId } }
        : { phase: "launched", launched: { huntId: "H.SAMPLE1" } };
    const d = deps(launch);
    const withHook = {
      ...d,
      veloLaunch: { ...d.veloLaunch!, onLaunched: (_c: string, id: string) => started.push(id) },
    };
    await applyWatsonProposal(withHook, CASE, "wp-coll", "apply");
    await applyWatsonProposal(withHook, CASE, "wp-hunt", "apply");
    expect(started).toEqual(["wp-coll"]);
    const watch = (await stored("wp-coll")).watch;
    expect(watch?.state).toBe("watching");
    expect(Date.parse(watch!.deadline) - Date.parse((await stored("wp-coll")).launched!.at)).toBe(
      30 * 60_000,
    );
    expect((await stored("wp-hunt")).watch).toBeUndefined();
  });

  it("refuses a second apply of the same proposal without launching again", async () => {
    await seed(huntProposal());
    await applyWatsonProposal(deps(), CASE, "wp-hunt", "apply");
    await expect(applyWatsonProposal(deps(), CASE, "wp-hunt", "apply")).rejects.toBeInstanceOf(
      WatsonProposalStateError,
    );
    expect(calls).toHaveLength(1);
  });

  it("launches exactly once when two applies race", async () => {
    await seed(huntProposal());
    const results = await Promise.allSettled([
      applyWatsonProposal(deps(), CASE, "wp-hunt", "apply"),
      applyWatsonProposal(deps(), CASE, "wp-hunt", "apply"),
    ]);
    expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
    expect(calls).toHaveLength(1);
  });

  it("refuses a sibling proposal with the same fingerprint once one launched", async () => {
    await seed(huntProposal("wp-a"), huntProposal("wp-b"));
    await applyWatsonProposal(deps(), CASE, "wp-a", "apply");
    await expect(applyWatsonProposal(deps(), CASE, "wp-b", "apply")).rejects.toBeInstanceOf(
      WatsonProposalConflict,
    );
    expect(calls).toHaveLength(1);
  });

  it("refuses a stored proposal whose VQL now fails the risk check, launching nothing", async () => {
    await seed(huntProposal("wp-risky", "SELECT * FROM execve(argv=['whoami'])"));
    await expect(applyWatsonProposal(deps(), CASE, "wp-risky", "apply")).rejects.toThrow(/will not launch/);
    expect(calls).toHaveLength(0);
    expect((await stored("wp-risky")).status).toBe("pending");
  });

  it("refuses when the fingerprint reservation is refused, launching nothing", async () => {
    await seed(huntProposal());
    const refusing = {
      load: async () => new Set<string>(),
      reserve: async () => ({ ok: false, added: [] }),
      release: async () => {},
    };
    await expect(applyWatsonProposal(deps(undefined, refusing), CASE, "wp-hunt", "apply")).rejects.toThrow(
      /already ran/,
    );
    expect(calls).toHaveLength(0);
    expect((await stored("wp-hunt")).status).toBe("pending");
  });

  it("releases the reservation when the intent save fails, launching nothing", async () => {
    await seed(huntProposal());
    chatStore.failOn = chatStore.saves + 1;
    await expect(applyWatsonProposal(deps(), CASE, "wp-hunt", "apply")).rejects.toThrow(/EIO/);
    expect(calls).toHaveLength(0);
    expect((await stored("wp-hunt")).status).toBe("pending");
    expect((await fps.load(CASE)).size).toBe(0);
  });

  it("returns to pending and releases its keys when the deploy failed before launching", async () => {
    await seed(collectionProposal());
    const fail: Launch = async () => ({
      phase: "before-launch",
      error: "No enrolled Velociraptor client matches",
    });
    await expect(applyWatsonProposal(deps(fail), CASE, "wp-coll", "apply")).rejects.toThrow(/nothing ran/);
    const p = await stored("wp-coll");
    expect(p.status).toBe("pending");
    expect(p.launching).toBeUndefined();
    expect((await fps.load(CASE)).size).toBe(0);
    await applyWatsonProposal(deps(), CASE, "wp-coll", "apply"); // a later apply may launch
    expect(calls).toHaveLength(2);
  });

  it.each<[string, Launch]>([
    ["the launch call fails", async () => ({ phase: "launch-unknown", error: "timeout" })],
    [
      "the launch seam throws",
      async () => {
        throw new Error("socket hang up");
      },
    ],
  ])("goes uncertain, keeps its keys and never relaunches when %s", async (_name, launch) => {
    await seed(huntProposal());
    await expect(applyWatsonProposal(deps(launch), CASE, "wp-hunt", "apply")).rejects.toBeInstanceOf(
      WatsonLaunchUncertain,
    );
    const p = await stored("wp-hunt");
    expect(p.status).toBe("uncertain");
    expect(p.launching?.reserved).toEqual(p.fingerprints);
    expect([...(await fps.load(CASE))]).toEqual(expect.arrayContaining(p.fingerprints));
    await expect(applyWatsonProposal(deps(), CASE, "wp-hunt", "apply")).rejects.toBeInstanceOf(
      WatsonProposalStateError,
    );
    expect(calls).toHaveLength(1);
    const entry = (await activity.load(CASE)).find((e) => e.action === "watson.apply");
    expect(entry?.outcome).toBe("error");
  });

  it("is applied when the launch returned ids but later bookkeeping failed", async () => {
    await seed(huntProposal());
    const partial: Launch = async () => ({
      phase: "launched",
      launched: { huntId: "H.SAMPLE2" },
      error: "EACCES",
    });
    await applyWatsonProposal(deps(partial), CASE, "wp-hunt", "apply");
    expect((await stored("wp-hunt")).launched?.huntId).toBe("H.SAMPLE2");
  });

  it("stays launching when the save after the launch fails; the boot sweep makes it uncertain", async () => {
    await seed(huntProposal());
    chatStore.failOn = chatStore.saves + 2;
    await expect(applyWatsonProposal(deps(), CASE, "wp-hunt", "apply")).rejects.toThrow(/EIO/);
    expect(calls).toHaveLength(1);
    expect((await stored("wp-hunt")).status).toBe("launching");
    expect(await markStrandedLaunches(chatStore, CASE)).toBe(1);
    const p = await stored("wp-hunt");
    expect(p.status).toBe("uncertain");
    expect(p.launching?.error).toMatch(/server stopped/);
  });

  it("the boot sweep leaves a launch that is still in flight alone", async () => {
    await seed(huntProposal());
    let swept = -1;
    const slow: Launch = async () => {
      swept = await markStrandedLaunches(chatStore, CASE);
      return { phase: "launched", launched: { huntId: "H.SAMPLE3" } };
    };
    await applyWatsonProposal(deps(slow), CASE, "wp-hunt", "apply");
    expect(swept).toBe(0);
    expect((await stored("wp-hunt")).status).toBe("applied");
  });

  it("a losing double-click never makes the running launch look stranded", async () => {
    await seed(huntProposal());
    let finish: (o: VeloLaunchOutcome) => void = () => {};
    let started: () => void = () => {};
    const running = new Promise<void>((r) => (started = r));
    const slow: Launch = () =>
      new Promise((r) => {
        finish = r;
        started();
      });
    const first = applyWatsonProposal(deps(slow), CASE, "wp-hunt", "apply");
    await running;
    await expect(applyWatsonProposal(deps(), CASE, "wp-hunt", "apply")).rejects.toBeInstanceOf(
      WatsonProposalStateError,
    );
    expect(await markStrandedLaunches(chatStore, CASE)).toBe(0);
    await expect(
      resolveVeloLaunch({ chatStore, activity, fingerprints: fps }, CASE, "wp-hunt", "retry"),
    ).rejects.toBeInstanceOf(WatsonProposalStateError);
    finish({ phase: "launched", launched: { huntId: "H.SAMPLE4" } });
    await first;
    expect((await stored("wp-hunt")).status).toBe("applied");
    expect(calls).toHaveLength(1);
  });

  it("rethrows the original save error and logs it when the release after a failed save #1 also fails", async () => {
    await seed(huntProposal());
    chatStore.failOn = chatStore.saves + 1;
    const lines: string[] = [];
    const failingRelease = {
      load: (id: string) => fps.load(id),
      reserve: (id: string, keys: readonly string[]) => fps.reserve(id, keys),
      release: async () => {
        throw new Error("EACCES: index locked");
      },
    };
    const d = deps(undefined, failingRelease);
    const withLog = { ...d, veloLaunch: { ...d.veloLaunch!, log: (l: string) => void lines.push(l) } };
    await expect(applyWatsonProposal(withLog, CASE, "wp-hunt", "apply")).rejects.toThrow(/EIO: disk gone/);
    expect(calls).toHaveLength(0);
    expect(lines.join("\n")).toMatch(/EACCES: index locked/);
  });

  it("launches from the proposal save #1 stored, without reloading the chat in between", async () => {
    await seed(huntProposal());
    chatStore.failLoadsAfter = chatStore.loads + 1; // the dispatcher's kind lookup only
    await applyWatsonProposal(deps(), CASE, "wp-hunt", "apply");
    expect(calls).toHaveLength(1);
    chatStore.failLoadsAfter = Infinity;
    expect((await stored("wp-hunt")).status).toBe("applied");
  });

  it("refuses undo: a launched hunt cannot be undone", async () => {
    await seed(huntProposal());
    await applyWatsonProposal(deps(), CASE, "wp-hunt", "apply");
    await expect(applyWatsonProposal(deps(), CASE, "wp-hunt", "undo")).rejects.toThrow(UNDO_REFUSED);
  });
});

describe("resolving an uncertain launch", () => {
  const unknown: Launch = async () => ({ phase: "launch-unknown", error: "timeout" });
  const resolveDeps = () => ({ chatStore, activity, fingerprints: fps });

  it("retry releases the reserved keys, returns it to pending, and a new apply launches", async () => {
    await seed(huntProposal());
    await applyWatsonProposal(deps(unknown), CASE, "wp-hunt", "apply").catch(() => undefined);
    await resolveVeloLaunch(resolveDeps(), CASE, "wp-hunt", "retry", "Dana Analyst");
    expect((await stored("wp-hunt")).status).toBe("pending");
    expect((await fps.load(CASE)).size).toBe(0);
    await applyWatsonProposal(deps(), CASE, "wp-hunt", "apply");
    expect(calls).toHaveLength(2);
    const entry = (await activity.load(CASE)).find((e) => e.action === "watson.resolve");
    expect(entry).toMatchObject({ category: "hunt", actor: "Dana Analyst" });
  });

  it("launched marks it applied without ids and keeps the keys", async () => {
    await seed(huntProposal());
    await applyWatsonProposal(deps(unknown), CASE, "wp-hunt", "apply").catch(() => undefined);
    await resolveVeloLaunch(resolveDeps(), CASE, "wp-hunt", "launched");
    const p = await stored("wp-hunt");
    expect(p.status).toBe("applied");
    expect(p.launched?.huntId).toBeUndefined();
    expect((await fps.load(CASE)).size).toBeGreaterThan(0);
  });

  it("launched records a source watson outcome at the original launch time, with no ids", async () => {
    await seed(collectionProposal());
    await applyWatsonProposal(deps(unknown), CASE, "wp-coll", "apply").catch(() => undefined);
    const at = (await stored("wp-coll")).launching?.at;
    const recorded: unknown[] = [];
    const d = {
      ...resolveDeps(),
      recordDeploy: async (_id: string, input: unknown) => void recorded.push(input),
    };
    await resolveVeloLaunch(d, CASE, "wp-coll", "launched");
    expect(recorded).toEqual([
      {
        source: "watson",
        title: "Process listing",
        vql: PSLIST,
        hostname: HOST,
        coverage: "snapshot",
        deployedAt: at,
      },
    ]);
  });

  it("retry records no outcome", async () => {
    await seed(huntProposal());
    await applyWatsonProposal(deps(unknown), CASE, "wp-hunt", "apply").catch(() => undefined);
    const recorded: unknown[] = [];
    const d = {
      ...resolveDeps(),
      recordDeploy: async (_id: string, input: unknown) => void recorded.push(input),
    };
    await resolveVeloLaunch(d, CASE, "wp-hunt", "retry");
    expect(recorded).toEqual([]);
  });

  it("refuses a proposal that is not uncertain", async () => {
    await seed(huntProposal());
    await expect(resolveVeloLaunch(resolveDeps(), CASE, "wp-hunt", "launched")).rejects.toBeInstanceOf(
      WatsonProposalStateError,
    );
  });
});
