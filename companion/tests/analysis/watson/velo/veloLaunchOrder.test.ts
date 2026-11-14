import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import { ActivityLogStore } from "../../../../src/analysis/activityLog.js";
import { WatsonChatStore } from "../../../../src/analysis/ai/watson/chatStore.js";
import { applyWatsonProposal, type WriterDeps } from "../../../../src/analysis/ai/watson/proposals.js";
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
import type { VeloLaunchRequest } from "../../../../src/analysis/ai/watson/velo/launchTypes.js";
import { clearInFlight } from "../../../../src/analysis/ai/watson/velo/launchInFlight.js";
import { StateLock } from "../../../../src/analysis/stateLock.js";
import { StateStore } from "../../../../src/analysis/stateStore.js";
import { matchClient } from "../../../../src/integrations/velociraptor/clientInventory.js";
import { CaseStore } from "../../../../src/storage/caseStore.js";

// Final review G4 (a case closed mid-round launches nothing) and G5 (the launch intent is saved
// BEFORE the reservation, so a crash never strands a pending proposal behind reserved keys).

const CASE = "c1";
const PSLIST = "SELECT * FROM pslist()";
const HOST = "web01.example.com";
const CLIENTS = [{ clientId: "C.webserver1", hostname: HOST, fqdn: HOST }];

let store: CaseStore;
let chatStore: WatsonChatStore;
let fps: HuntFingerprintStore;
let calls: VeloLaunchRequest[];
let frozen: boolean;

function deps(fingerprints: Pick<HuntFingerprintStore, "load" | "reserve" | "release"> = fps): WriterDeps {
  return {
    stateStore: new StateStore(store),
    stateLock: new StateLock(),
    chatStore,
    activity: new ActivityLogStore(store),
    markConclusionsOutOfDate: async () => {},
    veloLaunch: {
      launch: async (_c, req) => {
        calls.push(req);
        return { phase: "launched", launched: { flowId: "F.SAMPLE1", clientId: "C.webserver1" } };
      },
      fleet: {
        veloConnected: () => true,
        velociraptorClientStore: { load: async () => ({ updatedAt: "", clients: CLIENTS }) },
      },
      matchClient,
      fingerprints,
      isFrozen: async () => frozen,
    },
  };
}

function collection(id = "wp-coll"): WatsonVeloLaunchProposal {
  const keys = launchFingerprints(PSLIST, HOST);
  return {
    id,
    turnId: "t1",
    kind: "velo_launch",
    status: "pending",
    targetId: keys[0],
    mode: "collection",
    hostname: HOST,
    title: "Process listing",
    vql: PSLIST,
    fingerprint: keys[0],
    fingerprints: keys,
  };
}

const seed = (p: WatsonVeloLaunchProposal) =>
  chatStore.update(CASE, (c: WatsonChat) => ({ ...c, proposals: [...c.proposals, p] }));
const stored = async (id: string) =>
  (await chatStore.load(CASE)).proposals.find((p) => p.id === id) as WatsonVeloLaunchProposal;

beforeEach(async () => {
  store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-velo-order-")));
  await store.createCase({ caseId: CASE, name: "n", investigator: "i", aiProvider: null });
  chatStore = new WatsonChatStore(store);
  fps = fingerprintStoreFor(store);
  calls = [];
  frozen = false;
});

describe("G4 — a case closed before the launch", () => {
  it("launches nothing, releases its keys and returns the proposal to pending", async () => {
    await seed(collection());
    frozen = true;
    await expect(applyWatsonProposal(deps(), CASE, "wp-coll", "apply")).rejects.toThrow(/closed or archived/);
    expect(calls).toHaveLength(0);
    expect((await stored("wp-coll")).status).toBe("pending");
    expect((await fps.load(CASE)).size).toBe(0);
  });
});

describe("G5 — launching is saved before the reservation", () => {
  it("the proposal is already launching, with its planned keys, when reserve runs", async () => {
    await seed(collection());
    let seen: WatsonVeloLaunchProposal | undefined;
    const spying = {
      load: (id: string) => fps.load(id),
      reserve: async (id: string, keys: readonly string[], absent?: readonly string[]) => {
        seen = await stored("wp-coll");
        return fps.reserve(id, keys, absent);
      },
      release: (id: string, keys: readonly string[]) => fps.release(id, keys),
    };
    await applyWatsonProposal(deps(spying), CASE, "wp-coll", "apply");
    expect(seen?.status).toBe("launching");
    expect(seen?.launching?.planned).toEqual(seen?.fingerprints);
    expect(seen?.launching?.reserved).toEqual([]);
    expect((await stored("wp-coll")).status).toBe("applied");
  });

  it("a refused reserve returns the proposal to pending, launching nothing", async () => {
    await seed(collection());
    const refusing = {
      load: async () => new Set<string>(),
      reserve: async () => ({ ok: false, added: [] }),
      release: async () => {},
    };
    await expect(applyWatsonProposal(deps(refusing), CASE, "wp-coll", "apply")).rejects.toThrow(
      /already ran/,
    );
    expect(calls).toHaveLength(0);
    const p = await stored("wp-coll");
    expect(p.status).toBe("pending");
    expect(p.launching).toBeUndefined();
  });

  it("a crash inside reserve leaves a launching proposal the boot sweep can resolve, not a stranded pending one", async () => {
    await seed(collection());
    const crashing = {
      load: (id: string) => fps.load(id),
      reserve: async (id: string, keys: readonly string[]) => {
        await fps.reserve(id, keys); // the keys hit the disk...
        throw new Error("process killed"); // ...and the server dies before anything else
      },
      release: async () => {
        throw new Error("process killed");
      },
    };
    await expect(applyWatsonProposal(deps(crashing), CASE, "wp-coll", "apply")).rejects.toThrow(/killed/);
    // A real crash would also skip the pending revert: simulate the state on disk after it.
    await chatStore.update(CASE, (c) => ({
      ...c,
      proposals: c.proposals.map((p) =>
        p.id === "wp-coll" && p.kind === "velo_launch"
          ? {
              ...p,
              status: "launching" as const,
              launching: {
                at: "",
                by: "x",
                fingerprint: p.fingerprint,
                planned: p.fingerprints,
                reserved: [],
              },
            }
          : p,
      ),
    }));
    clearInFlight(CASE, "wp-coll");
    expect(await markStrandedLaunches(chatStore, CASE)).toBe(1);
    expect((await stored("wp-coll")).status).toBe("uncertain");
    // The analyst can still settle it: "launched" applies it.
    const resolveDeps = { chatStore, activity: new ActivityLogStore(store), fingerprints: fps };
    await resolveVeloLaunch(resolveDeps, CASE, "wp-coll", "launched", "Dana Analyst");
    expect((await stored("wp-coll")).status).toBe("applied");
    expect(calls).toHaveLength(0);
  });

  it("a collection's reserve refuses atomically when the VQL already ran fleet-wide", async () => {
    await seed(collection());
    const racing = {
      load: async () => new Set<string>(), // the check saw nothing...
      reserve: async (id: string, keys: readonly string[], absent?: readonly string[]) => {
        await fps.add(id, launchFingerprints(PSLIST)); // ...a fleet hunt of it lands meanwhile
        return fps.reserve(id, keys, absent);
      },
      release: (id: string, keys: readonly string[]) => fps.release(id, keys),
    };
    await expect(applyWatsonProposal(deps(racing), CASE, "wp-coll", "apply")).rejects.toThrow(/already ran/);
    expect(calls).toHaveLength(0);
  });
});
