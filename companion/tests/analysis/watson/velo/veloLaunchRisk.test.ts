import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import { ActivityLogStore } from "../../../../src/analysis/activityLog.js";
import { WatsonChatStore } from "../../../../src/analysis/ai/watson/chatStore.js";
import {
  applyWatsonProposal,
  WatsonProposalConflict,
  type WriterDeps,
} from "../../../../src/analysis/ai/watson/proposals.js";
import {
  WatsonLaunchUncertain,
  WatsonRiskNotAccepted,
} from "../../../../src/analysis/ai/watson/proposalErrors.js";
import type { WatsonVeloLaunchProposal } from "../../../../src/analysis/ai/watson/types.js";
import {
  fingerprintStoreFor,
  launchFingerprints,
} from "../../../../src/analysis/ai/watson/velo/fingerprintIndex.js";
import type { HuntFingerprintStore } from "../../../../src/analysis/ai/watson/velo/huntFingerprintStore.js";
import { resolveVeloLaunch } from "../../../../src/analysis/ai/watson/velo/launchResolve.js";
import type {
  VeloLaunchOutcome,
  VeloLaunchRequest,
} from "../../../../src/analysis/ai/watson/velo/launchTypes.js";
import { StateLock } from "../../../../src/analysis/stateLock.js";
import { StateStore } from "../../../../src/analysis/stateStore.js";
import { matchClient } from "../../../../src/integrations/velociraptor/clientInventory.js";
import { CaseStore } from "../../../../src/storage/caseStore.js";

// Task 9: a risky velo_launch launches only with the analyst's explicit acceptRisk, only when the
// recheck finds no risk beyond what the proposal stored, and the record says who accepted what.

const CASE = "c1";
const HOST = "web01.example.com";
const CLIENTS = [{ clientId: "C.webserver1", hostname: HOST, fqdn: HOST }];
const EXECVE = "SELECT * FROM execve(argv=['calc'])";
const EXECVE_RAW = "the VQL calls execve, which is not on Watson's read-only list";
const EXECVE_PLAIN = "runs a program on the endpoint (execve)";

let store: CaseStore;
let chatStore: WatsonChatStore;
let activity: ActivityLogStore;
let fps: HuntFingerprintStore;
let calls: Array<{ req: VeloLaunchRequest; actor: string; suffix?: string }>;

function deps(
  launch: () => Promise<VeloLaunchOutcome> = async () => ({
    phase: "launched",
    launched: { huntId: "H.SAMPLE1" },
  }),
): WriterDeps {
  return {
    stateStore: new StateStore(store),
    stateLock: new StateLock(),
    chatStore,
    activity,
    markConclusionsOutOfDate: async () => {},
    veloLaunch: {
      launch: async (_caseId, req, actor, suffix) => {
        calls.push({ req, actor, ...(suffix ? { suffix } : {}) });
        return launch();
      },
      fleet: {
        veloConnected: () => true,
        velociraptorClientStore: { load: async () => ({ updatedAt: "", clients: CLIENTS }) },
      },
      matchClient,
      fingerprints: fps,
    },
  };
}

function risky(vql = EXECVE, checks = [EXECVE_RAW], id = "wp-risk"): WatsonVeloLaunchProposal {
  const keys = launchFingerprints(vql);
  return {
    id,
    turnId: "t1",
    kind: "velo_launch",
    status: "pending",
    targetId: keys[0],
    mode: "hunt",
    title: "Run calc",
    vql,
    fingerprint: keys[0],
    fingerprints: keys,
    risk: { reasons: [EXECVE_PLAIN], checks },
  };
}

async function seed(p: WatsonVeloLaunchProposal): Promise<void> {
  await chatStore.update(CASE, (c) => ({ ...c, proposals: [...c.proposals, p] }));
}

const stored = async (id = "wp-risk") =>
  (await chatStore.load(CASE)).proposals.find((p) => p.id === id) as WatsonVeloLaunchProposal;

beforeEach(async () => {
  store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-velo-risk-")));
  await store.createCase({ caseId: CASE, name: "n", investigator: "i", aiProvider: null });
  chatStore = new WatsonChatStore(store);
  activity = new ActivityLogStore(store);
  fps = fingerprintStoreFor(store);
  calls = [];
});

describe("approving a risky Watson launch (Task 9)", () => {
  it("without acceptRisk: refused with the reasons, still pending, nothing launched or reserved", async () => {
    await seed(risky());
    const err = await applyWatsonProposal(deps(), CASE, "wp-risk", "apply", "Dana Analyst").catch((e) => e);
    expect(err).toBeInstanceOf(WatsonRiskNotAccepted);
    expect(err).toBeInstanceOf(WatsonProposalConflict);
    expect((err as WatsonRiskNotAccepted).reasons).toEqual([EXECVE_PLAIN]);
    expect((err as Error).message).toContain(EXECVE_PLAIN);
    expect(calls).toHaveLength(0);
    expect((await stored()).status).toBe("pending");
    expect([...(await fps.load(CASE))]).toEqual([]);
  });

  it("with acceptRisk: launches the stored VQL byte for byte and records who accepted what", async () => {
    await seed(risky());
    await applyWatsonProposal(deps(), CASE, "wp-risk", "apply", "Dana Analyst", { acceptRisk: true });
    expect(calls).toHaveLength(1);
    expect(calls[0].req.vql).toBe(EXECVE);
    const note = `; approved by Dana Analyst despite warning: ${EXECVE_PLAIN}`;
    expect(calls[0].suffix).toContain(note);
    const p = await stored();
    expect(p.status).toBe("applied");
    expect(p.launched?.riskAccepted).toMatchObject({ by: "Dana Analyst", reasons: [EXECVE_PLAIN] });
    const entries = await activity.load(CASE);
    expect(entries.some((e) => e.action === "watson.apply" && e.detail.includes(note))).toBe(true);
  });

  it("refuses a risk the proposal did not store (no new risk slips in)", async () => {
    const vql = "SELECT * FROM execve(argv=['calc'])\n\nSELECT * FROM shell(cmd='x')";
    await seed(risky(vql));
    const err = await applyWatsonProposal(deps(), CASE, "wp-risk", "apply", "Dana Analyst", {
      acceptRisk: true,
    }).catch((e) => e);
    expect(err).toBeInstanceOf(WatsonProposalConflict);
    expect((err as Error).message).toContain("shell");
    expect(calls).toHaveLength(0);
    expect((await stored()).status).toBe("pending");
  });

  it("a risky query without a stored risk is refused even with acceptRisk (strict)", async () => {
    const { risk: _drop, ...bare } = risky();
    await seed(bare);
    await expect(
      applyWatsonProposal(deps(), CASE, "wp-risk", "apply", "Dana Analyst", { acceptRisk: true }),
    ).rejects.toBeInstanceOf(WatsonProposalConflict);
    expect(calls).toHaveLength(0);
  });

  it("a HARD reason refuses even with a stored risk and acceptRisk", async () => {
    await seed(risky(`${EXECVE} -- hidden`, [EXECVE_RAW, "comments are not allowed"]));
    await expect(
      applyWatsonProposal(deps(), CASE, "wp-risk", "apply", "Dana Analyst", { acceptRisk: true }),
    ).rejects.toBeInstanceOf(WatsonProposalConflict);
    expect(calls).toHaveLength(0);
  });

  it("an uncertain risky launch keeps the acceptance; Mark as launched carries it, Try again needs it anew", async () => {
    await seed(risky());
    const unknown = async (): Promise<VeloLaunchOutcome> => ({ phase: "launch-unknown", error: "timeout" });
    await expect(
      applyWatsonProposal(deps(unknown), CASE, "wp-risk", "apply", "Dana Analyst", { acceptRisk: true }),
    ).rejects.toBeInstanceOf(WatsonLaunchUncertain);
    expect((await stored()).launching?.riskAccepted?.by).toBe("Dana Analyst");
    const rdeps = { chatStore, activity, fingerprints: fps };
    await resolveVeloLaunch(rdeps, CASE, "wp-risk", "retry", "Lee Lead");
    expect((await stored()).status).toBe("pending");
    await expect(applyWatsonProposal(deps(), CASE, "wp-risk", "apply", "Lee Lead")).rejects.toBeInstanceOf(
      WatsonRiskNotAccepted,
    );
    await expect(
      applyWatsonProposal(deps(unknown), CASE, "wp-risk", "apply", "Lee Lead", { acceptRisk: true }),
    ).rejects.toBeInstanceOf(WatsonLaunchUncertain);
    await resolveVeloLaunch(rdeps, CASE, "wp-risk", "launched", "Lee Lead");
    const p = await stored();
    expect(p.launched?.riskAccepted).toMatchObject({ by: "Lee Lead", reasons: [EXECVE_PLAIN] });
    const entries = await activity.load(CASE);
    expect(entries.some((e) => e.action === "watson.resolve" && e.detail.includes("despite warning"))).toBe(
      true,
    );
  });
});
