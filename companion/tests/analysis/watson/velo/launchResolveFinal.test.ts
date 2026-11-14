import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import { ActivityLogStore } from "../../../../src/analysis/activityLog.js";
import { WatsonChatStore } from "../../../../src/analysis/ai/watson/chatStore.js";
import type { WatsonVeloLaunchProposal } from "../../../../src/analysis/ai/watson/types.js";
import { fingerprintStoreFor } from "../../../../src/analysis/ai/watson/velo/fingerprintIndex.js";
import { clearInFlight, markInFlight } from "../../../../src/analysis/ai/watson/velo/launchInFlight.js";
import {
  resolveVeloLaunch,
  withStalledLaunches,
} from "../../../../src/analysis/ai/watson/velo/launchResolve.js";
import { CaseStore } from "../../../../src/storage/caseStore.js";

// Final review G10 (resolving keeps who launched it), G11 (a stranded launching card is flagged)
// and G17 (the resolve audit is written before the hunt outcome is recorded).

const CASE = "c1";
let store: CaseStore;
let chatStore: WatsonChatStore;
let activity: ActivityLogStore;

const uncertain = (status: WatsonVeloLaunchProposal["status"] = "uncertain"): WatsonVeloLaunchProposal => ({
  id: "wp-1",
  turnId: "t1",
  kind: "velo_launch",
  status,
  targetId: "fp1",
  mode: "collection",
  hostname: "web01.example.com",
  title: "Process listing",
  vql: "SELECT * FROM pslist()",
  fingerprint: "fp1",
  fingerprints: ["fp1"],
  launching: { at: "2026-11-14T10:00:00.000Z", by: "Watson (Auto)", fingerprint: "fp1", reserved: ["fp1"] },
});

beforeEach(async () => {
  store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-velo-resolve-")));
  await store.createCase({ caseId: CASE, name: "n", investigator: "i", aiProvider: null });
  chatStore = new WatsonChatStore(store);
  activity = new ActivityLogStore(store);
  await chatStore.update(CASE, (c) => ({ ...c, proposals: [uncertain()] }));
});

const deps = (recordDeploy?: () => Promise<void>) => ({
  chatStore,
  activity,
  fingerprints: fingerprintStoreFor(store),
  ...(recordDeploy ? { recordDeploy } : {}),
});

describe("resolving an uncertain launch", () => {
  it("keeps the launcher as launched.by / appliedBy and records the analyst as resolvedBy (G10)", async () => {
    await resolveVeloLaunch(deps(), CASE, "wp-1", "launched", "Dana Analyst");
    const p = (await chatStore.load(CASE)).proposals[0] as WatsonVeloLaunchProposal;
    expect(p.status).toBe("applied");
    expect(p.launched?.by).toBe("Watson (Auto)");
    expect(p.appliedBy).toBe("Watson (Auto)");
    expect(p.resolvedBy).toBe("Dana Analyst");
    expect(p.launched?.at).toBe("2026-11-14T10:00:00.000Z");
  });

  it("writes the audit before the outcome record, and audits a failed record (G17)", async () => {
    const order: string[] = [];
    const failing = async () => {
      order.push(`record after ${(await activity.load(CASE)).length} entries`);
      throw new Error("ledger locked");
    };
    await resolveVeloLaunch(deps(failing), CASE, "wp-1", "launched", "Dana Analyst");
    expect(order).toEqual(["record after 1 entries"]);
    const entries = await activity.load(CASE);
    expect(entries.map((e) => e.detail).join("\n")).toMatch(/marked as launched/);
    expect(entries.find((e) => e.outcome === "error")?.detail).toMatch(
      /could not be recorded: ledger locked/,
    );
  });
});

describe("withStalledLaunches (G11)", () => {
  it("flags a launching proposal no live request owns, and only that one", async () => {
    const chat = { ...(await chatStore.load(CASE)), proposals: [uncertain("launching")] };
    expect((withStalledLaunches(CASE, chat).proposals[0] as WatsonVeloLaunchProposal).stalled).toBe(true);
    markInFlight(CASE, "wp-1");
    expect(
      (withStalledLaunches(CASE, chat).proposals[0] as WatsonVeloLaunchProposal).stalled,
    ).toBeUndefined();
    clearInFlight(CASE, "wp-1");
  });

  it("the flag is never stored", async () => {
    const chat = withStalledLaunches(CASE, {
      ...(await chatStore.load(CASE)),
      proposals: [uncertain("launching")],
    });
    await chatStore.save(CASE, chat);
    expect((await chatStore.load(CASE)).proposals[0]).not.toHaveProperty("stalled");
  });
});
