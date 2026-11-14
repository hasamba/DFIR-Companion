import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import { ActivityLogStore } from "../../../src/analysis/activityLog.js";
import { autoApply, listingText, WATSON_AUTO_ACTOR } from "../../../src/analysis/ai/watson/autoApply.js";
import { WatsonChatStore } from "../../../src/analysis/ai/watson/chatStore.js";
import {
  applyWatsonProposal,
  WatsonProposalStateError,
  type WriterDeps,
} from "../../../src/analysis/ai/watson/proposals.js";
import type {
  WatsonChat,
  WatsonEventPromoteProposal,
  WatsonFindingProposal,
  WatsonProposal,
  WatsonVeloLaunchProposal,
} from "../../../src/analysis/ai/watson/types.js";
import {
  fingerprintStoreFor,
  launchFingerprints,
} from "../../../src/analysis/ai/watson/velo/fingerprintIndex.js";
import type {
  VeloLaunchOutcome,
  VeloLaunchRequest,
} from "../../../src/analysis/ai/watson/velo/launchTypes.js";
import { StateLock } from "../../../src/analysis/stateLock.js";
import { StateStore } from "../../../src/analysis/stateStore.js";
import { emptyState, type Finding, type ForensicEvent } from "../../../src/analysis/stateTypes.js";
import type { PromotionOutcome } from "../../../src/analysis/ingest/promotionOutcome.js";
import { runWithIdentity } from "../../../src/auth/identityContext.js";
import type { AuthIdentity } from "../../../src/auth/types.js";
import { matchClient } from "../../../src/integrations/velociraptor/clientInventory.js";
import { CaseStore } from "../../../src/storage/caseStore.js";

// Auto mode (phase 3, P1/P3): after a round, Watson applies its own proposals of that round. Host
// collections launch only from a round an analyst started; fleet hunts always wait; case writes apply
// from every round. Every action is audited as "Watson (Auto)" and listed in one system turn.

const CASE = "c1";
const TURN = "wt-round";
const OLD_TURN = "wt-old";
const HOST_A = "web01.example.com";
const HOST_B = "db02.example.com";
const PSLIST = "SELECT Pid, Name FROM pslist()";
const NETSTAT = "SELECT * FROM netstat()";
const CLIENTS = [
  { clientId: "C.webserver1", hostname: HOST_A, fqdn: HOST_A },
  { clientId: "C.dbserver2", hostname: HOST_B, fqdn: HOST_B },
];
const SINCE = "2026-11-14T07:30:00.000Z";
const AUTO_ON = {
  watsonRunMode: "auto" as const,
  watsonAutoSince: SINCE,
  watsonAutoBy: { name: "Robin Lead" },
};
const APPROVE = { watsonRunMode: "approve" as const };

const ANALYST: AuthIdentity = {
  id: "u-dana",
  kind: "local",
  username: "dana",
  displayName: "Dana Analyst",
  globalRole: "member",
  disabled: false,
  createdAt: SINCE,
  updatedAt: SINCE,
};

const e1: ForensicEvent = {
  id: "e1",
  timestamp: "2026-03-01T08:05:00Z",
  description: "powershell launched by winword",
  severity: "High",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
};

const finding = (id: string, title: string): Finding => ({
  id,
  severity: "High",
  title,
  description: "Encoded PowerShell ran after the mail.",
  relatedIocs: [],
  sourceScreenshots: [],
  mitreTechniques: [],
  relatedEventIds: ["e1"],
  firstSeen: "2026-03-01T08:00:00Z",
  lastUpdated: "2026-03-01T09:00:00Z",
  status: "open",
});

const findingNew = (id: string, turnId: string, fid: string, title: string): WatsonFindingProposal => ({
  id,
  turnId,
  kind: "finding_new",
  targetId: fid,
  after: finding(fid, title),
  pasteLineEvents: [],
  status: "pending",
});

function launch(id: string, turnId: string, mode: "hunt" | "collection", vql: string, host?: string) {
  const keys = launchFingerprints(vql, host);
  const p: WatsonVeloLaunchProposal = {
    id,
    turnId,
    kind: "velo_launch",
    status: "pending",
    targetId: keys[0],
    mode,
    title: `${mode} ${id}`,
    vql,
    fingerprint: keys[0],
    fingerprints: keys,
    ...(host ? { hostname: host } : {}),
  };
  return p;
}

const held = (id: string, turnId: string): WatsonEventPromoteProposal => ({
  id,
  turnId,
  kind: "event_promote",
  targetId: "ev-held-1",
  events: [{ ...e1, id: "ev-held-1", description: "ntdsutil ifm on db02" }],
  pasteId: "wf-1",
  status: "pending",
});

let cases: CaseStore;
let chatStore: WatsonChatStore;
let activity: ActivityLogStore;
let stateStore: StateStore;
let launches: VeloLaunchRequest[];
let promoted: number;
let launchResult: () => Promise<VeloLaunchOutcome>;

function deps(): WriterDeps {
  return {
    stateStore,
    stateLock: new StateLock(),
    chatStore,
    activity,
    markConclusionsOutOfDate: async () => {},
    promoteEvents: async (caseId) => {
      promoted++;
      const outcome = { added: [], replaced: [] } as unknown as PromotionOutcome;
      return { state: await stateStore.load(caseId), outcome };
    },
    veloLaunch: {
      launch: async (_caseId, req) => {
        launches.push(req);
        return launchResult();
      },
      fleet: {
        veloConnected: () => true,
        velociraptorClientStore: { load: async () => ({ updatedAt: "", clients: CLIENTS }) },
      },
      matchClient,
      fingerprints: fingerprintStoreFor(cases),
    },
  };
}

async function seed(watsonTurnProposals: WatsonProposal[], others: WatsonProposal[] = []): Promise<void> {
  const turns = [
    {
      id: OLD_TURN,
      at: SINCE,
      role: "watson" as const,
      text: "earlier",
      proposalIds: others.map((p) => p.id),
    },
    {
      id: TURN,
      at: SINCE,
      role: "watson" as const,
      text: "now",
      proposalIds: watsonTurnProposals.map((p) => p.id),
    },
  ];
  await chatStore.update(CASE, (c) => ({ ...c, turns, proposals: [...others, ...watsonTurnProposals] }));
}

const status = async (id: string) => (await chatStore.load(CASE)).proposals.find((p) => p.id === id)?.status;
const lastTurn = (chat: WatsonChat) => chat.turns[chat.turns.length - 1];

beforeEach(async () => {
  cases = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-watson-auto-")));
  await cases.createCase({ caseId: CASE, name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(cases);
  await stateStore.save({ ...emptyState(CASE), forensicTimeline: [e1] });
  chatStore = new WatsonChatStore(cases);
  activity = new ActivityLogStore(cases);
  launches = [];
  promoted = 0;
  launchResult = async () => ({
    phase: "launched",
    launched: { flowId: "F.SAMPLE1", clientId: "C.webserver1" },
  });
});

describe("autoApply", () => {
  it("approve mode applies nothing and adds no turn", async () => {
    await seed([
      findingNew("wp-f", TURN, "f-watson-0a1b2c3d", "Phish"),
      launch("wp-c", TURN, "collection", PSLIST, HOST_A),
    ]);
    const chat = await autoApply(deps(), CASE, { turnId: TURN, reaction: false }, APPROVE);
    expect(chat.proposals.map((p) => p.status)).toEqual(["pending", "pending"]);
    expect(chat.turns).toHaveLength(2);
    expect(launches).toHaveLength(0);
  });

  it("an analyst round: the host collection launches and the finding applies, audited as Watson (Auto) inside an analyst request", async () => {
    await seed([
      findingNew("wp-f", TURN, "f-watson-0a1b2c3d", "Phish"),
      launch("wp-c", TURN, "collection", PSLIST, HOST_A),
    ]);
    await runWithIdentity(ANALYST, () => autoApply(deps(), CASE, { turnId: TURN, reaction: false }, AUTO_ON));
    expect(await status("wp-f")).toBe("applied");
    expect(await status("wp-c")).toBe("applied");
    expect(launches).toEqual([
      expect.objectContaining({ mode: "collection", hostname: HOST_A, vql: PSLIST }),
    ]);
    expect((await stateStore.loadOverview(CASE)).findings.map((f) => f.id)).toContain("f-watson-0a1b2c3d");
    const entries = (await activity.load(CASE)).filter((e) => e.action === "watson.apply");
    expect(entries).toHaveLength(2);
    for (const e of entries) {
      expect(e.actor).toBe(WATSON_AUTO_ACTOR);
      expect(e.actorDisplayName).toBeUndefined();
      expect(e.detail).toContain(`Auto mode on since ${SINCE}, switched on by Robin Lead`);
    }
    const applied = (await chatStore.load(CASE)).proposals.find((p) => p.id === "wp-f");
    expect(applied).toMatchObject({ appliedBy: WATSON_AUTO_ACTOR });
  });

  it("a fleet-wide hunt stays pending in Auto, and the turn says it waits for an analyst", async () => {
    await seed([launch("wp-h", TURN, "hunt", PSLIST)]);
    const chat = await autoApply(deps(), CASE, { turnId: TURN, reaction: false }, AUTO_ON);
    expect(await status("wp-h")).toBe("pending");
    expect(launches).toHaveLength(0);
    expect(lastTurn(chat)).toMatchObject({ role: "system" });
    expect(lastTurn(chat).text).toMatch(/fleet-wide hunts always wait for an analyst/);
  });

  it("a reaction round (the one reading its own result) launches nothing but still applies its writes", async () => {
    await seed([
      findingNew("wp-f", TURN, "f-watson-0a1b2c3d", "Phish"),
      launch("wp-c", TURN, "collection", NETSTAT, HOST_A),
    ]);
    const chat = await autoApply(deps(), CASE, { turnId: TURN, reaction: true }, AUTO_ON);
    expect(await status("wp-c")).toBe("pending");
    expect(await status("wp-f")).toBe("applied");
    expect(launches).toHaveLength(0);
    expect(lastTurn(chat).text).toMatch(/does not launch from a round it started itself/);
  });

  it("two collections in one analyst round both launch (no cap), and the turn lists each exact VQL", async () => {
    await seed([
      launch("wp-a", TURN, "collection", PSLIST, HOST_A),
      launch("wp-b", TURN, "collection", NETSTAT, HOST_B),
    ]);
    const chat = await autoApply(deps(), CASE, { turnId: TURN, reaction: false }, AUTO_ON);
    expect(launches.map((l) => l.hostname)).toEqual([HOST_A, HOST_B]);
    expect(await status("wp-a")).toBe("applied");
    expect(await status("wp-b")).toBe("applied");
    const text = lastTurn(chat).text;
    expect(text).toContain(PSLIST);
    expect(text).toContain(NETSTAT);
    expect(text).toContain(HOST_B);
    // The listing survives a reload.
    expect(lastTurn(await chatStore.load(CASE)).text).toBe(text);
  });

  it("undo of an auto-applied finding works as in phase 2", async () => {
    await seed([findingNew("wp-f", TURN, "f-watson-0a1b2c3d", "Phish")]);
    await autoApply(deps(), CASE, { turnId: TURN, reaction: false }, AUTO_ON);
    await applyWatsonProposal(deps(), CASE, "wp-f", "undo", "Dana Analyst");
    expect(await status("wp-f")).toBe("undone");
    expect((await stateStore.loadOverview(CASE)).findings).toHaveLength(0);
  });

  it("touches nothing outside the round: an older pending proposal and a carried id that is not a held promotion", async () => {
    const older = findingNew("wp-old", OLD_TURN, "f-watson-11111111", "Older");
    const oldLaunch = launch("wp-oldc", OLD_TURN, "collection", PSLIST, HOST_A);
    await seed([findingNew("wp-f", TURN, "f-watson-0a1b2c3d", "Phish")], [older, oldLaunch]);
    await autoApply(deps(), CASE, { turnId: TURN, reaction: false, heldIds: ["wp-old", "wp-oldc"] }, AUTO_ON);
    expect(await status("wp-old")).toBe("pending");
    expect(await status("wp-oldc")).toBe("pending");
    expect(launches).toHaveLength(0);
    expect(await status("wp-f")).toBe("applied");
  });

  it("applies the held promotions carried on the round (a result's rows, a paste's rows), pending ones only", async () => {
    const fromResult = held("wp-held", OLD_TURN);
    const fromPaste = held("wp-paste", OLD_TURN);
    const otherPaste = { ...held("wp-other", OLD_TURN), pasteId: "wf-2" };
    const undone = { ...held("wp-undone", OLD_TURN), status: "undone" as const };
    await seed([], [fromResult, fromPaste, otherPaste, undone]);
    await autoApply(
      deps(),
      CASE,
      {
        turnId: TURN,
        reaction: true,
        heldIds: ["wp-held", "wp-undone"],
        paste: { pasteId: "wf-1", proposalIds: ["wp-paste", "wp-other"] },
      },
      AUTO_ON,
    );
    expect(await status("wp-held")).toBe("applied");
    expect(await status("wp-paste")).toBe("applied");
    expect(await status("wp-other")).toBe("pending"); // not from this round's paste
    expect(await status("wp-undone")).toBe("undone"); // an analyst's undo is never redone by Auto
    expect(promoted).toBe(2);
  });

  it("a launch Watson cannot confirm is listed as uncertain and never retried", async () => {
    launchResult = async () => {
      throw new Error("socket hang up");
    };
    await seed([launch("wp-c", TURN, "collection", PSLIST, HOST_A)]);
    const chat = await autoApply(deps(), CASE, { turnId: TURN, reaction: false }, AUTO_ON);
    expect(await status("wp-c")).toBe("uncertain");
    expect(launches).toHaveLength(1);
    expect(lastTurn(chat).text).toMatch(/could not confirm/i);
  });

  it("a refused apply stays pending and is listed as such", async () => {
    const d = { ...deps(), promoteEvents: undefined };
    await seed([], [held("wp-held", OLD_TURN)]);
    const chat = await autoApply(d, CASE, { turnId: TURN, reaction: true, heldIds: ["wp-held"] }, AUTO_ON);
    expect(await status("wp-held")).toBe("pending");
    expect(lastTurn(chat).text).toMatch(/stays pending/);
  });

  it("an auto apply racing an analyst's click on the same collection: exactly one wins, one launch", async () => {
    await seed([launch("wp-c", TURN, "collection", PSLIST, HOST_A)]);
    const results = await Promise.allSettled([
      applyWatsonProposal(deps(), CASE, "wp-c", "apply", "Dana Analyst"),
      applyWatsonProposal(deps(), CASE, "wp-c", "apply", WATSON_AUTO_ACTOR, { pendingOnly: true }),
    ]);
    expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
    const lost = results.find((r) => r.status === "rejected") as PromiseRejectedResult;
    expect(lost.reason).toBeInstanceOf(WatsonProposalStateError);
    expect(launches).toHaveLength(1);
  });

  it("an auto apply racing an analyst's click on the same finding: exactly one wins", async () => {
    await seed([findingNew("wp-f", TURN, "f-watson-0a1b2c3d", "Phish")]);
    const [click, auto] = await Promise.allSettled([
      applyWatsonProposal(deps(), CASE, "wp-f", "apply", "Dana Analyst"),
      autoApply(deps(), CASE, { turnId: TURN, reaction: false }, AUTO_ON),
    ]);
    expect(auto.status).toBe("fulfilled"); // a lost race is listed, never thrown
    const applies = (await activity.load(CASE)).filter((e) => e.action === "watson.apply");
    expect(applies).toHaveLength(1);
    if (click.status === "rejected") expect(click.reason).toBeInstanceOf(WatsonProposalStateError);
    expect((await stateStore.loadOverview(CASE)).findings).toHaveLength(1);
  });

  it("a VQL too long for the turn is pointed at, never cut", () => {
    const long = `SELECT * FROM pslist() WHERE Name =~ '${"a".repeat(9000)}'`;
    const text = listingText("Robin Lead", [
      { line: "- Launched Velociraptor collection on web01.example.com: short", vql: PSLIST },
      { line: "- Launched Velociraptor collection on db02.example.com: long", vql: long },
    ]);
    expect(text).toContain(PSLIST);
    expect(text).not.toContain(long.slice(0, 100));
    expect(text).toContain(`VQL: ${long.length} characters, too long to repeat here`);
  });
});
