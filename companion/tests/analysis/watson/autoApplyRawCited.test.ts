import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import { ActivityLogStore } from "../../../src/analysis/activityLog.js";
import {
  autoApply,
  eligibleProposals,
  isRawCited,
  type WatsonAutoRound,
} from "../../../src/analysis/ai/watson/autoApply.js";
import { WatsonChatStore } from "../../../src/analysis/ai/watson/chatStore.js";
import type { WriterDeps } from "../../../src/analysis/ai/watson/proposals.js";
import type {
  WatsonChat,
  WatsonEventPromoteProposal,
  WatsonFindingProposal,
  WatsonProposal,
} from "../../../src/analysis/ai/watson/types.js";
import type { PromotionOutcome } from "../../../src/analysis/ingest/promotionOutcome.js";
import { StateLock } from "../../../src/analysis/stateLock.js";
import { StateStore } from "../../../src/analysis/stateStore.js";
import { emptyState, type Finding, type ForensicEvent } from "../../../src/analysis/stateTypes.js";
import { CaseStore } from "../../../src/storage/caseStore.js";

// U5: in Auto, a case write that cites rows Watson saw in the super-timeline or in a paste waits for
// an analyst, from every round source. Writes on forensic-timeline events only still auto-apply.
// Promotions (a paste's held rows, the round's super-timeline promotion) keep today's behaviour.

const CASE = "c1";
const TURN = "wt-round";
const WAITS = "Waits for you: it rests on rows Watson saw in the super-timeline or in a paste.";
const AUTO_ON = {
  watsonRunMode: "auto" as const,
  watsonAutoSince: "2026-11-14T07:30:00.000Z",
  watsonAutoBy: { name: "Robin Lead" },
};
const DASHBOARD: WatsonAutoRound = { turnId: TURN, reaction: false, source: "dashboard" };

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

const findingNew = (
  id: string,
  title: string,
  extra: Partial<WatsonFindingProposal> = {},
): WatsonFindingProposal => ({
  id,
  turnId: TURN,
  kind: "finding_new",
  targetId: `f-watson-${id}`,
  after: finding(`f-watson-${id}`, title),
  pasteLineEvents: [],
  status: "pending",
  ...extra,
});

const RAW = { rawEvidenceIds: ["ev-raw-1"] };

const question = (id: string): WatsonProposal =>
  ({
    id,
    turnId: TURN,
    kind: "question_new",
    questionId: `q-${id}`,
    after: { id: `q-${id}`, question: "Who ran it?", answer: "dana", status: "answered" },
    ...RAW,
    status: "pending",
  }) as unknown as WatsonProposal;

const nextStep = (id: string): WatsonProposal =>
  ({
    id,
    turnId: TURN,
    kind: "next_step_new",
    targetId: `ns-${id}`,
    after: { id: `ns-${id}`, action: "Pull the MFT", status: "open" },
    ...RAW,
    status: "pending",
  }) as unknown as WatsonProposal;

const report = (id: string): WatsonProposal => ({
  id,
  turnId: TURN,
  kind: "report_text",
  targetId: "conclusions",
  field: "conclusions",
  before: "",
  after: "The actor used a paste row.",
  ...RAW,
  status: "pending",
});

const promotion = (id: string, extra: Partial<WatsonEventPromoteProposal>): WatsonEventPromoteProposal => ({
  id,
  turnId: TURN,
  kind: "event_promote",
  targetId: `ev-${id}`,
  events: [{ ...e1, id: `ev-${id}`, description: "ntdsutil ifm on db02" }],
  status: "pending",
  ...extra,
});

let cases: CaseStore;
let chatStore: WatsonChatStore;
let stateStore: StateStore;
let promoted: number;

function deps(): WriterDeps {
  return {
    stateStore,
    stateLock: new StateLock(),
    chatStore,
    activity: new ActivityLogStore(cases),
    markConclusionsOutOfDate: async () => {},
    promoteEvents: async (caseId) => {
      promoted++;
      const outcome = { added: [], replaced: [] } as unknown as PromotionOutcome;
      return { state: await stateStore.load(caseId), outcome };
    },
  };
}

async function seed(own: WatsonProposal[], others: WatsonProposal[] = []): Promise<void> {
  const turns = [
    {
      id: TURN,
      at: AUTO_ON.watsonAutoSince,
      role: "watson" as const,
      text: "now",
      proposalIds: own.map((p) => p.id),
    },
  ];
  await chatStore.update(CASE, (c) => ({ ...c, turns, proposals: [...others, ...own] }));
}

const status = (chat: WatsonChat, id: string) => chat.proposals.find((p) => p.id === id)?.status;
const listing = (chat: WatsonChat) =>
  chat.turns
    .filter((t) => t.role === "system")
    .map((t) => t.text)
    .join("\n");

beforeEach(async () => {
  cases = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-watson-rawcited-")));
  await cases.createCase({ caseId: CASE, name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(cases);
  await stateStore.save({ ...emptyState(CASE), forensicTimeline: [e1] });
  chatStore = new WatsonChatStore(cases);
  promoted = 0;
});

describe("isRawCited", () => {
  it("is true for rawEvidenceIds or cited paste lines, false for forensic-only writes and promotions", () => {
    expect(isRawCited(findingNew("a", "A", RAW))).toBe(true);
    expect(isRawCited(findingNew("b", "B", { pasteLineEvents: [{ ...e1, id: "ev-paste-1" }] }))).toBe(true);
    expect(isRawCited(findingNew("c", "C"))).toBe(false);
    expect(isRawCited(findingNew("d", "D", { rawEvidenceIds: [] }))).toBe(false);
    expect(isRawCited(promotion("p", { source: "supertimeline" }))).toBe(false);
  });
});

describe("Auto holds raw-cited writes (U5)", () => {
  it("Auto holds a finding with rawEvidenceIds; it stays pending and the listing says it waits", async () => {
    await seed([findingNew("f1", "From super rows", RAW)]);
    const chat = await autoApply(deps(), CASE, DASHBOARD, AUTO_ON);
    expect(status(chat, "f1")).toBe("pending");
    expect(listing(chat)).toContain("new finding: From super rows");
    expect(listing(chat)).toContain(WAITS);
    expect((await stateStore.load(CASE)).findings).toHaveLength(0);
    // F8: Watson applied nothing, so the heading does not say it did these actions.
    expect(listing(chat)).toMatch(
      /^Watson left these actions for you in Auto mode\. Robin Lead set Auto mode\./,
    );
  });

  it("Auto holds a finding that cites pasteLines", async () => {
    await seed([findingNew("f2", "From a paste", { pasteLineEvents: [{ ...e1, id: "ev-paste-1" }] })]);
    const chat = await autoApply(deps(), CASE, DASHBOARD, AUTO_ON);
    expect(status(chat, "f2")).toBe("pending");
    expect(listing(chat)).toContain(WAITS);
  });

  it("Auto holds a question / next-step / report proposal with rawEvidenceIds", async () => {
    await seed([question("q1"), nextStep("n1"), report("r1")]);
    const chat = await autoApply(deps(), CASE, DASHBOARD, AUTO_ON);
    expect(["q1", "n1", "r1"].map((id) => status(chat, id))).toEqual(["pending", "pending", "pending"]);
    expect(listing(chat).split(WAITS)).toHaveLength(4);
  });

  it("Auto still applies a finding that cites only forensic-timeline eventIds", async () => {
    await seed([findingNew("f3", "Forensic only"), findingNew("f4", "Raw", RAW)]);
    const chat = await autoApply(deps(), CASE, DASHBOARD, AUTO_ON);
    expect(status(chat, "f3")).toBe("applied");
    expect(status(chat, "f4")).toBe("pending");
    expect(listing(chat)).toContain("Applied new finding: Forensic only");
    expect(listing(chat)).toMatch(/^Watson did these actions in Auto mode\./);
  });

  it("the rule holds for dashboard, slash and reaction rounds alike", async () => {
    const rounds: WatsonAutoRound[] = [
      DASHBOARD,
      { turnId: TURN, reaction: false, source: "slash" },
      { turnId: TURN, reaction: true },
    ];
    for (const round of rounds) {
      await seed([findingNew("f5", "Raw", RAW), report("r5")]);
      expect(eligibleProposals(await chatStore.load(CASE), round)).toEqual([]);
      const chat = await autoApply(deps(), CASE, round, AUTO_ON);
      expect([status(chat, "f5"), status(chat, "r5")]).toEqual(["pending", "pending"]);
      expect(listing(chat)).toContain(WAITS);
    }
  });

  it("the round's own super-timeline promotion and held paste promotions keep today's behaviour", async () => {
    const roundPromo = promotion("sp", { source: "supertimeline" });
    const pastePromo = promotion("pp", { pasteId: "wf-1" });
    await seed([roundPromo], [pastePromo]);
    const round = { ...DASHBOARD, paste: { pasteId: "wf-1", proposalIds: ["pp"] } };
    expect(eligibleProposals(await chatStore.load(CASE), round).map((p) => p.id)).toEqual(["pp"]);
    const chat = await autoApply(deps(), CASE, round, AUTO_ON);
    expect(status(chat, "pp")).toBe("applied");
    expect(status(chat, "sp")).toBe("pending");
    expect(promoted).toBe(1);
    expect(listing(chat)).not.toContain(WAITS);
  });
});
