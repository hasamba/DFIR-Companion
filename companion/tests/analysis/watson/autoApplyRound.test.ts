import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { ActivityLogStore } from "../../../src/analysis/activityLog.js";
import { AiCostStore } from "../../../src/analysis/aiCost.js";
import { AnonControlStore } from "../../../src/analysis/anonControl.js";
import { analyzeRestored } from "../../../src/analysis/ai/providerCall.js";
import { WATSON_AUTO_ACTOR, type WatsonAutoControl } from "../../../src/analysis/ai/watson/autoApply.js";
import { WatsonChatStore } from "../../../src/analysis/ai/watson/chatStore.js";
import { runWatsonRound, type WatsonRoundContext } from "../../../src/analysis/ai/watson/round.js";
import type {
  WatsonCaseEvent,
  WatsonEventPromoteProposal,
  WatsonProposal,
} from "../../../src/analysis/ai/watson/types.js";
import type { PromotionOutcome } from "../../../src/analysis/ingest/promotionOutcome.js";
import { StateLock } from "../../../src/analysis/stateLock.js";
import { StateStore } from "../../../src/analysis/stateStore.js";
import { emptyState, type ForensicEvent } from "../../../src/analysis/stateTypes.js";
import { runWithIdentity } from "../../../src/auth/identityContext.js";
import type { AuthIdentity } from "../../../src/auth/types.js";
import type { Logger } from "../../../src/logging/logger.js";
import type { AIProvider, AnalyzeRequest, AnalyzeResult } from "../../../src/providers/provider.js";
import { CaseStore } from "../../../src/storage/caseStore.js";

// Auto mode wired into the round: the round's own proposals and the held promotions it carried are
// applied after the save; nothing older is; the mode is read after the model call.

const CASE = "c1";
const SINCE = "2026-11-14T07:30:00.000Z";
const AUTO: WatsonAutoControl = {
  watsonRunMode: "auto",
  watsonAutoSince: SINCE,
  watsonAutoBy: { name: "Robin Lead" },
};
const log: Logger = {
  debug: () => undefined,
  info: () => undefined,
  warn: () => undefined,
  error: () => undefined,
  getLevel: () => "debug",
  setLevel: () => undefined,
  close: async () => undefined,
};
const ANALYST: AuthIdentity = {
  id: "u-dana",
  kind: "local",
  displayName: "Dana Analyst",
  globalRole: "member",
  disabled: false,
  createdAt: SINCE,
  updatedAt: SINCE,
};

const e1: ForensicEvent = {
  id: "e1",
  timestamp: "2026-01-01T10:00:00Z",
  description: "powershell.exe -enc AAA on HOST-A",
  severity: "High",
  sources: ["Hayabusa"],
  asset: "HOST-A",
  mitreTechniques: ["T1059.001"],
  relatedFindingIds: [],
  sourceScreenshots: [],
};

const reply = JSON.stringify({
  message: "Encoded PowerShell ran.",
  workingOn: "initial access",
  learned: "",
  questionUpdates: [
    { questionId: "wq-std-what", status: "partial", answer: "Encoded PowerShell ran", pointer: "e1" },
  ],
  newQuestions: [],
  request: null,
  search: null,
  memory: "m",
});

class OneReply implements AIProvider {
  readonly name = "fake";
  readonly model = "fake-model";
  constructor(private readonly onCall: () => void = () => undefined) {}
  async analyze(_req: AnalyzeRequest): Promise<AnalyzeResult> {
    this.onCall();
    return { rawText: reply, usage: { costUSD: 0.01 } };
  }
}

const heldPromotion = (id: string, pasteId = "wf-1"): WatsonEventPromoteProposal => ({
  id,
  turnId: "wt-ingest",
  kind: "event_promote",
  targetId: `ev-${id}`,
  events: [{ ...e1, id: `ev-${id}` }],
  pasteId,
  status: "pending",
});

async function harness(control: () => WatsonAutoControl, onCall?: () => void) {
  const cases = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-watson-auto-round-")));
  await cases.createCase({ caseId: CASE, name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(cases);
  await stateStore.save({ ...emptyState(CASE), forensicTimeline: [e1] });
  const anonStore = new AnonControlStore(cases);
  await anonStore.save(CASE, { ...(await anonStore.load(CASE)), enabled: false });
  const costStore = new AiCostStore(cases);
  const provider = new OneReply(onCall);
  const chatStore = new WatsonChatStore(cases);
  const activity = new ActivityLogStore(cases);
  const stateLock = new StateLock();
  const promoted: string[] = [];
  const gateCtx = { log, opts: { anonStore, aiCostStore: costStore } };
  const ctx: WatsonRoundContext = {
    opts: { stateStore, retries: 0, backoffMs: 0 },
    log,
    requireProvider: () => provider,
    getKevCatalog: async () => undefined,
    withRetry: (_c, _l, fn) => fn(),
    analyzeRestored: (caseId, state, p, req, label, skip) =>
      analyzeRestored(gateCtx, caseId, state, p, req, label, skip),
    chatStore,
    stateStore,
    stateLock,
    cases,
    costStore,
    provider,
    isAiEnabled: async () => true,
    auto: {
      control: async () => control(),
      writer: {
        stateStore,
        stateLock,
        chatStore,
        activity,
        markConclusionsOutOfDate: async () => {},
        promoteEvents: async (caseId, events) => {
          promoted.push(...events.map((e) => e.id));
          const outcome = { added: [], replaced: [] } as unknown as PromotionOutcome;
          return { state: await stateStore.load(caseId), outcome };
        },
      },
    },
  };
  const seed = (proposals: WatsonProposal[], pendingCaseEvents: WatsonCaseEvent[] = [], engaged = true) =>
    chatStore.update(CASE, (c) => ({
      ...c,
      analystEngaged: engaged,
      turns: [{ id: "wt-ingest", at: SINCE, role: "system", text: "parsed" }],
      proposals,
      pendingCaseEvents,
    }));
  return { ctx, chatStore, activity, promoted, seed };
}

const statusOf = (chat: { proposals: WatsonProposal[] }, id: string) =>
  chat.proposals.find((p) => p.id === id)?.status;

describe("Auto mode in a Watson round", () => {
  it("applies the round's own proposal as Watson (Auto), even inside an analyst request, and leaves older ones", async () => {
    const h = await harness(() => AUTO);
    await h.seed([heldPromotion("wp-older")]);
    const chat = await runWithIdentity(ANALYST, () =>
      runWatsonRound(h.ctx, CASE, { text: "What happened?", actor: "Dana Analyst" }),
    );
    const own = chat.proposals.find((p) => p.kind === "question_update");
    expect(own?.status).toBe("applied");
    expect(statusOf(chat, "wp-older")).toBe("pending");
    expect(h.promoted).toEqual([]);
    expect(chat.turns[chat.turns.length - 1]).toMatchObject({ role: "system" });
    expect(chat.turns[chat.turns.length - 1].text).toContain("key question");
    const entry = (await h.activity.load(CASE)).find((e) => e.action === "watson.apply");
    expect(entry).toMatchObject({ actor: WATSON_AUTO_ACTOR });
    expect(entry?.detail).toContain("switched on by Robin Lead");
  });

  it("reads the mode after the model call: a switch to Approve mid-round applies nothing", async () => {
    let mode: WatsonAutoControl = AUTO;
    const h = await harness(
      () => mode,
      () => (mode = { watsonRunMode: "approve" }),
    );
    const chat = await runWatsonRound(h.ctx, CASE, { text: "What happened?" });
    expect(chat.proposals.find((p) => p.kind === "question_update")?.status).toBe("pending");
    expect(chat.turns.map((t) => t.role)).toEqual(["analyst", "watson"]); // no Auto listing
  });

  it("a reaction applies only the held promotions on the result events it showed", async () => {
    const h = await harness(() => AUTO);
    const shown: WatsonCaseEvent = {
      kind: "hunt",
      text: "Watson's collection on web01.example.com returned 3 rows",
      at: SINCE,
      proposalIds: ["wp-shown"],
    };
    await h.seed([heldPromotion("wp-shown"), heldPromotion("wp-not-shown")], [shown]);
    const chat = await runWatsonRound(h.ctx, CASE, {
      text: "",
      reaction: true,
      heldProposalIds: ["wp-shown", "wp-not-shown"],
    });
    expect(statusOf(chat, "wp-shown")).toBe("applied");
    expect(statusOf(chat, "wp-not-shown")).toBe("pending");
    expect(h.promoted).toEqual(["ev-wp-shown"]);
  });

  it("an analyst round never applies held promotions a result event carried", async () => {
    const h = await harness(() => AUTO);
    const shown: WatsonCaseEvent = { kind: "hunt", text: "result", at: SINCE, proposalIds: ["wp-shown"] };
    await h.seed([heldPromotion("wp-shown")], [shown]);
    const chat = await runWatsonRound(h.ctx, CASE, { text: "Anything new?", heldProposalIds: ["wp-shown"] });
    expect(statusOf(chat, "wp-shown")).toBe("pending");
  });

  it("a paste round applies the held promotions its own paste created, not another paste's", async () => {
    const h = await harness(() => AUTO);
    await h.seed([heldPromotion("wp-mine", "wf-1"), heldPromotion("wp-other", "wf-2")]);
    const chat = await runWatsonRound(h.ctx, CASE, {
      text: "Pasted netstat.txt",
      pasteId: "wf-1",
      pasteProposalIds: ["wp-mine", "wp-other"],
    });
    expect(statusOf(chat, "wp-mine")).toBe("applied");
    expect(statusOf(chat, "wp-other")).toBe("pending");
  });

  it("a reaction that shows an import keeps the door shut: a result's held rows stay pending", async () => {
    const h = await harness(() => AUTO);
    const result: WatsonCaseEvent = { kind: "hunt", text: "result", at: SINCE, proposalIds: ["wp-shown"] };
    const imported: WatsonCaseEvent = { kind: "import", text: "An import finished", at: SINCE };
    await h.seed([heldPromotion("wp-shown")], [imported, result]);
    const chat = await runWatsonRound(h.ctx, CASE, {
      text: "",
      reaction: true,
      heldProposalIds: ["wp-shown"],
    });
    expect(statusOf(chat, "wp-shown")).toBe("pending");
    expect(h.promoted).toEqual([]);
  });

  it("a paste round with writes off applies none of its paste's rows", async () => {
    const h = await harness(() => AUTO);
    await h.seed([heldPromotion("wp-mine", "wf-1")]);
    const chat = await runWatsonRound(h.ctx, CASE, {
      text: "Pasted netstat.txt",
      pasteId: "wf-1",
      pasteProposalIds: ["wp-mine"],
      allowWrites: false,
    });
    expect(statusOf(chat, "wp-mine")).toBe("pending");
  });
});
