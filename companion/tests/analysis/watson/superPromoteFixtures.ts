import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ActivityLogStore, NewActivityEntry } from "../../../src/analysis/activityLog.js";
import { AiCostStore } from "../../../src/analysis/aiCost.js";
import { AnonControlStore } from "../../../src/analysis/anonControl.js";
import { analyzeRestored } from "../../../src/analysis/ai/providerCall.js";
import { WatsonChatStore } from "../../../src/analysis/ai/watson/chatStore.js";
import type { WriterDeps } from "../../../src/analysis/ai/watson/proposals.js";
import { runWatsonRound, type WatsonRoundContext } from "../../../src/analysis/ai/watson/round.js";
import type { WatsonChat, WatsonEventPromoteProposal } from "../../../src/analysis/ai/watson/types.js";
import type { WatsonReportFields } from "../../../src/analysis/ai/watson/writers/writerTypes.js";
import { AnalysisPipeline } from "../../../src/analysis/pipeline.js";
import { StateLock } from "../../../src/analysis/stateLock.js";
import { StateStore } from "../../../src/analysis/stateStore.js";
import { emptyState, type ForensicEvent } from "../../../src/analysis/stateTypes.js";
import { SuperTimelineStore } from "../../../src/analysis/superTimelineStore.js";
import type { Logger } from "../../../src/logging/logger.js";
import type { AIProvider, AnalyzeRequest, AnalyzeResult } from "../../../src/providers/provider.js";
import { CaseStore } from "../../../src/storage/caseStore.js";

// Shared harness for Watson's evidence-first promotion (phase 4, Task 5): a real state store, a real
// promotion seam (the pipeline's), a real super-timeline, and a chat store whose updates a test can
// fail or hold.

export const CASE = "c1";
export const log: Logger = {
  debug: () => undefined,
  info: () => undefined,
  warn: () => undefined,
  error: () => undefined,
  getLevel: () => "debug",
  setLevel: () => undefined,
  close: async () => undefined,
};

export class FakeProvider implements AIProvider {
  readonly name = "fake";
  readonly model = "fake-model";
  calls = 0;
  constructor(
    private readonly replies: string[],
    private readonly onCall?: (n: number) => void | Promise<void>,
  ) {}
  async analyze(_req: AnalyzeRequest): Promise<AnalyzeResult> {
    this.calls++;
    await this.onCall?.(this.calls);
    return { rawText: this.replies.shift() ?? reply(), usage: { costUSD: 0.01 } };
  }
}

export function reply(over: Record<string, unknown> = {}): string {
  return JSON.stringify({
    message: "I looked at the case.",
    workingOn: "",
    learned: "",
    questionUpdates: [],
    newQuestions: [],
    request: null,
    search: null,
    memory: "memory v1",
    ...over,
  });
}

export const answer = (ids: string[], text = "a") => ({
  answer: { question: "q?", status: "answered", answer: text, pointer: "p", relatedEventIds: ids },
});
export const superLookup = () => ({ lookup: { source: "supertimeline", text: "rclone" } });
export const finding = (eventIds: string[], description = "rclone copied the share") => ({
  severity: "High",
  title: "Exfiltration with rclone",
  description,
  mitreTechniques: ["T1567"],
  eventIds,
  pasteLines: [],
});
export const writes = (over: Record<string, unknown> = {}) => ({
  writes: { findings: [], nextSteps: [], report: [], ...over },
});

export const ev = (id: string, over: Partial<ForensicEvent> = {}): ForensicEvent => ({
  id,
  timestamp: "2026-01-01T15:00:00Z",
  description: `quiet event ${id}`,
  severity: "Low",
  sources: ["Hayabusa"],
  asset: "HOST-A",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
  ...over,
});
export const raw = (id: string, over: Partial<ForensicEvent> = {}): ForensicEvent =>
  ev(id, { severity: "Info", description: `rclone copy ${id}`, ...over });

/** A chat store whose updates a test can fail (throw in `hook`) or hold (`holdNext`). */
export class HookedChatStore extends WatsonChatStore {
  hook?: (before: WatsonChat, after: WatsonChat) => void | Promise<void>;
  /** Set: the next update() call waits for this promise before it starts. */
  holdNext?: { until: Promise<void>; started: () => void };
  override update(
    caseId: string,
    fn: (chat: WatsonChat) => WatsonChat | Promise<WatsonChat>,
  ): Promise<WatsonChat> {
    const hold = this.holdNext;
    this.holdNext = undefined;
    const run = () =>
      super.update(caseId, async (c) => {
        const next = await fn(c);
        await this.hook?.(c, next);
        return next;
      });
    if (!hold) return run();
    hold.started();
    return hold.until.then(run);
  }
}

export interface HarnessFlags {
  aiOn: boolean;
  frozen: boolean;
  activityThrows: boolean;
  markThrows: boolean;
}

export interface HarnessOpts {
  raw?: ForensicEvent[];
  forensic?: ForensicEvent[];
  mode?: "approve" | "auto";
  /** Called before each model call with its number and the harness flags (to freeze the case mid-round). */
  onCall?: (n: number, flags: HarnessFlags) => void | Promise<void>;
  /** Wraps the pipeline's promotion seam. */
  promote?: (real: NonNullable<WriterDeps["promoteEvents"]>) => NonNullable<WriterDeps["promoteEvents"]>;
  noRawSearch?: boolean;
}

export async function harness(replies: string[], opts: HarnessOpts = {}) {
  const root = await mkdtemp(join(tmpdir(), "dfir-watson-super-promote-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: CASE, name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(cases);
  await stateStore.save({ ...emptyState(CASE), forensicTimeline: opts.forensic ?? [ev("e1")] });
  const anonStore = new AnonControlStore(cases);
  await anonStore.save(CASE, { ...(await anonStore.load(CASE)), enabled: false });
  const superStore = new SuperTimelineStore(cases);
  await superStore.append(CASE, opts.raw ?? [raw("raw1"), raw("raw2")]);
  const stateLock = new StateLock();
  const pipeline = new AnalysisPipeline({
    stateStore,
    stateLock,
    imageLoader: async () => ({ base64: "", mimeType: "image/webp" }),
  });
  const chatStore = new HookedChatStore(cases);
  const flags: HarnessFlags = { aiOn: true, frozen: false, activityThrows: false, markThrows: false };
  const entries: NewActivityEntry[] = [];
  const outOfDate: string[] = [];
  let report: WatsonReportFields = { conclusions: "old", investigationLimitations: "" };
  const reportText = {
    load: async () => report,
    update: async (
      _c: string,
      fn: (r: WatsonReportFields) => WatsonReportFields | Promise<WatsonReportFields>,
    ) => (report = await fn(report)),
  };
  const real: NonNullable<WriterDeps["promoteEvents"]> = (caseId, events, o) =>
    pipeline.promoteSuperTimelineWithOutcome(caseId, events, o);
  const deps: WriterDeps = {
    stateStore,
    stateLock,
    chatStore,
    activity: {
      add: async (_c: string, e: NewActivityEntry) => {
        if (flags.activityThrows) throw new Error("activity log is read-only");
        entries.push(e);
        return e;
      },
    } as unknown as ActivityLogStore,
    cases,
    reportText,
    markConclusionsOutOfDate: async (_c, why) => {
      if (flags.markThrows) throw new Error("report meta is locked");
      outOfDate.push(why);
    },
    promoteEvents: opts.promote ? opts.promote(real) : real,
  };
  const costStore = new AiCostStore(cases);
  const provider = new FakeProvider(replies, opts.onCall && ((n) => opts.onCall?.(n, flags)));
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
    reportText,
    reportBlockText: (t) => t,
    ...(opts.noRawSearch
      ? {}
      : {
          rawSearch: {
            reader: { query: (id, q) => superStore.query(id, q), meta: (id) => superStore.meta(id) },
            writer: deps,
            writable: async () => flags.aiOn && !flags.frozen,
          },
        }),
    ...(opts.mode === "auto"
      ? { auto: { control: async () => ({ watsonRunMode: "auto" as const }), writer: deps } }
      : {}),
  };
  const run = (text = "any rclone?", over: Partial<Parameters<typeof runWatsonRound>[2]> = {}) =>
    runWatsonRound(ctx, CASE, { text, source: "dashboard", ...over });
  const row = async (id: string) => (await stateStore.forensicRowsById(CASE, [id]))[0]?.event;
  return {
    ctx,
    deps,
    chatStore,
    stateStore,
    provider,
    flags,
    entries,
    outOfDate,
    run,
    row,
    report: () => report,
  };
}

export const lastWatsonTurn = (chat: WatsonChat) => chat.turns.filter((t) => t.role === "watson").at(-1)!;
export const promotionOf = (chat: WatsonChat) =>
  chat.proposals.find((p) => p.kind === "event_promote" && p.source === "supertimeline") as
    WatsonEventPromoteProposal | undefined;
export const turnProposals = (chat: WatsonChat) => {
  const ids = new Set(lastWatsonTurn(chat).proposalIds ?? []);
  return chat.proposals.filter((p) => ids.has(p.id));
};
