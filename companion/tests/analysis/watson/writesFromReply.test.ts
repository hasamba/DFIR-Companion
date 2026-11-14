import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { ActivityLogStore, NewActivityEntry } from "../../../src/analysis/activityLog.js";
import { AiCostStore } from "../../../src/analysis/aiCost.js";
import { AnonControlStore } from "../../../src/analysis/anonControl.js";
import { analyzeRestored } from "../../../src/analysis/ai/providerCall.js";
import { WatsonChatStore } from "../../../src/analysis/ai/watson/chatStore.js";
import {
  applyWatsonProposal,
  WatsonProposalConflict,
  type WriterDeps,
} from "../../../src/analysis/ai/watson/proposals.js";
import { sanitizeWatsonReply, watsonReplySchema } from "../../../src/analysis/ai/watson/replySchema.js";
import { runWatsonRound, type WatsonRoundContext } from "../../../src/analysis/ai/watson/round.js";
import { blockMd } from "../../../src/reports/mdText.js";
import { buildWriteProposals } from "../../../src/analysis/ai/watson/writeProposals.js";
import type { WatsonFindingDraft } from "../../../src/analysis/ai/watson/writesSchema.js";
import type {
  WatsonFindingProposal,
  WatsonNextStepProposal,
  WatsonPaste,
  WatsonReportTextProposal,
} from "../../../src/analysis/ai/watson/types.js";
import { StateLock } from "../../../src/analysis/stateLock.js";
import { StateStore } from "../../../src/analysis/stateStore.js";
import { emptyState, type Finding, type ForensicEvent } from "../../../src/analysis/stateTypes.js";
import type { Logger } from "../../../src/logging/logger.js";
import type { AIProvider, AnalyzeRequest, AnalyzeResult } from "../../../src/providers/provider.js";
import { ReportMetaStore } from "../../../src/reports/reportMeta.js";
import { CaseStore } from "../../../src/storage/caseStore.js";

// The model proposes writes (findings, next steps, report text) in its reply. Every write becomes a
// PENDING proposal; nothing reaches the case until an analyst applies it. A finding is proposed only
// with a citation that exists: a forensic-timeline event or a line of a stored paste.

const CASE = "c1";
const PASTE_LINES = [
  "2026-03-01 08:00:00 mailer.example.com accepted message",
  "2026-03-01T08:05:10Z powershell -enc dGVzdA== on host wkstn-blue",
  "2026-03-01T08:06:00Z outbound to cdn.example.com:443",
];

const log: Logger = {
  debug: () => undefined,
  info: () => undefined,
  warn: () => undefined,
  error: () => undefined,
  getLevel: () => "debug",
  setLevel: () => undefined,
  close: async () => undefined,
};

class FakeProvider implements AIProvider {
  readonly name = "fake";
  readonly model = "fake-model";
  readonly sent: AnalyzeRequest[] = [];
  constructor(private readonly replies: string[]) {}
  async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
    this.sent.push(req);
    return { rawText: this.replies.shift() ?? "{}", usage: { costUSD: 0.01 } };
  }
}

const ev = (id: string): ForensicEvent => ({
  id,
  timestamp: "2026-03-01T08:05:00Z",
  description: "powershell launched by winword on wkstn-blue",
  severity: "High",
  mitreTechniques: ["T1059.001"],
  relatedFindingIds: [],
  sourceScreenshots: [],
});

const synthFinding: Finding = {
  id: "f-model-1",
  severity: "High",
  title: "Phishing mail",
  description: "A mail from mailer.example.com.",
  relatedIocs: [],
  sourceScreenshots: [],
  mitreTechniques: [],
  relatedEventIds: ["e1"],
  firstSeen: "2026-03-01T08:00:00Z",
  lastUpdated: "2026-03-01T08:00:00Z",
  status: "open",
};

const watsonFinding: Finding = { ...synthFinding, id: "f-watson-0a1b2c3d", author: "watson" };

const reply = (writes: unknown, over: Record<string, unknown> = {}): string =>
  JSON.stringify({
    message: "Here is what I found.",
    workingOn: "",
    learned: "",
    questionUpdates: [],
    newQuestions: [],
    request: null,
    search: null,
    memory: "m",
    writes,
    ...over,
  });

const findingDraft = (over: Record<string, unknown> = {}) => ({
  severity: "High",
  title: "Encoded PowerShell after the phishing mail",
  description: "The mail was followed by encoded PowerShell on wkstn-blue.",
  mitreTechniques: ["T1059.001"],
  eventIds: ["e1"],
  pasteLines: [],
  ...over,
});

interface Harness {
  ctx: WatsonRoundContext;
  chatStore: WatsonChatStore;
  stateStore: StateStore;
  reportMeta: ReportMetaStore;
  cases: CaseStore;
  paste: WatsonPaste;
}

async function harness(replies: string[]): Promise<Harness> {
  const root = await mkdtemp(join(tmpdir(), "dfir-watson-writes-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: CASE, name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(cases);
  await stateStore.save({
    ...emptyState(CASE),
    forensicTimeline: [ev("e1"), ev("e2")],
    findings: [synthFinding, watsonFinding],
  });
  const anonStore = new AnonControlStore(cases);
  await anonStore.save(CASE, { ...(await anonStore.load(CASE)), enabled: false });
  const costStore = new AiCostStore(cases);
  const provider = new FakeProvider(replies);
  const gateCtx = { log, opts: { anonStore, aiCostStore: costStore } };
  const chatStore = new WatsonChatStore(cases);
  await mkdir(cases.importsDir(CASE), { recursive: true });
  const paste: WatsonPaste = {
    id: "wf-1",
    storedName: "watson-paste-wf-1.txt",
    filename: "mail.log",
    bytes: 200,
    lines: PASTE_LINES.length,
    at: "2026-03-01T09:00:00Z",
  };
  await writeFile(join(cases.importsDir(CASE), paste.storedName), PASTE_LINES.join("\n"));
  await chatStore.update(CASE, (c) => ({ ...c, pastes: [paste] }));
  const reportMeta = new ReportMetaStore(cases);
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
    stateLock: new StateLock(),
    cases,
    costStore,
    provider,
    isAiEnabled: async () => true,
    reportText: reportMeta,
    reportBlockText: blockMd,
  };
  return { ctx, chatStore, stateStore, reportMeta, cases, paste };
}

const ofKind = <K extends string>(chat: { proposals: { kind: string }[] }, kind: K) =>
  chat.proposals.filter((p) => p.kind === kind);

describe("Watson writes from the reply", () => {
  it("a finding citing a real event, an invented event and a paste line → one finding_new with the real citations", async () => {
    const h = await harness([
      reply({
        findings: [
          findingDraft({ eventIds: ["e1", "e-invented"], pasteLines: [{ pasteId: "wf-1", line: 2 }] }),
        ],
        nextSteps: [],
        report: [],
      }),
    ]);
    const chat = await runWatsonRound(h.ctx, CASE, { text: "What happened?" });
    const found = ofKind(chat, "finding_new") as WatsonFindingProposal[];
    expect(found).toHaveLength(1);
    const p = found[0];
    expect(p.status).toBe("pending");
    expect(p.targetId).toMatch(/^f-watson-[0-9a-f]{8}$/);
    expect(p.after.id).toBe(p.targetId);
    expect(p.after.author).toBe("watson");
    expect(p.after.relatedEventIds).toEqual(["e1", "ev-watson-wf-1-2"]);
    expect(p.after.citedPasteLines).toEqual([{ pasteId: "wf-1", line: 2 }]);
    expect(p.pasteLineEvents).toHaveLength(1);
    expect(p.pasteLineEvents[0].id).toBe("ev-watson-wf-1-2");
    expect(p.pasteLineEvents[0].description).toContain("powershell -enc dGVzdA== on host wkstn-blue");
    expect(p.pasteLineEvents[0].relatedFindingIds).toEqual([p.targetId]);
    // Proposed only: the case has no new finding until an analyst applies it.
    const state = await h.stateStore.loadOverview(CASE);
    expect(state.findings.map((f) => f.id)).toEqual(["f-model-1", "f-watson-0a1b2c3d"]);
    expect(chat.turns.at(-1)?.proposalIds).toEqual([p.id]);
  });

  it("a finding citing only an invented event is not proposed", async () => {
    const h = await harness([
      reply({ findings: [findingDraft({ eventIds: ["e-invented"] })], nextSteps: [], report: [] }),
    ]);
    const chat = await runWatsonRound(h.ctx, CASE, { text: "What happened?" });
    expect(ofKind(chat, "finding_new")).toEqual([]);
  });

  it("a paste line the paste does not have, or an unknown paste, is not a citation", async () => {
    const h = await harness([
      reply({
        findings: [
          findingDraft({ eventIds: [], pasteLines: [{ pasteId: "wf-1", line: 99 }] }),
          findingDraft({ eventIds: [], pasteLines: [{ pasteId: "history", line: 1 }] }),
          findingDraft({ eventIds: [], pasteLines: [{ pasteId: "wf-nope", line: 1 }] }),
        ],
        nextSteps: [],
        report: [],
      }),
    ]);
    const chat = await runWatsonRound(h.ctx, CASE, { text: "What happened?" });
    expect(ofKind(chat, "finding_new")).toEqual([]);
  });

  it("a paste line whose stored file is gone is dropped, and the reply is kept", async () => {
    const h = await harness([
      reply({
        findings: [findingDraft({ eventIds: [], pasteLines: [{ pasteId: "wf-1", line: 1 }] })],
        nextSteps: [{ priority: "high", action: "Pull the mail log", rationale: "r", pointer: "p" }],
        report: [],
      }),
    ]);
    const { unlink } = await import("node:fs/promises");
    await unlink(join(h.cases.importsDir(CASE), h.paste.storedName));
    const chat = await runWatsonRound(h.ctx, CASE, { text: "What happened?" });
    expect(chat.turns.at(-1)).toMatchObject({ role: "watson", text: "Here is what I found." });
    expect(ofKind(chat, "finding_new")).toEqual([]);
    expect(ofKind(chat, "next_step_new")).toHaveLength(1);
  });

  it("allowWrites: false → only question proposals", async () => {
    const h = await harness([
      reply(
        {
          findings: [findingDraft()],
          nextSteps: [{ priority: "high", action: "Pull the mail log", rationale: "r", pointer: "p" }],
          report: [{ field: "conclusions", text: "The mail started it." }],
        },
        { newQuestions: [{ question: "Who opened the mail?", why: "e1" }] },
      ),
    ]);
    const chat = await runWatsonRound(h.ctx, CASE, { text: "What happened?", allowWrites: false });
    expect(chat.proposals.map((p) => p.kind)).toEqual(["question_new"]);
  });

  it("a reaction with an import among its events → only question proposals (spec §4.4)", async () => {
    const draft = () =>
      reply(
        {
          findings: [findingDraft()],
          nextSteps: [{ priority: "high", action: "Pull the mail log", rationale: "r", pointer: "p" }],
          report: [],
        },
        { newQuestions: [{ question: "Who opened the mail?", why: "e1" }] },
      );
    const at = "2026-11-01T00:00:00Z";
    const h = await harness([draft()]);
    await h.chatStore.update(CASE, (c) => ({
      ...c,
      pendingCaseEvents: [{ kind: "import", text: "An import finished", at }],
    }));
    const chat = await runWatsonRound(h.ctx, CASE, { text: "", reaction: true });
    expect(chat.proposals.map((p) => p.kind)).toEqual(["question_new"]);

    const star = await harness([draft()]);
    await star.chatStore.update(CASE, (c) => ({
      ...c,
      pendingCaseEvents: [{ kind: "star", text: "Analyst starred 1 event: e1", at }],
    }));
    const starred = await runWatsonRound(star.ctx, CASE, { text: "", reaction: true });
    expect(starred.proposals.map((p) => p.kind)).toContain("next_step_new");
  });

  it("an updateId naming a Watson finding → finding_update; one naming a synthesis finding is dropped", async () => {
    const h = await harness([
      reply({
        findings: [
          findingDraft({ updateId: "f-watson-0a1b2c3d", title: "Refined title" }),
          findingDraft({ updateId: "f-model-1", title: "Not Watson's" }),
          findingDraft({ updateId: "f-watson-ffffffff", title: "Does not exist" }),
        ],
        nextSteps: [],
        report: [],
      }),
    ]);
    const chat = await runWatsonRound(h.ctx, CASE, { text: "Refine it" });
    const upd = ofKind(chat, "finding_update") as WatsonFindingProposal[];
    expect(upd).toHaveLength(1);
    expect(upd[0].targetId).toBe("f-watson-0a1b2c3d");
    expect(upd[0].after.id).toBe("f-watson-0a1b2c3d");
    expect(upd[0].before).toMatchObject({ id: "f-watson-0a1b2c3d", title: "Phishing mail" });
    expect(upd[0].after.title).toBe("Refined title");
    // Never a near-duplicate new finding under a fresh id.
    expect(ofKind(chat, "finding_new")).toEqual([]);
  });

  it("an update whose Watson finding is gone by the time proposals are built is dropped", () => {
    const draft: WatsonFindingDraft = {
      updateId: "f-watson-0a1b2c3d",
      severity: "High",
      title: "Refined title",
      description: "d",
      mitreTechniques: [],
      eventIds: ["e1"],
      pasteLines: [],
    };
    const inputs = { findings: new Map(), pastes: new Map(), lines: new Map() };
    let n = 0;
    const out = buildWriteProposals(
      { findings: [draft], nextSteps: [], report: [] },
      inputs,
      "t1",
      (prefix) => `${prefix}-0000000${n++}`,
    );
    expect(out).toEqual([]);
  });

  it("next steps and report text become pending proposals; the executive summary is never written", async () => {
    const h = await harness([
      reply({
        findings: [],
        nextSteps: [
          { priority: "critical", action: "Isolate wkstn-blue", rationale: "e1 ran", pointer: "wkstn-blue" },
        ],
        report: [
          { field: "conclusions", text: "The phishing mail led to encoded PowerShell." },
          { field: "conclusions", text: "A second version of the same field." },
          { field: "executiveSummary", text: "Never written by Watson." },
        ],
      }),
    ]);
    await h.reportMeta.save(CASE, { conclusions: "Analyst draft." });
    const chat = await runWatsonRound(h.ctx, CASE, { text: "Write it up" });
    const steps = ofKind(chat, "next_step_new") as WatsonNextStepProposal[];
    expect(steps).toHaveLength(1);
    expect(steps[0].targetId).toMatch(/^ns-watson-[0-9a-f]{8}$/);
    expect(steps[0].after).toMatchObject({
      id: steps[0].targetId,
      priority: "critical",
      action: "Isolate wkstn-blue",
      author: "watson",
    });
    const report = ofKind(chat, "report_text") as WatsonReportTextProposal[];
    expect(report).toHaveLength(1);
    expect(report[0]).toMatchObject({
      field: "conclusions",
      targetId: "conclusions",
      before: "Analyst draft.",
      after: "The phishing mail led to encoded PowerShell.",
      status: "pending",
    });
    expect((await h.reportMeta.load(CASE)).conclusions).toBe("Analyst draft.");
  });
});

describe("sanitizeWatsonReply writes", () => {
  const sets = {
    pasteLines: new Map([["wf-1", 3]]),
    watsonFindingIds: new Set(["f-watson-0a1b2c3d"]),
  };
  const sanitize = (writes: unknown) =>
    sanitizeWatsonReply(
      watsonReplySchema.parse({ message: "x", writes }),
      new Set(),
      new Set(["wf-1"]),
      new Set(["e1"]),
      sets,
    ).writes;

  it("caps each list and each text", () => {
    const out = sanitize({
      findings: Array.from({ length: 5 }, () =>
        findingDraft({ title: "t".repeat(300), description: "d".repeat(5000) }),
      ),
      nextSteps: Array.from({ length: 5 }, () => ({
        priority: "low",
        action: "a".repeat(400),
        rationale: "r".repeat(600),
        pointer: "p".repeat(600),
      })),
      report: [
        { field: "conclusions", text: "c".repeat(7000) },
        { field: "investigationLimitations", text: "l" },
        { field: "conclusions", text: "again" },
      ],
    });
    expect(out.findings).toHaveLength(3);
    expect(out.findings[0].title).toHaveLength(200);
    expect(out.findings[0].description).toHaveLength(4000);
    expect(out.nextSteps).toHaveLength(3);
    expect(out.nextSteps[0].action).toHaveLength(300);
    expect(out.nextSteps[0].rationale).toHaveLength(500);
    expect(out.nextSteps[0].pointer).toHaveLength(500);
    expect(out.report.map((r) => r.field)).toEqual(["conclusions", "investigationLimitations"]);
    expect(out.report[0].text).toHaveLength(6000);
  });

  it("drops invented events, out-of-range paste lines, and a finding left with no citation", () => {
    const out = sanitize({
      findings: [
        findingDraft({
          eventIds: ["e1", "e-x"],
          pasteLines: [
            { pasteId: "wf-1", line: 3 },
            { pasteId: "wf-1", line: 0 },
            { pasteId: "wf-1", line: 4 },
          ],
        }),
        findingDraft({ eventIds: ["e-x"], pasteLines: [] }),
      ],
      nextSteps: [],
      report: [],
    });
    expect(out.findings).toHaveLength(1);
    expect(out.findings[0].eventIds).toEqual(["e1"]);
    expect(out.findings[0].pasteLines).toEqual([{ pasteId: "wf-1", line: 3 }]);
  });

  it("keeps an update only for a Watson-authored finding; any other update draft is dropped", () => {
    const out = sanitize({
      findings: [
        findingDraft({ updateId: "f-watson-0a1b2c3d" }),
        findingDraft({ updateId: "f-model-1" }),
        findingDraft({ updateId: "f-watson-ffffffff" }),
        findingDraft(),
      ],
      nextSteps: [],
      report: [],
    });
    expect(out.findings.map((f) => f.updateId)).toEqual(["f-watson-0a1b2c3d", undefined]);
  });

  it("a reply with no writes, or without the citation sets, proposes no finding", () => {
    expect(sanitize(undefined)).toEqual({ findings: [], nextSteps: [], report: [] });
    const noSets = sanitizeWatsonReply(
      watsonReplySchema.parse({
        writes: { findings: [findingDraft({ eventIds: [], pasteLines: [{ pasteId: "wf-1", line: 1 }] })] },
      }),
      new Set(),
      new Set(["wf-1"]),
      new Set(["e1"]),
    );
    expect(noSets.writes.findings).toEqual([]);
  });
});

describe("Watson next-step writer", () => {
  async function setup() {
    const root = await mkdtemp(join(tmpdir(), "dfir-watson-step-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: CASE, name: "n", investigator: "i", aiProvider: null });
    const stateStore = new StateStore(cases);
    await stateStore.save(emptyState(CASE));
    const chatStore = new WatsonChatStore(cases);
    const entries: NewActivityEntry[] = [];
    const outOfDate: string[] = [];
    const activity = {
      add: async (_c: string, e: NewActivityEntry) => {
        entries.push(e);
        return { ...e, id: "a", at: "t", actor: e.actor ?? "x" };
      },
    } as unknown as ActivityLogStore;
    const deps: WriterDeps = {
      stateStore,
      stateLock: new StateLock(),
      chatStore,
      activity,
      cases,
      markConclusionsOutOfDate: async (_c, why) => {
        outOfDate.push(why);
      },
    };
    const proposal: WatsonNextStepProposal = {
      id: "wp-s",
      turnId: "t1",
      kind: "next_step_new",
      targetId: "ns-watson-0a1b2c3d",
      after: {
        id: "ns-watson-0a1b2c3d",
        priority: "high",
        action: "Pull Security.evtx from wkstn-blue",
        rationale: "Confirms the logon",
        pointer: "wkstn-blue",
        author: "watson",
      },
      status: "pending",
    };
    await chatStore.update(CASE, (c) => ({ ...c, proposals: [proposal] }));
    return { deps, stateStore, entries, outOfDate };
  }

  it("apply appends the step with the Watson mark; undo removes it", async () => {
    const { deps, stateStore, entries } = await setup();
    await applyWatsonProposal(deps, CASE, "wp-s", "apply", "ana");
    const steps = (await stateStore.loadOverview(CASE)).nextSteps;
    expect(steps).toHaveLength(1);
    expect(steps[0]).toMatchObject({ id: "ns-watson-0a1b2c3d", author: "watson" });
    await applyWatsonProposal(deps, CASE, "wp-s", "undo", "ana");
    expect((await stateStore.loadOverview(CASE)).nextSteps).toEqual([]);
    expect(entries.map((e) => e.action)).toEqual(["watson.apply", "watson.undo"]);
    expect(entries[0]).toMatchObject({ category: "ai", targetType: "next_step", actor: "ana" });
  });

  it("undo refuses a step the analyst changed, and ignores the stale badge", async () => {
    const { deps, stateStore } = await setup();
    await applyWatsonProposal(deps, CASE, "wp-s", "apply");
    const o = await stateStore.loadOverview(CASE);
    await stateStore.saveOverview({ ...o, nextSteps: [{ ...o.nextSteps[0], action: "Edited by analyst" }] });
    await expect(applyWatsonProposal(deps, CASE, "wp-s", "undo")).rejects.toBeInstanceOf(
      WatsonProposalConflict,
    );
    await stateStore.saveOverview({ ...o, nextSteps: [{ ...o.nextSteps[0], staleReSynth: true }] });
    await applyWatsonProposal(deps, CASE, "wp-s", "undo");
    expect((await stateStore.loadOverview(CASE)).nextSteps).toEqual([]);
  });
});
