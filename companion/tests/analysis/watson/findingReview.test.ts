import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import { ActivityLogStore } from "../../../src/analysis/activityLog.js";
import { autoApply, HIGH_FINDING_WAIT } from "../../../src/analysis/ai/watson/autoApply.js";
import { WatsonChatStore } from "../../../src/analysis/ai/watson/chatStore.js";
import { proposalSchema } from "../../../src/analysis/ai/watson/proposalSchema.js";
import { applyWatsonProposal, type WriterDeps } from "../../../src/analysis/ai/watson/proposals.js";
import { citationSets } from "../../../src/analysis/ai/watson/roundWrites.js";
import type { WatsonFindingReviewProposal, WatsonProposal } from "../../../src/analysis/ai/watson/types.js";
import { buildWriteProposals } from "../../../src/analysis/ai/watson/writeProposals.js";
import { sanitizeWrites, writesSchema } from "../../../src/analysis/ai/watson/writesSchema.js";
import { reviewChange } from "../../../src/analysis/ai/watson/writers/findingReviewWriter.js";
import { StateLock } from "../../../src/analysis/stateLock.js";
import { StateStore } from "../../../src/analysis/stateStore.js";
import {
  emptyState,
  type Finding,
  type ForensicEvent,
  type InvestigationState,
  type Severity,
} from "../../../src/analysis/stateTypes.js";
import { persistSynthesis } from "../../../src/analysis/ai/synthesisPersist.js";
import { diffFindings } from "../../../src/analysis/findingsDiff.js";
import { backfillHighSeverityFindings } from "../../../src/analysis/highSeverityFindings.js";
import { applyWatsonVerdicts } from "../../../src/analysis/timeline/watsonVerdicts.js";
import { watsonFindingLines } from "../../../src/reports/watsonFindingMd.js";
import { renderMarkdownReport } from "../../../src/reports/markdown.js";
import { CaseStore } from "../../../src/storage/caseStore.js";

// #2682: Watson proposes to demote or dismiss a synthesis finding its cited evidence disproves. It
// never touches a finding Watson (the analyst) wrote. Auto applies it only to a Low or Medium finding.
// The verdict is the case's own record: it survives a re-synthesis that mints new finding ids, and
// the finding opens again only when a run cites evidence the verdict did not consider.

const CASE = "c1";
const TURN = "wt-round";

const ev = (id: string): ForensicEvent => ({
  id,
  timestamp: "2026-03-01T08:05:00Z",
  description: `MsMpEng.exe wrote a Defender registry value on WS-FAKE01 (${id})`,
  severity: "Medium",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
});

const finding = (id: string, severity: Severity, over: Partial<Finding> = {}): Finding => ({
  id,
  severity,
  title: "Defender exclusion added on WS-FAKE01",
  description: "A registry write added a Defender exclusion.",
  relatedIocs: [],
  sourceScreenshots: [],
  mitreTechniques: ["T1562.001"],
  relatedEventIds: ["e1"],
  firstSeen: "2026-03-01T08:00:00Z",
  lastUpdated: "2026-03-01T08:00:00Z",
  status: "open",
  ...over,
});

const review = (
  before: Finding,
  over: Partial<WatsonFindingReviewProposal> = {},
): WatsonFindingReviewProposal => ({
  id: "wp-r1",
  turnId: TURN,
  kind: "finding_review",
  targetId: before.id,
  action: "dismiss",
  why: "e2 shows the writer is MsMpEng.exe, Defender's own engine.",
  eventIds: ["e2"],
  before,
  status: "pending",
  ...over,
});

let cases: CaseStore;
let stateStore: StateStore;
let chatStore: WatsonChatStore;
let activity: ActivityLogStore;

function deps(): WriterDeps {
  return {
    stateStore,
    stateLock: new StateLock(),
    chatStore,
    activity,
    markConclusionsOutOfDate: async () => {},
  };
}

async function seed(findings: Finding[], proposals: WatsonProposal[]): Promise<void> {
  await stateStore.save({ ...emptyState(CASE), forensicTimeline: [ev("e1"), ev("e2"), ev("e3")], findings });
  const turns = [
    {
      id: TURN,
      at: "2026-03-01T09:00:00Z",
      role: "watson" as const,
      text: "t",
      proposalIds: proposals.map((p) => p.id),
    },
  ];
  await chatStore.update(CASE, (c) => ({ ...c, turns, proposals }));
}

const stored = async (): Promise<InvestigationState> => stateStore.load(CASE);

beforeEach(async () => {
  cases = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-watson-review-")));
  await cases.createCase({ caseId: CASE, name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(cases);
  chatStore = new WatsonChatStore(cases);
  activity = new ActivityLogStore(cases);
});

describe("finding reviews from a reply", () => {
  const synth = finding("f-model-1", "Medium");
  const mine = finding("f-watson-0a1b2c3d", "Medium", { author: "watson", title: "Watson's own" });
  const sets = citationSets([], [synth, mine]);
  const known = new Set(["e1", "e2"]);
  const parse = (findingReviews: unknown[]) =>
    sanitizeWrites(writesSchema.parse({ findingReviews }), known, sets).findingReviews ?? [];

  it("keeps a review of a synthesis finding and drops one of a Watson (analyst) finding", () => {
    const out = parse([
      { findingId: "f-model-1", action: "dismiss", why: "e2 disproves it", eventIds: ["e2"] },
      { findingId: "f-watson-0a1b2c3d", action: "dismiss", why: "x", eventIds: ["e2"] },
    ]);
    expect(out.map((r) => r.findingId)).toEqual(["f-model-1"]);
  });

  it("drops a review with no live citation, no reason, or a demotion that does not lower", () => {
    expect(parse([{ findingId: "f-model-1", action: "dismiss", why: "x", eventIds: ["gone"] }])).toEqual([]);
    expect(parse([{ findingId: "f-model-1", action: "dismiss", why: " ", eventIds: ["e2"] }])).toEqual([]);
    expect(
      parse([{ findingId: "f-model-1", action: "demote", severity: "High", why: "x", eventIds: ["e2"] }]),
    ).toEqual([]);
    expect(
      parse([{ findingId: "f-model-1", action: "demote", severity: "Low", why: "x", eventIds: ["e2"] }]),
    ).toHaveLength(1);
  });

  it("builds a pending proposal on a synthesis finding, never on a Watson finding", () => {
    const writes = sanitizeWrites(
      writesSchema.parse({
        findingReviews: [
          { findingId: "f-model-1", action: "demote", severity: "Low", why: "e2", eventIds: ["e2"] },
        ],
      }),
      known,
      sets,
    );
    let n = 0;
    const inputs = {
      findings: new Map(),
      pastes: new Map(),
      lines: new Map(),
      reviewable: new Map([[synth.id, synth]]),
    };
    const props = buildWriteProposals(writes, inputs, TURN, (p) => `${p}-${++n}`);
    expect(props).toHaveLength(1);
    expect(props[0]).toMatchObject({ kind: "finding_review", targetId: "f-model-1", severity: "Low" });
    // The finding is now Watson's (or gone): nothing is proposed.
    const none = buildWriteProposals(
      writes,
      { ...inputs, reviewable: new Map([[synth.id, mine]]) },
      TURN,
      (p) => p,
    );
    expect(none).toEqual([]);
  });
});

describe("applying, undoing and Auto", () => {
  it("apply dismisses the finding with Watson's mark and a verdict; Undo restores it", async () => {
    const f = finding("f-model-1", "High");
    await seed([f], [review(f)]);
    await applyWatsonProposal(deps(), CASE, "wp-r1", "apply", "Dana Analyst");
    let st = await stored();
    expect(st.findings[0]).toMatchObject({
      status: "dismissed",
      watsonReview: { approvedBy: "Dana Analyst" },
    });
    expect(st.watsonFindingVerdicts).toHaveLength(1);
    await applyWatsonProposal(deps(), CASE, "wp-r1", "undo", "Dana Analyst");
    st = await stored();
    expect(st.findings[0].status).toBe("open");
    expect(st.findings[0].watsonReview).toBeUndefined();
    expect(st.watsonFindingVerdicts ?? []).toEqual([]);
  });

  it("apply refuses a Watson-authored finding and a finding that changed", async () => {
    const mine = finding("f-watson-0a1b2c3d", "Medium", { author: "watson" });
    await seed([mine], [review(mine)]);
    await expect(applyWatsonProposal(deps(), CASE, "wp-r1", "apply", "Dana")).rejects.toThrow(/you wrote/);
    const f = finding("f-model-1", "Medium");
    await seed([{ ...f, severity: "High" }], [review(f)]);
    await expect(applyWatsonProposal(deps(), CASE, "wp-r1", "apply", "Dana")).rejects.toThrow(/changed/);
  });

  it("Auto applies a Medium finding's change and holds a High one for approval", async () => {
    const med = finding("f-model-1", "Medium");
    const high = finding("f-model-2", "High", { title: "Other finding" });
    await seed([med, high], [review(med), review(high, { id: "wp-r2" })]);
    const control = { watsonRunMode: "auto" as const, watsonAutoSince: "t", watsonAutoBy: { name: "Robin" } };
    const chat = await autoApply(
      deps(),
      CASE,
      { turnId: TURN, reaction: false, source: "dashboard" },
      control,
    );
    expect(chat.proposals.map((p) => [p.id, p.status])).toEqual([
      ["wp-r1", "applied"],
      ["wp-r2", "pending"],
    ]);
    expect(chat.turns[chat.turns.length - 1].text).toContain(HIGH_FINDING_WAIT);
    const st = await stored();
    expect(st.findings.find((f) => f.id === "f-model-1")?.status).toBe("dismissed");
    expect(st.findings.find((f) => f.id === "f-model-2")?.status).toBe("open");
  });

  it("says the change in words, and a stored proposal parses back", () => {
    const f = finding("f-model-1", "High");
    expect(reviewChange(review(f, { action: "demote", severity: "Low" }))).toBe(
      "demote finding High -> Low: Defender exclusion added on WS-FAKE01",
    );
    const parsed = proposalSchema.safeParse(review(f));
    expect(parsed.success && parsed.data).toMatchObject({ kind: "finding_review", action: "dismiss" });
  });
});

describe("the verdict across re-synthesis", () => {
  async function appliedVerdict(action: "dismiss" | "demote" = "dismiss") {
    const f = finding("f-model-1", "Medium");
    const p = review(f, action === "demote" ? { action, severity: "Low" } : {});
    await seed([f], [p]);
    await applyWatsonProposal(deps(), CASE, "wp-r1", "apply", "Dana");
    return stored();
  }

  /** A synthesis run that re-mints the finding under a new id, and saves through the real write. */
  async function resynth(rerun: Finding): Promise<InvestigationState> {
    const loaded = await stored();
    const next = { ...loaded, findings: [rerun] };
    return persistSynthesis({ opts: { stateStore } }, CASE, {
      loaded,
      next,
      findingsDiff: diffFindings(loaded.findings, next.findings),
    });
  }

  it("survives a re-synthesis that mints a new id", async () => {
    await appliedVerdict();
    const saved = await resynth(finding("f-model-9", "Medium"));
    expect(saved.findings[0]).toMatchObject({ id: "f-model-9", status: "dismissed" });
    expect(saved.findings[0].watsonReview?.newEventIds).toBeUndefined();
  });

  it("a demotion never raises, and is applied again to the re-minted finding", async () => {
    await appliedVerdict("demote");
    const saved = await resynth(finding("f-model-9", "Medium"));
    expect(saved.findings[0]).toMatchObject({ severity: "Low", status: "open" });
    const lower = applyWatsonVerdicts({ ...saved, findings: [finding("f-model-9", "Low")] });
    expect(lower.findings[0].watsonReview).toBeUndefined(); // already at or below the verdict
  });

  it("reopens when a new run cites evidence the verdict did not consider", async () => {
    await appliedVerdict();
    const saved = await resynth(finding("f-model-9", "Medium", { relatedEventIds: ["e1", "e3"] }));
    expect(saved.findings[0].status).toBe("open");
    expect(saved.findings[0].watsonReview?.newEventIds).toEqual(["e3"]);
  });

  it("Undo on a reopened finding removes the note and the verdict, and changes nothing else", async () => {
    await appliedVerdict();
    await resynth(finding("f-model-9", "Medium", { relatedEventIds: ["e1", "e3"] }));
    await applyWatsonProposal(deps(), CASE, "wp-r1", "undo", "Dana");
    const st = await stored();
    expect(st.findings[0]).toMatchObject({ id: "f-model-9", status: "open", severity: "Medium" });
    expect(st.findings[0].watsonReview).toBeUndefined();
    expect(st.watsonFindingVerdicts ?? []).toEqual([]);
  });

  it("an Auto apply records the verdict as Auto's", async () => {
    const f = finding("f-model-1", "Medium");
    await seed([f], [review(f)]);
    await applyWatsonProposal(deps(), CASE, "wp-r1", "apply", "Watson (Auto)");
    expect((await stored()).watsonFindingVerdicts?.[0].auto).toBe(true);
  });

  it("an event correlation folded away is not new evidence", async () => {
    const st = await appliedVerdict();
    const folded = applyWatsonVerdicts({
      ...st,
      eventAliases: { e1: "e1b" },
      forensicTimeline: [ev("e1b"), ev("e2")],
      findings: [finding("f-model-9", "Medium", { relatedEventIds: ["e1b"] })],
    });
    expect(folded.findings[0].status).toBe("dismissed");
  });

  it("Undo after a re-synthesis finds the re-minted finding by its mark", async () => {
    await appliedVerdict();
    await resynth(finding("f-model-9", "Medium"));
    await applyWatsonProposal(deps(), CASE, "wp-r1", "undo", "Dana");
    const st = await stored();
    expect(st.findings[0]).toMatchObject({ id: "f-model-9", status: "open" });
    expect(st.findings[0].watsonReview).toBeUndefined();
    const again = await resynth(finding("f-model-10", "Medium"));
    expect(again.findings[0].status).toBe("open");
  });
});

describe("automatic (f-auto) findings", () => {
  const high: ForensicEvent = { ...ev("e9"), severity: "High" };
  const base = (): InvestigationState => ({ ...emptyState(CASE), forensicTimeline: [high] });
  const minted = (prior: Finding) =>
    backfillHighSeverityFindings(base(), new Set(["e9"]), "t", new Map([[prior.id, prior]])).findings[0];

  it("a Watson dismissal is not carried by the #2092 re-mint; the verdict decides at the save", () => {
    const autoId = "f-auto-e9";
    const watsonDismissed = finding(autoId, "High", {
      status: "dismissed",
      watsonReview: {
        action: "dismiss",
        reason: "r",
        eventIds: ["e9"],
        proposalId: "wp-r1",
        approvedBy: "Dana",
        at: "t",
        fromSeverity: "High",
        fromStatus: "open",
      },
    });
    expect(minted(watsonDismissed)).toMatchObject({ id: autoId, status: "open" });
    // The analyst's own dismissal is still carried.
    expect(minted(finding(autoId, "High", { status: "dismissed" })).status).toBe("dismissed");
  });
});

describe("reports", () => {
  it("the report shows Watson's change, who approved it and why", async () => {
    const f = finding("f-model-1", "High");
    await seed([f], [review(f)]);
    await applyWatsonProposal(deps(), CASE, "wp-r1", "apply", "Dana | Analyst");
    const st = await stored();
    const lines = watsonFindingLines(st.findings[0]);
    expect(lines).toHaveLength(1);
    expect(lines[0]).toContain("Dismissed by Watson");
    expect(lines[0]).toContain("MsMpEng.exe");
    expect(lines[0]).toContain("e2");
    const md = renderMarkdownReport(st);
    expect(md).toContain("Dismissed by Watson (was open), approved by Dana");
  });
});
