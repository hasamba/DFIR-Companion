import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import { ActivityLogStore } from "../../../src/analysis/activityLog.js";
import { autoApply } from "../../../src/analysis/ai/watson/autoApply.js";
import { WatsonChatStore } from "../../../src/analysis/ai/watson/chatStore.js";
import { proposalSchema } from "../../../src/analysis/ai/watson/proposalSchema.js";
import { applyWatsonProposal, type WriterDeps } from "../../../src/analysis/ai/watson/proposals.js";
import { citationSets } from "../../../src/analysis/ai/watson/roundWrites.js";
import type { WatsonFindingReviewProposal, WatsonProposal } from "../../../src/analysis/ai/watson/types.js";
import { buildWriteProposals } from "../../../src/analysis/ai/watson/writeProposals.js";
import { sanitizeWrites, writesSchema } from "../../../src/analysis/ai/watson/writesSchema.js";
import { StateLock } from "../../../src/analysis/stateLock.js";
import { StateStore } from "../../../src/analysis/stateStore.js";
import { emptyState, type Finding, type ForensicEvent } from "../../../src/analysis/stateTypes.js";
import { CaseStore } from "../../../src/storage/caseStore.js";

// #2682 review: Watson's verdict on a synthesis finding rests on the evidence Watson saw. When an
// import or delta adds citations to the finding while Watson thinks, or while the proposal waits for
// approval, the change is refused: otherwise the verdict would record evidence Watson never read as
// "considered", and that evidence could never reopen the finding.

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

const finding = (over: Partial<Finding> = {}): Finding => ({
  id: "f-model-1",
  severity: "Medium",
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
  seenEventIds: [...(before.relatedEventIds ?? [])],
  status: "pending",
  ...over,
});

let stateStore: StateStore;
let chatStore: WatsonChatStore;
let activity: ActivityLogStore;

const deps = (): WriterDeps => ({
  stateStore,
  stateLock: new StateLock(),
  chatStore,
  activity,
  markConclusionsOutOfDate: async () => {},
});

async function seed(findings: Finding[], proposals: WatsonProposal[]): Promise<void> {
  const timeline = ["e1", "e2", "e3"].map(ev);
  await stateStore.save({ ...emptyState(CASE), forensicTimeline: timeline, findings });
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

beforeEach(async () => {
  const cases = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-watson-review-stale-")));
  await cases.createCase({ caseId: CASE, name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(cases);
  chatStore = new WatsonChatStore(cases);
  activity = new ActivityLogStore(cases);
});

describe("building a review proposal", () => {
  const seen = finding();
  const writes = sanitizeWrites(
    writesSchema.parse({
      findingReviews: [
        { findingId: "f-model-1", action: "dismiss", why: "e2 disproves it", eventIds: ["e2"] },
      ],
    }),
    new Set(["e1", "e2", "e3"]),
    citationSets([], [seen]),
  );
  const inputs = (now: Finding) => ({
    findings: new Map(),
    pastes: new Map(),
    lines: new Map(),
    reviewable: new Map([[now.id, now]]),
  });

  it("snapshots the citations Watson saw", () => {
    const props = buildWriteProposals(writes, inputs(seen), TURN, (p) => p);
    expect(props).toHaveLength(1);
    expect(props[0]).toMatchObject({ kind: "finding_review", seenEventIds: ["e1"] });
  });

  it("proposes nothing when the finding gained evidence while Watson thought", () => {
    const grown = finding({ relatedEventIds: ["e1", "e3"] });
    expect(buildWriteProposals(writes, inputs(grown), TURN, (p) => p)).toEqual([]);
  });

  it("a stored proposal with the snapshot parses back", () => {
    const parsed = proposalSchema.safeParse(review(seen));
    expect(parsed.success && parsed.data).toMatchObject({ seenEventIds: ["e1"] });
  });
});

describe("applying a review whose finding gained evidence", () => {
  it("refuses a manual apply and stores no verdict", async () => {
    const f = finding();
    await seed([{ ...f, relatedEventIds: ["e1", "e3"] }], [review(f)]);
    await expect(applyWatsonProposal(deps(), CASE, "wp-r1", "apply", "Dana")).rejects.toThrow(
      /changed since Watson proposed this/,
    );
    const st = await stateStore.load(CASE);
    expect(st.findings[0].status).toBe("open");
    expect(st.findings[0].watsonReview).toBeUndefined();
    expect(st.watsonFindingVerdicts ?? []).toEqual([]);
  });

  it("Auto does not apply it either; the proposal stays pending", async () => {
    const f = finding();
    await seed([{ ...f, relatedEventIds: ["e1", "e3"] }], [review(f)]);
    const control = { watsonRunMode: "auto" as const, watsonAutoSince: "t", watsonAutoBy: { name: "Robin" } };
    const chat = await autoApply(
      deps(),
      CASE,
      { turnId: TURN, reaction: false, source: "dashboard" },
      control,
    );
    expect(chat.proposals.map((p) => p.status)).toEqual(["pending"]);
    const st = await stateStore.load(CASE);
    expect(st.findings[0].status).toBe("open");
    expect(st.watsonFindingVerdicts ?? []).toEqual([]);
  });

  it("applies when the evidence is unchanged; the verdict considers only what Watson saw", async () => {
    const f = finding();
    await seed([f], [review(f)]);
    await applyWatsonProposal(deps(), CASE, "wp-r1", "apply", "Dana");
    const st = await stateStore.load(CASE);
    expect(st.findings[0].status).toBe("dismissed");
    expect(st.watsonFindingVerdicts?.[0].consideredEventIds.sort()).toEqual(["e1", "e2"]);
  });

  it("an older proposal with no snapshot falls back to the finding as proposed", async () => {
    const f = finding();
    const { seenEventIds: _s, ...old } = review(f);
    await seed([{ ...f, relatedEventIds: ["e1", "e3"] }], [old]);
    await expect(applyWatsonProposal(deps(), CASE, "wp-r1", "apply", "Dana")).rejects.toThrow(
      /changed since Watson proposed this/,
    );
  });
});
