import { describe, expect, it } from "vitest";
import { buildFindingsEcho } from "../../../src/analysis/ai/synthesisPromptBlocks.js";
import { collectRawRefs, settleRawRefs } from "../../../src/analysis/ai/watson/rawReferences.js";
import type { WatsonReply } from "../../../src/analysis/ai/watson/replySchema.js";
import { mergeDelta } from "../../../src/analysis/stateMerge.js";
import type { AnalysisDelta } from "../../../src/analysis/responseSchema.js";
import {
  emptyState,
  type Finding,
  type ForensicEvent,
  type InvestigationState,
  type Severity,
} from "../../../src/analysis/stateTypes.js";
import { applyWatsonVerdicts, findingVerdictKey } from "../../../src/analysis/timeline/watsonVerdicts.js";
import type { WatsonFindingVerdict } from "../../../src/analysis/watsonItemTypes.js";
import { watsonReviewText } from "../../../src/reports/watsonFindingMd.js";

// #2682, the synthesis side of Watson's verdicts: what the next prompt shows, what Auto may not do to a
// re-minted High finding, a delta that re-grades a marked finding, two findings on one key, and the
// super-timeline boundary for a review that cites a raw row.

const CASE = "c1";
const ev = (id: string): ForensicEvent => ({
  id,
  timestamp: "2026-03-01T08:05:00Z",
  description: `registry write on WS-FAKE01 (${id})`,
  severity: "Medium",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
});
const finding = (id: string, severity: Severity, over: Partial<Finding> = {}): Finding => ({
  id,
  severity,
  title: "Defender exclusion added on WS-FAKE01",
  description: "d",
  relatedIocs: [],
  sourceScreenshots: [],
  mitreTechniques: ["T1562.001"],
  relatedEventIds: ["e1"],
  firstSeen: "t",
  lastUpdated: "t",
  status: "open",
  ...over,
});
const verdict = (over: Partial<WatsonFindingVerdict> = {}): WatsonFindingVerdict => ({
  key: findingVerdictKey(finding("f-model-1", "Medium")),
  action: "demote",
  severity: "Low",
  reason: "e2 shows Defender's own engine wrote it",
  eventIds: ["e2"],
  consideredEventIds: ["e1", "e2"],
  proposalId: "wp-r1",
  approvedBy: "Dana",
  at: "t",
  title: "Defender exclusion added on WS-FAKE01",
  ...over,
});
const stateWith = (findings: Finding[], verdicts: WatsonFindingVerdict[]): InvestigationState => ({
  ...emptyState(CASE),
  forensicTimeline: [ev("e1"), ev("e2"), ev("e3")],
  findings,
  watsonFindingVerdicts: verdicts,
});

describe("the next synthesis prompt", () => {
  it("echoes a Watson-demoted finding at the severity synthesis gave it, so the model does not adopt it", () => {
    const st = applyWatsonVerdicts(stateWith([finding("f-model-1", "Medium")], [verdict()]));
    expect(st.findings[0].severity).toBe("Low");
    expect(buildFindingsEcho(st)).toContain("[f-model-1] (severity: Medium)");
  });
});

describe("Auto verdicts and High/Critical", () => {
  it("an Auto verdict is not applied to a re-minted finding now graded High; it says so", () => {
    const st = applyWatsonVerdicts(
      stateWith([finding("f-model-9", "High")], [verdict({ auto: true, approvedBy: "Watson (Auto)" })]),
    );
    expect(st.findings[0]).toMatchObject({ severity: "High", watsonReview: { autoHeld: true } });
    expect(watsonReviewText(st.findings[0])).toContain("Auto mode never changes a High or Critical finding");
    expect(watsonReviewText(st.findings[0])).toContain("applied by Watson in Auto mode, without asking");
  });

  it("an analyst-approved verdict still applies to a High finding", () => {
    const st = applyWatsonVerdicts(stateWith([finding("f-model-9", "High")], [verdict()]));
    expect(st.findings[0].severity).toBe("Low");
  });
});

describe("two findings on one key in one run", () => {
  it("the one citing only considered events takes the verdict; the one with new evidence stays open", () => {
    const st = applyWatsonVerdicts(
      stateWith(
        [finding("f-model-a", "Medium"), finding("f-model-b", "Medium", { relatedEventIds: ["e3"] })],
        [verdict({ action: "dismiss", severity: undefined })],
      ),
    );
    expect(st.findings.map((f) => f.status)).toEqual(["dismissed", "open"]);
    expect(st.findings[1].watsonReview?.newEventIds).toEqual(["e3"]);
  });
});

describe("a delta that re-grades a marked finding", () => {
  const ctx = { windowSequence: 1, timestamp: "2026-05-28T10:00:00.000Z", sourceScreenshots: [] };
  const delta = (severity: Severity): AnalysisDelta => ({
    findings: [
      {
        id: "f-model-1",
        severity,
        title: "Defender exclusion added on WS-FAKE01",
        description: "d",
        relatedIocs: [],
        mitreTechniques: ["T1562.001"],
        relatedEventIds: ["e1"],
        status: "open",
      },
    ],
    iocs: [],
    mitreTechniques: [],
    threadsOpened: [],
    threadsClosed: [],
    timelineNote: "",
    summary: "",
  });

  it("drops the stale mark and applies the verdict to the delta's new grade", () => {
    const marked = applyWatsonVerdicts(stateWith([finding("f-model-1", "Medium")], [verdict()]));
    const next = mergeDelta(marked, delta("High"), ctx);
    expect(next.findings[0]).toMatchObject({ severity: "Low", watsonReview: { fromSeverity: "High" } });
    expect(next.watsonFindingVerdicts).toHaveLength(1);
  });
});

describe("the super-timeline boundary (§7)", () => {
  const reply = (eventIds: string[]): WatsonReply => ({
    message: "",
    workingOn: "",
    learned: "",
    questionUpdates: [],
    newQuestions: [],
    request: null,
    search: null,
    lookup: null,
    memory: "",
    answer: null,
    writes: {
      findings: [],
      nextSteps: [],
      report: [],
      findingReviews: [{ findingId: "f-model-1", action: "dismiss", why: "see it", eventIds }],
    },
  });

  it("a review citing a raw row that did not land is dropped; a landed one carries its evidence", () => {
    const r = reply(["raw-1", "e1"]);
    const refs = collectRawRefs(r, new Set(["raw-1"]));
    expect(refs.map((x) => x.item)).toEqual([{ kind: "findingReview", index: 0 }]);
    const dropped = settleRawRefs(r, refs, new Map());
    expect(dropped.reply.writes.findingReviews).toEqual([]);
    const landed = settleRawRefs(r, refs, new Map([["raw-1", "ev-promoted-1"]]));
    expect(landed.reply.writes.findingReviews?.[0].eventIds).toEqual(["ev-promoted-1", "e1"]);
    expect(landed.evidence.get("findingReview:0")).toEqual(["ev-promoted-1"]);
  });
});
