import { describe, it, expect } from "vitest";
import {
  applyBurstGapQuestions,
  BURST_GAP_ID_PREFIX,
  BURST_GAP_LISTED_IDS,
  MAX_BURST_GAP_QUESTIONS,
} from "../../src/analysis/burstGapQuestions.js";
import { WATSON_LOOKUP_LIMITS } from "../../src/analysis/ai/watson/lookupSchema.js";
import type { Finding, ForensicEvent, InvestigationQuestion } from "../../src/analysis/stateTypes.js";

// #2681: a burst group whose prompt row hid distinct command lines ("+N more") gets one pinned,
// system-made Key Question that points at the hidden event ids, so Watson Auto reads them.

const IMAGE = "C:\\ProgramData\\svc\\winupd.exe";

function proc(id: string, second: number, args: string, extra: Partial<ForensicEvent> = {}): ForensicEvent {
  const ts = new Date(Date.UTC(2026, 10, 1, 10, 0, 0) + second * 1000).toISOString();
  return {
    id,
    timestamp: ts,
    description: `Sigma: Renamed cmd - Image=${IMAGE} - CommandLine=… ${args}`,
    severity: "High",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset: "WS-07",
    path: IMAGE,
    processName: "winupd.exe",
    commandLine: `"${IMAGE}" ${args}`,
    ...extra,
  };
}

/** A burst of `n` members, every one a different command, ids `<p>0..<p>n-1`. */
function burst(prefix: string, n: number, start = 0): ForensicEvent[] {
  return Array.from({ length: n }, (_, i) => proc(`${prefix}${i}`, start + i, `/c echo step${prefix}${i}`));
}

function membersOf(...groups: ForensicEvent[][]): Map<string, string[]> {
  return new Map(groups.map((g) => [g[0].id, g.map((e) => e.id)] as const));
}

function finding(id: string, relatedEventIds: string[], extra: Partial<Finding> = {}): Finding {
  return {
    id,
    title: id,
    severity: "High",
    confidence: 80,
    description: "",
    relatedEventIds,
    mitreTechniques: [],
    iocIds: [],
    status: "open",
    ...extra,
  } as Finding;
}

const run = (
  questions: InvestigationQuestion[],
  groups: ForensicEvent[][] | undefined,
  findings: Finding[] = [],
): InvestigationQuestion[] =>
  applyBurstGapQuestions(questions, {
    membersOf: groups ? membersOf(...groups) : undefined,
    events: (groups ?? []).flat(),
    findings,
  });

const gapQs = (qs: InvestigationQuestion[]) => qs.filter((q) => q.id.startsWith(BURST_GAP_ID_PREFIX));

describe("applyBurstGapQuestions", () => {
  it("a 39-member burst with 39 distinct commands yields one unknown pinned question listing the 26 hidden ids", () => {
    const g = burst("a", 39);
    const [q] = gapQs(run([], [g]));
    expect(q).toBeDefined();
    expect(q.id).toBe(`${BURST_GAP_ID_PREFIX}a0`);
    expect(q.status).toBe("unknown");
    expect(q.answer).toBe("");
    expect(q.pinned).toBe(true);
    expect(q.author).toBeUndefined(); // system-made, not Watson's and not an analyst's
    expect(q.coverageGap?.kind).toBe("burst-hidden-lines");
    expect(q.coverageGap?.hiddenCount).toBe(26);
    expect(q.coverageGap?.hiddenEventIds).toEqual(g.slice(13).map((e) => e.id));
    expect(q.question).toContain("26");
    expect(q.pointer).toContain("a13");
    expect(q.pointer).toContain("a38");
  });

  it("asks nothing for a burst that repeats one command", () => {
    const same = Array.from({ length: 30 }, (_, i) => proc(`s${i}`, i, "/c whoami"));
    expect(gapQs(run([], [same]))).toEqual([]);
  });

  it("asks nothing for a burst whose distinct lines all fit on the row", () => {
    expect(gapQs(run([], [burst("b", 10)]))).toEqual([]);
  });

  it("a finding that cites only the representative leaves the question unknown", () => {
    const g = burst("a", 20);
    const [q] = gapQs(run([], [g], [finding("f1", ["a0"])]));
    expect(q.status).toBe("unknown");
  });

  it("is answered when findings cite every hidden id, partial when they cite some", () => {
    const g = burst("a", 20);
    const hidden = g.slice(13).map((e) => e.id);
    const all = gapQs(run([], [g], [finding("f1", hidden.slice(0, 3)), finding("f2", hidden.slice(3))]))[0];
    expect(all.status).toBe("answered");
    expect(all.relatedFindingIds).toEqual(["f1", "f2"]);
    expect(all.answer).toContain("f1");
    const some = gapQs(run([], [g], [finding("f1", hidden.slice(0, 2))]))[0];
    expect(some.status).toBe("partial");
    expect(some.answer).toContain("2 of 7");
  });

  it("does not count automatic or dismissed findings as reading the hidden lines", () => {
    const g = burst("a", 20);
    const hidden = g.slice(13).map((e) => e.id);
    const [q] = gapQs(
      run([], [g], [finding("f-auto-x", hidden), finding("f9", hidden, { status: "dismissed" })]),
    );
    expect(q.status).toBe("unknown");
  });

  it("drops the question when the group no longer hides lines", () => {
    const first = run([], [burst("a", 20)]);
    expect(gapQs(first)).toHaveLength(1);
    expect(gapQs(run(first, [burst("a", 8)]))).toEqual([]);
    expect(gapQs(run(first, []))).toEqual([]);
  });

  it("leaves existing questions alone when the run has no grouping information", () => {
    const first = run([], [burst("a", 20)]);
    expect(run(first, undefined)).toEqual(first);
  });

  it("keeps one question per group on a re-run and re-stamps a model echo of its id", () => {
    const g = burst("a", 20);
    const once = run([], [g]);
    const twice = run(once, [g]);
    expect(gapQs(twice)).toHaveLength(1);
    expect(twice).toEqual(once);
    const echoed: InvestigationQuestion = {
      id: `${BURST_GAP_ID_PREFIX}a0`,
      question: "model text",
      status: "answered",
      answer: "the model says so",
      pointer: "",
      pinned: true,
    };
    const [q] = gapQs(run([echoed], [g]));
    expect(q.status).toBe("unknown");
    expect(q.answer).toBe("");
    expect(q.coverageGap?.hiddenCount).toBe(7);
  });

  it("keeps an answer the analyst applied from Watson while the group still hides lines", () => {
    const g = burst("a", 20);
    const [base] = gapQs(run([], [g]));
    const watson: InvestigationQuestion = {
      ...base,
      status: "answered",
      answer: "They set persistence and dumped LSASS",
      author: "watson",
    };
    const [q] = gapQs(run([watson], [g]));
    expect(q.status).toBe("answered");
    expect(q.answer).toBe("They set persistence and dumped LSASS");
    expect(q.coverageGap?.hiddenCount).toBe(7);
  });

  it(`caps the questions per case at ${MAX_BURST_GAP_QUESTIONS}, largest gap first, keeping ones already asked`, () => {
    const groups = [20, 30, 40, 25, 35].map((n, i) => burst(String.fromCharCode(97 + i), n, i * 100));
    const qs = gapQs(run([], groups));
    expect(qs).toHaveLength(MAX_BURST_GAP_QUESTIONS);
    expect(qs.map((q) => q.id)).toEqual(["c0", "e0", "b0"].map((id) => `${BURST_GAP_ID_PREFIX}${id}`));
    // An already-asked smaller gap keeps its seat when a bigger one appears.
    const small = run([], [groups[0]]);
    const later = gapQs(run(small, groups));
    expect(later).toHaveLength(MAX_BURST_GAP_QUESTIONS);
    expect(later.map((q) => q.id)).toContain(`${BURST_GAP_ID_PREFIX}a0`);
  });

  it("lists at most Watson's lookup limit of ids and closes against the listed ones", () => {
    expect(BURST_GAP_LISTED_IDS).toBe(WATSON_LOOKUP_LIMITS.eventIds);
    const g = burst("z", 13 + 60);
    const [q] = gapQs(run([], [g]));
    expect(q.coverageGap?.hiddenCount).toBe(60);
    expect(q.coverageGap?.hiddenEventIds).toHaveLength(BURST_GAP_LISTED_IDS);
    const cited = q.coverageGap!.hiddenEventIds;
    expect(gapQs(run([], [g], [finding("f1", cited)]))[0].status).toBe("answered");
  });

  it("keeps command text out of the question and cleans the host and image it names", () => {
    const g = burst("a", 20).map((e) => ({ ...e, asset: "WS-07\n<script>x</script>\u0007" }));
    const [q] = gapQs(run([], [g]));
    expect(q.question).not.toContain("echo");
    expect(q.question).not.toMatch(/[\n\u0007]/);
    expect(q.question).toContain("winupd.exe");
  });

  it("leaves the case's other questions untouched and in order", () => {
    const other: InvestigationQuestion = {
      id: "q1",
      question: "How?",
      status: "unknown",
      answer: "",
      pointer: "",
    };
    const out = run([other], [burst("a", 20)]);
    expect(out[0]).toBe(other);
    expect(out).toHaveLength(2);
  });
});
