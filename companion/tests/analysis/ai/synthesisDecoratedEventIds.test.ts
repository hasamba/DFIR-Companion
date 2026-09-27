import { describe, expect, it } from "vitest";
import { foldSynthesisDelta, type DeltaFoldContext } from "../../../src/analysis/ai/synthesisMerge.js";
import { deltaSchema } from "../../../src/analysis/responseSchema.js";
import { mergeDelta } from "../../../src/analysis/stateMerge.js";
import { emptyState, type ForensicEvent, type InvestigationState } from "../../../src/analysis/stateTypes.js";

/**
 * #1693 — a synthesis finding that cites a decorated event id keeps its evidence.
 *
 * Seen on the cloud-vpn-contradiction eval case: the model reached the right conclusion and cited
 * `["e_cld-e1", "e_cld-e2"]`. Nothing matched, so the events never linked to the finding, the High
 * backfill raised them again as `f-auto-cld-e1`, and grading dropped the finding's evidence. Our own
 * prompt renders rows as `~[id]`, so `~` and brackets are as likely as the `e_` prefix.
 */

const event = (id: string, at: string): ForensicEvent => ({
  id,
  timestamp: at,
  description: `Azure AD sign-in from a new country (${id})`,
  severity: "High",
  mitreTechniques: ["T1078"],
  relatedFindingIds: [],
  sourceScreenshots: [],
  asset: "cloud",
});

const timeline = (): ForensicEvent[] => [
  event("cld-e1", "2026-08-30T10:00:00.000Z"),
  event("cld-e2", "2026-08-30T10:20:00.000Z"),
];

const delta = (relatedEventIds: string[], hypotheses?: unknown[]) =>
  deltaSchema.parse({
    findings: [
      {
        id: "f1",
        severity: "High",
        title: "Impossible travel after a VPN exit-IP change",
        description: "Two sign-ins 20 minutes apart from countries 9,000 km apart.",
        relatedIocs: [],
        mitreTechniques: ["T1078"],
        status: "open",
        relatedEventIds,
      },
    ],
    iocs: [],
    mitreTechniques: [],
    threadsOpened: [],
    threadsClosed: [],
    timelineNote: "",
    summary: "s",
    ...(hypotheses ? { hypotheses } : {}),
  });

function context(state: InvestigationState): DeltaFoldContext {
  return {
    opts: { stateStore: { load: async () => state } } as unknown as DeltaFoldContext["opts"],
    mergeWithAliases: async (base, d, ctx) => mergeDelta(base, d, ctx),
  };
}

async function fold(d: ReturnType<typeof delta>, scopedEvents?: ForensicEvent[], all = timeline()) {
  const state = { ...emptyState("c1"), forensicTimeline: all };
  return foldSynthesisDelta(context(state), {
    caseId: "c1",
    state,
    delta: d,
    markers: [],
    scopedEvents: scopedEvents ?? state.forensicTimeline,
    playbookTasks: [],
  });
}

const linkedTo = (s: InvestigationState, fid: string): string[] =>
  s.forensicTimeline
    .filter((e) => e.relatedFindingIds.includes(fid))
    .map((e) => e.id)
    .sort();
const autoIds = (s: InvestigationState): string[] =>
  s.findings.filter((f) => f.id.startsWith("f-auto-")).map((f) => f.id);

describe("a decorated event citation keeps a synthesis finding's evidence (#1693)", () => {
  it.each([
    [["e_cld-e1", "e_cld-e2"]],
    [["~cld-e1", "~cld-e2"]],
    [["[cld-e1]", "[cld-e2]"]],
    [["~[cld-e1]", "~[cld-e2]"]],
    [["CLD-E1", "CLD-E2"]],
  ])("links %j to the real events and raises no duplicate auto finding", async (cited) => {
    const { next, delta: folded } = await fold(delta(cited));
    expect(linkedTo(next, "f1")).toEqual(["cld-e1", "cld-e2"]);
    expect(next.findings.find((f) => f.id === "f1")?.relatedEventIds).toEqual(["cld-e1", "cld-e2"]);
    expect(folded.findings[0].relatedEventIds).toEqual(["cld-e1", "cld-e2"]);
    expect(autoIds(next)).toEqual([]);
  });

  it("hands the resolved hypothesis citations to the hypothesis step", async () => {
    const { delta: folded } = await fold(
      delta(
        ["cld-e1"],
        [{ title: "VPN exit change", relatedEventIds: ["e_cld-e1"], contradictingEventIds: ["~[cld-e2]"] }],
      ),
    );
    expect(folded.hypotheses?.[0].relatedEventIds).toEqual(["cld-e1"]);
    expect(folded.hypotheses?.[0].contradictingEventIds).toEqual(["cld-e2"]);
  });

  it("does not resolve a decorated citation onto an event outside this run's scope", async () => {
    const all = [...timeline(), event("cld-e9", "2026-08-29T10:00:00.000Z")];
    const { next, delta: folded } = await fold(delta(["cld-e1", "e_cld-e9"]), timeline(), all);
    expect(folded.findings[0].relatedEventIds).toEqual(["cld-e1", "e_cld-e9"]);
    // …and the merge inside the fold does not widen it to the whole timeline.
    expect(next.findings.find((f) => f.id === "f1")?.relatedEventIds).toEqual(["cld-e1", "e_cld-e9"]);
    expect(linkedTo(next, "f1")).toEqual(["cld-e1"]);
  });

  it("keeps a citation that names no event as the model sent it", async () => {
    const { delta: folded } = await fold(delta(["e_cld-e1", "e_nope"]));
    expect(folded.findings[0].relatedEventIds).toEqual(["cld-e1", "e_nope"]);
  });
});

describe("the shared merge seam (import and MCP agent) resolves a decorated citation (#1693)", () => {
  const ctx = { windowSequence: 0, timestamp: "2026-08-30T11:00:00.000Z", sourceScreenshots: [] };

  it("stores the real event id for a finding that cites e_cld-e1", () => {
    const state = { ...emptyState("c1"), forensicTimeline: timeline() };
    const merged = mergeDelta(state, delta(["e_cld-e1", "[cld-e2]"]), ctx);
    expect(merged.findings.find((f) => f.id === "f1")?.relatedEventIds).toEqual(["cld-e1", "cld-e2"]);
  });

  it("resolves onto an event the same delta adds", () => {
    const d = deltaSchema.parse({
      ...delta(["e_cld-e3"]),
      forensicEvents: [event("cld-e3", "2026-08-30T10:30:00.000Z")],
    });
    const merged = mergeDelta({ ...emptyState("c1"), forensicTimeline: timeline() }, d, ctx);
    expect(merged.findings.find((f) => f.id === "f1")?.relatedEventIds).toEqual(["cld-e3"]);
  });

  it("does not resolve onto an incoming event the merge rejects as analyst work-log narration", () => {
    const narration: ForensicEvent = {
      ...event("cld-e4", "2026-08-30T10:40:00.000Z"),
      description: "Velociraptor Response and Monitoring session continued",
      severity: "Info",
      mitreTechniques: [],
      asset: undefined,
    };
    const d = deltaSchema.parse({ ...delta(["e_cld-e4"]), forensicEvents: [narration] });
    const merged = mergeDelta({ ...emptyState("c1"), forensicTimeline: timeline() }, d, ctx);
    expect(merged.forensicTimeline.map((e) => e.id)).not.toContain("cld-e4");
    expect(merged.findings.find((f) => f.id === "f1")?.relatedEventIds).toEqual(["e_cld-e4"]);
  });
});
