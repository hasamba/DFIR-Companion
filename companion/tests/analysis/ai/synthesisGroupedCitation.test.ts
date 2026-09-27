import { describe, expect, it } from "vitest";
import { foldSynthesisDelta, type DeltaFoldContext } from "../../../src/analysis/ai/synthesisMerge.js";
import { deltaSchema } from "../../../src/analysis/responseSchema.js";
import { mergeDelta } from "../../../src/analysis/stateMerge.js";
import {
  emptyState,
  type Finding,
  type ForensicEvent,
  type InvestigationState,
} from "../../../src/analysis/stateTypes.js";

/**
 * #1702 — a finding that cites a GROUPED prompt row covers the whole group.
 *
 * The synthesis prompt collapses a detection burst into one representative row (synthGroup.ts). On
 * INC-2026-014 the services.exe "Reg Key Value Set" rows at 15:00:39 and 15:00:44 were one grouped row;
 * the model dismissed it in f18, citing the representative only. The other 17 members stayed unlinked,
 * and the High backfill raised them as f-auto-22e717 — "benign" in one finding, High and open in another.
 */

const REP = "e1";
const MEMBERS = ["e1", "e2", "e3", "e4"];

const event = (id: string, at: string, related: string[] = []): ForensicEvent => ({
  id,
  timestamp: at,
  description: `Velociraptor [Windows.Sigma.Base] Sigma: Reg Key Value Set (Sysmon Alert) - Image=C:\\WINDOWS\\system32\\services.exe - TargetObject=HKLM\\System\\CurrentControlSet\\Services\\Svc${id}\\Start`,
  severity: "High",
  mitreTechniques: ["T1112"],
  relatedFindingIds: related,
  sourceScreenshots: [],
  asset: "HOST-A",
});

// The burst: the representative first, the rest seconds later (not twins by the #1556 rule).
const burst = (): ForensicEvent[] => [
  event("e1", "2026-08-30T15:00:39.876Z"),
  event("e2", "2026-08-30T15:00:44.243Z"),
  event("e3", "2026-08-30T15:00:46.249Z"),
  event("e4", "2026-08-30T15:00:48.252Z"),
];
const grouping = () => new Map([[REP, MEMBERS]]);

function context(state: InvestigationState): DeltaFoldContext {
  return {
    opts: { stateStore: { load: async () => state } } as unknown as DeltaFoldContext["opts"],
    mergeWithAliases: async (base, delta, ctx) => mergeDelta(base, delta, ctx),
  };
}

const delta = (findings: unknown[]) =>
  deltaSchema.parse({
    findings,
    iocs: [],
    mitreTechniques: [],
    threadsOpened: [],
    threadsClosed: [],
    timelineNote: "",
    summary: "s",
  });

const modelFinding = (id: string, status: "open" | "dismissed", relatedEventIds: string[]) => ({
  id,
  severity: status === "dismissed" ? "Info" : "High",
  title: "Service registry changes during the Sysmon install",
  description: "services.exe rewrote service Start values during the Defender platform update.",
  relatedIocs: [],
  mitreTechniques: [],
  status,
  relatedEventIds,
});

async function fold(
  state: InvestigationState,
  d: ReturnType<typeof delta>,
  membersOf?: Map<string, string[]>,
): Promise<InvestigationState> {
  const result = await foldSynthesisDelta(context(state), {
    caseId: "c1",
    state,
    delta: d,
    markers: [],
    scopedEvents: state.forensicTimeline,
    playbookTasks: [],
    ...(membersOf ? { membersOf } : {}),
  });
  return result.next;
}

// The auto finding an earlier synthesis minted on the uncited members — the case holds it, so the model
// may echo its id (an unknown f-auto id would be renamed as forged, #787).
const priorAuto = (eventIds: string[]): Finding => ({
  id: "f-auto-e2",
  severity: "High",
  confidence: 100,
  title: "Reg Key Value Set (Sysmon Alert)",
  description: "auto-flagged",
  relatedIocs: [],
  mitreTechniques: ["T1112"],
  sourceScreenshots: [],
  firstSeen: "2026-08-30T15:00:44.243Z",
  lastUpdated: "2026-08-30T15:00:44.243Z",
  status: "open",
  relatedEventIds: eventIds,
});

const autoFindings = (s: InvestigationState): Finding[] =>
  s.findings.filter((f) => f.id.startsWith("f-auto-"));
const linkedTo = (s: InvestigationState, fid: string): string[] =>
  s.forensicTimeline
    .filter((e) => e.relatedFindingIds.includes(fid))
    .map((e) => e.id)
    .sort();

describe("a finding citing a grouped prompt row covers every member (#1702)", () => {
  it("links every member to a DISMISSED finding that cited the representative, and raises no auto finding", async () => {
    const state = { ...emptyState("c1"), forensicTimeline: burst() };
    const next = await fold(state, delta([modelFinding("f18", "dismissed", [REP])]), grouping());
    expect(linkedTo(next, "f18")).toEqual(MEMBERS);
    expect(autoFindings(next)).toEqual([]);
  });

  it("links every member to a LIVE finding the same way", async () => {
    const state = { ...emptyState("c1"), forensicTimeline: burst() };
    const next = await fold(state, delta([modelFinding("f5", "open", [REP])]), grouping());
    expect(linkedTo(next, "f5")).toEqual(MEMBERS);
    expect(autoFindings(next)).toEqual([]);
  });

  it("keeps the model's own citation list on the finding", async () => {
    const state = { ...emptyState("c1"), forensicTimeline: burst() };
    const next = await fold(state, delta([modelFinding("f18", "dismissed", [REP])]), grouping());
    expect(next.findings.find((f) => f.id === "f18")?.relatedEventIds).toEqual([REP]);
  });

  it("drops an echoed auto finding whose every event a dismissed finding now covers", async () => {
    const echoed = {
      id: "f-auto-e2",
      severity: "High",
      title: "Reg Key Value Set (Sysmon Alert)",
      description: "auto-flagged",
      relatedIocs: [],
      mitreTechniques: ["T1112"],
      status: "open",
      relatedEventIds: ["e2", "e3", "e4"],
    };
    const state = {
      ...emptyState("c1"),
      forensicTimeline: burst(),
      findings: [priorAuto(["e2", "e3", "e4"])],
    };
    const next = await fold(state, delta([modelFinding("f18", "dismissed", [REP]), echoed]), grouping());
    expect(next.findings.map((f) => f.id)).not.toContain("f-auto-e2");
  });

  it("keeps an echoed auto finding when one of its events is not covered by the dismissal", async () => {
    const outside = event("e9", "2026-08-30T18:00:00.000Z");
    const echoed = {
      id: "f-auto-e2",
      severity: "High",
      title: "Reg Key Value Set (Sysmon Alert)",
      description: "auto-flagged",
      relatedIocs: [],
      mitreTechniques: ["T1112"],
      status: "open",
      relatedEventIds: ["e2", "e9"],
    };
    const state = {
      ...emptyState("c1"),
      forensicTimeline: [...burst(), outside],
      findings: [priorAuto(["e2", "e9"])],
    };
    const next = await fold(state, delta([modelFinding("f18", "dismissed", [REP]), echoed]), grouping());
    expect(next.findings.map((f) => f.id)).toContain("f-auto-e2");
  });

  it("without a grouping map, behaves as before: the uncited members raise an auto finding", async () => {
    const state = { ...emptyState("c1"), forensicTimeline: burst() };
    const next = await fold(state, delta([modelFinding("f18", "dismissed", [REP])]));
    expect(linkedTo(next, "f18")).toEqual([REP]);
    expect(autoFindings(next).length).toBe(1);
  });
});

describe("a DISMISSED grouped row does not reach a different act in its group (#1702, Codex review)", () => {
  // Members the prompt group holds by rule head alone: another program, much later, another host.
  const attacker = (id: string, at: string, over: Partial<ForensicEvent> = {}): ForensicEvent => ({
    ...event(id, at),
    ...over,
  });
  const cases: Array<[string, ForensicEvent]> = [
    [
      "another acting image",
      attacker("x1", "2026-08-30T15:00:50.000Z", {
        description:
          "Velociraptor [Windows.Sigma.Base] Sigma: Reg Key Value Set (Sysmon Alert) - Image=C:\\Users\\Public\\evil.exe - TargetObject=HKLM\\System\\CurrentControlSet\\Services\\evil\\ImagePath",
      }),
    ],
    ["the same image 30 minutes later", attacker("x1", "2026-08-30T15:30:39.000Z")],
    ["another host", attacker("x1", "2026-08-30T15:00:45.000Z", { asset: "HOST-B" })],
  ];

  for (const [label, row] of cases) {
    it(`leaves ${label} uncovered, so the backfill still raises it`, async () => {
      const state = { ...emptyState("c1"), forensicTimeline: [...burst(), row] };
      const next = await fold(
        state,
        delta([modelFinding("f18", "dismissed", [REP])]),
        new Map([[REP, [...MEMBERS, "x1"]]]),
      );
      expect(linkedTo(next, "f18")).toEqual(MEMBERS);
      const auto = autoFindings(next);
      expect(auto).toHaveLength(1);
      expect(linkedTo(next, auto[0].id)).toEqual(["x1"]);
    });
  }

  it("a LIVE finding still covers every member of the group", async () => {
    const far = attacker("x1", "2026-08-30T15:30:39.000Z");
    const state = { ...emptyState("c1"), forensicTimeline: [...burst(), far] };
    const next = await fold(
      state,
      delta([modelFinding("f5", "open", [REP])]),
      new Map([[REP, [...MEMBERS, "x1"]]]),
    );
    expect(linkedTo(next, "f5")).toEqual([...MEMBERS, "x1"].sort());
    expect(autoFindings(next)).toEqual([]);
  });
});

describe("an echoed auto finding that cites nothing (#1702, Codex review)", () => {
  it("is dropped when the events it held before this synthesis are all dismissed now", async () => {
    const linkedBefore = burst().map((e) => (e.id === REP ? e : { ...e, relatedFindingIds: ["f-auto-e2"] }));
    const state = { ...emptyState("c1"), forensicTimeline: linkedBefore, findings: [priorAuto([])] };
    const echoedWithoutEvents = {
      id: "f-auto-e2",
      severity: "High",
      title: "Reg Key Value Set (Sysmon Alert)",
      description: "auto-flagged",
      relatedIocs: [],
      mitreTechniques: ["T1112"],
      status: "open",
    };
    const next = await fold(
      state,
      delta([modelFinding("f18", "dismissed", [REP]), echoedWithoutEvents]),
      grouping(),
    );
    expect(next.findings.map((f) => f.id)).not.toContain("f-auto-e2");
  });
});
