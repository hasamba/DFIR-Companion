import { describe, expect, it } from "vitest";
import { computeMainSource, type MainSourceOverride } from "../../src/analysis/caseMainSource.js";
import { buildCollectionInventory, CLASS_COLLECTION } from "../../src/analysis/collectionInventory.js";
import { applyNegativeAnswerCoverage } from "../../src/analysis/negativeAnswerCoverage.js";
import {
  emptyState,
  type Finding,
  type ForensicEvent,
  type InvestigationQuestion,
  type InvestigationState,
} from "../../src/analysis/stateTypes.js";

// #2559: the automatic "collect X to settle this" next step speaks the main source's tool. A
// Velociraptor (or unknown / host-tool / cloud) main source keeps today's text byte for byte.

const T = "2026-08-26T13:00:00.000Z";
const FILE = CLASS_COLLECTION["file-activity"];

function ev(id: string, sources: string[], batch: string): ForensicEvent {
  return {
    id,
    timestamp: T,
    description: `Detection ${id}`,
    severity: "High",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset: "WS01",
    sources,
    importBatchId: batch,
  };
}

const impactQ = (over: Partial<InvestigationQuestion> = {}): InvestigationQuestion => ({
  id: "q_impact",
  question: "What was the impact?",
  status: "answered",
  answer: "No confirmed data encryption or destruction was observed.",
  pointer: "",
  ...over,
});

function run(
  events: ForensicEvent[],
  override: MainSourceOverride = null,
  findings: Finding[] = [],
  q = impactQ(),
) {
  const state: InvestigationState = {
    ...emptyState("c1"),
    forensicTimeline: events,
    keyQuestions: [q],
    findings,
  };
  const inv = buildCollectionInventory({ events });
  const mainSource = computeMainSource(events, override);
  return { state, out: applyNegativeAnswerCoverage(state, inv, { mainSource }) };
}

const csEvents = (): ForensicEvent[] => [
  ev("c1", ["CrowdStrike Falcon"], "b1"),
  ev("c2", ["CrowdStrike Falcon"], "b2"),
  ev("c3", ["CrowdStrike Falcon"], "b3"),
];

describe("coverage next step by main source (#2559)", () => {
  it("a CrowdStrike case is told to search Falcon, with no Velociraptor collect directive", () => {
    const { out } = run(csEvents());
    const step = out.nextSteps[0];
    expect(step.id).toBe("ns-coverage-q-impact-ws01");
    expect(step.action).toMatch(/^Search CrowdStrike Falcon/);
    expect(step.action).toContain("PeFileWritten");
    expect(step.action).toMatch(/on WS01 to settle: What was the impact\?$/);
    expect(step.action).not.toContain(FILE.artifact);
    expect(step.collect).toBeUndefined();
    const q = out.keyQuestions[0];
    expect(q.status).toBe("partial");
    expect(q.answer).toMatch(
      /Not settled — file-activity evidence was not collected raw on WS01; search CrowdStrike Falcon/,
    );
    expect(q.collect).toBeUndefined();
  });

  it("Defender, Elastic and Splunk cases each name their own tables or fields", () => {
    const mk = (src: string) => csEvents().map((e) => ({ ...e, sources: [src] }));
    expect(run(mk("Microsoft Defender")).out.nextSteps[0].action).toContain("DeviceFileEvents");
    expect(run(mk("Elastic")).out.nextSteps[0].action).toContain("file.path");
    expect(run(mk("Splunk")).out.nextSteps[0].action).toContain("EventCode=11");
  });

  it("a Velociraptor, host-tool or unknown main source keeps today's text exactly", () => {
    const today = `Collect ${FILE.artifact} (${FILE.logSource}) on WS01 to settle: What was the impact?`;
    const velo = csEvents().map((e) => ({
      ...e,
      sources: ["Velociraptor"],
      artifactName: "Windows.EventLogs.Hayabusa",
    }));
    expect(run(velo).out.nextSteps[0].action).toBe(today);
    const host = csEvents().map((e) => ({ ...e, sources: ["Chainsaw"] }));
    expect(run(host).out.nextSteps[0].action).toBe(today);
    expect(run(host).out.nextSteps[0].collect).toMatchObject({ artifact: FILE.artifact });
    // No main source passed at all → the pre-#2559 behaviour.
    const state: InvestigationState = {
      ...emptyState("c1"),
      forensicTimeline: csEvents(),
      keyQuestions: [impactQ()],
    };
    const out = applyNegativeAnswerCoverage(state, buildCollectionInventory({ events: csEvents() }));
    expect(out.nextSteps[0].action).toBe(today);
  });

  it("the override decides the tool", () => {
    const host = csEvents().map((e) => ({ ...e, sources: ["Chainsaw"] }));
    expect(run(host, "splunk").out.nextSteps[0].action).toMatch(/^Search Splunk/);
  });

  it("on a mixed case the question uses its own findings' evidence", () => {
    const events = [ev("c1", ["CrowdStrike Falcon"], "b1"), ev("v1", ["Velociraptor"], "b2")];
    const f = { id: "f1", relatedEventIds: ["c1"], title: "x" } as unknown as Finding;
    const { out } = run(events, null, [f], impactQ({ relatedFindingIds: ["f1"] }));
    expect(out.nextSteps[0].action).toMatch(/^Search CrowdStrike Falcon/);
    const plain = run(events);
    expect(plain.out.nextSteps[0].action).toMatch(/^Collect /); // no findings → default
  });

  it("running the pass twice changes nothing more", () => {
    const { out } = run(csEvents());
    const again = applyNegativeAnswerCoverage(out, buildCollectionInventory({ events: csEvents() }), {
      mainSource: computeMainSource(csEvents(), null),
    });
    expect(again.nextSteps).toEqual(out.nextSteps);
    expect(again.keyQuestions).toEqual(out.keyQuestions);
  });

  it("a cloud-only case keeps #2555's precedence: no host step at all", () => {
    const cloud = [
      { ...ev("m1", ["Microsoft 365"], "b1"), asset: undefined },
      { ...ev("m2", ["Microsoft 365"], "b2"), asset: undefined },
    ];
    const { out } = run(cloud);
    expect(out.nextSteps).toEqual([]);
    expect(out.keyQuestions[0].status).toBe("answered");
  });
});
