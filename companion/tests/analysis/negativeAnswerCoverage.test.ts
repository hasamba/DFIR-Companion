import { describe, it, expect } from "vitest";
import { applyNegativeAnswerCoverage } from "../../src/analysis/negativeAnswerCoverage.js";
import { buildCollectionInventory, CLASS_COLLECTION } from "../../src/analysis/collectionInventory.js";
import { createCanonicalEvent } from "../../src/analysis/canonicalEvent.js";
import {
  emptyState,
  type ForensicEvent,
  type InvestigationQuestion,
  type InvestigationState,
  type NextStep,
  type Severity,
} from "../../src/analysis/stateTypes.js";
import type { VeloHuntJob } from "../../src/analysis/veloHuntStore.js";

const T = "2026-08-26T13:00:00.000Z";
const FILE = CLASS_COLLECTION["file-activity"];
const EXEC = CLASS_COLLECTION.execution;

function ev(id: string, over: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id,
    timestamp: T,
    description: `row ${id}`,
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...over,
  };
}

const chainsaw = (id: string, host: string, severity: Severity = "Medium"): ForensicEvent =>
  ev(id, { asset: host, sources: ["Chainsaw"], severity, description: `Sigma hit ${id}` });

const mft = (id: string, host: string): ForensicEvent =>
  ev(id, { asset: host, sources: ["Velociraptor"], artifactName: "Windows.NTFS.MFT" });

function job(over: Partial<VeloHuntJob>): VeloHuntJob {
  return {
    bundleId: "b1",
    bundleName: "Bundle",
    artifacts: [],
    huntId: "H.1",
    launchedAt: T,
    waitMinutes: 5,
    collectAt: T,
    status: "imported",
    ...over,
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

function stateWith(
  events: ForensicEvent[],
  keyQuestions: InvestigationQuestion[],
  nextSteps: NextStep[] = [],
): InvestigationState {
  return { ...emptyState("c1"), forensicTimeline: events, keyQuestions, nextSteps };
}

// INC-2026-005: WS01 holds only Chainsaw rule hits (one High), nothing raw.
const incEvents = (): ForensicEvent[] => [
  chainsaw("e1", "WS01", "High"),
  chainsaw("e2", "WS01"),
  chainsaw("e3", "WS01"),
];

describe("applyNegativeAnswerCoverage — uncovered negative keyQuestion", () => {
  it("INC-2026-005: a 'no encryption observed' answer on detections only becomes partial with one collection step", () => {
    const events = incEvents();
    const state = stateWith(events, [impactQ()]);
    const inv = buildCollectionInventory({ events });
    const out = applyNegativeAnswerCoverage(state, inv);
    const q = out.keyQuestions[0];
    expect(q.status).toBe("partial");
    expect(q.answer.startsWith("No confirmed data encryption or destruction was observed.")).toBe(true);
    expect(q.answer).toMatch(
      /Not settled — file-activity evidence was not collected raw on WS01; collect Windows\.EventLogs\.Evtx \(/,
    );
    expect(q.answer.endsWith(`collect ${FILE.artifact} (${FILE.logSource}).`)).toBe(true);
    expect(q.collect).toMatchObject({ host: "WS01", artifact: FILE.artifact, logSource: FILE.logSource });
    expect(q.collect?.expectedOutcome).toBe("would show whether file-activity activity occurred");
    expect(out.nextSteps).toHaveLength(1);
    const step = out.nextSteps[0];
    expect(step.id).toBe("ns-coverage-q-impact-ws01");
    expect(step.priority).toBe("high");
    expect(step.action).toBe(
      `Collect ${FILE.artifact} (${FILE.logSource}) on WS01 to settle: What was the impact?`,
    );
    expect(step.pointer).toBe(FILE.logSource);
    expect(step.collect).toMatchObject({ host: "WS01", artifact: FILE.artifact, logSource: FILE.logSource });
    expect(step.relatedFindingIds).toEqual([]);
    // inputs untouched
    expect(state.keyQuestions[0].status).toBe("answered");
    expect(state.nextSteps).toHaveLength(0);
  });

  it("keeps a question collect the model already gave", () => {
    const events = incEvents();
    const given = { host: "WS01", artifact: "Windows.Search.FileFinder" };
    const out = applyNegativeAnswerCoverage(
      stateWith(events, [impactQ({ collect: given })]),
      buildCollectionInventory({ events }),
    );
    expect(out.keyQuestions[0].status).toBe("partial");
    expect(out.keyQuestions[0].collect).toEqual(given);
  });

  it("leaves the answer alone when a raw MFT listing covers file activity on the host", () => {
    const events = [...incEvents(), mft("m1", "WS01")];
    const state = stateWith(events, [impactQ()]);
    const out = applyNegativeAnswerCoverage(state, buildCollectionInventory({ events }));
    expect(out.keyQuestions[0]).toEqual(state.keyQuestions[0]);
    expect(out.nextSteps).toHaveLength(0);
  });

  it("counts raw Sysmon collected through Windows.EventLogs.Evtx for the class its record type names", () => {
    const sysmon = ev("s1", {
      asset: "WS01",
      sources: ["Velociraptor"],
      artifactName: "Windows.EventLogs.Evtx",
      sourceRecordId: "evtx:microsoft-windows-sysmon/operational:123",
      canonical: createCanonicalEvent({
        event: { category: "file", type: "creation" },
        time: { observed: T, normalized: T },
        evidence: { rawRecords: [{ source: "test", locator: "row:s1" }] },
        producer: { importer: "test", parserVersion: "1", mappingVersion: "1" },
      }),
    });
    const events = [...incEvents(), sysmon];
    const state = stateWith(events, [impactQ()]);
    const out = applyNegativeAnswerCoverage(state, buildCollectionInventory({ events }));
    expect(out.keyQuestions[0]).toEqual(state.keyQuestions[0]);
    expect(out.nextSteps).toHaveLength(0);
  });

  it("judges the host the question names, not the host that has coverage", () => {
    const events = [mft("m1", "WS01"), chainsaw("c2", "WS02", "High")];
    const q = impactQ({ answer: "No file encryption was observed on ws02." });
    const out = applyNegativeAnswerCoverage(stateWith(events, [q]), buildCollectionInventory({ events }));
    expect(out.keyQuestions[0].status).toBe("partial");
    expect(out.keyQuestions[0].collect?.host).toBe("WS02");
    expect(out.nextSteps[0].collect?.host).toBe("WS02");
    expect(out.nextSteps[0].id).toBe("ns-coverage-q-impact-ws02");
  });

  it("matches a host by its short name when the inventory holds the FQDN", () => {
    const events = [mft("m1", "ws01.corp.example.com"), chainsaw("c2", "ws02.corp.example.com", "High")];
    const q = impactQ({ answer: "No file encryption was observed on WS02." });
    const out = applyNegativeAnswerCoverage(stateWith(events, [q]), buildCollectionInventory({ events }));
    expect(out.keyQuestions[0].collect?.host).toBe("ws02.corp.example.com");
  });

  it("falls back to the hosts of events cited by the question's findings", () => {
    const events = [mft("m1", "WS01"), chainsaw("c2", "WS02"), chainsaw("c3", "WS01", "High")];
    const state: InvestigationState = {
      ...stateWith(events, [impactQ({ relatedFindingIds: ["f1"] })]),
      findings: [
        { id: "f1", severity: "Medium", title: "t", description: "d", relatedEventIds: ["c2"] } as never,
      ],
    };
    const out = applyNegativeAnswerCoverage(state, buildCollectionInventory({ events }));
    expect(out.keyQuestions[0].collect?.host).toBe("WS02");
    expect(out.nextSteps[0].relatedFindingIds).toEqual(["f1"]);
  });

  it("accepts a clean zero-row FLEET-WIDE hunt of a single-record-type artifact as settling the class", () => {
    const events = incEvents();
    const inv = buildCollectionInventory({
      events,
      hunts: [
        job({ artifacts: ["Windows.Search.FileFinder"], emptyArtifacts: ["Windows.Search.FileFinder"] }),
      ],
    });
    const state = stateWith(events, [impactQ()]);
    const out = applyNegativeAnswerCoverage(state, inv);
    expect(out.keyQuestions[0]).toEqual(state.keyQuestions[0]);
    expect(out.nextSteps).toHaveLength(0);
  });

  // #1588 review: the generic EVTX artifact collects whichever channels its parameters named, so an
  // empty result says nothing about file, execution or network — and a label-filtered hunt names no hosts.
  it("does not let an empty Windows.EventLogs.Evtx hunt, or a label-filtered one, settle anything", () => {
    const events = incEvents();
    for (const hunt of [
      job({ artifacts: ["Windows.EventLogs.Evtx"], emptyArtifacts: ["Windows.EventLogs.Evtx"] }),
      job({
        artifacts: ["Windows.Search.FileFinder"],
        emptyArtifacts: ["Windows.Search.FileFinder"],
        target: { includeLabels: ["finance"] },
      }),
    ]) {
      const out = applyNegativeAnswerCoverage(
        stateWith(events, [impactQ()]),
        buildCollectionInventory({ events, hunts: [hunt] }),
      );
      expect(out.keyQuestions[0].status).toBe("partial");
    }
  });

  it("still qualifies an absence answer answerContradiction downgraded, keeping its contradiction", () => {
    const events = incEvents();
    const contradicted = impactQ({
      status: "partial",
      contradicted: { techniques: ["T1486"], eventIds: ["e1"] },
    });
    const inv = buildCollectionInventory({ events });
    const out = applyNegativeAnswerCoverage(stateWith(events, [contradicted]), inv);
    expect(out.keyQuestions[0].answer).toMatch(/Not settled — file-activity/);
    expect(out.keyQuestions[0].contradicted).toEqual(contradicted.contradicted);
    expect(out.nextSteps).toHaveLength(1);
    expect(applyNegativeAnswerCoverage(out, inv)).toEqual(out);
    // A partial answer the MODEL wrote is its own to finish — it already owes a collect.
    const modelPartial = impactQ({ status: "partial" });
    expect(applyNegativeAnswerCoverage(stateWith(events, [modelPartial]), inv).keyQuestions[0]).toEqual(
      modelPartial,
    );
  });

  it("asks to search the archive, not to re-collect, when the artifact is in the archive only", () => {
    const events = incEvents();
    const inv = buildCollectionInventory({ events, hunts: [job({ artifacts: ["Windows.EventLogs.Evtx"] })] });
    const out = applyNegativeAnswerCoverage(stateWith(events, [impactQ()]), inv);
    expect(out.keyQuestions[0].status).toBe("partial");
    expect(out.keyQuestions[0].collect).toBeUndefined();
    expect(out.nextSteps).toHaveLength(1);
    expect(out.nextSteps[0].action).toBe(
      "Search the archive for Windows.EventLogs.Evtx on WS01 and promote the relevant rows to settle: What was the impact?",
    );
    expect(out.nextSteps[0].collect).toBeUndefined();
  });

  it("does not add a second step when one already collects the same host, artifact and log source", () => {
    const events = incEvents();
    const existing: NextStep = {
      id: "n6",
      priority: "medium",
      action: "Collect Sysmon",
      rationale: "r",
      pointer: "p",
      collect: { host: "ws01", artifact: FILE.artifact, logSource: FILE.logSource },
    };
    const out = applyNegativeAnswerCoverage(
      stateWith(events, [impactQ()], [existing]),
      buildCollectionInventory({ events }),
    );
    expect(out.keyQuestions[0].status).toBe("partial");
    expect(out.nextSteps).toEqual([existing]);
  });

  it("treats a paraphrased Sysmon step on the same host as the same collection, but not a Security one", () => {
    const events = incEvents();
    const inv = buildCollectionInventory({ events });
    const step = (logSource: string): NextStep => ({
      id: "n1",
      priority: "medium",
      action: "Collect event logs",
      rationale: "r",
      pointer: "p",
      collect: { host: "WS01", artifact: "Windows.EventLogs.Evtx", logSource },
    });
    const paraphrased = applyNegativeAnswerCoverage(
      stateWith(events, [impactQ()], [step("Sysmon EID 11")]),
      inv,
    );
    expect(paraphrased.nextSteps).toHaveLength(1);
    const security = applyNegativeAnswerCoverage(
      stateWith(events, [impactQ()], [step("Security 4624/4625")]),
      inv,
    );
    expect(security.nextSteps).toHaveLength(2);
  });

  it("falls back only to hosts active in the events synthesis reasoned over", () => {
    // WS01 is covered (raw MFT). WS09 has no raw file collection and only a DISMISSED Critical row,
    // which is not in the events synthesis reasoned over — so WS09 must not be judged.
    const events = [chainsaw("e1", "WS01", "High"), mft("m1", "WS01"), chainsaw("x9", "WS09", "Critical")];
    const inv = buildCollectionInventory({ events });
    const q = impactQ();
    const scoped = events.filter((e) => e.id !== "x9");
    const judged = applyNegativeAnswerCoverage(stateWith(events, [q]), inv, { scopedEvents: scoped });
    expect(judged.keyQuestions[0]).toEqual(q);
    // With the dismissed row in scope, WS09 is a subject host and the answer is not settled.
    const unscoped = applyNegativeAnswerCoverage(stateWith(events, [q]), inv, { scopedEvents: events });
    expect(unscoped.keyQuestions[0].collect?.host).toBe("WS09");
  });

  it("is idempotent", () => {
    const events = incEvents();
    const inv = buildCollectionInventory({ events });
    const once = applyNegativeAnswerCoverage(stateWith(events, [impactQ()]), inv);
    const twice = applyNegativeAnswerCoverage(once, inv);
    expect(twice).toEqual(once);
  });

  it("leaves positive answers and non-answered statuses alone", () => {
    const events = incEvents();
    const qs = [
      impactQ({ answer: "Files were encrypted at 09:04" }),
      impactQ({ id: "q2", status: "partial" }),
      impactQ({ id: "q3", status: "unknown" }),
    ];
    const state = stateWith(events, qs);
    const out = applyNegativeAnswerCoverage(state, buildCollectionInventory({ events }));
    expect(out.keyQuestions).toEqual(qs);
    expect(out.nextSteps).toHaveLength(0);
  });
});

describe("applyNegativeAnswerCoverage — step asks for a cleared log", () => {
  const clear = (id: string, at: string, host = "WS01"): ForensicEvent =>
    ev(id, { asset: host, timestamp: at, description: "Security audit log cleared (EID 1102)" });
  const securityStep = (id: string, host: string): NextStep => ({
    id,
    priority: "high",
    action: "Collect Security 4624/4625 before 2026-08-28",
    rationale: "Logons show who came in.",
    pointer: "Security.evtx",
    collect: { host, artifact: "Windows.EventLogs.Evtx", logSource: "Security 4624/4625" },
  });
  const CLEAR_AT = "2026-08-27T10:00:00.000Z";

  it("demotes a Security step on the host whose Security log was cleared and suggests Sysmon", () => {
    const events = [clear("x1", CLEAR_AT)];
    const steps = [securityStep("n6", "WS01"), securityStep("n7", "WS02")];
    const out = applyNegativeAnswerCoverage(
      stateWith(events, [], steps),
      buildCollectionInventory({ events }),
    );
    const [n6, n7] = out.nextSteps;
    expect(n6.priority).toBe("low");
    expect(n6.rationale).toBe(
      `⚠ The case shows the Security log on WS01 was cleared at ${CLEAR_AT}; this collection will likely return nothing from before then.` +
        ` Prefer ${EXEC.artifact} on Microsoft-Windows-Sysmon/Operational, which was not cleared. Logons show who came in.`,
    );
    expect(n6.action).toBe(steps[0].action);
    expect(n7).toEqual(steps[1]);
    expect(steps[0].priority).toBe("high");
  });

  it("does not treat a wevtutil.exe execution row as a clear", () => {
    const events = [
      ev("p1", {
        asset: "WS01",
        description: "wevtutil.exe executed",
        artifactName: "Windows.Forensics.Prefetch",
        sources: ["Velociraptor"],
        mitreTechniques: ["T1070.001"],
      }),
    ];
    const inv = buildCollectionInventory({ events });
    expect(inv.cleared).toEqual([]);
    const steps = [securityStep("n6", "WS01")];
    const out = applyNegativeAnswerCoverage(stateWith(events, [], steps), inv);
    expect(out.nextSteps).toEqual(steps);
  });

  it("names the latest clear on the host and channel", () => {
    const events = [
      clear("x1", "2026-08-25T10:00:00.000Z"),
      clear("x2", CLEAR_AT),
      clear("x3", "2026-08-26T10:00:00.000Z"),
    ];
    const out = applyNegativeAnswerCoverage(
      stateWith(events, [], [securityStep("n6", "WS01")]),
      buildCollectionInventory({ events }),
    );
    expect(out.nextSteps[0].rationale).toContain(`was cleared at ${CLEAR_AT};`);
  });

  it("flags a step that names no host, and is idempotent", () => {
    const events = [clear("x1", CLEAR_AT)];
    const step: NextStep = { ...securityStep("n6", ""), collect: undefined };
    const inv = buildCollectionInventory({ events });
    const once = applyNegativeAnswerCoverage(stateWith(events, [], [step]), inv);
    expect(once.nextSteps[0].priority).toBe("low");
    expect(applyNegativeAnswerCoverage(once, inv)).toEqual(once);
  });

  it("does not flag a step that asks for a different channel", () => {
    const events = [clear("x1", CLEAR_AT)];
    const step: NextStep = {
      id: "n8",
      priority: "high",
      action: "Collect Autoruns",
      rationale: "r",
      pointer: "Autoruns",
      collect: { host: "WS01", artifact: "Windows.Sysinternals.Autoruns", logSource: "Autoruns" },
    };
    const out = applyNegativeAnswerCoverage(
      stateWith(events, [], [step]),
      buildCollectionInventory({ events }),
    );
    expect(out.nextSteps).toEqual([step]);
  });
});
