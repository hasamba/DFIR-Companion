import { describe, it, expect } from "vitest";
import { parseVelociraptorJson } from "../../src/analysis/velociraptorImport.js";
import { deltaSchema, stripAiExtractedFrom, type AnalysisDelta } from "../../src/analysis/responseSchema.js";
import { mergeDelta } from "../../src/analysis/stateMerge.js";
import { collectedEvidenceClasses } from "../../src/analysis/refutationGate.js";
import {
  buildCollectionInventory,
  coveredOnAll,
  renderCollectionInventory,
} from "../../src/analysis/collectionInventory.js";
import { applyNegativeAnswerCoverage } from "../../src/analysis/negativeAnswerCoverage.js";
import {
  emptyState,
  type ForensicEvent,
  type InvestigationQuestion,
  type InvestigationState,
} from "../../src/analysis/stateTypes.js";
import type { VeloHuntJob } from "../../src/analysis/veloHuntStore.js";

// #1651 — rows from an artifact read only in part (its source list could not be looked up, #1635)
// may qualify coverage of their evidence class, but never count as full raw coverage of it.

const TS = "Windows.System.TaskScheduler";
const T = "2026-09-20T10:00:00Z";

function ev(id: string, over: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id,
    timestamp: T,
    description: `row ${id}`,
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset: "WS01",
    sources: ["Velociraptor"],
    ...over,
  };
}

const partialTask = (id: string, host = "WS01"): ForensicEvent =>
  ev(id, { asset: host, artifactName: TS, partlyReadArtifact: TS });
const fullAutoruns = (id: string, host = "WS01"): ForensicEvent =>
  ev(id, { asset: host, artifactName: "Windows.Sysinternals.Autoruns" });
const prefetch = (id: string, host = "WS01"): ForensicEvent =>
  ev(id, { asset: host, artifactName: "Windows.Forensics.Prefetch" });

const baseDelta: AnalysisDelta = {
  findings: [],
  iocs: [],
  mitreTechniques: [],
  threadsOpened: [],
  threadsClosed: [],
  timelineNote: "",
  summary: "",
};

describe("the importer stamps every row of a partly read artifact (#1651)", () => {
  const rows = [
    { _Source: TS, Name: "\\Updater", Command: "C:\\Users\\Public\\u.exe", Computer: "WS01" },
    { _Source: TS, Name: "\\Updater", Command: "C:\\Users\\Public\\u.exe", Computer: "WS01" },
  ];

  it("stamps the artifact on each event, through aggregation", () => {
    const r = parseVelociraptorJson(JSON.stringify(rows), { artifact: TS, partlyReadArtifact: TS });
    expect(r.events.length).toBeGreaterThan(0);
    for (const e of r.events) expect(e.partlyReadArtifact).toBe(TS);
  });

  it("stamps nothing on a full read", () => {
    const r = parseVelociraptorJson(JSON.stringify(rows), { artifact: TS });
    for (const e of r.events) expect(e.partlyReadArtifact).toBeUndefined();
  });
});

describe("the stamp survives the merge and stays the importer's alone (#1651)", () => {
  const ctx = { windowSequence: 1, timestamp: T, sourceScreenshots: [] };

  it("keeps the stamp on a created row and never clears it on an unstamped restatement", () => {
    const stamped = deltaSchema.parse({ ...baseDelta, forensicEvents: [partialTask("e1")] });
    let state = mergeDelta(emptyState("c1"), stamped, ctx);
    expect(state.forensicTimeline[0].partlyReadArtifact).toBe(TS);
    const restated = deltaSchema.parse({
      ...baseDelta,
      forensicEvents: [{ ...partialTask("e1"), partlyReadArtifact: undefined }],
    });
    state = mergeDelta(state, restated, ctx);
    expect(state.forensicTimeline[0].partlyReadArtifact).toBe(TS);
  });

  it("strips the stamp from a model delta", () => {
    const parsed = deltaSchema.parse({ ...baseDelta, forensicEvents: [partialTask("e1")] });
    const stripped = stripAiExtractedFrom(parsed);
    expect(stripped.forensicEvents?.[0]).not.toHaveProperty("partlyReadArtifact");
  });
});

describe("refutation coverage ignores partly read rows (#1651)", () => {
  it("a partly read TaskScheduler row is not persistence coverage", () => {
    expect(collectedEvidenceClasses([partialTask("e1")])).toEqual(new Set());
    expect(collectedEvidenceClasses([partialTask("e1"), fullAutoruns("e2")])).toEqual(
      new Set(["persistence"]),
    );
  });
});

describe("collection inventory — partly read coverage (#1651)", () => {
  it("lists the class as partly read, never as collected raw, and asks to collect it", () => {
    const inv = buildCollectionInventory({ events: [partialTask("e1"), partialTask("e2"), prefetch("p1")] });
    expect(coveredOnAll(inv, ["WS01"])).toEqual(new Set(["execution"]));
    expect(inv.partlyByHost.get("WS01")?.get("persistence")).toEqual(new Set([TS]));
    const text = renderCollectionInventory(inv);
    expect(text).toContain(
      `- WS01: collected raw: execution; partly read (source list not looked up, not full coverage): persistence (${TS}); no raw collection found: file-activity, network`,
    );
    expect(text).toContain(`- Collect again (partly read): ${TS} on WS01`);
    expect(text).not.toMatch(/Where to collect: .*persistence → /);
    expect(text).toContain(`${TS} (raw; 2 partly read) 2`);
    expect(text).toMatch(/partly read.*is not settled/);
  });

  it("a full read of the class on the host wins over a partial one", () => {
    const inv = buildCollectionInventory({ events: [partialTask("e1"), fullAutoruns("a1")] });
    expect(coveredOnAll(inv, ["WS01"])).toEqual(new Set(["persistence"]));
    expect(inv.partlyByHost.get("WS01")?.has("persistence") ?? false).toBe(false);
    expect(renderCollectionInventory(inv)).toContain("- WS01: collected raw: persistence; no raw");
  });

  it("is per host: full on one host does not cover a host read only in part", () => {
    const inv = buildCollectionInventory({ events: [fullAutoruns("a1", "WS01"), partialTask("e1", "WS02")] });
    expect(coveredOnAll(inv, ["WS01"])).toEqual(new Set(["persistence"]));
    expect(coveredOnAll(inv, ["WS02"])).toEqual(new Set());
    expect(inv.partlyByHost.get("WS02")?.get("persistence")).toEqual(new Set([TS]));
  });
});

describe("negative-answer coverage — partly read class (#1651)", () => {
  const persistQ = (): InvestigationQuestion => ({
    id: "q_persist",
    question: "Did the attacker establish persistence?",
    status: "answered",
    answer: "No persistence mechanism was observed on WS01.",
    pointer: "",
  });
  const stateWith = (events: ForensicEvent[]): InvestigationState => ({
    ...emptyState("c1"),
    forensicTimeline: events,
    keyQuestions: [persistQ()],
  });

  it("downgrades the answer and asks to collect the partly read artifact again", () => {
    const events = [partialTask("e1")];
    const out = applyNegativeAnswerCoverage(stateWith(events), buildCollectionInventory({ events }));
    const q = out.keyQuestions[0];
    expect(q.status).toBe("partial");
    expect(q.answer).toContain(
      `Not settled — persistence evidence on WS01 comes only from ${TS}, which was only partly read (its source list could not be looked up); collect ${TS} again.`,
    );
    expect(q.collect).toMatchObject({ host: "WS01", artifact: TS });
    expect(out.nextSteps).toHaveLength(1);
    expect(out.nextSteps[0].action).toBe(
      `Collect ${TS} again on WS01 — it was only partly read — to settle: Did the attacker establish persistence?`,
    );
    expect(out.nextSteps[0].collect).toMatchObject({ host: "WS01", artifact: TS });
  });

  it("asks to collect again, not to promote from the archive, when the artifact is also archive-only", () => {
    const events = [partialTask("e1")];
    const hunt: VeloHuntJob = {
      bundleId: "b",
      bundleName: "B",
      artifacts: ["Windows.Sysinternals.Autoruns"],
      huntId: "H.1",
      launchedAt: T,
      waitMinutes: 5,
      collectAt: T,
      status: "imported",
    };
    const out = applyNegativeAnswerCoverage(
      stateWith(events),
      buildCollectionInventory({ events, hunts: [hunt] }),
    );
    expect(out.nextSteps[0].action).toMatch(/^Collect Windows\.System\.TaskScheduler again/);
    expect(out.nextSteps[0].collect).toMatchObject({ artifact: TS });
  });

  it("leaves the answer alone when the class is also collected in full on the host", () => {
    const events = [partialTask("e1"), fullAutoruns("a1")];
    const state = stateWith(events);
    const out = applyNegativeAnswerCoverage(state, buildCollectionInventory({ events }));
    expect(out.keyQuestions[0]).toEqual(state.keyQuestions[0]);
  });
});
