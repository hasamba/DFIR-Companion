import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { rejectedTechniqueIds, withoutRejectedTechniques } from "../../src/analysis/rejectedTechniques.js";
import { applyAcceptedSecondOpinion, type SecondOpinion } from "../../src/analysis/secondOpinion.js";
import { mergeDelta } from "../../src/analysis/stateMerge.js";
import {
  emptyState,
  type Finding,
  type ForensicEvent,
  type InvestigationState,
} from "../../src/analysis/stateTypes.js";
import type { AnalysisDelta } from "../../src/analysis/responseSchema.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ReportWriter } from "../../src/reports/reportWriter.js";
import { LiveHub } from "../../src/live/hub.js";
import { createApp } from "../../src/server.js";

// #1742: an accepted second-opinion technique removal is RECORDED and hidden at every read seam —
// never deleted from stored data, so switching the decision back restores it.

type Decision = { kind: "mitre_added" | "mitre_removed"; title: string; status: "accepted" | "rejected" };

function record(...decisions: Decision[]): SecondOpinion {
  return {
    generatedAt: "t",
    modelA: "a",
    modelB: "b",
    referee: "",
    summary: "",
    agreementCount: 0,
    deltas: decisions.map((d, i) => ({
      id: `d${i}`,
      ...d,
      techniqueName: `${d.title} name`,
      rationale: "",
      recommendation: "review",
    })),
  };
}

const removeT1105 = (status: "accepted" | "rejected" = "accepted"): Decision => ({
  kind: "mitre_removed",
  title: "T1105",
  status,
});

function event(id: string, tags: string[]): ForensicEvent {
  return {
    id,
    timestamp: "2026-07-30T00:00:00Z",
    description: `event ${id}`,
    severity: "High",
    mitreTechniques: tags,
    relatedFindingIds: [],
    sourceScreenshots: [],
  };
}

function caseState(): InvestigationState {
  const s = emptyState("c1");
  s.mitreTechniques = [
    { id: "T1105", name: "Ingress Tool Transfer", findingIds: ["f1"] },
    { id: "T1059", name: "Command and Scripting Interpreter", findingIds: ["f1"] },
  ];
  s.findings = [
    {
      id: "f1",
      title: "Tool transfer then execution",
      severity: "High",
      mitreTechniques: ["T1105", "T1059"],
      relatedEventIds: ["e1"],
    } as Finding,
  ];
  s.forensicTimeline = [event("e1", ["T1105", "T1059"])];
  return s;
}

const ids = (s: Partial<InvestigationState>) => (s.mitreTechniques ?? []).map((t) => t.id);

describe("rejectedTechniqueIds", () => {
  it("lists accepted removals, lets a later accepted addition win, and ignores rejected deltas", () => {
    expect(rejectedTechniqueIds(record(removeT1105()).deltas)).toEqual(["T1105"]);
    expect(rejectedTechniqueIds(record(removeT1105("rejected")).deltas)).toEqual([]);
    expect(
      rejectedTechniqueIds(
        record(removeT1105(), { kind: "mitre_added", title: "T1105", status: "accepted" }).deltas,
      ),
    ).toEqual([]);
  });
});

describe("applyAcceptedSecondOpinion records a removal instead of deleting data (#1742)", () => {
  it("records the id and leaves the stored table, findings and events untouched", () => {
    const before = caseState();
    const out = applyAcceptedSecondOpinion(before, record(removeT1105()));
    expect(out.rejectedTechniques).toEqual(["T1105"]);
    expect(ids(out)).toEqual(["T1105", "T1059"]);
    expect(out.findings[0].mitreTechniques).toEqual(["T1105", "T1059"]);
    expect(out.forensicTimeline[0].mitreTechniques).toEqual(["T1105", "T1059"]);
    expect(before.rejectedTechniques).toBeUndefined(); // pure
  });

  it("clears the record when the analyst switches the removal back to rejected", () => {
    const removed = applyAcceptedSecondOpinion(caseState(), record(removeT1105()));
    const undone = applyAcceptedSecondOpinion(removed, record(removeT1105("rejected")));
    expect(undone).not.toHaveProperty("rejectedTechniques");
    expect(ids(withoutRejectedTechniques(undone))).toEqual(["T1105", "T1059"]);
  });

  it("is idempotent", () => {
    const once = applyAcceptedSecondOpinion(caseState(), record(removeT1105()));
    expect(applyAcceptedSecondOpinion(once, record(removeT1105()))).toBe(once);
  });
});

describe("withoutRejectedTechniques", () => {
  it("hides the id from the table, every finding and every event, without editing the input", () => {
    const stored = { ...caseState(), rejectedTechniques: ["T1105"] };
    const view = withoutRejectedTechniques(stored);
    expect(ids(view)).toEqual(["T1059"]);
    expect(view.findings[0].mitreTechniques).toEqual(["T1059"]);
    expect(view.forensicTimeline[0].mitreTechniques).toEqual(["T1059"]);
    expect(stored.findings[0].mitreTechniques).toEqual(["T1105", "T1059"]);
  });

  it("returns the same object when nothing is rejected", () => {
    const s = caseState();
    expect(withoutRejectedTechniques(s)).toBe(s);
  });
});

describe("the decision survives the reducers that rebuild the state", () => {
  it("mergeDelta keeps it (an import after the decision)", () => {
    const delta: AnalysisDelta = {
      findings: [],
      iocs: [],
      mitreTechniques: [],
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: "",
      summary: "",
    };
    const merged = mergeDelta({ ...caseState(), rejectedTechniques: ["T1105"] }, delta, {
      windowSequence: 1,
      timestamp: "2026-07-30T01:00:00.000Z",
      sourceScreenshots: [],
    });
    expect(merged.rejectedTechniques).toEqual(["T1105"]);
  });

  it("the state store saves and loads it", async () => {
    const cases = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-rejected-")));
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const store = new StateStore(cases);
    await store.save({ ...caseState(), rejectedTechniques: ["T1105"] });
    expect((await store.load("c1")).rejectedTechniques).toEqual(["T1105"]);
  });
});

describe("every read seam hides a rejected technique (#1742)", () => {
  async function savedCase() {
    const cases = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-rejected-seam-")));
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const stateStore = new StateStore(cases);
    await stateStore.save({ ...caseState(), rejectedTechniques: ["T1105"] });
    return { cases, stateStore };
  }

  it("the report projection (reports, STIX, Navigator, pushes)", async () => {
    const { cases, stateStore } = await savedCase();
    const view = await new ReportWriter(cases, stateStore).filteredState("c1");
    expect(ids(view)).toEqual(["T1059"]); // the event tag no longer re-derives the row
    expect(view.findings[0].mitreTechniques).toEqual(["T1059"]);
    expect(view.forensicTimeline[0].mitreTechniques).toEqual(["T1059"]);
    const layer = JSON.stringify(await new ReportWriter(cases, stateStore).attackLayer("c1"));
    expect(layer).toContain("T1059");
    expect(layer).not.toContain("T1105");
  });

  it("the dashboard state route, for the state and its events", async () => {
    const { cases, stateStore } = await savedCase();
    const res = await request(createApp(cases, { stateStore })).get("/cases/c1/state");
    expect(res.status).toBe(200);
    expect(ids(res.body)).toEqual(["T1059"]);
    expect(res.body.findings[0].mitreTechniques).toEqual(["T1059"]);
    expect(res.body.forensicTimeline[0].mitreTechniques).toEqual(["T1059"]);
    expect(res.body.techniqueNames).not.toHaveProperty("T1105");
  });

  it("the live state push", () => {
    const hub = new LiveHub();
    const sent: string[] = [];
    hub.subscribe("c1", { readyState: 1, OPEN: 1, send: (m: string) => void sent.push(m) });
    const stored = { ...caseState(), rejectedTechniques: ["T1105"] };
    hub.broadcast(stored);
    const pushed = JSON.parse(sent[0]).state as InvestigationState;
    expect(ids(pushed)).toEqual(["T1059"]);
    expect(pushed.forensicTimeline[0].mitreTechniques).toEqual(["T1059"]);
    expect(stored.forensicTimeline[0].mitreTechniques).toEqual(["T1105", "T1059"]);
  });
});
