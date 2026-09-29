import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { emptyState, type Finding, type InvestigationState } from "../../src/analysis/stateTypes.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ReportWriter } from "../../src/reports/reportWriter.js";
import { LiveHub } from "../../src/live/hub.js";
import { createApp } from "../../src/server.js";

// #1873: the techniques a finding's own text names reach every read seam — the report projection,
// the dashboard state route and the live push — and are never written to the stored case. An
// accepted referee removal (#1742) still hides them, because every seam applies it afterwards.

const staged = (over: Partial<Finding> = {}): Finding => ({
  id: "f1",
  severity: "High",
  title: "Staged batch scripts",
  description: "The scripts cover shadow-copy deletion and log clearing.",
  relatedIocs: [],
  sourceScreenshots: [],
  firstSeen: "2026-09-28T11:39:54Z",
  lastUpdated: "2026-09-28T11:39:58Z",
  mitreTechniques: ["T1074.001"],
  status: "open",
  ...over,
});

function caseState(over: Partial<InvestigationState> = {}): InvestigationState {
  return {
    ...emptyState("c1"),
    findings: [staged()],
    mitreTechniques: [{ id: "T1074.001", name: "Data Staged: Local Data Staging", findingIds: ["f1"] }],
    ...over,
  };
}

const ids = (s: Partial<InvestigationState>) => (s.mitreTechniques ?? []).map((t) => t.id).sort();

async function savedCase(over: Partial<InvestigationState> = {}) {
  const cases = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-text-techniques-")));
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(cases);
  await stateStore.save(caseState(over));
  return { cases, stateStore };
}

describe("every read seam shows the finding-text techniques (#1873)", () => {
  it("the report projection, and the stored case is untouched", async () => {
    const { cases, stateStore } = await savedCase();
    const view = await new ReportWriter(cases, stateStore).filteredState("c1");
    expect(ids(view)).toEqual(["T1070.001", "T1074.001", "T1490"]);
    expect(view.findings[0].mitreTechniques).toEqual(["T1074.001", "T1490", "T1070.001"]);
    const layer = JSON.stringify(await new ReportWriter(cases, stateStore).attackLayer("c1"));
    expect(layer).toContain("T1490");
    const stored = await stateStore.load("c1");
    expect(ids(stored)).toEqual(["T1074.001"]);
    expect(stored.findings[0].mitreTechniques).toEqual(["T1074.001"]);
  });

  it("the dashboard state route", async () => {
    const { cases, stateStore } = await savedCase();
    const res = await request(createApp(cases, { stateStore })).get("/cases/c1/state");
    expect(res.status).toBe(200);
    expect(ids(res.body)).toEqual(["T1070.001", "T1074.001", "T1490"]);
    expect(res.body.techniqueNames).toHaveProperty("T1490", "Inhibit System Recovery");
  });

  it("the live state push", () => {
    const hub = new LiveHub();
    const sent: string[] = [];
    hub.subscribe("c1", { readyState: 1, OPEN: 1, send: (m: string) => void sent.push(m) });
    hub.broadcast(caseState());
    expect(ids(JSON.parse(sent[0]).state)).toEqual(["T1070.001", "T1074.001", "T1490"]);
  });

  it("an accepted referee removal still hides the technique", async () => {
    const { cases, stateStore } = await savedCase({ rejectedTechniques: ["T1490"] });
    const view = await new ReportWriter(cases, stateStore).filteredState("c1");
    expect(ids(view)).toEqual(["T1070.001", "T1074.001"]);
    expect(view.findings[0].mitreTechniques).not.toContain("T1490");
  });

  it("a dismissed finding adds nothing", async () => {
    const { cases, stateStore } = await savedCase({ findings: [staged({ status: "dismissed" })] });
    const res = await request(createApp(cases, { stateStore })).get("/cases/c1/state");
    expect(ids(res.body)).toEqual(["T1074.001"]);
  });
});
