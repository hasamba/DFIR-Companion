// #1406: GET /cases/:id/handoff — the brief from real stores, the note through the notebook route.
import { describe, it, expect, vi } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { NotebookStore } from "../../src/analysis/notebookStore.js";
import { FindingWorkflowStore } from "../../src/analysis/findingWorkflow.js";
import { createApp } from "../../src/server.js";
import { emptyState, type Finding, type ForensicEvent, type IOC } from "../../src/analysis/stateTypes.js";

describe("GET /cases/:id/handoff", () => {
  it("501 without a state store", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-handoff-"));
    const res = await request(createApp(new CaseStore(root), {})).get("/cases/c1/handoff");
    expect(res.status).toBe(501);
  });

  it("builds the brief from the state, the workflow side file and a handoff note posted through the notebook", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-handoff-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const notebookStore = new NotebookStore(store);
    const findingWorkflowStore = new FindingWorkflowStore(store);
    const app = createApp(store, { stateStore, notebookStore, findingWorkflowStore });
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const finding = {
      id: "f1",
      title: "Beacon on WS-01",
      description: "d",
      severity: "High",
      status: "open",
      confidence: 70,
      relatedIocs: [],
      relatedEventIds: [],
      mitreTechniques: [],
    } as unknown as Finding;
    await stateStore.save({ ...emptyState("c1"), findings: [finding] });
    await findingWorkflowStore.patch("c1", "f1", {
      assignee: "alice",
      status: "in_progress",
      updatedBy: "alice",
    });
    const posted = await request(app)
      .post("/cases/c1/notebook")
      .send({ type: "handoff", text: "Check WS-03 first thing.", author: "alice" });
    expect(posted.status).toBe(201);
    const res = await request(app).get("/cases/c1/handoff");
    expect(res.status).toBe(200);
    expect(res.body.brief.findings.open[0]).toMatchObject({
      id: "f1",
      assignee: "alice",
      workflowStatus: "in_progress",
    });
    expect(res.body.brief.handoffNotes[0]).toMatchObject({
      author: "alice",
      text: "Check WS-03 first thing.",
    });
    expect(res.body.markdown).toContain("### From the outgoing analyst");
    expect(res.body.markdown).toContain("Check WS-03 first thing.");
  });

  it("reads the overview (IOCs kept), never the forensic timeline, and the brief is unchanged (#2127)", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-handoff-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const app = createApp(store, { stateStore });
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const finding = {
      id: "f1",
      title: "Beacon on WS-01",
      description: "d",
      severity: "High",
      status: "open",
      relatedIocs: ["i1"],
      mitreTechniques: [],
    } as unknown as Finding;
    const iocs: IOC[] = [
      { id: "i1", type: "ip", value: "203.0.113.5", firstSeen: "2026-01-01T00:00:00.000Z" },
      {
        id: "i2",
        type: "domain",
        value: "bad.example",
        firstSeen: "2026-01-01T00:00:00.000Z",
        enrichedBy: ["VirusTotal"],
      },
    ];
    const event = {
      id: "e1",
      timestamp: "2026-01-01T00:00:00.000Z",
      description: "beacon",
      severity: "High",
      mitreTechniques: [],
      relatedFindingIds: ["f1"],
      sourceScreenshots: [],
    } as ForensicEvent;
    await stateStore.save({ ...emptyState("c1"), findings: [finding], iocs, forensicTimeline: [event] });
    const full = vi.spyOn(stateStore, "load");
    const overview = vi.spyOn(stateStore, "loadOverview");
    const res = await request(app).get("/cases/c1/handoff");
    expect(full).not.toHaveBeenCalled();
    expect(overview).toHaveBeenCalledTimes(1);
    expect(res.status).toBe(200);
    // Pinned so a later switch to the IOC-less overview fails loudly instead of zeroing the counts.
    expect(res.body.brief.iocs).toMatchObject({ total: 2, unenriched: 1 });
    expect(res.body.brief.findings.open.map((f: { id: string }) => f.id)).toEqual(["f1"]);
    full.mockRestore();
    overview.mockRestore();
  });
});
