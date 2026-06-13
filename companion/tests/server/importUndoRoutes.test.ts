import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ImportUndoStore, pushCheckpoint, emptyUndoStack } from "../../src/analysis/importUndo.js";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
import { emptyState, type ForensicEvent, type IOC, type Finding, type InvestigationState } from "../../src/analysis/stateTypes.js";

const ev = (id: string): ForensicEvent => ({
  id, timestamp: "2026-01-01T00:00:00Z", description: id, severity: "Info",
  mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [],
});
const ioc = (id: string): IOC => ({ id, type: "ip", value: id, firstSeen: "2026-01-01T00:00:00Z" });
const finding = (id: string): Finding => ({
  id, severity: "High", title: id, description: "d", relatedIocs: [], sourceScreenshots: [],
  mitreTechniques: [], firstSeen: "2026-01-01T00:00:00Z", lastUpdated: "2026-01-01T00:00:00Z", status: "open",
});
const mkState = (caseId: string, events: string[], iocs: string[], findings: string[]): InvestigationState => ({
  ...emptyState(caseId), forensicTimeline: events.map(ev), iocs: iocs.map(ioc), findings: findings.map(finding),
});

async function harness(opts: { wireUndo?: boolean } = {}) {
  const root = await mkdtemp(join(tmpdir(), "dfir-undo-route-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const importUndoStore = new ImportUndoStore(store, 5);
  const importMetaStore = new ImportMetaStore(store);
  // No pipeline wired → no AI; the undo route restores state verbatim (no re-synthesis) so the
  // result is fully observable immediately.
  const app = createApp(store, {
    stateStore, importMetaStore,
    ...(opts.wireUndo === false ? {} : { importUndoStore }),
  });
  return { app, store, stateStore, importUndoStore, importMetaStore };
}

const ids = (a: { id: string }[]) => a.map((x) => x.id);

describe("import undo/redo routes (#76)", () => {
  it("undo restores the full pre-import state (findings + IOCs + timeline); redo re-applies it", async () => {
    const { app, stateStore, importUndoStore } = await harness();
    await request(app).post("/cases").send({ caseId: "INC-1", name: "C", investigator: "a", aiProvider: null });

    // Current (post-import) state: 3 events / 2 IOCs / 2 findings.
    await stateStore.save(mkState("INC-1", ["e1", "e2", "e3"], ["i1", "i2"], ["f1", "f2"]));
    // Pre-import checkpoint: 1 event / 1 IOC / 1 finding.
    await importUndoStore.save("INC-1", pushCheckpoint(emptyUndoStack(), {
      label: "thor (0003_thor.json)", at: "2026-06-13T00:00:00Z", state: mkState("INC-1", ["e1"], ["i1"], ["f1"]),
    }));

    const stack0 = await request(app).get("/cases/INC-1/import/undo-stack");
    expect(stack0.status).toBe(200);
    expect(stack0.body.canUndo).toBe(true);
    expect(stack0.body.canRedo).toBe(false);
    expect(stack0.body.nextUndo).toMatchObject({ label: "thor (0003_thor.json)", events: 1, iocs: 1, findings: 1 });

    const undo = await request(app).post("/cases/INC-1/import/undo");
    expect(undo.status).toBe(200);
    expect(undo.body.canUndo).toBe(false);
    expect(undo.body.canRedo).toBe(true);

    let state = (await request(app).get("/cases/INC-1/state")).body;
    expect(ids(state.forensicTimeline)).toEqual(["e1"]);
    expect(ids(state.iocs)).toEqual(["i1"]);
    expect(ids(state.findings)).toEqual(["f1"]); // findings rolled back too

    const redo = await request(app).post("/cases/INC-1/import/redo");
    expect(redo.status).toBe(200);
    expect(redo.body.canUndo).toBe(true);
    expect(redo.body.canRedo).toBe(false);

    state = (await request(app).get("/cases/INC-1/state")).body;
    expect(ids(state.forensicTimeline)).toEqual(["e1", "e2", "e3"]);
    expect(ids(state.iocs)).toEqual(["i1", "i2"]);
    expect(ids(state.findings)).toEqual(["f1", "f2"]);
  });

  it("undo clears the last-import banner", async () => {
    const { app, stateStore, importUndoStore, importMetaStore } = await harness();
    await request(app).post("/cases").send({ caseId: "INC-2", name: "C", investigator: "a", aiProvider: null });
    await stateStore.save(mkState("INC-2", ["e1", "e2"], [], ["f1"]));
    await importMetaStore.record("INC-2", {
      kind: "thor", file: "f", diff: { added: [{ timestamp: "t", description: "e2", severity: "High" }], removed: [] }, iocsDiff: { added: [], removed: [] },
    });
    await importUndoStore.save("INC-2", pushCheckpoint(emptyUndoStack(), {
      label: "thor (f)", at: "2026-06-13T00:00:00Z", state: mkState("INC-2", ["e1"], [], []),
    }));

    await request(app).post("/cases/INC-2/import/undo");
    const meta = (await request(app).get("/cases/INC-2/import-meta")).body;
    expect(meta.lastImportedAt).toBe("");
    expect(meta.addedCount).toBe(0);
  });

  it("400s when there is nothing to undo / redo", async () => {
    const { app } = await harness();
    await request(app).post("/cases").send({ caseId: "INC-3", name: "C", investigator: "a", aiProvider: null });
    expect((await request(app).post("/cases/INC-3/import/undo")).status).toBe(400);
    expect((await request(app).post("/cases/INC-3/import/redo")).status).toBe(400);
  });

  it("501s when the undo store is not wired", async () => {
    const { app } = await harness({ wireUndo: false });
    await request(app).post("/cases").send({ caseId: "INC-4", name: "C", investigator: "a", aiProvider: null });
    expect((await request(app).get("/cases/INC-4/import/undo-stack")).status).toBe(501);
    expect((await request(app).post("/cases/INC-4/import/undo")).status).toBe(501);
  });
});
