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
import { emptyState, type ForensicEvent, type IOC } from "../../src/analysis/stateTypes.js";

const ev = (id: string): ForensicEvent => ({
  id, timestamp: "2026-01-01T00:00:00Z", description: id, severity: "Info",
  mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [],
});
const ioc = (id: string): IOC => ({ id, type: "ip", value: id, firstSeen: "2026-01-01T00:00:00Z" });

async function harness(opts: { wireUndo?: boolean } = {}) {
  const root = await mkdtemp(join(tmpdir(), "dfir-undo-route-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const importUndoStore = new ImportUndoStore(store, 5);
  const importMetaStore = new ImportMetaStore(store);
  // No pipeline wired → resynthesizeInBackground is a no-op, so the route's state restore is the
  // only mutation and is observable immediately.
  const app = createApp(store, {
    stateStore, importMetaStore,
    ...(opts.wireUndo === false ? {} : { importUndoStore }),
  });
  return { app, store, stateStore, importUndoStore, importMetaStore };
}

describe("import undo/redo routes (#76)", () => {
  it("undo restores the pre-import snapshot; redo re-applies it", async () => {
    const { app, store, stateStore, importUndoStore } = await harness();
    await request(app).post("/cases").send({ caseId: "INC-1", name: "C", investigator: "a", aiProvider: null });

    // Current (post-import) state: 3 events / 2 IOCs. Pre-import checkpoint: 1 event / 1 IOC.
    await stateStore.save({ ...emptyState("INC-1"), forensicTimeline: [ev("e1"), ev("e2"), ev("e3")], iocs: [ioc("i1"), ioc("i2")] });
    await importUndoStore.save("INC-1", pushCheckpoint(emptyUndoStack(), {
      forensicTimeline: [ev("e1")], iocs: [ioc("i1")], label: "thor (0003_thor.json)", at: "2026-06-13T00:00:00Z",
    }));

    const stack0 = await request(app).get("/cases/INC-1/import/undo-stack");
    expect(stack0.status).toBe(200);
    expect(stack0.body.canUndo).toBe(true);
    expect(stack0.body.canRedo).toBe(false);
    expect(stack0.body.nextUndo).toMatchObject({ label: "thor (0003_thor.json)", events: 1, iocs: 1 });

    const undo = await request(app).post("/cases/INC-1/import/undo");
    expect(undo.status).toBe(200);
    expect(undo.body.canUndo).toBe(false);
    expect(undo.body.canRedo).toBe(true);

    let state = await request(app).get("/cases/INC-1/state");
    expect(state.body.forensicTimeline.map((e: ForensicEvent) => e.id)).toEqual(["e1"]);
    expect(state.body.iocs.map((i: IOC) => i.id)).toEqual(["i1"]);

    const redo = await request(app).post("/cases/INC-1/import/redo");
    expect(redo.status).toBe(200);
    expect(redo.body.canUndo).toBe(true);
    expect(redo.body.canRedo).toBe(false);

    state = await request(app).get("/cases/INC-1/state");
    expect(state.body.forensicTimeline.map((e: ForensicEvent) => e.id)).toEqual(["e1", "e2", "e3"]);
    expect(state.body.iocs.map((i: IOC) => i.id)).toEqual(["i1", "i2"]);
  });

  it("undo clears the last-import banner", async () => {
    const { app, stateStore, importUndoStore, importMetaStore } = await harness();
    await request(app).post("/cases").send({ caseId: "INC-2", name: "C", investigator: "a", aiProvider: null });
    await stateStore.save({ ...emptyState("INC-2"), forensicTimeline: [ev("e1"), ev("e2")], iocs: [] });
    await importMetaStore.record("INC-2", {
      kind: "thor", file: "f", diff: { added: [{ timestamp: "t", description: "e2", severity: "High" }], removed: [] }, iocsDiff: { added: [], removed: [] },
    });
    await importUndoStore.save("INC-2", pushCheckpoint(emptyUndoStack(), {
      forensicTimeline: [ev("e1")], iocs: [], label: "thor (f)", at: "2026-06-13T00:00:00Z",
    }));

    await request(app).post("/cases/INC-2/import/undo");
    const meta = await request(app).get("/cases/INC-2/import-meta");
    expect(meta.body.lastImportedAt).toBe("");
    expect(meta.body.addedCount).toBe(0);
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
