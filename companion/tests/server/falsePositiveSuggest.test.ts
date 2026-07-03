import { describe, it, expect, beforeEach } from "vitest";
import request from "supertest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createApp } from "../../src/server.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";

function ev(id: string, ts: string, overrides: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id,
    timestamp: ts,
    description: "PsExec run",
    severity: "Medium",
    mitreTechniques: ["T1569.002"],
    relatedFindingIds: [],
    sourceScreenshots: [],
    processName: "PsExec.exe",
    ...overrides,
  };
}

describe("POST /cases/:id/false-positive/suggest", () => {
  let app: ReturnType<typeof createApp>;
  let store: CaseStore;
  let stateStore: StateStore;

  beforeEach(async () => {
    const dir = await mkdtemp(join(tmpdir(), "dfir-fpsuggest-"));
    store = new CaseStore(dir);
    stateStore = new StateStore(store);
    await store.createCase({ caseId: "c1", name: "c1", investigator: "tester", aiProvider: null });
    const state = emptyState("c1");
    state.forensicTimeline.push(
      ev("e1", "2026-01-01T00:00:00Z"),
      ev("e2", "2026-01-01T00:05:00Z", { description: "PsExec run again" }),
      ev("e3", "2026-01-01T00:10:00Z", { description: "unrelated login", severity: "Low", mitreTechniques: [], processName: undefined }),
    );
    await stateStore.save(state);
    app = createApp(store, { stateStore });
  });

  it("returns deterministic candidates for an event anchor, excluding the anchor itself", async () => {
    const res = await request(app).post("/cases/c1/false-positive/suggest").send({ kind: "event", ref: "e1" });
    expect(res.status).toBe(200);
    expect(res.body.candidates.map((c: { id: string }) => c.id)).toEqual(["e2"]);
  });

  it("400s when ref is missing", async () => {
    const res = await request(app).post("/cases/c1/false-positive/suggest").send({ kind: "event" });
    expect(res.status).toBe(400);
  });
});
