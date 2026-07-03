import { describe, it, expect, beforeEach } from "vitest";
import request from "supertest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createApp } from "../../src/server.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { emptyState, type ForensicEvent, type Finding } from "../../src/analysis/stateTypes.js";

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

function finding(id: string, overrides: Partial<Finding> = {}): Finding {
  return {
    id,
    severity: "Medium",
    title: "Lateral movement via PsExec",
    description: "PsExec used to move laterally between hosts",
    relatedIocs: ["ioc-1"],
    sourceScreenshots: [],
    mitreTechniques: ["T1569.002"],
    firstSeen: "2026-01-01T00:00:00Z",
    lastUpdated: "2026-01-01T00:00:00Z",
    status: "open",
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
    state.findings.push(
      finding("f1"),
      finding("f2", { title: "Lateral movement via PsExec (second host)", relatedIocs: ["ioc-1", "ioc-2"] }),
      finding("f3", { title: "Unrelated phishing email opened", description: "User opened a phishing attachment", relatedIocs: ["ioc-9"], mitreTechniques: ["T1566.001"] }),
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

  it("returns deterministic candidates for a finding anchor, excluding the anchor itself", async () => {
    const res = await request(app).post("/cases/c1/false-positive/suggest").send({ kind: "finding", ref: "f1" });
    expect(res.status).toBe(200);
    expect(res.body.candidates.map((c: { id: string }) => c.id)).toEqual(["f2"]);
  });

  it("returns aiUnavailable:true alongside deterministic candidates when no AI provider is configured", async () => {
    const res = await request(app).post("/cases/c1/false-positive/suggest").send({ kind: "event", ref: "e1", ai: true });
    expect(res.status).toBe(200);
    expect(res.body.aiUnavailable).toBe(true);
    expect(res.body.candidates.map((c: { id: string }) => c.id)).toEqual(["e2"]);
  });
});
