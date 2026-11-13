import { describe, it, expect, vi, afterEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { HypothesisStore } from "../../src/analysis/hypothesisStore.js";
import { patternKey } from "../../src/analysis/prevalence.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";

// #2616: marking a false positive must not read or rewrite the whole case. The route used two or three
// whole-case loads plus a whole-case save; on a 70k-event case that was ~15 s for a one-row mark.
const EVENT_COUNT = 40;

const event = (i: number): ForensicEvent => ({
  id: `e${i}`,
  timestamp: `2026-05-28T09:00:${String(i % 60).padStart(2, "0")}Z`,
  description: `client admin task ${i}`,
  severity: "Medium",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
  processName: "tool.exe",
});

async function harness() {
  const store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-fp-loads-")));
  const stateStore = new StateStore(store);
  const hypothesisStore = new HypothesisStore(store);
  const app = createApp(store, { stateStore, hypothesisStore });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const seeded = emptyState("c1");
  seeded.forensicTimeline = Array.from({ length: EVENT_COUNT }, (_, i) => event(i));
  seeded.iocs.push({ id: "i1", type: "ip", value: "10.9.9.9", firstSeen: "" });
  seeded.findings.push({
    id: "f1",
    severity: "High",
    title: "Suspicious admin tool",
    description: "",
    relatedIocs: [],
    mitreTechniques: [],
    sourceScreenshots: [],
    firstSeen: "",
    lastUpdated: "",
    status: "open",
  });
  seeded.keyQuestions.push({
    id: "q1",
    question: "How did they get in?",
    status: "answered",
    answer: "via the admin tool",
    pointer: "f1",
    relatedFindingIds: ["f1"],
  });
  seeded.nextSteps.push({
    id: "n1",
    priority: "high",
    action: "Pull logs",
    rationale: "confirms f1",
    pointer: "host",
    relatedFindingIds: ["f1"],
  });
  await stateStore.save(seeded);
  await hypothesisStore.add("c1", {
    title: "Admin tool abuse",
    relatedEventIds: ["e3"],
    relatedIocIds: ["i1"],
  });
  return { app, stateStore, hypothesisStore };
}

afterEach(() => vi.restoreAllMocks());

describe("false-positive route avoids whole-case load/save (#2616)", () => {
  it("event marker: no whole-case load/save, fingerprint stamped, hypothesis reconsidered, timeline intact", async () => {
    const { app, stateStore, hypothesisStore } = await harness();
    const load = vi.spyOn(StateStore.prototype, "load");
    const save = vi.spyOn(StateStore.prototype, "save");
    const res = await request(app)
      .post("/cases/c1/false-positive")
      .send({ kind: "event", ref: "e3", reason: "known-good-tool", label: "client admin task 3" });
    expect(res.status).toBe(200);
    expect(load).not.toHaveBeenCalled();
    expect(save).not.toHaveBeenCalled();
    load.mockRestore();
    save.mockRestore();
    const marker = res.body.find((m: { ref: string }) => m.ref === "e3");
    expect(marker.patternFingerprint).toBe(patternKey(event(3)));
    expect((await hypothesisStore.load("c1"))[0].needsReview).toBe(true);
    expect((await stateStore.load("c1")).forensicTimeline).toHaveLength(EVENT_COUNT);
  });

  it("finding marker: no whole-case load/save, stale flags still set, timeline row count unchanged", async () => {
    const { app, stateStore } = await harness();
    const before = await stateStore.load("c1");
    const load = vi.spyOn(StateStore.prototype, "load");
    const save = vi.spyOn(StateStore.prototype, "save");
    const res = await request(app)
      .post("/cases/c1/false-positive")
      .send({ kind: "finding", ref: "Suspicious admin tool", reason: "known-good-tool" });
    expect(res.status).toBe(200);
    expect(load).not.toHaveBeenCalled();
    expect(save).not.toHaveBeenCalled();
    load.mockRestore();
    save.mockRestore();
    const after = await stateStore.load("c1");
    expect(after.keyQuestions[0].staleReSynth).toBe(true);
    expect(after.keyQuestions[0].status).toBe("unknown");
    expect(after.nextSteps[0].staleReSynth).toBe(true);
    expect(after.forensicTimeline).toHaveLength(EVENT_COUNT);
    expect(after.forensicTimeline.map((e) => e.id)).toEqual(before.forensicTimeline.map((e) => e.id));
    expect(after.iocs).toEqual(before.iocs);
  });

  it("ioc marker reconsiders a hypothesis through the overview IOC map", async () => {
    const { app, hypothesisStore } = await harness();
    const res = await request(app)
      .post("/cases/c1/false-positive")
      .send({ kind: "ioc", ref: "10.9.9.9", reason: "known-good-tool" });
    expect(res.status).toBe(200);
    expect((await hypothesisStore.load("c1"))[0].needsReview).toBe(true);
  });
});
