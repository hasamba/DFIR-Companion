// #1595: "treat as real intrusion" is one click, stored per case, applied straight to the stored
// findings — and it never starts a synthesis (#1599).
import { describe, it, expect, beforeEach, vi } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { AiControlStore } from "../../src/analysis/aiControl.js";
import { SynthMetaStore } from "../../src/analysis/synthMeta.js";
import { createApp } from "../../src/server.js";
import { applySimulationVerdict } from "../../src/analysis/simulationVerdict.js";
import {
  emptyState,
  type Finding,
  type ForensicEvent,
  type Severity,
} from "../../src/analysis/stateTypes.js";
import type { AnalysisPipeline } from "../../src/analysis/pipeline.js";

const T = "2026-09-24T09:04:00.000Z";

function finding(id: string, severity: Severity, title: string, confidence = 90): Finding {
  return {
    id,
    severity,
    confidence,
    title,
    description: "d",
    relatedIocs: [],
    sourceScreenshots: [],
    mitreTechniques: [],
    relatedEventIds: [`e-${id}`],
    firstSeen: T,
    lastUpdated: T,
    status: "open",
  };
}

const ev = (id: string): ForensicEvent => ({
  id,
  timestamp: T,
  description: "row",
  severity: "High",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
  asset: "ws-01.example.com",
});

let app: ReturnType<typeof createApp>;
let synthesize: ReturnType<typeof vi.fn>;
let stateStore: StateStore;
let meta: SynthMetaStore;
let broadcasts: number;

beforeEach(async () => {
  const cases = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-sim-override-")));
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(cases);
  const s = emptyState("c1");
  const raw = [
    finding("f1", "Critical", "Mimikatz executed against LSASS"),
    finding("f14", "Info", "Activity is likely an authorized attack-simulation exercise", 85),
  ];
  s.forensicTimeline.push(ev("e-f1"), ev("e-f14"));
  s.findings = applySimulationVerdict(raw, s.forensicTimeline);
  await stateStore.save(s);
  await new AiControlStore(cases).save("c1", { enabled: true, lastAnalyzedSeq: 0 });
  synthesize = vi.fn(async () => stateStore.load("c1"));
  const pipeline = {
    hasAiProvider: () => true,
    hasSynthesisProvider: () => true,
    synthesize,
  } as unknown as AnalysisPipeline;
  meta = new SynthMetaStore(cases);
  broadcasts = 0;
  app = createApp(cases, {
    stateStore,
    pipeline,
    synthMetaStore: meta,
    onState: () => {
      broadcasts++;
    },
  });
});

const sev = async (id: string): Promise<Severity | undefined> =>
  (await stateStore.load("c1")).findings.find((f) => f.id === id)?.severity;

describe("POST /cases/:id/simulation-override (#1595)", () => {
  it("treats the case as a real intrusion at once, stores it, and starts no synthesis", async () => {
    expect(await sev("f1")).toBe("Medium");
    const res = await request(app).post("/cases/c1/simulation-override").send({ treatAsReal: true });
    expect(res.status).toBe(200);
    expect(await sev("f1")).toBe("Critical");
    expect(await sev("f14")).toBe("Info");
    expect(await meta.treatAsReal("c1")).toBe(true);
    expect((await meta.load("c1")).outOfDate ?? null).toBeNull();
    expect(broadcasts).toBe(1);
    await new Promise((r) => setTimeout(r, 20));
    expect(synthesize).not.toHaveBeenCalled();
  });

  it("undoes the override", async () => {
    await request(app).post("/cases/c1/simulation-override").send({ treatAsReal: true });
    const res = await request(app).post("/cases/c1/simulation-override").send({ treatAsReal: false });
    expect(res.status).toBe(200);
    expect(await sev("f1")).toBe("Medium");
    expect(await sev("f14")).toBe("Critical");
    expect(await meta.treatAsReal("c1")).toBe(false);
  });

  it("rejects a body without a boolean", async () => {
    const res = await request(app).post("/cases/c1/simulation-override").send({ treatAsReal: "yes" });
    expect(res.status).toBe(400);
    expect(await sev("f1")).toBe("Medium");
  });
});
