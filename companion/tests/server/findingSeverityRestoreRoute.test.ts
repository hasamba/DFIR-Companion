// #1973: "Restore High" on a capped finding is one click, stored per finding, applied straight to the
// stored findings, broadcast, and written to the activity log. It starts no synthesis.
import { describe, it, expect, beforeEach, vi } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SynthMetaStore } from "../../src/analysis/synthMeta.js";
import { ActivityLogStore } from "../../src/analysis/activityLog.js";
import { createApp } from "../../src/server.js";
import { applySimulationVerdict } from "../../src/analysis/simulationVerdict.js";
import {
  FindingSeverityRestoreStore,
  severityRestoredOf,
} from "../../src/analysis/findingSeverityRestore.js";
import {
  emptyState,
  type Finding,
  type ForensicEvent,
  type Severity,
} from "../../src/analysis/stateTypes.js";
import type { AnalysisPipeline } from "../../src/analysis/pipeline.js";

const T = "2026-10-06T09:00:00.000Z";

function finding(
  id: string,
  severity: Severity,
  title: string,
  extra: Record<string, unknown> = {},
): Finding {
  return {
    id,
    severity,
    confidence: 90,
    title,
    description: "d",
    relatedIocs: [],
    sourceScreenshots: [],
    mitreTechniques: [],
    relatedEventIds: [`e-${id}`],
    firstSeen: T,
    lastUpdated: T,
    status: "open",
    ...extra,
  };
}

const capped = (id: string) =>
  finding(id, "Medium", "Microsoft Defender real-time protection disabled", {
    severityCap: { from: "High", to: "Medium", gates: ["tamper-timing"] },
    tamperTiming: "date-unknown",
  });

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
let cases: CaseStore;
let stateStore: StateStore;
let restoreStore: FindingSeverityRestoreStore;
let activity: ActivityLogStore;
let synthesize: ReturnType<typeof vi.fn>;
let broadcasts: number;

async function build(findings: Finding[]) {
  cases = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-sev-restore-route-")));
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(cases);
  const s = emptyState("c1");
  s.forensicTimeline.push(...findings.map((f) => ev(`e-${f.id}`)));
  s.findings = applySimulationVerdict(findings, s.forensicTimeline);
  await stateStore.save(s);
  restoreStore = new FindingSeverityRestoreStore(cases);
  activity = new ActivityLogStore(cases);
  synthesize = vi.fn(async () => stateStore.load("c1"));
  broadcasts = 0;
  app = createApp(cases, {
    stateStore,
    pipeline: { hasAiProvider: () => true, synthesize } as unknown as AnalysisPipeline,
    synthMetaStore: new SynthMetaStore(cases),
    findingSeverityRestoreStore: restoreStore,
    activityLogStore: activity,
    onState: () => {
      broadcasts++;
    },
  });
}

const get = async (id: string): Promise<Finding | undefined> =>
  (await stateStore.load("c1")).findings.find((f) => f.id === id);
const settle = () => new Promise((r) => setTimeout(r, 20));
const URL = "/cases/c1/findings/f1/severity-restore";

describe("POST/DELETE /cases/:id/findings/:findingId/severity-restore (#1973)", () => {
  beforeEach(async () => {
    await build([capped("f1"), finding("f2", "High", "Cobalt Strike beacon")]);
  });

  it("lifts the cap at once, stores the record, broadcasts, logs, and starts no synthesis", async () => {
    const res = await request(app).post(URL).send({ updatedBy: "Alice" });
    expect(res.status).toBe(200);
    const f1 = await get("f1");
    expect(f1?.severity).toBe("High");
    expect(severityRestoredOf(f1!)?.by).toBe("Alice");
    expect((await restoreStore.load("c1")).map((r) => r.findingId)).toEqual(["f1"]);
    expect(broadcasts).toBe(1);
    await settle();
    const log = await activity.load("c1");
    expect(log).toHaveLength(1);
    expect(log[0]).toMatchObject({
      category: "triage",
      action: "finding-severity-restore",
      actor: "Alice",
      targetType: "finding",
      targetId: "f1",
    });
    expect(log[0].detail).toMatch(/High/);
    expect(synthesize).not.toHaveBeenCalled();
  });

  it("undoes the restore", async () => {
    await request(app).post(URL).send({ updatedBy: "Alice" });
    const res = await request(app).delete(URL).send({ updatedBy: "Alice" });
    expect(res.status).toBe(200);
    const f1 = await get("f1");
    expect(f1?.severity).toBe("Medium");
    expect(severityRestoredOf(f1!)).toBeUndefined();
    expect(await restoreStore.load("c1")).toEqual([]);
    expect(broadcasts).toBe(2);
    await settle();
    expect((await activity.load("c1")).map((e) => e.action)).toEqual([
      "finding-severity-restore",
      "finding-severity-restore",
    ]);
  });

  it("refuses a finding no gate capped (409) and an unknown finding (404)", async () => {
    expect((await request(app).post("/cases/c1/findings/f2/severity-restore").send({})).status).toBe(409);
    expect((await request(app).post("/cases/c1/findings/nope/severity-restore").send({})).status).toBe(404);
    expect(await restoreStore.load("c1")).toEqual([]);
    expect(broadcasts).toBe(0);
  });
});

describe("severity restore under a simulation verdict (#1973 D3)", () => {
  it("keeps the case-wide simulation cap after the restore", async () => {
    await build([
      capped("f1"),
      finding("f14", "Info", "Activity is likely an authorized attack-simulation exercise", {
        confidence: 85,
      }),
    ]);
    const res = await request(app).post(URL).send({ updatedBy: "Alice" });
    expect(res.status).toBe(200);
    const f1 = await get("f1");
    expect(f1?.severity).toBe("Medium");
    expect(f1?.simulation).toMatchObject({ role: "simulated", originalSeverity: "High" });
    expect(severityRestoredOf(f1!)?.by).toBe("Alice");
  });
});
