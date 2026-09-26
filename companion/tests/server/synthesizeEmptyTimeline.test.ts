// #1676: Re-synthesize on a case with an empty forensic timeline. synthesize() stops before any
// model call and records no run, so the route used to answer "synthesis ran — 0 finding(s)" and the
// #1599 "conclusions out of date" marker survived the press. Now the route says plainly that nothing
// was synthesized. When the case also holds no findings, its (empty) conclusions match the case, so
// the marker is cleared. When findings remain from an earlier run, they are stale and the marker stays.
import { describe, it, expect, beforeEach, vi } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SynthMetaStore } from "../../src/analysis/synthMeta.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { emptyState, type Finding } from "../../src/analysis/stateTypes.js";
import type { AIProvider } from "../../src/providers/provider.js";

const SKIP_MESSAGE = "nothing to synthesize — the forensic timeline is empty";

let cases: CaseStore;
let stateStore: StateStore;
let meta: SynthMetaStore;
let analyze: ReturnType<typeof vi.fn>;
let activity: Array<{ action: string; detail?: string }>;
let app: ReturnType<typeof createApp>;

function finding(id: string): Finding {
  return {
    id,
    severity: "High",
    title: "old finding",
    description: "d",
    relatedIocs: [],
    mitreTechniques: [],
    status: "open",
    relatedEventIds: [],
  } as unknown as Finding;
}

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-synth-empty-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(cases);
  await stateStore.save(emptyState("c1"));
  meta = new SynthMetaStore(cases);
  // An earlier synthesis finished, then a change marked the conclusions out of date.
  await meta.record("c1", null as never, "2026-09-25T09:00:00.000Z");
  await meta.markOutOfDate("c1", "anonymization changed");
  analyze = vi.fn(async () => {
    throw new Error("the model must not be called on an empty timeline");
  });
  const pipeline = buildRuntimePipeline({
    provider: undefined,
    synthesisProvider: { name: "fake", analyze } as unknown as AIProvider,
    stateStore,
    store: cases,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  activity = [];
  app = createApp(cases, {
    pipeline,
    stateStore,
    aiConfigured: false,
    synthMetaStore: meta,
    activityLogStore: {
      add: async (_c: string, e: { action: string; detail?: string }) => {
        activity.push(e);
      },
    } as never,
  });
});

/** logActivity is fire-and-forget in the route; let it land before reading it. */
const settle = () => new Promise((r) => setTimeout(r, 30));

describe("Re-synthesize on an empty forensic timeline (#1676)", () => {
  it("with no findings: says nothing was synthesized and clears the out-of-date marker", async () => {
    const res = await request(app).post("/cases/c1/synthesize").send({});
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ skipped: "empty-timeline", message: SKIP_MESSAGE, findings: 0 });
    expect(analyze).not.toHaveBeenCalled();
    expect((await meta.load("c1")).outOfDate ?? null).toBeNull();
    const aiState = await request(app).get("/cases/c1/ai-state");
    expect(aiState.body.outOfDate).toBe(false);
    await settle();
    const details = activity.map((a) => a.detail ?? "");
    expect(details.some((d) => d.includes("synthesis ran"))).toBe(false);
    expect(details.some((d) => d.includes(SKIP_MESSAGE))).toBe(true);
  });

  it("with findings left from an earlier run: keeps the marker, because they are stale", async () => {
    const s = emptyState("c1");
    s.findings.push(finding("f1"));
    await stateStore.save(s);
    const res = await request(app).post("/cases/c1/synthesize").send({});
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ skipped: "empty-timeline", message: SKIP_MESSAGE, findings: 1 });
    expect((await meta.load("c1")).outOfDate?.reason).toBe("anonymization changed");
    await settle();
    expect(activity.some((a) => (a.detail ?? "").includes("synthesis ran"))).toBe(false);
  });
});
