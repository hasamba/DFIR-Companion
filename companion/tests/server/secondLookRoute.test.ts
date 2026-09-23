import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { SynthMetaStore } from "../../src/analysis/synthMeta.js";
import { MockProvider } from "../../src/providers/provider.js";
import { ActivityLogStore } from "../../src/analysis/activityLog.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";

// The second look at the route (#1554). It stopped being the tail of every synthesis and became a
// button, so the properties worth pinning here are the ones only the route can show: the preview
// changes nothing, the default run re-synthesizes, the opt-out promotes without re-synthesizing,
// and an install with no raw record says so instead of reporting an empty sweep as a success.

const ev = (id: string, timestamp: string, description: string): ForensicEvent => ({
  id,
  timestamp,
  description,
  severity: "High",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
});

// A schema-valid synthesis delta whose evidenceRequest names the keyword only the raw row carries.
const DELTA = JSON.stringify({
  findings: [],
  iocs: [],
  mitreTechniques: [],
  forensicEvents: [],
  threadsOpened: [],
  threadsClosed: [],
  timelineNote: "",
  summary: "s",
  evidenceRequests: [{ keywords: ["rsync"], reason: "rows the prompt did not show" }],
});

async function harness(opts: { withSuperTimeline?: boolean } = {}) {
  const withSuper = opts.withSuperTimeline !== false;
  const store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-secondlook-route-")));
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
  const stateStore = new StateStore(store);
  const seeded = emptyState("c1");
  seeded.forensicTimeline.push(
    ev("e1", "2026-05-20T09:00:00.000Z", "powershell -enc"),
    ev("e2", "2026-05-20T11:00:00.000Z", "net use"),
  );
  await stateStore.save(seeded);

  const superTimelineStore = new SuperTimelineStore(store);
  await superTimelineStore.append("c1", [
    ev("rawhit", "2026-05-20T10:00:00.000Z", "rsync -a /data nfs-01:/backup archive.zip"),
    ev("rawmiss", "2026-05-20T10:05:00.000Z", "unrelated noise"),
  ]);

  const provider = new MockProvider("mock", DELTA);
  const pipeline = buildRuntimePipeline({
    provider,
    synthesisProvider: provider,
    stateStore,
    store,
    imageLoader: async () => ({ base64: "A", mimeType: "image/webp" }),
  });
  // The route gates on the APP's super-timeline option, the way the Jev review does — omitting it
  // is how an install without a raw record is modelled here.
  const app = createApp(store, {
    pipeline,
    stateStore,
    aiConfigured: true,
    activityLogStore: new ActivityLogStore(store),
    ...(withSuper ? { superTimelineStore } : {}),
  });
  return { app, stateStore, synthMetaStore: new SynthMetaStore(store), superTimelineStore };
}

/** One synthesis, so the model's own evidence request is on the synth-meta for the button to read. */
async function seedSynthesis(app: Awaited<ReturnType<typeof harness>>["app"]): Promise<void> {
  const res = await request(app).post("/cases/c1/synthesize").send({});
  expect(res.status).toBe(200);
}

describe("GET /cases/:id/second-look/preview", () => {
  it("counts the sweep without promoting anything", async () => {
    const { app, stateStore } = await harness();
    await seedSynthesis(app);

    const res = await request(app).get("/cases/c1/second-look/preview");
    expect(res.status).toBe(200);
    expect(res.body.configured).toBe(true);
    expect(res.body.modelRequests).toBe(1);
    expect(res.body.requests).toBe(1);
    expect(res.body.wouldPromote).toBe(1);
    expect(res.body.leads).toEqual([]);
    expect(res.body.truncated).toBe(false);
    expect(res.body.shapeHeld).toBe(0);

    // A preview that writes is not a preview.
    const after = await stateStore.load("c1");
    expect(after.forensicTimeline.map((e) => e.id).sort()).toEqual(["e1", "e2"]);
  });

  it("answers 404 for a case that does not exist", async () => {
    const { app } = await harness();
    const res = await request(app).get("/cases/nope/second-look/preview");
    expect(res.status).toBe(404);
  });

  it("answers 501 with a reason when the super-timeline is not configured", async () => {
    const { app } = await harness({ withSuperTimeline: false });
    const res = await request(app).get("/cases/c1/second-look/preview");
    expect(res.status).toBe(501);
    expect(res.body.error).toMatch(/super-timeline/i);
  });
});

describe("POST /cases/:id/second-look", () => {
  it("promotes and re-synthesizes by default", async () => {
    const { app, stateStore, synthMetaStore } = await harness();
    await seedSynthesis(app);

    const res = await request(app).post("/cases/c1/second-look").send({});
    expect(res.status).toBe(200);
    expect(res.body.promoted).toBe(1);
    expect(res.body.resynthesized).toBe(true);
    expect(res.body.summary).toContain("promoted");
    expect(res.body.truncated).toBe(false);
    expect(res.body.shapeCapped).toBe(0);

    const after = await stateStore.load("c1");
    const promoted = after.forensicTimeline.find((e) => e.id === "rawhit");
    expect(promoted).toBeDefined();
    expect(promoted!.provenance?.some((p) => p.startsWith("[second-look:"))).toBe(true);
    expect(after.forensicTimeline.some((e) => e.id === "rawmiss")).toBe(false);

    // Recorded AFTER the re-synthesis, which rewrites this document wholesale.
    expect((await synthMetaStore.load("c1")).secondLook?.promoted).toBe(1);
  });

  it("promotes without re-synthesizing when the analyst sends resynthesize: false", async () => {
    const { app, stateStore, synthMetaStore } = await harness();
    await seedSynthesis(app);
    // The stamp of the last real model call. A re-synthesis would move it; nothing else does.
    const before = (await synthMetaStore.load("c1")).lastSynthesizedAt;

    const res = await request(app).post("/cases/c1/second-look").send({ resynthesize: false });
    expect(res.status).toBe(200);
    expect(res.body.promoted).toBe(1);
    expect(res.body.resynthesized).toBe(false);

    const after = await stateStore.load("c1");
    expect(after.forensicTimeline.some((e) => e.id === "rawhit")).toBe(true);
    const meta = await synthMetaStore.load("c1");
    expect(meta.lastSynthesizedAt).toBe(before); // the conclusions were deliberately left alone
    expect(meta.secondLook?.promoted).toBe(1); // but the sweep itself is still on the record
  });

  it("treats a missing or non-boolean flag as the default, never as the opt-out", async () => {
    // The opt-out leaves the record changed and the conclusions stale. A typo must not produce it.
    const { app } = await harness();
    await seedSynthesis(app);
    const res = await request(app).post("/cases/c1/second-look").send({ resynthesize: "no" });
    expect(res.status).toBe(200);
    expect(res.body.resynthesized).toBe(true);
  });

  it("answers 501 with a reason when the super-timeline is not configured", async () => {
    const { app } = await harness({ withSuperTimeline: false });
    const res = await request(app).post("/cases/c1/second-look").send({});
    expect(res.status).toBe(501);
    expect(res.body.error).toMatch(/super-timeline/i);
  });
});
