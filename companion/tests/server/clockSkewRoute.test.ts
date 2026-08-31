import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ClockSkewStore } from "../../src/analysis/clockSkewStore.js";
import { ActivityLogStore } from "../../src/analysis/activityLog.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

function ev(id: string, timestamp: string, extra: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id,
    timestamp,
    description: "",
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...extra,
  };
}

// Three anchors: one artifact each, recorded by the endpoint (30s fast) and by the DC.
function anchoredTimeline(hostSkewSec: number): ForensicEvent[] {
  return [0, 1, 2].flatMap((i) => {
    const at = Date.parse("2026-05-20T14:00:00Z") + i * 600_000;
    return [
      ev(`h-${i}`, new Date(at + hostSkewSec * 1000).toISOString(), {
        asset: "WS-01",
        sha256: `hash${i}`,
        sources: ["Velociraptor"],
      }),
      ev(`dc-${i}`, new Date(at).toISOString(), {
        asset: "DC01",
        sha256: `hash${i}`,
        sources: ["Windows Security"],
      }),
    ];
  });
}

async function makeApp(opts: { withStore?: boolean; timeline?: ForensicEvent[] } = {}) {
  const withStore = opts.withStore !== false;
  const root = await mkdtemp(join(tmpdir(), "dfir-skew-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const clockSkewStore = new ClockSkewStore(store);
  const pipeline = buildRuntimePipeline({
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AA", mimeType: "image/webp" }),
  });
  const app = createApp(store, {
    pipeline,
    stateStore,
    aiConfigured: false,
    activityLogStore: new ActivityLogStore(store),
    ...(withStore ? { clockSkewStore } : {}),
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  if (opts.timeline) {
    const state = await stateStore.load("c1");
    await stateStore.save({ ...state, forensicTimeline: opts.timeline });
  }
  return { app, store, stateStore, clockSkewStore };
}

describe("clock-skew routes (#228)", () => {
  it("GET returns empty state and the thresholds it measures against", async () => {
    const { app } = await makeApp();
    const res = await request(app).get("/cases/c1/clock-skew");
    expect(res.status).toBe(200);
    expect(res.body.results).toEqual([]);
    expect(res.body.overrides).toEqual({});
    expect(res.body.alignEnabled).toBe(false);
    // minTimeGapMs is the standalone gap warning's floor (#740) — advisory, not an alignment
    // threshold, but it travels with the others so the panel can say what it measures against.
    expect(res.body.thresholds).toEqual({
      alertThresholdMs: 60_000,
      minAnchors: 3,
      minTimeGapMs: 30 * 24 * 3_600_000,
    });
  });

  it("GET does not write to disk", async () => {
    const { app, store } = await makeApp({ timeline: anchoredTimeline(120) });
    await request(app).get("/cases/c1/clock-skew");
    const { readdir } = await import("node:fs/promises");
    const files = await readdir(store.stateDir("c1")).catch(() => [] as string[]);
    expect(files).not.toContain("clock-skew.json");
  });

  it("recompute measures per-host offsets from the timeline", async () => {
    const { app } = await makeApp({ timeline: anchoredTimeline(120) });
    const res = await request(app).post("/cases/c1/clock-skew/recompute").send({});
    expect(res.status).toBe(200);
    const byHost = Object.fromEntries(res.body.results.map((r: { hostKey: string }) => [r.hostKey, r]));
    expect(byHost["ws-01"].offsetMs).toBe(120_000); // relative to the reference clock, DC01
    expect(byHost["dc01"].offsetMs).toBe(0);
    expect(res.body.referenceHost).toBe("DC01");
    expect(byHost["ws-01"].skewed).toBe(true);
    expect(byHost["ws-01"].qualified).toBe(true);
    expect(res.body.anchorGroups).toBe(3);
    // ...and it persists, so a later GET sees it.
    expect((await request(app).get("/cases/c1/clock-skew")).body.results).toHaveLength(2);
  });

  it("align toggles, logs to the case activity log, and survives a re-read", async () => {
    const { app } = await makeApp({ timeline: anchoredTimeline(120) });
    await request(app).post("/cases/c1/clock-skew/recompute").send({});
    const on = await request(app).post("/cases/c1/clock-skew/align").send({ enable: true });
    expect(on.status).toBe(200);
    expect(on.body.alignEnabled).toBe(true);
    expect((await request(app).get("/cases/c1/clock-skew")).body.alignEnabled).toBe(true);

    const log = await request(app).get("/cases/c1/activity-log");
    const entries = Array.isArray(log.body) ? log.body : log.body.entries;
    expect(
      entries.some(
        (e: { action: string; detail: string }) =>
          e.action === "clock-skew-align" && e.detail.includes("enabled"),
      ),
    ).toBe(true);

    const off = await request(app).post("/cases/c1/clock-skew/align").send({ enable: false });
    expect(off.body.alignEnabled).toBe(false);
  });

  it("no route returns the timeline — alignment is applied on the read paths", async () => {
    const { app } = await makeApp({ timeline: anchoredTimeline(120) });
    const res = await request(app).post("/cases/c1/clock-skew/align").send({ enable: true });
    expect(res.body.events).toBeUndefined();
  });

  it("stores, then clears, a manual per-host override", async () => {
    const { app } = await makeApp({ timeline: anchoredTimeline(120) });
    const set = await request(app)
      .put("/cases/c1/clock-skew/override")
      .send({ host: "WS-01.corp.local", offsetMs: 45_000 });
    expect(set.status).toBe(200);
    expect(set.body.overrides).toEqual({ "ws-01": 45_000 });

    const cleared = await request(app)
      .put("/cases/c1/clock-skew/override")
      .send({ host: "ws-01", offsetMs: null });
    expect(cleared.body.overrides).toEqual({});
  });

  it("rejects a malformed override", async () => {
    const { app } = await makeApp();
    expect((await request(app).put("/cases/c1/clock-skew/override").send({ offsetMs: 1000 })).status).toBe(
      400,
    );
    expect(
      (await request(app).put("/cases/c1/clock-skew/override").send({ host: "ws-01", offsetMs: "soon" }))
        .status,
    ).toBe(400);
    expect(
      (await request(app).put("/cases/c1/clock-skew/override").send({ host: "  ", offsetMs: 1 })).status,
    ).toBe(400);
  });

  it("501s cleanly when the store is not configured", async () => {
    const { app } = await makeApp({ withStore: false });
    expect((await request(app).get("/cases/c1/clock-skew")).status).toBe(501);
    expect((await request(app).post("/cases/c1/clock-skew/align").send({})).status).toBe(501);
    expect(
      (await request(app).put("/cases/c1/clock-skew/override").send({ host: "a", offsetMs: 1 })).status,
    ).toBe(501);
  });
});

describe("clock-skew alignment as a read-path projection (#228)", () => {
  it("GET /state shifts a skewed host and keeps the recorded time", async () => {
    const { app } = await makeApp({ timeline: anchoredTimeline(120) });
    await request(app).post("/cases/c1/clock-skew/recompute").send({});

    const before = await request(app).get("/cases/c1/state");
    expect(before.body.forensicTimeline.every((e: ForensicEvent) => !e.originalTimestamp)).toBe(true);

    await request(app).post("/cases/c1/clock-skew/align").send({ enable: true });
    const after = await request(app).get("/cases/c1/state");
    const shifted = after.body.forensicTimeline.filter((e: ForensicEvent) => e.originalTimestamp);
    expect(shifted).toHaveLength(3); // the three WS-01 rows; DC01 is the reference
    expect(shifted.every((e: ForensicEvent) => e.asset === "WS-01")).toBe(true);
    expect(shifted[0].skewOffsetMs).toBe(120_000);
    expect(Date.parse(shifted[0].timestamp)).toBe(Date.parse(shifted[0].originalTimestamp) - 120_000);

    // The timeline comes back in aligned order...
    const times = after.body.forensicTimeline.map((e: ForensicEvent) => Date.parse(e.timestamp));
    expect([...times].sort((a: number, b: number) => a - b)).toEqual(times);
  });

  it("never writes the projection into the stored case", async () => {
    const { app, stateStore } = await makeApp({ timeline: anchoredTimeline(120) });
    await request(app).post("/cases/c1/clock-skew/recompute").send({});
    await request(app).post("/cases/c1/clock-skew/align").send({ enable: true });
    await request(app).get("/cases/c1/state");

    const stored = await stateStore.load("c1");
    expect(stored.forensicTimeline.every((e) => !e.originalTimestamp && e.skewOffsetMs === undefined)).toBe(
      true,
    );
    expect(stored.forensicTimeline.find((e) => e.id === "h-0")!.timestamp).toBe(
      new Date(Date.parse("2026-05-20T14:00:00Z") + 120_000).toISOString(),
    );
  });

  it("turning alignment off restores the recorded times", async () => {
    const { app } = await makeApp({ timeline: anchoredTimeline(120) });
    await request(app).post("/cases/c1/clock-skew/recompute").send({});
    await request(app).post("/cases/c1/clock-skew/align").send({ enable: true });
    await request(app).post("/cases/c1/clock-skew/align").send({ enable: false });
    const res = await request(app).get("/cases/c1/state");
    expect(res.body.forensicTimeline.every((e: ForensicEvent) => !e.originalTimestamp)).toBe(true);
  });

  it("an analyst override drives alignment even with no detection behind it", async () => {
    const { app } = await makeApp({ timeline: anchoredTimeline(0) });
    await request(app).put("/cases/c1/clock-skew/override").send({ host: "WS-01", offsetMs: 300_000 });
    await request(app).post("/cases/c1/clock-skew/align").send({ enable: true });
    const shifted = (await request(app).get("/cases/c1/state")).body.forensicTimeline.filter(
      (e: ForensicEvent) => e.originalTimestamp,
    );
    expect(shifted).toHaveLength(3);
    expect(shifted[0].skewOffsetMs).toBe(300_000);
  });
});
