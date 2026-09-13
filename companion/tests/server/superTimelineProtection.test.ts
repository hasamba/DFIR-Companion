import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { TagsStore } from "../../src/analysis/tags.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// #958 — a star or analyst tag placed through the public /tags route protects the raw row it
// names from the super-timeline cap. Every assertion goes through the routes an analyst uses;
// only the bulk import past the cap is fed to the store directly.
function ev(id: string, day: number): ForensicEvent {
  return {
    id,
    timestamp: `2026-06-${String(day).padStart(2, "0")}T00:00:00Z`,
    description: `event ${id}`,
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
  };
}

async function harness(cap: number) {
  const root = await mkdtemp(join(tmpdir(), "dfir-super-protect-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const pipeline = buildRuntimePipeline({
    provider: undefined,
    synthesisProvider: undefined,
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const superStore = new SuperTimelineStore(store, cap);
  const app = createApp(store, {
    pipeline,
    stateStore,
    tagsStore: new TagsStore(store, superStore),
    superTimelineStore: superStore,
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, superStore, stateStore };
}

const star = (app: ReturnType<typeof createApp>, targetId: string, author = "analyst") =>
  request(app).post("/cases/c1/tags").send({ targetType: "event", targetId, label: "starred", author });

describe("super-timeline protection through /tags (#958)", () => {
  it("a starred row survives a bulk import past the cap and still promotes", async () => {
    const { app, superStore, stateStore } = await harness(2);
    await superStore.append("c1", [ev("row0", 1)]);
    expect((await star(app, "row0")).status).toBe(201);
    // Out of date order and past the cap: row0 is the oldest insert and would go first.
    await superStore.append("c1", [ev("r1", 9), ev("r2", 5), ev("r3", 7)]);
    const ids = (await superStore.query("c1", {})).events.map((e) => e.id);
    expect(ids).toContain("row0");
    expect(ids).toHaveLength(3);

    const promote = await request(app)
      .post("/cases/c1/super-timeline/promote")
      .send({ eventIds: ["row0"] });
    expect(promote.status).toBe(200);
    expect(promote.body).toEqual({ promoted: 1 });
    expect((await stateStore.load("c1")).forensicTimeline.map((e) => e.id)).toContain("row0");
  });

  it("a tagger-authored tag does not protect the row", async () => {
    const { app, superStore } = await harness(1);
    await superStore.append("c1", [ev("row0", 1)]);
    expect((await star(app, "row0", "tagger:rule-1")).status).toBe(201);
    await superStore.append("c1", [ev("r1", 2)]);
    expect(await superStore.get("c1", "row0")).toBeNull();
  });

  it("removing the last analyst tag on a row makes it evictable again", async () => {
    const { app, superStore } = await harness(1);
    await superStore.append("c1", [ev("row0", 1)]);
    const starred = await star(app, "row0");
    const tagged = await request(app)
      .post("/cases/c1/tags")
      .send({ targetType: "event", targetId: "row0", label: "key-evidence", author: "analyst" });
    expect((await request(app).delete(`/cases/c1/tags/${starred.body.id}`)).status).toBe(204);
    await superStore.append("c1", [ev("r1", 2)]);
    expect((await superStore.get("c1", "row0"))?.id).toBe("row0"); // key-evidence still holds it
    expect((await request(app).delete(`/cases/c1/tags/${tagged.body.id}`)).status).toBe(204);
    await superStore.append("c1", [ev("r2", 3)]);
    expect(await superStore.get("c1", "row0")).toBeNull();
  });

  it("a tag on an id that is not a raw row is kept, and protects nothing", async () => {
    const { app, superStore } = await harness(1);
    const res = await star(app, "forensic-only");
    expect(res.status).toBe(201);
    expect(
      (await request(app).get("/cases/c1/tags")).body.map((t: { targetId: string }) => t.targetId),
    ).toEqual(["forensic-only"]);
    expect(await superStore.protectedIds("c1")).toEqual([]);
  });

  it("a star racing an append past the cap never leaves protection on a missing row", async () => {
    const { app, superStore } = await harness(1);
    await superStore.append("c1", [ev("row0", 1)]);
    const [starred] = await Promise.all([star(app, "row0"), superStore.append("c1", [ev("r1", 2)])]);
    expect(starred.status).toBe(201);
    const present = new Set((await superStore.query("c1", {})).events.map((e) => e.id));
    const protectedIds = await superStore.protectedIds("c1");
    for (const id of protectedIds) expect(present.has(id)).toBe(true);
    if (present.has("row0")) expect(protectedIds).toEqual(["row0"]);
    else expect(protectedIds).toEqual([]);
  });

  it("the legacy label route refuses an id that is not in the store", async () => {
    const { app, superStore } = await harness(10);
    await superStore.append("c1", [ev("row0", 1)]);
    expect(
      (
        await request(app)
          .post("/cases/c1/super-timeline/label")
          .send({ eventId: "ghost", labels: ["x"] })
      ).status,
    ).toBe(404);
    expect(
      (
        await request(app)
          .post("/cases/c1/super-timeline/label")
          .send({ eventId: "row0", labels: ["x"] })
      ).status,
    ).toBe(200);
  });
});
