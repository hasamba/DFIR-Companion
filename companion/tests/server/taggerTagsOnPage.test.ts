// #2059: GET /tags used to return every tag in the case — on an auto-tagged case that is one tagger
// tag per matched event, ~10 MB, rebuilt on every tag change by every open dashboard. The list now
// carries analyst tags only; the automatic tagger's labels travel with the timeline page that shows
// their rows (forensic timeline and super-timeline), so the pills the analyst sees are unchanged.
import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { TagsStore } from "../../src/analysis/tags.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";

const ev = (id: string, minute = 0): ForensicEvent => ({
  id,
  timestamp: `2026-06-10T12:${String(minute).padStart(2, "0")}:00Z`,
  description: `event ${id}`,
  severity: "Low",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
});

async function harness(eventCount = 3) {
  const root = await mkdtemp(join(tmpdir(), "dfir-2059-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const tagsStore = new TagsStore(store);
  const superStore = new SuperTimelineStore(store);
  const app = createApp(store, {
    aiConfigured: false,
    stateStore,
    tagsStore,
    superTimelineStore: superStore,
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const events = Array.from({ length: eventCount }, (_, i) => ev(`e${i}`, i % 60));
  await stateStore.save({ ...emptyState("c1"), forensicTimeline: events });
  await superStore.append("c1", [...events, ev("raw1"), ev("raw2")]);
  return { app, stateStore, tagsStore, superStore };
}

const tagger = (targetId: string, label: string, rule = "svc") => ({
  targetType: "event",
  targetId,
  label,
  author: `tagger:${rule}`,
});

describe("GET /cases/:id/tags carries analyst tags only (#2059)", () => {
  it("leaves the tagger's event tags out and keeps every analyst tag", async () => {
    const { app, tagsStore } = await harness();
    await tagsStore.addMany("c1", [tagger("e0", "win-service"), tagger("e1", "persistence")]);
    await request(app)
      .post("/cases/c1/tags")
      .send({ targetType: "event", targetId: "e0", label: "key-evidence", author: "alice" });
    await request(app)
      .post("/cases/c1/tags")
      .send({ targetType: "ioc", targetId: "i1", label: "c2-comms", author: "alice" });
    const res = await request(app).get("/cases/c1/tags");
    expect(res.status).toBe(200);
    expect(res.body.map((t: { label: string }) => t.label).sort()).toEqual(["c2-comms", "key-evidence"]);
    expect(res.headers["x-tagger-tags-version"]).toMatch(/^\d+:\d+$/);
  });

  it("stays small however many tagger tags the case holds", async () => {
    const { app, tagsStore } = await harness(2000);
    await tagsStore.addMany(
      "c1",
      Array.from({ length: 2000 }, (_, i) => tagger(`e${i}`, "win-service")),
    );
    await request(app)
      .post("/cases/c1/tags")
      .send({ targetType: "event", targetId: "e5", label: "starred", author: "alice" });
    const res = await request(app).get("/cases/c1/tags");
    expect(res.body).toHaveLength(1);
    expect(res.text.length).toBeLessThan(1000);
  });

  it("changes the tagger version when the tagger's tags change, and only then", async () => {
    const { app, tagsStore } = await harness();
    const version = async () => (await request(app).get("/cases/c1/tags")).headers["x-tagger-tags-version"];
    const v0 = await version();
    await request(app)
      .post("/cases/c1/tags")
      .send({ targetType: "event", targetId: "e0", label: "starred", author: "alice" });
    expect(await version()).toBe(v0);
    await tagsStore.addMany("c1", [tagger("e0", "win-service")]);
    const v1 = await version();
    expect(v1).not.toBe(v0);
    await tagsStore.removeByAuthorPrefix("c1", "tagger:");
    expect(await version()).not.toBe(v1);
  });

  it("pages the tagger's tags on an explicit opt-in", async () => {
    const { app, tagsStore } = await harness(5);
    await tagsStore.addMany(
      "c1",
      Array.from({ length: 5 }, (_, i) => tagger(`e${i}`, "win-service")),
    );
    const first = await request(app).get("/cases/c1/tags?scope=tagger&limit=2");
    expect(first.status).toBe(200);
    expect(first.body.total).toBe(5);
    expect(first.body.tags.map((t: { targetId: string }) => t.targetId)).toEqual(["e0", "e1"]);
    expect(first.body.nextOffset).toBe(2);
    const last = await request(app).get("/cases/c1/tags?scope=tagger&offset=4&limit=2");
    expect(last.body.tags.map((t: { targetId: string }) => t.targetId)).toEqual(["e4"]);
    expect(last.body.nextOffset).toBeNull();
    expect((await request(app).get("/cases/c1/tags?scope=bogus")).status).toBe(400);
  });
});

describe("timeline pages carry their rows' tagger tags (#2059)", () => {
  it("the forensic timeline page carries each row's tagger tags, for its own rows only", async () => {
    const { app, tagsStore } = await harness(4);
    await tagsStore.addMany("c1", [
      tagger("e0", "win-service"),
      tagger("e0", "persistence", "pers"),
      tagger("e3", "lateral-movement"),
    ]);
    await request(app)
      .post("/cases/c1/tags")
      .send({ targetType: "event", targetId: "e0", label: "key-evidence", author: "alice" });
    const full = await request(app).get("/cases/c1/state");
    expect(full.status).toBe(200);
    const onE0 = full.body.eventTaggerTags.e0 as Array<{ id: string; label: string; author: string }>;
    expect(onE0.map((t) => t.label).sort()).toEqual(["persistence", "win-service"]);
    expect(onE0.every((t) => t.author.startsWith("tagger:") && typeof t.id === "string")).toBe(true);
    expect(full.body.eventTaggerTags.e3.map((t: { label: string }) => t.label)).toEqual(["lateral-movement"]);
    expect(full.body.eventTaggerTags.e1).toBeUndefined();

    const page = await request(app).get("/cases/c1/state?timelineLimit=2");
    const ids = page.body.forensicTimeline.map((e: ForensicEvent) => e.id);
    expect(Object.keys(page.body.eventTaggerTags).every((id) => ids.includes(id))).toBe(true);
  });

  it("the super-timeline page carries each row's tagger tags", async () => {
    const { app, tagsStore } = await harness(2);
    await tagsStore.addMany("c1", [tagger("raw1", "web-scanner"), tagger("e1", "win-service")]);
    const res = await request(app).get("/cases/c1/super-timeline?limit=50");
    expect(res.status).toBe(200);
    expect(res.body.eventTaggerTags.raw1.map((t: { label: string }) => t.label)).toEqual(["web-scanner"]);
    expect(res.body.eventTaggerTags.e1.map((t: { label: string }) => t.label)).toEqual(["win-service"]);
    expect(res.body.eventTaggerTags.raw2).toBeUndefined();
    // The label filter and the facet still see the tagger's labels.
    expect(res.body.labelsAvailable).toEqual(expect.arrayContaining(["web-scanner", "win-service"]));
    const filtered = await request(app).get("/cases/c1/super-timeline?labels=web-scanner");
    expect(filtered.body.events.map((e: ForensicEvent) => e.id)).toEqual(["raw1"]);
  });

  it("a tagger tag on an event correlation folded away shows on the survivor's row", async () => {
    const { app, stateStore, tagsStore } = await harness(2);
    await tagsStore.addMany("c1", [tagger("gone", "persistence")]);
    const state = await stateStore.load("c1");
    await stateStore.save({ ...state, eventAliases: { gone: "e1" } });
    const res = await request(app).get("/cases/c1/state");
    expect(res.body.eventTaggerTags.e1.map((t: { label: string }) => t.label)).toEqual(["persistence"]);
  });

  it("answers the tagger tags of the rows the dashboard names, bounded", async () => {
    const { app, tagsStore } = await harness(3);
    await tagsStore.addMany("c1", [tagger("e2", "win-service")]);
    const res = await request(app)
      .post("/cases/c1/tags/tagger-for")
      .send({ ids: ["e0", "e2"] });
    expect(res.status).toBe(200);
    expect(Object.keys(res.body.eventTaggerTags)).toEqual(["e2"]);
    expect((await request(app).post("/cases/c1/tags/tagger-for").send({ ids: "e0" })).status).toBe(400);
    const tooMany = Array.from({ length: 5001 }, (_, i) => `x${i}`);
    expect((await request(app).post("/cases/c1/tags/tagger-for").send({ ids: tooMany })).status).toBe(400);
  });
});
