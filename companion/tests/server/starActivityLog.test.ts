import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { TagsStore } from "../../src/analysis/tags.js";
import { ActivityLogStore } from "../../src/analysis/activityLog.js";

// A star is the reserved "starred" analyst tag — a high-frequency triage gesture (starring 50
// rows would otherwise spam 50 tag-added/tag-removed entries). The activity log must stay silent
// for that ONE reserved label while still logging every normal tag add/remove.

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "dfir-staract-"));
  const store = new CaseStore(root);
  const app = createApp(store, {
    aiConfigured: false,
    tagsStore: new TagsStore(store),
    activityLogStore: new ActivityLogStore(store),
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app };
}

describe("activity log suppression for the reserved 'starred' tag", () => {
  it("logs a tag-added entry for a normal label", async () => {
    const { app } = await harness();
    const post = await request(app).post("/cases/c1/tags").send({
      targetType: "event", targetId: "ev1", label: "needs-review", author: "an",
    });
    expect(post.status).toBe(201);
    const log = await request(app).get("/cases/c1/activity-log");
    expect(log.status).toBe(200);
    const added = log.body.filter((e: { action: string }) => e.action === "tag-added");
    expect(added.length).toBe(1);
    expect(added[0].detail).toContain("needs-review");
  });

  it("does NOT log a tag-added entry for the reserved 'starred' label", async () => {
    const { app } = await harness();
    const post = await request(app).post("/cases/c1/tags").send({
      targetType: "event", targetId: "ev1", label: "starred", author: "an",
    });
    expect(post.status).toBe(201);
    const log = await request(app).get("/cases/c1/activity-log");
    expect(log.status).toBe(200);
    const added = log.body.filter((e: { action: string }) => e.action === "tag-added");
    expect(added.length).toBe(0);
  });

  it("does NOT log a tag-removed entry when the removed tag was 'starred'", async () => {
    const { app } = await harness();
    const post = await request(app).post("/cases/c1/tags").send({
      targetType: "event", targetId: "ev1", label: "starred", author: "an",
    });
    const tagId = post.body.id;
    const del = await request(app).delete(`/cases/c1/tags/${tagId}`);
    expect(del.status).toBe(204);
    const log = await request(app).get("/cases/c1/activity-log");
    const removed = log.body.filter((e: { action: string }) => e.action === "tag-removed");
    expect(removed.length).toBe(0);
  });

  it("DOES log a tag-removed entry for a normal label", async () => {
    const { app } = await harness();
    const post = await request(app).post("/cases/c1/tags").send({
      targetType: "event", targetId: "ev1", label: "needs-review", author: "an",
    });
    const tagId = post.body.id;
    const del = await request(app).delete(`/cases/c1/tags/${tagId}`);
    expect(del.status).toBe(204);
    const log = await request(app).get("/cases/c1/activity-log");
    const removed = log.body.filter((e: { action: string }) => e.action === "tag-removed");
    expect(removed.length).toBe(1);
    expect(removed[0].detail).toContain(tagId);
  });

  it("404s on a repeat DELETE of the same tag id (remove() null path, no double-log)", async () => {
    const { app } = await harness();
    const post = await request(app).post("/cases/c1/tags").send({
      targetType: "event", targetId: "ev1", label: "needs-review", author: "an",
    });
    const tagId = post.body.id;
    await request(app).delete(`/cases/c1/tags/${tagId}`);
    const second = await request(app).delete(`/cases/c1/tags/${tagId}`);
    expect(second.status).toBe(404);
    const log = await request(app).get("/cases/c1/activity-log");
    const removed = log.body.filter((e: { action: string }) => e.action === "tag-removed");
    expect(removed.length).toBe(1);
  });
});
