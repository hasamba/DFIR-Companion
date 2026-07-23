import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { TagsStore } from "../../src/analysis/tags.js";
import { CommentsStore } from "../../src/analysis/comments.js";
import { ActivityLogStore, type ActivityLogEntry, type NewActivityEntry } from "../../src/analysis/activityLog.js";

// The dashboard refreshes the activity log the moment a collaboration mutation responds, so those
// routes must await their append instead of firing it and forgetting. The existing suppression
// tests (starActivityLog.test.ts) also POST-then-GET, but they pass either way whenever the append
// happens to win the race — which is how this regressed into a load-dependent flake in the first
// place. Here the append is deliberately slowed so a missing `await` ALWAYS loses: drop one and the
// matching case below fails every run, not one in twenty.
const APPEND_DELAY_MS = 50;

class SlowActivityLogStore extends ActivityLogStore {
  async add(caseId: string, input: NewActivityEntry): Promise<ActivityLogEntry> {
    await new Promise((resolve) => setTimeout(resolve, APPEND_DELAY_MS));
    return super.add(caseId, input);
  }
}

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "dfir-actraw-"));
  const store = new CaseStore(root);
  const app = createApp(store, {
    aiConfigured: false,
    tagsStore: new TagsStore(store),
    commentsStore: new CommentsStore(store),
    activityLogStore: new SlowActivityLogStore(store),
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app };
}

/** Actions present in the activity log read immediately after the mutation responded. */
async function actionsAfterResponse(app: ReturnType<typeof createApp>): Promise<string[]> {
  const log = await request(app).get("/cases/c1/activity-log");
  expect(log.status).toBe(200);
  return log.body.map((e: { action: string }) => e.action);
}

describe("collaboration activity log is read-after-write consistent", () => {
  it("tag-added is readable the instant POST /tags responds", async () => {
    const { app } = await harness();
    const post = await request(app).post("/cases/c1/tags").send({
      targetType: "event", targetId: "ev1", label: "needs-review", author: "an",
    });
    expect(post.status).toBe(201);
    expect(await actionsAfterResponse(app)).toContain("tag-added");
  });

  it("tag-removed is readable the instant DELETE /tags responds", async () => {
    const { app } = await harness();
    const post = await request(app).post("/cases/c1/tags").send({
      targetType: "event", targetId: "ev1", label: "needs-review", author: "an",
    });
    const del = await request(app).delete(`/cases/c1/tags/${post.body.id}`);
    expect(del.status).toBe(204);
    expect(await actionsAfterResponse(app)).toContain("tag-removed");
  });

  it("comment-added is readable the instant POST /comments responds", async () => {
    const { app } = await harness();
    const post = await request(app).post("/cases/c1/comments").send({
      targetType: "event", targetId: "ev1", text: "looks like staging", author: "an",
    });
    expect(post.status).toBe(201);
    expect(await actionsAfterResponse(app)).toContain("comment-added");
  });

  it("comment-removed is readable the instant DELETE /comments responds", async () => {
    const { app } = await harness();
    const post = await request(app).post("/cases/c1/comments").send({
      targetType: "event", targetId: "ev1", text: "looks like staging", author: "an",
    });
    const del = await request(app).delete(`/cases/c1/comments/${post.body.id}`);
    expect(del.status).toBe(204);
    expect(await actionsAfterResponse(app)).toContain("comment-removed");
  });

  // The reserved star stays fire-and-forget-free by never logging at all — awaiting must not have
  // turned the suppressed path into a logged one (or into a 50ms tax on every star).
  it("still logs nothing for the reserved 'starred' tag", async () => {
    const { app } = await harness();
    const post = await request(app).post("/cases/c1/tags").send({
      targetType: "event", targetId: "ev1", label: "starred", author: "an",
    });
    expect(post.status).toBe(201);
    expect(await actionsAfterResponse(app)).not.toContain("tag-added");
  });
});
