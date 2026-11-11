// #2543 part 1b: GET/PUT /cases/:id/ioc-attribution — validation, the activity-log (custody) entry
// with old → new, and the label never entering the case state the AI reads.
import { describe, expect, it } from "vitest";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { ActivityLogStore } from "../../src/analysis/activityLog.js";

async function appWith() {
  const store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-iocattr-route-")));
  const activityLogStore = new ActivityLogStore(store);
  const app = createApp(store, { activityLogStore });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, store, activityLogStore };
}

describe("ioc-attribution routes (#2543)", () => {
  it("GET is empty at first; PUT sets a label and GET reflects it", async () => {
    const { app } = await appWith();
    expect((await request(app).get("/cases/c1/ioc-attribution")).body).toEqual({});
    const res = await request(app)
      .put("/cases/c1/ioc-attribution")
      .send({ value: "203.0.113.10", label: "ours", actor: "alice" });
    expect(res.status).toBe(200);
    expect(res.body["203.0.113.10"]).toMatchObject({ value: "203.0.113.10", label: "ours", setBy: "alice" });
    expect((await request(app).get("/cases/c1/ioc-attribution")).body["203.0.113.10"].label).toBe("ours");
  });

  it("PUT with label null clears it", async () => {
    const { app } = await appWith();
    await request(app).put("/cases/c1/ioc-attribution").send({ value: "a.example", label: "attacker" });
    const res = await request(app).put("/cases/c1/ioc-attribution").send({ value: "a.example", label: null });
    expect(res.status).toBe(200);
    expect(res.body).toEqual({});
  });

  it("rejects a label outside the vocabulary, a missing label, and a bad value", async () => {
    const { app } = await appWith();
    const put = (body: unknown) =>
      request(app)
        .put("/cases/c1/ioc-attribution")
        .send(body as object);
    expect((await put({ value: "x", label: "victim" })).status).toBe(400);
    expect((await put({ value: "x" })).status).toBe(400);
    expect((await put({ value: "", label: "ours" })).status).toBe(400);
    expect((await put({ value: "a\nb", label: "ours" })).status).toBe(400);
    expect((await put({ value: "x".repeat(3000), label: "ours" })).status).toBe(400);
  });

  it("logs every set and clear with the analyst and old → new; a no-op change logs nothing", async () => {
    const { app, activityLogStore } = await appWith();
    const put = (label: string | null) =>
      request(app).put("/cases/c1/ioc-attribution").send({ value: "198.51.100.23", label, actor: "alice" });
    await put("unknown");
    await put("attacker");
    await put("attacker");
    await put(null);
    // The append is best-effort and not awaited by the route; give it a tick.
    await new Promise((r) => setTimeout(r, 50));
    const entries = (await activityLogStore.load("c1")) // newest first
      .filter((e) => /ioc-attribution/.test(e.action))
      .reverse();
    expect(entries.map((e) => [e.action, e.actor, e.detail])).toEqual([
      ["set-ioc-attribution", "alice", "ioc 198.51.100.23: unset → unknown"],
      ["set-ioc-attribution", "alice", "ioc 198.51.100.23: unknown → attacker"],
      ["clear-ioc-attribution", "alice", "ioc 198.51.100.23: attacker → unset"],
    ]);
    expect(entries.every((e) => e.targetType === "ioc" && e.targetId === "198.51.100.23")).toBe(true);
  });

  it("the label lives in its own side file; the case state the AI reads does not carry it", async () => {
    const { app, store } = await appWith();
    await request(app).put("/cases/c1/ioc-attribution").send({ value: "203.0.113.10", label: "responder" });
    const side = await readFile(join(store.stateDir("c1"), "ioc-attribution.json"), "utf8");
    expect(side).toContain("responder");
    const state = await request(app).get("/cases/c1/state");
    expect(JSON.stringify(state.body)).not.toContain("responder");
  });
});
