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

// #2561: an ours/responder mark re-tags the source's routine forensic rows `trusted-activity`, pins
// the mark in custody, and lists the honoured rows; clearing it removes them; tagger/clear puts them back.
describe("trusted-source marks (#2561)", () => {
  async function labApp() {
    const { parseCloudTrail } = await import("../../src/analysis/awsImport.js");
    const { CustodyStore } = await import("../../src/analysis/custody.js");
    const { StateStore } = await import("../../src/analysis/stateStore.js");
    const { TagsStore } = await import("../../src/analysis/tags.js");
    const { emptyState } = await import("../../src/analysis/stateTypes.js");
    const { sans504Records, COMPANY_IP } = await import("../analysis/fixtures/sans504Lab.js");
    const store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-trusted-route-")));
    const stateStore = new StateStore(store);
    const tagsStore = new TagsStore(store);
    const custodyStore = new CustodyStore(store);
    const app = createApp(store, { stateStore, tagsStore, custodyStore });
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const rows = parseCloudTrail(JSON.stringify({ Records: sans504Records() }), {
      aggregate: false,
    }).events.map((e, i) => ({ ...e, id: `ev${i}` }));
    await stateStore.save({ ...emptyState("c1"), forensicTimeline: rows as never });
    return { app, custodyStore, tagsStore, ip: COMPANY_IP };
  }

  it("marking the admin IP tags its routine rows, records custody, and clearing undoes it", async () => {
    const { app, custodyStore, ip } = await labApp();
    await request(app)
      .put("/cases/c1/ioc-attribution")
      .send({ value: ip, label: "responder", actor: "alice" });
    const listed = (await request(app).get("/cases/c1/trusted-activity")).body;
    expect(listed.count).toBeGreaterThan(0);
    expect(Object.values(listed.rows)[0]).toEqual({ label: "responder", value: ip });
    const custody = await custodyStore.load("c1");
    const entry = custody.find((r) => r.event === "trusted-source-marked");
    expect(entry?.artifactPath).toBe(`trusted-source:${ip}`);
    expect(entry?.trustedSource).toMatchObject({
      value: ip,
      before: null,
      after: "responder",
      rowsTagged: listed.count,
    });
    expect(entry?.collectedBy).toBe("alice");

    await request(app).put("/cases/c1/ioc-attribution").send({ value: ip, label: null, actor: "alice" });
    expect((await request(app).get("/cases/c1/trusted-activity")).body.count).toBe(0);
    const after = (await custodyStore.load("c1")).filter((r) => r.event === "trusted-source-marked");
    expect(after.at(-1)?.trustedSource).toMatchObject({ before: "responder", after: null, rowsTagged: 0 });
    expect((await custodyStore.verifyIntegrity("c1")).length).toBe(0);
  });

  it("a failed custody write is reported and re-saving the same label repairs it", async () => {
    const { app, custodyStore, ip } = await labApp();
    const real = custodyStore.record.bind(custodyStore);
    let fail = true;
    custodyStore.record = async (...args: Parameters<typeof real>) => {
      if (fail) throw new Error("disk full");
      return real(...args);
    };
    const first = await request(app)
      .put("/cases/c1/ioc-attribution")
      .send({ value: ip, label: "ours", actor: "alice" });
    expect(first.status).toBe(500);
    expect(first.body.error).toMatch(/custody entry could not be written/);
    expect(first.body.map[ip].label).toBe("ours");
    expect((await custodyStore.load("c1")).some((r) => r.event === "trusted-source-marked")).toBe(false);
    fail = false;
    const retry = await request(app)
      .put("/cases/c1/ioc-attribution")
      .send({ value: ip, label: "ours", actor: "alice" });
    expect(retry.status).toBe(200);
    const entries = (await custodyStore.load("c1")).filter((r) => r.event === "trusted-source-marked");
    expect(entries).toHaveLength(1);
    expect(entries[0].trustedSource).toMatchObject({ before: null, after: "ours" });
    const again = await request(app).put("/cases/c1/ioc-attribution").send({ value: ip, label: "ours" });
    expect(again.status).toBe(200);
    expect((await custodyStore.load("c1")).filter((r) => r.event === "trusted-source-marked")).toHaveLength(
      1,
    );
  });

  it("an attacker or unknown label writes no custody entry and tags nothing", async () => {
    const { app, custodyStore, ip } = await labApp();
    await request(app).put("/cases/c1/ioc-attribution").send({ value: ip, label: "unknown" });
    expect((await request(app).get("/cases/c1/trusted-activity")).body.count).toBe(0);
    expect((await custodyStore.load("c1")).some((r) => r.event === "trusted-source-marked")).toBe(false);
  });

  it("tagger/clear puts the trusted tags back", async () => {
    const { app, ip } = await labApp();
    await request(app).put("/cases/c1/ioc-attribution").send({ value: ip, label: "ours" });
    const before = (await request(app).get("/cases/c1/trusted-activity")).body.count;
    expect((await request(app).post("/cases/c1/tagger/clear")).status).toBe(200);
    expect((await request(app).get("/cases/c1/trusted-activity")).body.count).toBe(before);
  });
});
