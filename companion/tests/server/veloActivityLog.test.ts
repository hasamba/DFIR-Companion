import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { ActivityLogStore } from "../../src/analysis/activityLog.js";
import {
  VelociraptorClient,
  type VqlRunner,
  type VelociraptorApiConfig,
} from "../../src/integrations/velociraptor/velociraptorApi.js";

// #832: the bare (case-less) VQL routes are the two Velociraptor actions that reached the fleet
// without a line in any case's activity log. When the caller names the case it is working in,
// the run and the hunt are now recorded there — what was run, against what, and how it ended —
// so "what was done to the endpoints" has an answer next to every other case action.

const veloCfg: VelociraptorApiConfig = {
  apiConfigPath: "/x/api.yaml",
  binary: "velociraptor",
  timeoutMs: 5000,
  maxRows: 1000,
  maxOutputBytes: 1024 * 1024,
};

async function makeApp(runner: VqlRunner, activityLogStoreOverride?: ActivityLogStore) {
  const root = await mkdtemp(join(tmpdir(), "dfir-velo-activity-"));
  const store = new CaseStore(root);
  const activityLogStore = activityLogStoreOverride ?? new ActivityLogStore(store);
  const app = createApp(store, {
    activityLogStore,
    velociraptorClient: new VelociraptorClient(veloCfg, runner),
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, activityLogStore };
}

const okRunner: VqlRunner = async (statements) => {
  if (statements[0].includes("hunt(")) {
    return { rows: [{ Hunt: { HuntId: "H.TEST1", state: "RUNNING" } }], raw: "" };
  }
  return { rows: [{ a: 1 }], raw: "" };
};

describe("Velociraptor VQL routes write to the case activity log (#832)", () => {
  it("POST /velociraptor/run with a caseId records the query in that case's log", async () => {
    const { app, activityLogStore } = await makeApp(okRunner);
    const res = await request(app)
      .post("/velociraptor/run")
      .send({ vql: "SELECT * FROM pslist()", caseId: "c1" });
    expect(res.status).toBe(200);
    const entries = await activityLogStore.load("c1", { category: "hunt" });
    expect(entries).toHaveLength(1);
    expect(entries[0].action).toBe("run-vql");
    expect(entries[0].detail).toContain("SELECT * FROM pslist()");
    expect(entries[0].detail).toContain("1 row");
    expect(entries[0].outcome).toBe("success");
  });

  it("POST /velociraptor/hunt with a caseId records the hunt id and description", async () => {
    const { app, activityLogStore } = await makeApp(okRunner);
    const res = await request(app)
      .post("/velociraptor/hunt")
      .send({ vql: "SELECT * FROM pslist()", description: "suspicious pslist", caseId: "c1" });
    expect(res.status).toBe(200);
    const entries = await activityLogStore.load("c1", { category: "hunt" });
    expect(entries).toHaveLength(1);
    expect(entries[0].action).toBe("launch-hunt");
    expect(entries[0].detail).toContain("H.TEST1");
    expect(entries[0].detail).toContain("suspicious pslist");
    expect(entries[0].detail).toContain("SELECT * FROM pslist()");
    expect(entries[0].targetId).toBe("H.TEST1");
  });

  it("truncates a long VQL in the detail so one entry cannot bloat the log", async () => {
    const { app, activityLogStore } = await makeApp(okRunner);
    const vql = "SELECT 1 FROM scope() -- " + "x".repeat(5_000);
    const res = await request(app).post("/velociraptor/run").send({ vql, caseId: "c1" });
    expect(res.status).toBe(200);
    const [entry] = await activityLogStore.load("c1", { category: "hunt" });
    expect(entry.detail.length).toBeLessThan(700);
    expect(entry.detail).toContain("…");
  });

  it("records a failed run with outcome=error, so an attempt that blew up is still on the record", async () => {
    const { app, activityLogStore } = await makeApp(async () => {
      throw new Error("velociraptor exploded");
    });
    const res = await request(app)
      .post("/velociraptor/run")
      .send({ vql: "SELECT * FROM pslist()", caseId: "c1" });
    expect(res.status).toBe(502);
    const [entry] = await activityLogStore.load("c1", { category: "hunt" });
    expect(entry.action).toBe("run-vql");
    expect(entry.outcome).toBe("error");
    expect(entry.detail).toContain("velociraptor exploded");
  });

  it("refuses an unknown caseId with a 404 before the query runs, so the audit line is never silently lost", async () => {
    const calls: string[][] = [];
    const { app } = await makeApp(async (statements) => {
      calls.push(statements);
      return { rows: [], raw: "" };
    });
    for (const path of ["/velociraptor/run", "/velociraptor/hunt"]) {
      const res = await request(app)
        .post(path)
        .send({ vql: "SELECT 1 FROM scope()", description: "d", caseId: "nope" });
      expect(res.status, path).toBe(404);
      expect(res.body.error).toMatch(/case "nope" not found/);
    }
    expect(calls).toHaveLength(0);
  });

  it("refuses a malformed caseId with a 400 rather than touching the filesystem with it", async () => {
    const { app } = await makeApp(okRunner);
    const res = await request(app)
      .post("/velociraptor/run")
      .send({ vql: "SELECT 1 FROM scope()", caseId: "../etc" });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/caseId/);
  });

  it("caps a huge description so one hunt cannot bloat every later activity-log load", async () => {
    const { app, activityLogStore } = await makeApp(okRunner);
    const description = "d".repeat(50_000);
    const res = await request(app)
      .post("/velociraptor/hunt")
      .send({ vql: "SELECT 1 FROM scope()", description, caseId: "c1" });
    expect(res.status).toBe(200);
    const [entry] = await activityLogStore.load("c1", { category: "hunt" });
    expect(entry.detail.length).toBeLessThan(1_000);
  });

  it("reports an audit append that failed instead of answering as if the line were written", async () => {
    // The shared logActivity helper swallows a rejected append (it is a side channel elsewhere). For
    // an audit line the caller asked for, silence is the one wrong answer: the response says so.
    class BrokenStore extends ActivityLogStore {
      override add(): Promise<never> {
        return Promise.reject(new Error("EACCES: activity.jsonl"));
      }
    }
    const root = await mkdtemp(join(tmpdir(), "dfir-velo-activity-broken-"));
    const { app } = await makeApp(okRunner, new BrokenStore(new CaseStore(root)));
    const res = await request(app)
      .post("/velociraptor/run")
      .send({ vql: "SELECT * FROM pslist()", caseId: "c1" });
    expect(res.status).toBe(200);
    expect(res.body.total).toBe(1);
    expect(res.body.auditWarning).toMatch(/activity log.*EACCES/);
  });

  it("still runs without a caseId and writes nothing — the pre-existing case-less contract holds", async () => {
    const { app, activityLogStore } = await makeApp(okRunner);
    const res = await request(app).post("/velociraptor/run").send({ vql: "SELECT 1 FROM scope()" });
    expect(res.status).toBe(200);
    expect(await activityLogStore.load("c1")).toHaveLength(0);
  });
});
