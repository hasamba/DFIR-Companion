// companion/tests/server/updateCheckRoutes.test.ts
import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { UpdateCheckStore } from "../../src/analysis/updateCheckStore.js";

async function makeStore() {
  const root = await mkdtemp(join(tmpdir(), "dfir-upd-"));
  return { caseStore: new CaseStore(root), updateStore: new UpdateCheckStore(join(root, "updates", "u.json")) };
}

// A fetch mock returning a GitHub releases/latest body.
function fetchReturning(tag: string) {
  return (async () => ({ ok: true, status: 200, json: async () => ({ tag_name: tag, html_url: "https://gh/rel", published_at: "2026-06-18T00:00:00Z" }) })) as unknown as typeof fetch;
}
function fetchFailing() {
  return (async () => { throw new Error("network down"); }) as unknown as typeof fetch;
}

describe("/update-check", () => {
  it("GET reports disabled by default and the current version", async () => {
    const { caseStore, updateStore } = await makeStore();
    const app = createApp(caseStore, { updateCheckStore: updateStore, appVersion: "0.23.0" });
    const res = await request(app).get("/update-check");
    expect(res.status).toBe(200);
    expect(res.body.enabled).toBe(false);
    expect(res.body.current).toBe("0.23.0");
    expect(res.body.isNewer).toBe(false);
  });

  it("POST /settings toggles enabled and GET reflects it", async () => {
    const { caseStore, updateStore } = await makeStore();
    const app = createApp(caseStore, { updateCheckStore: updateStore, appVersion: "0.23.0" });
    const post = await request(app).post("/update-check/settings").send({ enabled: true });
    expect(post.status).toBe(200);
    expect(post.body.enabled).toBe(true);
    expect((await request(app).get("/update-check")).body.enabled).toBe(true);
  });

  it("POST /run fetches, caches, and reports a newer version", async () => {
    const { caseStore, updateStore } = await makeStore();
    const app = createApp(caseStore, {
      updateCheckStore: updateStore, appVersion: "0.23.0",
      updateCheckEnv: "1", updateFetch: fetchReturning("v0.24.0"),
    });
    const run = await request(app).post("/update-check/run");
    expect(run.status).toBe(200);
    expect(run.body.latest).toBe("0.24.0");
    expect(run.body.isNewer).toBe(true);
    // Cached: a follow-up GET shows the same without re-fetching.
    expect((await request(app).get("/update-check")).body.latest).toBe("0.24.0");
  });

  it("POST /run records the error but does not 500 when the fetch fails", async () => {
    const { caseStore, updateStore } = await makeStore();
    const app = createApp(caseStore, {
      updateCheckStore: updateStore, appVersion: "0.23.0",
      updateCheckEnv: "1", updateFetch: fetchFailing(),
    });
    const run = await request(app).post("/update-check/run");
    expect(run.status).toBe(200);
    expect(run.body.error).toMatch(/network down/);
  });

  it("POST /run is 400 when not enabled", async () => {
    const { caseStore, updateStore } = await makeStore();
    const app = createApp(caseStore, { updateCheckStore: updateStore, appVersion: "0.23.0", updateFetch: fetchReturning("v9.9.9") });
    expect((await request(app).post("/update-check/run")).status).toBe(400);
  });

  it("is locked when DFIR_UPDATE_CHECK=0: settings and run return 423, /health flags it", async () => {
    const { caseStore, updateStore } = await makeStore();
    const app = createApp(caseStore, { updateCheckStore: updateStore, appVersion: "0.23.0", updateCheckEnv: "0" });
    expect((await request(app).post("/update-check/settings").send({ enabled: true })).status).toBe(423);
    expect((await request(app).post("/update-check/run")).status).toBe(423);
    expect((await request(app).get("/health")).body.updateCheckLocked).toBe(true);
  });

  it("GET works with no store configured (graceful degradation)", async () => {
    const { caseStore } = await makeStore();
    const app = createApp(caseStore, { appVersion: "0.23.0" }); // no updateCheckStore
    const res = await request(app).get("/update-check");
    expect(res.status).toBe(200);
    expect(res.body.enabled).toBe(false);
    expect(res.body.current).toBe("0.23.0");
  });
});
