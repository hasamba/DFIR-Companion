// #2498: POST /cases/:id/ai-state/skip-held-screenshots — the analyst accepts the gap left by
// screenshots the AI could not analyze. The pure watermark rule is tested in
// tests/composition/skipHeldScreenshots.test.ts; this suite is about the route: the token the GET
// hands out, the audit entry, and the refusals.
import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { AiControlStore } from "../../src/analysis/aiControl.js";
import { ActivityLogStore } from "../../src/analysis/activityLog.js";
import { createApp } from "../../src/server.js";

const URL_SKIP = "/cases/c1/ai-state/skip-held-screenshots";

async function build(opts: { activityLog?: ActivityLogStore | "broken" } = {}) {
  const root = await mkdtemp(join(tmpdir(), "dfir-skip-held-route-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const controls = new AiControlStore(cases);
  await controls.save("c1", {
    enabled: true,
    lastAnalyzedSeq: 0,
    analysisHold: {
      failedSeqs: [1, 2, 3],
      analyzedThrough: 0,
      attempts: 3,
      gaveUp: true,
      lastError: "401 invalid api key",
    },
  });
  const activity =
    opts.activityLog === "broken" ? undefined : (opts.activityLog ?? new ActivityLogStore(cases));
  const brokenLog = {
    add: async () => {
      throw new Error("disk full");
    },
  } as unknown as ActivityLogStore;
  const app = createApp(cases, {
    aiConfigured: true,
    activityLogStore: opts.activityLog === "broken" ? brokenLog : activity,
  });
  return { app, cases, controls, activity };
}

describe("GET /cases/:id/ai-state — the held screenshots the dashboard can offer to skip", () => {
  it("carries the count, the reason and a token", async () => {
    const { app } = await build();
    const res = await request(app).get("/cases/c1/ai-state");
    expect(res.body.screenshotHold).toMatchObject({
      count: 3,
      gaveUp: true,
      lastError: "401 invalid api key",
    });
    expect(typeof res.body.screenshotHold.token).toBe("string");
  });
});

describe("POST /cases/:id/ai-state/skip-held-screenshots", () => {
  it("skips the held screenshots, clears the error and records who-what in the activity log", async () => {
    const { app, controls, activity } = await build();
    const { token } = (await request(app).get("/cases/c1/ai-state")).body.screenshotHold;
    const res = await request(app).post(URL_SKIP).send({ token });
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ skipped: 3, remaining: 0, sequenceNumbers: [1, 2, 3] });
    expect(res.body.warning).toBeUndefined();

    const control = await controls.load("c1");
    expect(control.analysisHold).toBeUndefined();
    expect(control.lastAnalyzedSeq).toBe(3);
    const after = await request(app).get("/cases/c1/ai-state");
    expect(after.body.screenshotHold).toBeNull();
    expect(after.body.state).not.toBe("error");

    const entries = await activity!.load("c1");
    const entry = entries.find((e) => e.action === "screenshots-skipped");
    expect(entry?.category).toBe("ai");
    expect(entry?.detail).toContain("3 screenshot(s)");
    expect(entry?.detail).toContain("#1, #2, #3");
    expect(entry?.detail).toContain("401 invalid api key");
    expect(entry?.detail).toContain("saved as evidence");
  });

  it("refuses a stale token with 409 and changes nothing", async () => {
    const { app, controls } = await build();
    const res = await request(app).post(URL_SKIP).send({ token: "0000000000000000" });
    expect(res.status).toBe(409);
    expect((await controls.load("c1")).analysisHold?.failedSeqs).toEqual([1, 2, 3]);
  });

  it("400s without a token", async () => {
    const { app } = await build();
    expect((await request(app).post(URL_SKIP).send({})).status).toBe(400);
  });

  it("answers skipped: 0 when nothing is held", async () => {
    const { app } = await build();
    const { token } = (await request(app).get("/cases/c1/ai-state")).body.screenshotHold;
    await request(app).post(URL_SKIP).send({ token });
    const again = await request(app).post(URL_SKIP).send({ token });
    expect(again.status).toBe(200);
    expect(again.body).toMatchObject({ skipped: 0 });
  });

  it("404s for a case that does not exist", async () => {
    const { app } = await build();
    expect(
      (await request(app).post("/cases/nope/ai-state/skip-held-screenshots").send({ token: "x" })).status,
    ).toBe(404);
  });

  it("still skips, and says so, when the activity log cannot be written", async () => {
    const { app, controls } = await build({ activityLog: "broken" });
    const { token } = (await request(app).get("/cases/c1/ai-state")).body.screenshotHold;
    const res = await request(app).post(URL_SKIP).send({ token });
    expect(res.status).toBe(200);
    expect(res.body.skipped).toBe(3);
    expect(res.body.warning).toMatch(/activity log/);
    expect((await controls.load("c1")).analysisHold).toBeUndefined();
  });
});
