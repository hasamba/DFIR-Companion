import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import express, { type Request, type Response } from "express";
import "express-async-errors";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { mountTerminalHandlers } from "../../src/composition/httpStack.js";

async function makeApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-terminal-err-"));
  const store = new CaseStore(root);
  const app = createApp(store, { stateStore: new StateStore(store) });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return app;
}

describe("terminal error handler — client errors keep their 4xx (#8)", () => {
  it("answers 400, not 500, for malformed percent-encoding in an evidence file name", async () => {
    const res = await request(await makeApp()).get("/cases/c1/evidence/foo%c0%afbar");
    expect(res.status).toBe(400);
    expect(res.body).toEqual({ error: "malformed percent-encoding in URL" });
  });

  it("answers 400 for malformed percent-encoding in the case id, and never echoes the raw param", async () => {
    const res = await request(await makeApp()).get("/cases/%c0%af/state");
    expect(res.status).toBe(400);
    expect(JSON.stringify(res.body)).not.toMatch(/%c0|%af/i);
  });

  it("uses a fixed message for any other 4xx error and never echoes err.message", async () => {
    const app = express();
    app.get("/teapot", async (_req: Request, _res: Response) => {
      throw Object.assign(new Error("secret detail <script>"), { statusCode: 418 });
    });
    app.get("/bad", async (_req: Request, _res: Response) => {
      throw Object.assign(new Error("secret detail"), { status: 400 });
    });
    mountTerminalHandlers(app);
    const teapot = await request(app).get("/teapot");
    expect(teapot.status).toBe(418);
    expect(JSON.stringify(teapot.body)).not.toMatch(/secret/);
    const bad = await request(app).get("/bad");
    expect(bad.status).toBe(400);
    expect(bad.body).toEqual({ error: "bad request" });
  });

  it("still answers 500 for an error with a 5xx or no status", async () => {
    const app = express();
    app.get("/plain", async (_req: Request, _res: Response) => {
      throw new Error("kaboom");
    });
    app.get("/five", async (_req: Request, _res: Response) => {
      throw Object.assign(new Error("kaboom"), { status: 503 });
    });
    mountTerminalHandlers(app);
    expect((await request(app).get("/plain")).status).toBe(500);
    expect((await request(app).get("/five")).status).toBe(500);
  });

  it("leaves the malformed-JSON body answer unchanged", async () => {
    const res = await request(await makeApp())
      .post("/cases/c1/hypotheses")
      .set("content-type", "application/json")
      .send("{not json");
    expect(res.status).toBe(400);
    expect(res.body).toEqual({ error: "request body is not valid JSON" });
  });
});
