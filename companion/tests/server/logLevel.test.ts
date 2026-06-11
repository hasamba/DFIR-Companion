import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, setServerLogger } from "../../src/server.js";
import { createConsoleLogger } from "../../src/logging/logger.js";

let app: ReturnType<typeof createApp>;
beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-loglevel-"));
  const store = new CaseStore(root);
  // A console-only logger at a known starting level so each test is independent.
  setServerLogger(createConsoleLogger("info"));
  app = createApp(store, {});
});

describe("/log-level", () => {
  it("GET returns the current level and the allowed levels", async () => {
    const res = await request(app).get("/log-level");
    expect(res.status).toBe(200);
    expect(res.body.level).toBe("info");
    expect(res.body.levels).toEqual(["debug", "info", "warn", "error"]);
  });

  it("POST changes the level live and a follow-up GET reflects it", async () => {
    const post = await request(app).post("/log-level").send({ level: "debug" });
    expect(post.status).toBe(200);
    expect(post.body.level).toBe("debug");
    const get = await request(app).get("/log-level");
    expect(get.body.level).toBe("debug");
  });

  it("POST rejects an unknown level with 400", async () => {
    const res = await request(app).post("/log-level").send({ level: "trace" });
    expect(res.status).toBe(400);
    // The level must not have changed.
    expect((await request(app).get("/log-level")).body.level).toBe("info");
  });

  it("/health surfaces the current log level", async () => {
    await request(app).post("/log-level").send({ level: "warn" });
    const res = await request(app).get("/health");
    expect(res.status).toBe(200);
    expect(res.body.logLevel).toBe("warn");
  });
});
