import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";

/**
 * GET /settings/browse-fs is the one GET demo mode's blanket "GETs are safe" allowance does not
 * cover: unlike every other GET route, it walks the server's own filesystem on request, so on the
 * public demo it would let any visitor enumerate arbitrary directories the server process can read.
 */
async function harness(demoMode: boolean) {
  const root = await mkdtemp(join(tmpdir(), "dfir-browse-fs-demo-"));
  const store = new CaseStore(root);
  const app = createApp(store, { stateStore: new StateStore(store), demoMode });
  return { app };
}

describe("GET /settings/browse-fs in demo mode", () => {
  it("is rejected rather than allowed through the blanket GET rule", async () => {
    const { app } = await harness(true);
    const res = await request(app).get("/settings/browse-fs");
    expect(res.status).toBe(403);
    expect(res.body.error).toMatch(/demo mode/i);
  });

  it("still works when demo mode is off", async () => {
    const { app } = await harness(false);
    const res = await request(app).get("/settings/browse-fs");
    expect(res.status).toBe(200);
    expect(res.body.dir).toBeTruthy();
  });
});
