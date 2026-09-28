import { describe, it, expect, afterEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";

// #1770 — the cross-case pivot is off by default (#723) and its routes answer 404. /health says
// whether it is on, so the dashboard skips GET /cases/:id/related instead of logging a 404 on
// every case load and every idle.

async function health() {
  const app = createApp(new CaseStore(await mkdtemp(join(tmpdir(), "dfir-health-xcase-"))), {});
  return (await request(app).get("/health")).body as { crossCaseEnabled?: unknown };
}

afterEach(() => {
  delete process.env.DFIR_CROSS_CASE;
});

describe("/health crossCaseEnabled (#1770)", () => {
  it("is false by default", async () => {
    delete process.env.DFIR_CROSS_CASE;
    expect((await health()).crossCaseEnabled).toBe(false);
  });

  it("is true when DFIR_CROSS_CASE=on", async () => {
    process.env.DFIR_CROSS_CASE = "on";
    expect((await health()).crossCaseEnabled).toBe(true);
  });
});
