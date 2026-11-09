// In single-user mode the dashboard still asks GET /auth/me on every boot to learn whether team
// login is on. With no team-auth routes registered that was an Express 404, logged in the browser
// console on every case open (#2462). It now answers the "auth is off" shape the dashboard already
// reads. The body carries no data, so it opens nothing to a remote caller.
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createApp } from "../../src/server.js";
import { CaseStore } from "../../src/storage/caseStore.js";

describe("GET /auth/me in single-user mode", () => {
  let dir: string;
  let cases: CaseStore;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "dfir-auth-me-"));
    cases = new CaseStore(dir);
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("answers 200 with team auth off instead of a 404", async () => {
    const res = await request(createApp(cases, {})).get("/auth/me");
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ enabled: false, authenticated: false });
  });
});
