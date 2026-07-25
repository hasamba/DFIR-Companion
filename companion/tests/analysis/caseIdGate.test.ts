import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";

// #248 fixed the unvalidated-:id path-traversal gap for import.ts alone (a per-file app.use).
// Auditing every route file for isValidCaseId coverage found the identical gap in a dozen
// others — some of them write evidence (pushNotify's /push runs the same import pipeline as the
// Import button) or read files (captures' /evidence/:file) with the exact same unvalidated id.
// Replaced the per-file fix with one global gate (createCaseIdGate, mounted in server.ts before
// ANY /cases/:id/* route — including the lock gate, whose own getCaseMeta() call was itself
// unvalidated). These drive the REAL createApp() end to end across files that previously had NO
// isValidCaseId coverage at all, to prove the global gate actually reaches them.

let app: ReturnType<typeof createApp>;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-caseidgate-"));
  const store = new CaseStore(root);
  app = createApp(store, {});
});

// A single-path-segment id that fails isValidCaseId (contains ".." and a space) WITHOUT any
// slash-like character — deliberately avoids %2f-style traversal payloads, which get intercepted
// by Express's own built-in "failed to decode param" 400 for many (not all) of these routes,
// producing a false-positive pass that doesn't actually exercise the gate under test. This value
// still represents the real vulnerability class (join(root, caseId) with a caseId containing "..")
// while isolating the test to ONLY the gate's own logic.
const BAD_ID = "..bad id";

describe("global case-id gate — routes with NO prior isValidCaseId coverage (#248 follow-up)", () => {
  it("blocks a bad id on findings.ts (GET /cases/:id/false-positive)", async () => {
    const res = await request(app).get(`/cases/${encodeURIComponent(BAD_ID)}/false-positive`);
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid caseId");
  });

  it("blocks a bad id on threatIntel.ts (GET /cases/:id/ioc-sources)", async () => {
    const res = await request(app).get(`/cases/${encodeURIComponent(BAD_ID)}/ioc-sources`);
    expect(res.status).toBe(400);
  });

  it("blocks a bad id on velociraptor.ts (POST /cases/:id/velociraptor/suggest-hunts)", async () => {
    const res = await request(app).post(`/cases/${encodeURIComponent(BAD_ID)}/velociraptor/suggest-hunts`);
    expect(res.status).toBe(400);
  });

  it("blocks a bad id on aiSynthesis.ts (POST /cases/:id/synthesize)", async () => {
    const res = await request(app).post(`/cases/${encodeURIComponent(BAD_ID)}/synthesize`);
    expect(res.status).toBe(400);
  });

  it("blocks a bad id on pushNotify.ts (POST /cases/:id/push) — the write-primitive route named in #248's own threat model", async () => {
    const res = await request(app).post(`/cases/${encodeURIComponent(BAD_ID)}/push`).send({ source: "x", events: [] });
    expect(res.status).toBe(400);
  });

  it("blocks a bad id on captures.ts (GET /cases/:id/evidence/:file) — a READ primitive, not just write", async () => {
    const res = await request(app).get(`/cases/${encodeURIComponent(BAD_ID)}/evidence/shot.webp`);
    expect(res.status).toBe(400);
  });
});

describe("global case-id gate — doesn't break routes that already had their own check", () => {
  it("still 400s (via whichever gate fires first) for a bad id on casePassword.ts's /unlock", async () => {
    const res = await request(app).post(`/cases/${encodeURIComponent(BAD_ID)}/unlock`).send({ password: "x" });
    expect(res.status).toBe(400);
  });

  it("does NOT block a well-formed but nonexistent id — that stays a 404/other from the route itself", async () => {
    const res = await request(app).get("/cases/does-not-exist/false-positive");
    expect(res.status).not.toBe(400);
  });
});
