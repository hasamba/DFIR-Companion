import { describe, it, expect, vi } from "vitest";
import { mkdtemp, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { _resetDedupCache } from "../../src/ingest/captureIngest.js";
import { hashCasePassword, verifyCasePassword } from "../../src/analysis/casePassword.js";
import { resetLimiters } from "../../src/http/rateLimiter.js";

// #1855: POST /captures carries its case id in the body, so it is outside the /cases/:id gate. A
// capture that was waiting (here: on the password check) when its case was deleted and the id
// re-created must not land in the new case.
vi.mock("../../src/analysis/casePassword.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/analysis/casePassword.js")>();
  return { ...actual, verifyCasePassword: vi.fn(actual.verifyCasePassword) };
});

const CAPTURE_BODY = {
  caseId: "c1",
  timestamp: "2026-07-24T00:00:00.000Z",
  url: "http://victim.example.com/",
  tabTitle: "t",
  triggerType: "timer" as const,
  imageBase64: Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13]).toString("base64"),
  casePassword: "secret123",
};

describe("POST /captures after its case was deleted and re-created (#1855)", () => {
  it("is refused and leaves the new case untouched", async () => {
    _resetDedupCache();
    resetLimiters();
    const root = await mkdtemp(join(tmpdir(), "dfir-capture-incarnation-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "old", investigator: "i", aiProvider: null });
    await cases.updateCaseMeta("c1", { password: await hashCasePassword("secret123") });
    const app = createApp(cases, {});

    let resume!: () => void;
    const paused = new Promise<void>((ok) => (resume = ok));
    let entered!: () => void;
    const inCheck = new Promise<void>((ok) => (entered = ok));
    vi.mocked(verifyCasePassword).mockImplementationOnce(async () => {
      entered();
      await paused;
      return true;
    });

    const pending = request(app)
      .post("/captures")
      .send(CAPTURE_BODY)
      .then((r) => r);
    await inCheck;
    await cases.updateCaseMeta("c1", { status: "closed" });
    await cases.deleteCaseFolder("c1");
    await cases.createCase({ caseId: "c1", name: "new", investigator: "i", aiProvider: null });
    resume();
    const res = await pending;

    expect(res.status).not.toBe(201);
    expect(await readdir(cases.screenshotsDir("c1"))).toEqual([]);
    expect(await readdir(cases.metadataDir("c1"))).toEqual([]);
  });

  it("a capture on a live case still lands", async () => {
    _resetDedupCache();
    resetLimiters();
    const root = await mkdtemp(join(tmpdir(), "dfir-capture-incarnation-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const app = createApp(cases, {});
    const { casePassword: _unused, ...body } = CAPTURE_BODY;
    const res = await request(app).post("/captures").send(body);
    expect(res.status).toBe(201);
    expect((await readdir(cases.screenshotsDir("c1"))).length).toBe(1);
  });
});
