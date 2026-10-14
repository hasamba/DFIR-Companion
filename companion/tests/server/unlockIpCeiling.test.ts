import { describe, it, expect, beforeEach, vi } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { _resetDedupCache } from "../../src/ingest/captureIngest.js";
import { hashCasePassword, verifyCasePassword } from "../../src/analysis/casePassword.js";
import { resetLimiters, UNLOCK_IP_MAX_FAILURES } from "../../src/http/rateLimiter.js";

// Regression #2184: the case-password lockout is keyed by case id, so a client that knows N case
// ids got N independent budgets of guesses (and N concurrent scrypt derivations). A per-client
// ceiling now bounds FAILED guesses across every case and every password-checking route. Only
// failures count: the extension sends the password on every capture, and a correct one must never
// use up the analyst's budget.
vi.mock("../../src/analysis/casePassword.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/analysis/casePassword.js")>();
  return { ...actual, verifyCasePassword: vi.fn(actual.verifyCasePassword) };
});

const verifySpy = vi.mocked(verifyCasePassword);
const CASE_COUNT = UNLOCK_IP_MAX_FAILURES + 5;
const PNG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13]).toString("base64");

let app: ReturnType<typeof createApp>;

beforeEach(async () => {
  _resetDedupCache();
  resetLimiters();
  verifySpy.mockClear();
  const root = await mkdtemp(join(tmpdir(), "dfir-unlockip-"));
  const cases = new CaseStore(root);
  const password = await hashCasePassword("secret123");
  for (let i = 0; i < CASE_COUNT; i++) {
    await cases.createCase({ caseId: `c${i}`, name: "n", investigator: "i", aiProvider: null });
    await cases.updateCaseMeta(`c${i}`, { password });
  }
  app = createApp(cases, {});
});

const unlock = (caseId: string, password: string) =>
  request(app).post(`/cases/${caseId}/unlock`).send({ password });
const capture = (caseId: string, casePassword?: string) =>
  request(app)
    .post("/captures")
    .send({
      caseId,
      timestamp: "2026-07-24T00:00:00.000Z",
      url: `http://victim/${Math.random()}`,
      tabTitle: "t",
      triggerType: "timer",
      imageBase64: PNG,
      ...(casePassword === undefined ? {} : { casePassword }),
    });
const importInto = (caseId: string, casePassword: string) =>
  request(app)
    .post(`/cases/${caseId}/import`)
    .send({ filename: "x.csv", text: "timestamp,message\n", casePassword });

const caseIds = Array.from({ length: CASE_COUNT }, (_, i) => `c${i}`);

describe("per-client ceiling on failed case-password guesses (#2184)", () => {
  it("one wrong /unlock per case: the ceiling refuses the rest without deriving", async () => {
    const statuses: number[] = [];
    for (const id of caseIds) statuses.push((await unlock(id, "wrong")).status);
    expect(statuses.slice(0, UNLOCK_IP_MAX_FAILURES).every((s) => s === 401)).toBe(true);
    expect(statuses.slice(UNLOCK_IP_MAX_FAILURES).every((s) => s === 429)).toBe(true);
    expect(verifySpy).toHaveBeenCalledTimes(UNLOCK_IP_MAX_FAILURES);
    const last = await unlock("c0", "secret123");
    expect(last.status).toBe(429);
    expect(Number(last.headers["retry-after"])).toBeGreaterThan(0);
  });

  it("a concurrent burst across all cases derives at most the ceiling", async () => {
    const results = await Promise.all(caseIds.map((id) => unlock(id, "wrong")));
    expect(verifySpy).toHaveBeenCalledTimes(UNLOCK_IP_MAX_FAILURES);
    expect(results.filter((r) => r.status === 401)).toHaveLength(UNLOCK_IP_MAX_FAILURES);
    expect(results.filter((r) => r.status === 429)).toHaveLength(CASE_COUNT - UNLOCK_IP_MAX_FAILURES);
  });

  it("wrong guesses spread across /unlock, /captures and /import share one ceiling", async () => {
    const routes = [unlock, capture, importInto] as const;
    const statuses: number[] = [];
    for (let i = 0; i < CASE_COUNT; i++) {
      statuses.push((await routes[i % 3](caseIds[i], "wrong")).status);
    }
    expect(statuses.slice(0, UNLOCK_IP_MAX_FAILURES).every((s) => s === 401)).toBe(true);
    expect(statuses.slice(UNLOCK_IP_MAX_FAILURES).every((s) => s === 429)).toBe(true);
    expect(verifySpy).toHaveBeenCalledTimes(UNLOCK_IP_MAX_FAILURES);
  });

  it("correct passwords do not use up the ceiling", async () => {
    for (let i = 0; i < UNLOCK_IP_MAX_FAILURES - 1; i++) {
      expect((await unlock(caseIds[i], "wrong")).status).toBe(401);
    }
    for (let i = 0; i < 20; i++) {
      expect((await capture(caseIds[CASE_COUNT - 1], "secret123")).status).toBe(201);
    }
    expect((await unlock(caseIds[CASE_COUNT - 2], "wrong")).status).toBe(401);
    expect((await unlock(caseIds[CASE_COUNT - 3], "wrong")).status).toBe(429);
  });

  it("requests with no password are refused but never counted", async () => {
    for (let i = 0; i < CASE_COUNT * 2; i++) {
      expect((await capture(caseIds[i % CASE_COUNT])).status).toBe(401);
    }
    expect(verifySpy).not.toHaveBeenCalled();
    expect((await unlock("c0", "secret123")).status).toBe(200);
  });

  it("a per-case lockout refusal (no derivation) does not consume the client ceiling", async () => {
    // Lock c0 with 5 failures, then hammer it: every refusal is the per-case lockout, not a guess.
    for (let i = 0; i < 5; i++) await unlock("c0", "wrong");
    for (let i = 0; i < 30; i++) expect((await unlock("c0", "wrong")).status).toBe(429);
    expect(verifySpy).toHaveBeenCalledTimes(5);
    expect((await unlock("c1", "secret123")).status).toBe(200);
  });
});
