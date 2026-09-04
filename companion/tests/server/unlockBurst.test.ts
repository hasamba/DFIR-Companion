import { describe, it, expect, beforeEach, vi } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { _resetDedupCache } from "../../src/ingest/captureIngest.js";
import { hashCasePassword, verifyCasePassword } from "../../src/analysis/casePassword.js";
import { resetLimiters } from "../../src/http/rateLimiter.js";

// The password derivation moved off the event loop (#863). That made the unlock limiter's three
// steps — check the lockout, derive, record — separable: a burst of wrong guesses could all pass
// the check before any was counted, every one of them paying for a derivation on the threadpool,
// and a lucky correct guess could clear failures that had not been counted yet. The routes now go
// through AttemptLimiter.attempt(), which serializes the three steps per case. These tests count
// the derivations themselves, which the status codes alone cannot distinguish from the old order.
vi.mock("../../src/analysis/casePassword.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/analysis/casePassword.js")>();
  return { ...actual, verifyCasePassword: vi.fn(actual.verifyCasePassword) };
});

const verifySpy = vi.mocked(verifyCasePassword);

const CAPTURE_BODY = {
  caseId: "c1",
  timestamp: "2026-07-24T00:00:00.000Z",
  url: "http://victim/",
  tabTitle: "t",
  triggerType: "timer" as const,
  imageBase64: Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13]).toString("base64"),
};

let app: ReturnType<typeof createApp>;

beforeEach(async () => {
  _resetDedupCache();
  resetLimiters();
  verifySpy.mockClear();
  const root = await mkdtemp(join(tmpdir(), "dfir-unlockburst-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  await cases.updateCaseMeta("c1", { password: await hashCasePassword("secret123") });
  app = createApp(cases, {});
});

const unlock = (password: string) => request(app).post("/cases/c1/unlock").send({ password });
const capture = (casePassword: string) =>
  request(app)
    .post("/captures")
    .send({ ...CAPTURE_BODY, casePassword });

describe("unlock limiter under a concurrent burst", () => {
  it("a burst of 20 wrong /unlock guesses derives at most 5 times before the lockout", async () => {
    const results = await Promise.all(Array.from({ length: 20 }, () => unlock("wrong")));
    expect(verifySpy).toHaveBeenCalledTimes(5);
    expect(results.filter((r) => r.status === 401)).toHaveLength(4);
    expect(results.filter((r) => r.status === 429)).toHaveLength(16);
    expect(results.every((r) => r.status === 401 || r.status === 429)).toBe(true);
  });

  it("a burst of 20 wrong /captures passwords derives at most 5 times before the lockout", async () => {
    const results = await Promise.all(Array.from({ length: 20 }, () => capture("wrong")));
    expect(verifySpy).toHaveBeenCalledTimes(5);
    expect(results.filter((r) => r.status === 401)).toHaveLength(4);
    expect(results.filter((r) => r.status === 429)).toHaveLength(16);
  });

  it("a burst split across /unlock and /captures shares one budget of 5 derivations", async () => {
    const results = await Promise.all([
      ...Array.from({ length: 10 }, () => unlock("wrong")),
      ...Array.from({ length: 10 }, () => capture("wrong")),
    ]);
    expect(verifySpy).toHaveBeenCalledTimes(5);
    expect(results.filter((r) => r.status === 429)).toHaveLength(16);
    // The case is locked for BOTH endpoints afterwards, without another derivation.
    expect((await unlock("secret123")).status).toBe(429);
    expect((await capture("secret123")).status).toBe(429);
    expect(verifySpy).toHaveBeenCalledTimes(5);
  });

  // Requests reach the limiter in whatever order the HTTP layer delivers them, so the ORDER is not
  // asserted — the OUTCOME of that order is. The derivations are serialized, so the sequence of
  // passwords the mock saw IS the order the limiter processed; a five-line model of the limiter
  // over that sequence gives the statuses each request must have received, and any attempt the
  // model never derived must have been refused as locked. A success that cleared failures still
  // in flight, or a derivation past the lockout, breaks the match.
  function statusesForOrder(derived: string[], total: number): number[] {
    let failures = 0;
    let locked = false;
    const out: number[] = [];
    for (const pw of derived) {
      expect(locked, "derived after the lockout").toBe(false);
      if (pw === "secret123") {
        failures = 0;
        out.push(200);
      } else if (++failures >= 5) {
        locked = true;
        out.push(429);
      } else out.push(401);
    }
    while (out.length < total) out.push(429);
    return out.sort();
  }
  const derivedPasswords = () => verifySpy.mock.calls.map((c) => c[0]);

  it("a correct password racing wrong ones clears only the failures counted before it", async () => {
    const results = await Promise.all([
      ...Array.from({ length: 3 }, () => unlock("wrong")),
      unlock("secret123"),
      ...Array.from({ length: 5 }, () => capture("wrong")),
    ]);
    const derived = derivedPasswords();
    expect(derived.length).toBeLessThanOrEqual(9);
    expect(results.map((r) => r.status).sort()).toEqual(statusesForOrder(derived, 9));
    // Whatever the order, a success can only have cleared failures counted BEFORE it: once five
    // wrong guesses follow the last success (or no success derived at all), the case is locked.
    const afterSuccess = derived.lastIndexOf("secret123");
    const wrongAfter = derived.length - (afterSuccess + 1);
    if (afterSuccess === -1 || wrongAfter >= 5) {
      expect((await unlock("secret123")).status).toBe(429);
      expect(derivedPasswords()).toHaveLength(derived.length); // refused without a derivation
    }
  });

  it("a correct password that lands after five wrong ones is refused without a derivation", async () => {
    const results = await Promise.all([
      ...Array.from({ length: 5 }, () => unlock("wrong")),
      unlock("secret123"),
    ]);
    const derived = derivedPasswords();
    expect(results.map((r) => r.status).sort()).toEqual(statusesForOrder(derived, 6));
    // Five wrong guesses in a row lock the case; if the correct one was sequenced after them it
    // was never derived, and if it was sequenced earlier the five after it still lock the case.
    const wrongAfter = derived.length - (derived.lastIndexOf("secret123") + 1);
    if (wrongAfter >= 5) expect(derived.filter((pw) => pw === "secret123").length).toBeLessThanOrEqual(1);
    expect(derived.filter((pw) => pw === "wrong").length).toBeLessThanOrEqual(5);
  });

  it("a valid unlock cookie on /captures costs no derivation and does not touch the budget", async () => {
    const agent = request.agent(app);
    expect((await agent.post("/cases/c1/unlock").send({ password: "secret123" })).status).toBe(200);
    verifySpy.mockClear();
    const results = await Promise.all(
      Array.from({ length: 3 }, () =>
        agent.post("/captures").send({ ...CAPTURE_BODY, url: `http://v/${Math.random()}` }),
      ),
    );
    expect(results.every((r) => r.status === 201)).toBe(true);
    expect(verifySpy).not.toHaveBeenCalled();
  });
});
