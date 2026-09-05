import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AuthStore } from "../../src/auth/authStore.js";
import { TeamAuth } from "../../src/auth/teamAuth.js";
import { createApp } from "../../src/server.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import { verifyLocalPassword } from "../../src/auth/password.js";
import { resetLimiters } from "../../src/http/rateLimiter.js";

/**
 * POST /auth/local/login under a CONCURRENT burst (#872).
 *
 * The password derivation runs on the threadpool, so the route's old three steps — check the
 * lockout, verify, record the failure — were separable: twenty simultaneous guesses against one
 * account all passed the lockout check before any of them was counted, every one of them paying
 * for a scrypt derivation, and a correct guess could clear failures that had not been counted yet.
 * The five-attempt budget only ever held because the derivation used to hold the event loop.
 *
 * The route now goes through AttemptLimiter.attemptFor, which serializes the three steps per key.
 * These tests count the DERIVATIONS, which the status codes alone cannot distinguish from the old
 * order: on master the statuses came out the same and the CPU cost did not.
 */
vi.mock("../../src/auth/password.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/auth/password.js")>();
  return { ...actual, verifyLocalPassword: vi.fn(actual.verifyLocalPassword) };
});

const verifySpy = vi.mocked(verifyLocalPassword);

const BOOTSTRAP_TOKEN = "test-bootstrap-token-with-enough-entropy";
const GOOD = "correct horse battery staple";
const WRONG = "not the password";

let app: ReturnType<typeof createApp>;

beforeEach(async () => {
  resetLimiters();
  const root = await mkdtemp(join(tmpdir(), "dfir-loginburst-"));
  const cases = new CaseStore(join(root, "cases"));
  const authStore = new AuthStore(join(root, "auth.sqlite"));
  app = createApp(cases, {
    teamAuth: new TeamAuth({
      store: authStore,
      bootstrapToken: BOOTSTRAP_TOKEN,
      cookieSecure: false,
      sessionTtlMs: 60 * 60_000,
    }),
  });
  await request(app).post("/auth/bootstrap").send({
    bootstrapToken: BOOTSTRAP_TOKEN,
    username: "admin",
    password: GOOD,
    displayName: "Primary Admin",
  });
  verifySpy.mockClear(); // the bootstrap itself hashes, but never verifies
});

afterEach(() => resetLimiters());

const login = (password: string) =>
  request(app).post("/auth/local/login").send({ username: "admin", password });

const derivedPasswords = () => verifySpy.mock.calls.map((c) => c[0]);

describe("login limiter under a concurrent burst", () => {
  it("a burst of 20 wrong guesses for one account derives at most 5 times before the lockout", async () => {
    const results = await Promise.all(Array.from({ length: 20 }, () => login(WRONG)));
    expect(verifySpy).toHaveBeenCalledTimes(5);
    // The fifth failure locks the account but still answers 401 (a wrong password is a wrong
    // password); every guess refused by the lockout answers 429.
    expect(results.filter((r) => r.status === 401)).toHaveLength(5);
    expect(results.filter((r) => r.status === 429)).toHaveLength(15);
    expect(results.every((r) => r.status === 401 || r.status === 429)).toBe(true);
  });

  it("the account stays locked afterwards, and the correct password costs no derivation", async () => {
    await Promise.all(Array.from({ length: 20 }, () => login(WRONG)));
    expect(verifySpy).toHaveBeenCalledTimes(5);
    const res = await login(GOOD);
    expect(res.status).toBe(429);
    expect(res.headers["retry-after"]).toBeTruthy();
    expect(verifySpy).toHaveBeenCalledTimes(5); // refused before the threadpool was touched
  });

  // Requests reach the limiter in whatever order the HTTP layer delivers them, so the ORDER is not
  // asserted — the OUTCOME of that order is. The derivations are serialized, so the sequence of
  // passwords the mock saw IS the order the limiter processed them in; a short model of the
  // limiter over that sequence gives the status each request must have received, and any attempt
  // the model never derived must have been refused as locked. A success that cleared failures
  // still in flight, or a derivation past the lockout, breaks the match.
  function statusesForOrder(derived: string[], total: number): number[] {
    let failures = 0;
    let locked = false;
    const out: number[] = [];
    for (const pw of derived) {
      expect(locked, "derived after the lockout").toBe(false);
      if (pw === GOOD) {
        failures = 0;
        out.push(200);
      } else {
        if (++failures >= 5) locked = true;
        out.push(401);
      }
    }
    while (out.length < total) out.push(429);
    return out.sort();
  }

  it("a correct password racing wrong ones clears only the failures counted before it", async () => {
    const results = await Promise.all([
      ...Array.from({ length: 3 }, () => login(WRONG)),
      login(GOOD),
      ...Array.from({ length: 4 }, () => login(WRONG)),
    ]);
    const derived = derivedPasswords();
    expect(derived.length).toBeLessThanOrEqual(8);
    expect(results.map((r) => r.status).sort()).toEqual(statusesForOrder(derived, 8));
    // Whatever the order, a success can only have cleared failures counted BEFORE it: once five
    // wrong guesses follow the last success (or no success derived at all), the account is locked.
    const lastSuccess = derived.lastIndexOf(GOOD);
    if (derived.length - (lastSuccess + 1) >= 5) {
      expect((await login(GOOD)).status).toBe(429);
      expect(derivedPasswords()).toHaveLength(derived.length); // refused without a derivation
    }
  });

  it("a fresh account is unaffected by another account's lockout", async () => {
    await Promise.all(Array.from({ length: 20 }, () => login(WRONG)));
    // Keys never wait on each other, and a locked key never spends another account's budget.
    const other = await request(app)
      .post("/auth/local/login")
      .send({ username: "someone-else", password: WRONG });
    expect(other.status).toBe(401); // verified against the dummy hash, not refused as locked
    expect(verifySpy).toHaveBeenCalledTimes(6);
  });
});
