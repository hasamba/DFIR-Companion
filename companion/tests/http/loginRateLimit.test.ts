import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AuthStore } from "../../src/auth/authStore.js";
import { TeamAuth } from "../../src/auth/teamAuth.js";
import { createApp } from "../../src/server.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import { getLoginLimiter, resetLimiters } from "../../src/http/rateLimiter.js";

/**
 * POST /auth/local/login, resource bounds (#421).
 *
 * The limiter was keyed by `ip:username`, so an unauthenticated caller who changed the username on
 * every request got a fresh bucket each time — and with it an unbounded sequence of scrypt
 * verifications against the dummy hash, permanent audit rows, and Map entries in a limiter nothing
 * ever swept. The five-attempt lockout still protected one named account; it bounded nothing per
 * client.
 */
const BOOTSTRAP_TOKEN = "test-bootstrap-token-with-enough-entropy";

let cases: CaseStore;
let authStore: AuthStore;
let app: ReturnType<typeof createApp>;

beforeEach(async () => {
  resetLimiters();
  const root = await mkdtemp(join(tmpdir(), "dfir-login-limit-"));
  cases = new CaseStore(join(root, "cases"));
  authStore = new AuthStore(join(root, "auth.sqlite"));
  const auth = new TeamAuth({
    store: authStore,
    bootstrapToken: BOOTSTRAP_TOKEN,
    cookieSecure: false,
    sessionTtlMs: 60 * 60_000,
  });
  app = createApp(cases, { teamAuth: auth });
  await request(app).post("/auth/bootstrap").send({
    bootstrapToken: BOOTSTRAP_TOKEN,
    username: "admin",
    password: "correct horse battery staple",
    displayName: "Primary Admin",
  });
});

afterEach(() => {
  resetLimiters();
  vi.useRealTimers();
});

async function attempt(username: string) {
  return request(app).post("/auth/local/login").send({ username, password: "not the password" });
}

// 60s, not the suite's 15s default. MEASURED at 10.0s on an idle machine: each test here drives 70
// real login round-trips through the app to reach a client-wide limit, which is the behaviour under
// test and cannot be faked down. At 67% of the default budget this was the second test to fail under
// contention, for no reason other than having no room to be slowed down.
//
// THE NUMBER IS ABOVE THE WORST CASE ACTUALLY OBSERVED, WHICH WAS 31s. The first attempt at this
// fix set 30s — under the very figure written beside it — so the known flake survived the change
// that was supposed to remove it. 60s is 6x the idle cost, which is the kind of margin a test this
// I/O-bound needs on a machine that is doing anything else; if it ever approaches that, the test's
// real cost has regressed and failing is the correct outcome.
describe("login limiter — rotating usernames", { timeout: 60_000 }, () => {
  it("reaches the client-wide limit instead of running forever", async () => {
    // Each username is well-formed and nonexistent: on master every one of these got its own
    // bucket and its own scrypt verification, and none ever reached a 429.
    let sawLimit = false;
    for (let i = 0; i < 70; i++) {
      const res = await attempt(`rotating-user-${i}`);
      if (res.status === 429) {
        sawLimit = true;
        break;
      }
      expect(res.status).toBe(401);
    }
    expect(sawLimit).toBe(true);
  });

  it("bounds the audit table along with the attempts", async () => {
    for (let i = 0; i < 70; i++) await attempt(`audit-rotate-${i}`);
    // One row per attempt that reached the credential check; the 429s add none.
    const failures = authStore.listAudit(500).filter((e) => e.action === "local-login-failed");
    expect(failures.length).toBeLessThan(70);
  });

  it("still locks out a single named account after five tries", async () => {
    // The per-account control is unchanged — the client-wide budget is an addition, not a swap.
    for (let i = 0; i < 5; i++) expect((await attempt("admin")).status).toBe(401);
    const res = await attempt("admin");
    expect(res.status).toBe(429);
    expect(res.headers["retry-after"]).toBeTruthy();
  });

  it("lets a correct password through", async () => {
    const res = await request(app)
      .post("/auth/local/login")
      .send({ username: "admin", password: "correct horse battery staple" });
    expect(res.status).toBe(200);
  });
});

describe("login limiter — malformed usernames", () => {
  it("rejects a username that could never name an account, without an audit row", async () => {
    const before = authStore.listAudit(500).length;
    for (const bad of ["", "ab", "x".repeat(200), "has space", "back\\slash", "sql'inject"]) {
      const res = await attempt(bad);
      expect(res.status).toBe(401);
      expect(res.body.error).toBe("invalid username or password"); // no user enumeration
    }
    expect(authStore.listAudit(500).length).toBe(before);
  });

  it("does not create a limiter bucket for a malformed username", async () => {
    await attempt("!!!");
    // remainingLockout on a key that was never recorded is 0; the point is that no entry exists
    // at all, so a rotation of malformed names cannot grow the Map.
    expect(getLoginLimiter().sweep(Date.now() + 7_200_000)).toBe(0);
  });
});

describe("login limiter — state does not accumulate", () => {
  it("sweeps idle keys on a schedule rather than keeping them forever", async () => {
    vi.useFakeTimers();
    resetLimiters();
    const limiter = getLoginLimiter(); // creating it schedules the sweep interval
    limiter.recordFailure("10.0.0.1:someone");
    expect(limiter.remainingLockout("10.0.0.1:someone")).toBe(0); // one failure, not yet locked

    // Past the 1h idle window, and past at least one 5-minute sweep tick.
    await vi.advanceTimersByTimeAsync(3_600_000 + 5 * 60_000 + 1_000);
    // The entry is gone, so a fresh failure starts from scratch rather than continuing a cycle.
    expect(limiter.sweep(Date.now() + 7_200_000)).toBe(0);
  });
});
