import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { AuthStore } from "../../src/auth/authStore.js";
import { TeamAuth } from "../../src/auth/teamAuth.js";
import { resolveTeamAuthConfig } from "../../src/auth/authConfig.js";
import { createApp } from "../../src/server.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import { resetLimiters } from "../../src/http/rateLimiter.js";

/**
 * POST /auth/bootstrap, brute-force bounds (#920).
 *
 * The route compared a caller-supplied token with no limiter, no lockout and no attempt count, and
 * the config accepted any nonempty token. The prize is the first administrator of the deployment:
 * whoever bootstraps creates the admin identity and receives its session cookie in the same
 * response. Every later access decision descends from that account.
 *
 * There is exactly ONE token, so the limiter is keyed on a constant rather than on the client: a
 * guesser gains nothing by rotating source addresses, and the budget is the token's, not the IP's.
 */
const BOOTSTRAP_TOKEN = "test-bootstrap-token-with-enough-entropy";
const ADMIN = { username: "admin", password: "correct horse battery staple", displayName: "Primary Admin" };

let authStore: AuthStore;
let app: ReturnType<typeof createApp>;

async function build(bootstrapToken: string | undefined) {
  const root = await mkdtemp(join(tmpdir(), "dfir-bootstrap-limit-"));
  authStore = new AuthStore(join(root, "auth.sqlite"));
  const auth = new TeamAuth({
    store: authStore,
    ...(bootstrapToken ? { bootstrapToken } : {}),
    cookieSecure: false,
    sessionTtlMs: 60 * 60_000,
  });
  app = createApp(new CaseStore(join(root, "cases")), { teamAuth: auth });
}

beforeEach(async () => {
  resetLimiters();
  await build(BOOTSTRAP_TOKEN);
});

afterEach(() => {
  resetLimiters();
});

async function attempt(bootstrapToken: string) {
  return request(app)
    .post("/auth/bootstrap")
    .send({ ...ADMIN, bootstrapToken });
}

describe("bootstrap limiter — wrong tokens", () => {
  it("locks the token out after five wrong guesses, with a Retry-After", async () => {
    for (let i = 0; i < 5; i++) expect((await attempt(`wrong-${i}`)).status).toBe(403);
    const res = await attempt("wrong-6");
    expect(res.status).toBe(429);
    expect(res.headers["retry-after"]).toBeTruthy();
  });

  it("refuses even the CORRECT token while locked — a guesser cannot keep going", async () => {
    for (let i = 0; i < 5; i++) await attempt(`wrong-${i}`);
    expect((await attempt(BOOTSTRAP_TOKEN)).status).toBe(429);
    // Nothing was created: the lockout ran before any comparison.
    expect(authStore.countIdentities()).toBe(0);
  });

  it("records every rejected token in the audit log with the source address", async () => {
    await attempt("wrong");
    const rows = authStore.listAudit(50).filter((e) => e.action === "bootstrap-token-rejected");
    expect(rows).toHaveLength(1);
    expect(rows[0].detail).toMatch(/ip=\S+/);
  });

  it("does not write the supplied token itself into the audit row", async () => {
    await attempt("do-not-log-me-9f8e7d");
    const rows = authStore.listAudit(50).filter((e) => e.action === "bootstrap-token-rejected");
    expect(rows[0].detail).not.toContain("do-not-log-me-9f8e7d");
  });
});

describe("bootstrap limiter — the legitimate operator", () => {
  it("still bootstraps with the correct token under the limit", async () => {
    for (let i = 0; i < 4; i++) await attempt(`typo-${i}`);
    const res = await attempt(BOOTSTRAP_TOKEN);
    expect(res.status).toBe(201);
    expect(authStore.countIdentities()).toBe(1);
  });

  it("a token-less refusal is not counted as a guess — the operator's own retries stay open (#945)", async () => {
    resetLimiters();
    await build(undefined);
    for (let i = 0; i < 7; i++) {
      // supertest connects over loopback; since #945 that no longer opens the door
      expect((await request(app).post("/auth/bootstrap").send(ADMIN)).status).toBe(403);
    }
    expect(authStore.countIdentities()).toBe(0);
  });
});

describe("bootstrap token — entropy floor at startup", () => {
  const team = { DFIR_AUTH_MODE: "team" };

  it("refuses a token shorter than 32 characters in team mode, naming the variable", () => {
    expect(() => resolveTeamAuthConfig({ ...team, DFIR_AUTH_BOOTSTRAP_TOKEN: "x".repeat(31) })).toThrow(
      /DFIR_AUTH_BOOTSTRAP_TOKEN.*32/,
    );
  });

  it("accepts exactly 32", () => {
    const cfg = resolveTeamAuthConfig({ ...team, DFIR_AUTH_BOOTSTRAP_TOKEN: "y".repeat(32) });
    expect(cfg.bootstrapToken).toBe("y".repeat(32));
  });

  it("measures the TRIMMED token — whitespace padding does not count", () => {
    expect(() =>
      resolveTeamAuthConfig({ ...team, DFIR_AUTH_BOOTSTRAP_TOKEN: `  ${"x".repeat(31)}  ` }),
    ).toThrow(/32/);
  });

  it("ignores a short token in single-user mode, where nothing reads it", () => {
    expect(() => resolveTeamAuthConfig({ DFIR_AUTH_BOOTSTRAP_TOKEN: "short" })).not.toThrow();
  });
});
