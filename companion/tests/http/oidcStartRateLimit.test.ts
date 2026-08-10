import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { AuthStore } from "../../src/auth/authStore.js";
import { TeamAuth } from "../../src/auth/teamAuth.js";
import { OidcClient } from "../../src/auth/oidcClient.js";
import { createApp } from "../../src/server.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import { resetLimiters } from "../../src/http/rateLimiter.js";

/**
 * GET /auth/oidc/start, resource bounds.
 *
 * This is the one PUBLIC route that allocates server state: every call stored a state, nonce,
 * verifier, return path and expiry in an unbounded in-memory map, each entry living ten minutes,
 * and expiry was swept only when another flow started. A caller reachable beyond localhost could
 * therefore consume memory as fast as it could issue requests, without ever authenticating.
 */
const ISSUER = "https://identity.example.test";
const BOOTSTRAP_TOKEN = "test-bootstrap-token-with-enough-entropy";

let app: ReturnType<typeof createApp>;
let started = 0;

const discoveryFetch = (async (input: RequestInfo | URL) => {
  if (String(input).endsWith("/.well-known/openid-configuration")) {
    started += 1;
    return Response.json({
      issuer: ISSUER,
      authorization_endpoint: `${ISSUER}/authorize`,
      token_endpoint: `${ISSUER}/token`,
      jwks_uri: `${ISSUER}/jwks`,
      code_challenge_methods_supported: ["S256"],
    });
  }
  throw new Error(`unexpected fetch: ${String(input)}`);
}) as typeof fetch;

beforeEach(async () => {
  resetLimiters();
  started = 0;
  const root = await mkdtemp(join(tmpdir(), "dfir-oidc-limit-"));
  const cases = new CaseStore(join(root, "cases"));
  const auth = new TeamAuth({
    store: new AuthStore(join(root, "auth.sqlite")),
    bootstrapToken: BOOTSTRAP_TOKEN,
    cookieSecure: false,
    sessionTtlMs: 60 * 60_000,
    oidcClient: new OidcClient(
      {
        issuer: ISSUER,
        clientId: "dfir-companion",
        redirectUri: "https://dfir.example.test/auth/oidc/callback",
        scopes: ["openid"],
      },
      discoveryFetch,
    ),
  });
  app = createApp(cases, { teamAuth: auth });
});

afterEach(() => {
  resetLimiters();
});

describe("GET /auth/oidc/start is rate-limited", () => {
  it("stops an unauthenticated caller from allocating flows without limit", async () => {
    let sawLimit = false;
    let redirects = 0;

    // Unlimited, every one of these stored a ten-minute flow and none ever answered 429.
    for (let i = 0; i < 40 && !sawLimit; i++) {
      const res = await request(app).get("/auth/oidc/start");
      if (res.status === 429) sawLimit = true;
      else if (res.status === 302) redirects += 1;
    }

    expect(sawLimit).toBe(true);
    // The budget is generous enough that ordinary use is unaffected — a human clicking "Sign in
    // with SSO", including retries, is nowhere near this.
    expect(redirects).toBeGreaterThanOrEqual(20);
  });

  it("answers a throttled request with Retry-After and allocates nothing for it", async () => {
    let res = await request(app).get("/auth/oidc/start");
    while (res.status !== 429) res = await request(app).get("/auth/oidc/start");

    expect(res.headers["retry-after"]).toBe("60");
    const afterThrottle = started;

    // A throttled request must cost nothing: gated BEFORE begin(), so no discovery fetch and no
    // flow stored. Otherwise the limiter would bound the response but not the work.
    await request(app).get("/auth/oidc/start");
    expect(started).toBe(afterThrottle);
  });

  it("still serves the first sign-in normally", async () => {
    const res = await request(app).get("/auth/oidc/start");

    expect(res.status).toBe(302);
    expect(res.headers.location).toContain(`${ISSUER}/authorize`);
    expect(res.headers["set-cookie"]).toBeDefined();
  });
});
