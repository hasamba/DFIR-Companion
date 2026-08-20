import { createSign, generateKeyPairSync, type KeyObject } from "node:crypto";
import { describe, expect, it } from "vitest";
import { OidcClient } from "../../src/auth/oidcClient.js";

const ISSUER = "https://identity.example.test";
const CLIENT_ID = "dfir-companion";
const REDIRECT_URI = "https://dfir.example.test/auth/oidc/callback";

function encode(value: unknown): string {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}

describe("OIDC authorization-code client", () => {
  it("uses transaction-bound state, nonce, and S256 PKCE and validates the signed ID token", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const jwk = publicKey.export({ format: "jwk" });
    let expectedNonce = "";
    let tokenBody = "";

    const fetchFn: typeof fetch = async (input, init) => {
      const url = String(input);
      if (url.endsWith("/.well-known/openid-configuration")) {
        return Response.json({
          issuer: ISSUER,
          authorization_endpoint: `${ISSUER}/authorize`,
          token_endpoint: `${ISSUER}/token`,
          jwks_uri: `${ISSUER}/jwks`,
          code_challenge_methods_supported: ["S256"],
          id_token_signing_alg_values_supported: ["RS256"],
        });
      }
      if (url === `${ISSUER}/jwks`) {
        return Response.json({ keys: [{ ...jwk, kid: "key-1", use: "sig", alg: "RS256" }] });
      }
      if (url === `${ISSUER}/token`) {
        tokenBody = String(init?.body ?? "");
        const now = Math.floor(Date.now() / 1_000);
        const header = encode({ alg: "RS256", kid: "key-1", typ: "JWT" });
        const payload = encode({
          iss: ISSUER,
          sub: "stable-subject",
          aud: CLIENT_ID,
          exp: now + 300,
          iat: now,
          nonce: expectedNonce,
          name: "Alice Analyst",
          email: "alice@example.test",
        });
        const signingInput = `${header}.${payload}`;
        const signature = createSign("RSA-SHA256").update(signingInput).sign(privateKey, "base64url");
        return Response.json({ id_token: `${signingInput}.${signature}`, access_token: "unused" });
      }
      return new Response("not found", { status: 404 });
    };

    const client = new OidcClient(
      {
        issuer: ISSUER,
        clientId: CLIENT_ID,
        redirectUri: REDIRECT_URI,
        scopes: ["openid", "profile", "email"],
      },
      fetchFn,
    );
    const started = await client.begin("/dashboard?caseId=c1");
    const authorization = new URL(started.authorizationUrl);
    expectedNonce = authorization.searchParams.get("nonce") ?? "";

    expect(authorization.searchParams.get("response_type")).toBe("code");
    expect(authorization.searchParams.get("state")).toBe(started.state);
    expect(authorization.searchParams.get("code_challenge_method")).toBe("S256");
    expect(authorization.searchParams.get("code_challenge")).toMatch(/^[A-Za-z0-9_-]{43}$/);

    const completed = await client.complete({
      state: started.state,
      browserState: started.state,
      code: "authorization-code",
    });
    expect(completed.claims).toMatchObject({
      issuer: ISSUER,
      subject: "stable-subject",
      displayName: "Alice Analyst",
      username: "alice@example.test",
    });
    expect(completed.returnTo).toBe("/dashboard?caseId=c1");
    expect(new URLSearchParams(tokenBody).get("code_verifier")).toMatch(/^[A-Za-z0-9_-]{43,128}$/);
  });

  it("rejects a callback not bound to the browser that started it and consumes state once", async () => {
    const fetchFn: typeof fetch = async () =>
      Response.json({
        issuer: ISSUER,
        authorization_endpoint: `${ISSUER}/authorize`,
        token_endpoint: `${ISSUER}/token`,
        jwks_uri: `${ISSUER}/jwks`,
        code_challenge_methods_supported: ["S256"],
      });
    const client = new OidcClient(
      {
        issuer: ISSUER,
        clientId: CLIENT_ID,
        redirectUri: REDIRECT_URI,
        scopes: ["openid"],
      },
      fetchFn,
    );
    const started = await client.begin("/dashboard");
    await expect(
      client.complete({
        state: started.state,
        browserState: "stolen-state-without-cookie",
        code: "code",
      }),
    ).rejects.toThrow(/browser|state/i);
    await expect(
      client.complete({
        state: started.state,
        browserState: started.state,
        code: "code",
      }),
    ).rejects.toThrow(/state/i);
  });
});

// Every token below is REFUSED. The happy path above proves a correct token verifies; these prove
// each individual check still fires, because any one of them regressing — a loosened algorithm
// allowlist, a dropped signature check, a skipped nonce comparison — makes OIDC login forgeable
// while the happy-path test stays green.
describe("OIDC ID-token verification refuses forged and invalid tokens", () => {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwk = publicKey.export({ format: "jwk" });

  function baseClaims(nonce: string): Record<string, unknown> {
    const now = Math.floor(Date.now() / 1_000);
    return { iss: ISSUER, sub: "stable-subject", aud: CLIENT_ID, exp: now + 300, iat: now, nonce };
  }

  function sign(
    header: Record<string, unknown>,
    payload: Record<string, unknown>,
    key: KeyObject = privateKey,
  ): string {
    const signingInput = `${encode(header)}.${encode(payload)}`;
    const signature = createSign("RSA-SHA256").update(signingInput).sign(key, "base64url");
    return `${signingInput}.${signature}`;
  }

  // Runs a full begin()/complete() round trip against a mock IdP whose token endpoint returns
  // whatever `makeToken` builds for the flow's real nonce. Discovery advertises RS256 only.
  async function completeWith(makeToken: (nonce: string) => string): Promise<unknown> {
    let nonce = "";
    const fetchFn: typeof fetch = async (input) => {
      const url = String(input);
      if (url.endsWith("/.well-known/openid-configuration")) {
        return Response.json({
          issuer: ISSUER,
          authorization_endpoint: `${ISSUER}/authorize`,
          token_endpoint: `${ISSUER}/token`,
          jwks_uri: `${ISSUER}/jwks`,
          code_challenge_methods_supported: ["S256"],
          id_token_signing_alg_values_supported: ["RS256"],
        });
      }
      if (url === `${ISSUER}/jwks`) {
        return Response.json({ keys: [{ ...jwk, kid: "key-1", use: "sig", alg: "RS256" }] });
      }
      if (url === `${ISSUER}/token`) {
        return Response.json({ id_token: makeToken(nonce), access_token: "unused" });
      }
      return new Response("not found", { status: 404 });
    };
    const client = new OidcClient(
      { issuer: ISSUER, clientId: CLIENT_ID, redirectUri: REDIRECT_URI, scopes: ["openid"] },
      fetchFn,
    );
    const started = await client.begin("/dashboard");
    nonce = new URL(started.authorizationUrl).searchParams.get("nonce") ?? "";
    return client.complete({ state: started.state, browserState: started.state, code: "authorization-code" });
  }

  const HEADER = { alg: "RS256", kid: "key-1", typ: "JWT" };

  it("rejects a token signed by a different key", async () => {
    const rogue = generateKeyPairSync("rsa", { modulusLength: 2048 });
    await expect(completeWith((nonce) => sign(HEADER, baseClaims(nonce), rogue.privateKey))).rejects.toThrow(
      /signature/i,
    );
  });

  it("rejects alg none even with a known kid and an empty signature", async () => {
    await expect(
      completeWith(
        (nonce) => `${encode({ alg: "none", kid: "key-1", typ: "JWT" })}.${encode(baseClaims(nonce))}.`,
      ),
    ).rejects.toThrow(/unsupported/i);
  });

  it("rejects the symmetric algorithm confusion (HS256)", async () => {
    // The allowlist fires before any signature check, so the signature bytes are irrelevant here —
    // the danger being pinned is HS256 verified against the PUBLIC key as its shared secret.
    await expect(
      completeWith((nonce) => sign({ alg: "HS256", kid: "key-1", typ: "JWT" }, baseClaims(nonce))),
    ).rejects.toThrow(/unsupported/i);
  });

  it("rejects an allowlisted algorithm the provider never advertised", async () => {
    // RS384 passes the static allowlist regex; discovery above only advertises RS256.
    await expect(
      completeWith((nonce) => sign({ alg: "RS384", kid: "key-1", typ: "JWT" }, baseClaims(nonce))),
    ).rejects.toThrow(/advertised/i);
  });

  it("rejects a correctly signed token from the wrong issuer", async () => {
    await expect(
      completeWith((nonce) => sign(HEADER, { ...baseClaims(nonce), iss: "https://rogue.example.test" })),
    ).rejects.toThrow(/issuer/i);
  });

  it("rejects a correctly signed token for a different audience", async () => {
    await expect(
      completeWith((nonce) => sign(HEADER, { ...baseClaims(nonce), aud: "other-client" })),
    ).rejects.toThrow(/audience/i);
  });

  it("rejects a correctly signed but expired token", async () => {
    const expired = Math.floor(Date.now() / 1_000) - 3_600;
    await expect(
      completeWith((nonce) => sign(HEADER, { ...baseClaims(nonce), exp: expired })),
    ).rejects.toThrow(/expired/i);
  });

  it("rejects a correctly signed token whose nonce is not this flow's", async () => {
    await expect(completeWith(() => sign(HEADER, baseClaims("wrong-nonce")))).rejects.toThrow(/nonce/i);
  });
});

// /auth/oidc/start is public and stores a state, nonce, verifier, return path and expiry per call,
// each living ten minutes. Expiry was swept only when ANOTHER flow started, so a caller issuing
// starts faster than they expire grew the map without limit — no credentials needed.
describe("OIDC flow storage is bounded", () => {
  const discoveryOnly: typeof fetch = async (input) => {
    if (String(input).endsWith("/.well-known/openid-configuration")) {
      return Response.json({
        issuer: ISSUER,
        authorization_endpoint: `${ISSUER}/authorize`,
        token_endpoint: `${ISSUER}/token`,
        jwks_uri: `${ISSUER}/jwks`,
        code_challenge_methods_supported: ["S256"],
      });
    }
    throw new Error(`unexpected fetch: ${String(input)}`);
  };

  function makeClient(): OidcClient {
    return new OidcClient(
      { issuer: ISSUER, clientId: CLIENT_ID, redirectUri: REDIRECT_URI, scopes: ["openid"] },
      discoveryOnly,
    );
  }

  it("keeps outstanding flows under a hard ceiling however many are started", async () => {
    const c = makeClient();
    const flows = () => (c as unknown as { flows: Map<string, unknown> }).flows;

    for (let i = 0; i < 1200; i++) await c.begin("/dashboard");

    // Unbounded, this would be 1200 live entries with nothing to remove them for ten minutes.
    expect(flows().size).toBeLessThanOrEqual(1000);
  });

  it("evicts the oldest flow, so the most recent logins still complete", async () => {
    const c = makeClient();
    const flows = () => (c as unknown as { flows: Map<string, unknown> }).flows;

    const first = await c.begin("/dashboard");
    for (let i = 0; i < 1100; i++) await c.begin("/dashboard");
    const last = await c.begin("/dashboard");

    // The oldest is gone (its owner restarts a login); the newest — the one a real user is
    // mid-way through — is still there.
    expect(flows().has(first.state)).toBe(false);
    expect(flows().has(last.state)).toBe(true);
  });

  // The pre-existing behaviour that must survive the cap: an expired flow is still dropped, and
  // a live one is still usable.
  it("still drops expired flows and keeps live ones", async () => {
    const c = makeClient();
    const flows = () => (c as unknown as { flows: Map<string, { expiresAt: number }> }).flows;

    const stale = await c.begin("/dashboard");
    const entry = flows().get(stale.state);
    if (entry) entry.expiresAt = Date.now() - 1;

    const fresh = await c.begin("/dashboard");

    expect(flows().has(stale.state)).toBe(false);
    expect(flows().has(fresh.state)).toBe(true);
  });
});
