import { createSign, generateKeyPairSync } from "node:crypto";
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
