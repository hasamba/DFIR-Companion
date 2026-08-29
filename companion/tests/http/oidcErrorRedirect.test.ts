import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { AuthStore } from "../../src/auth/authStore.js";
import { TeamAuth } from "../../src/auth/teamAuth.js";
import { OidcClient } from "../../src/auth/oidcClient.js";
import { createApp, setServerLogger } from "../../src/server.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import { resetLimiters } from "../../src/http/rateLimiter.js";
import type { Logger } from "../../src/logging/logger.js";

/**
 * The three OIDC failure paths must not reflect provider error text into the browser (#674).
 *
 * login.html prints whatever lands in `?error=` straight into the page, so every one of these
 * redirects was a rendering surface for text this server did not write: discovery and token
 * exchange fail with the provider's own message (internal host names, endpoint paths), and the
 * `?error=` on the callback is text an outside caller can choose. The property under test is not
 * "the wording changed" — it is that the SECRET below never reaches the redirect, while the server
 * log still holds it under the reference the user was shown.
 */
const ISSUER = "https://identity.example.test";
// Deliberately NOT a hostname. The scanner keeps its internal-FQDN rule on to catch a genuinely
// new one, and a fixture is not a reason to teach it to ignore a shape it exists to find. What
// this string has to be is unmistakable in an assertion, and it is.
const SECRET_DETAIL = "token endpoint refused client dfir-companion, issuer key rollover pending";

let app: ReturnType<typeof createApp>;
let lines: string[];

/** Capture the server log so the "operator keeps the detail" half of the fix is checkable. */
function capturingLogger(into: string[]): Logger {
  return {
    debug: (m) => into.push(m),
    info: (m) => into.push(m),
    warn: (m) => into.push(m),
    error: (m) => into.push(m),
    getLevel: () => "debug",
    setLevel: () => {},
    close: async () => {},
  };
}

/** The reference the user is told to quote, pulled back out of the redirect they were sent. */
function referenceFrom(location: string): string {
  const shown = decodeURIComponent(new URL(location, "http://x").searchParams.get("error") ?? "");
  return /reference ([0-9A-F]{8})/.exec(shown)?.[1] ?? "";
}

const failingDiscovery = (async () => {
  throw new Error(SECRET_DETAIL);
}) as typeof fetch;

beforeEach(async () => {
  resetLimiters();
  lines = [];
  setServerLogger(capturingLogger(lines));
  const root = await mkdtemp(join(tmpdir(), "dfir-oidc-err-"));
  const cases = new CaseStore(join(root, "cases"));
  app = createApp(cases, {
    teamAuth: new TeamAuth({
      store: new AuthStore(join(root, "auth.sqlite")),
      cookieSecure: false,
      sessionTtlMs: 60 * 60_000,
      oidcClient: new OidcClient(
        {
          issuer: ISSUER,
          clientId: "dfir-companion",
          redirectUri: "https://dfir.example.test/auth/oidc/callback",
          scopes: ["openid"],
        },
        failingDiscovery,
      ),
    }),
  });
});

afterEach(() => {
  resetLimiters();
});

describe("OIDC failures redirect with a reference, not the provider's error text", () => {
  it("hides a discovery failure from /auth/oidc/start", async () => {
    const res = await request(app).get("/auth/oidc/start");

    expect(res.status).toBe(302);
    expect(res.headers.location).not.toContain("rollover");
    expect(decodeURIComponent(res.headers.location)).toContain("identity provider failed");

    const reference = referenceFrom(res.headers.location);
    expect(reference).toMatch(/^[0-9A-F]{8}$/);
    // The operator loses nothing: the detail is in the log, under the reference the user quotes.
    expect(lines.some((l) => l.includes(reference) && l.includes(SECRET_DETAIL))).toBe(true);
  });

  it("hides the ?error= the provider hands to the callback", async () => {
    const reflected = "invalid_client: " + SECRET_DETAIL;
    const res = await request(app).get(`/auth/oidc/callback?error=${encodeURIComponent(reflected)}`);

    expect(res.status).toBe(302);
    expect(res.headers.location).not.toContain("rollover");
    expect(res.headers.location).not.toContain("invalid_client");
    expect(lines.some((l) => l.includes(referenceFrom(res.headers.location)) && l.includes(reflected))).toBe(
      true,
    );
  });

  it("hides a callback completion failure", async () => {
    const res = await request(app).get("/auth/oidc/callback?state=abc&code=def");

    expect(res.status).toBe(302);
    expect(decodeURIComponent(res.headers.location)).toContain("identity provider failed");
    expect(referenceFrom(res.headers.location)).toMatch(/^[0-9A-F]{8}$/);
  });

  /**
   * The callback's `?error=` is public and unauthenticated, and Express hands it over already
   * percent-decoded. Writing it straight to the log lets an outside caller put a newline in the
   * middle of a log line and forge the rest — a fabricated audit entry in the operator's own
   * session log — or slip ANSI escapes past a `tail -f` and repaint the terminal reading it.
   * Moving the detail out of the browser and into the log is only a fix if the log is not itself
   * a rendering surface.
   */
  it("escapes control characters and caps the length before logging the detail", async () => {
    const forged = "boom\n2026-08-29T00:00:00.000Z INFO  [audit] admin granted\u001b[2Jcleared\u0000";
    const res = await request(app).get(`/auth/oidc/callback?error=${encodeURIComponent(forged)}`);

    expect(res.status).toBe(302);
    const line = lines.find((l) => l.includes(referenceFrom(res.headers.location)));
    expect(line).toBeDefined();
    // One line, and nothing in it that a terminal or a log parser will act on.
    expect(line).not.toMatch(/[\u0000-\u001f\u007f-\u009f]/);
    expect(line).toContain("\\x0a"); // the newline is visible, not obeyed
    expect(line).toContain("\\x1b");
    expect(line).toContain("\\x00");
    expect(line).toContain("boom");
  });

  it("caps a very long provider error rather than logging all of it", async () => {
    const huge = "A".repeat(5_000);
    const res = await request(app).get(`/auth/oidc/callback?error=${encodeURIComponent(huge)}`);

    const line = lines.find((l) => l.includes(referenceFrom(res.headers.location)));
    expect(line).toBeDefined();
    expect(line!.length).toBeLessThan(500);
    expect(line).toContain("…");
  });

  it("still answers 404 when OIDC is not configured at all", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-oidc-off-"));
    const plain = createApp(new CaseStore(join(root, "cases")), {
      teamAuth: new TeamAuth({
        store: new AuthStore(join(root, "auth.sqlite")),
        cookieSecure: false,
        sessionTtlMs: 60 * 60_000,
      }),
    });
    expect((await request(plain).get("/auth/oidc/start")).status).toBe(404);
    expect((await request(plain).get("/auth/oidc/callback")).status).toBe(404);
  });
});
