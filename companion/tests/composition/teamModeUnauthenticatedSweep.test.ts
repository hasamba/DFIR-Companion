/**
 * Team mode, no credential: every route must refuse (#2168).
 *
 * Team authentication is NOT a per-route opt-in. It is one global gate pair mounted before every
 * app route — `preAuthBodyGate` (composition/httpStack.ts) and `teamAuth.middleware()` — and the
 * path policy behind it (auth/policy.ts) falls through to global-admin by default. A route nobody
 * thought about is therefore refused, by design, and this test does not re-test that design.
 *
 * What it guards is the two ways that design can still regress without any route test noticing,
 * since almost every route test builds the app in single-user mode:
 *   1. a route or router registered ABOVE the gate, in httpStack.ts or earlier in createApp;
 *   2. the public allowlist growing — PUBLIC_GET, the webhook prefixes, or isTeamAuthRoutePath.
 *
 * So it builds the real app in team mode (no session, no stub), walks the live router stack — not
 * route-inventory.json, which is built in single-user mode and has no team-only routes — and sends
 * every verb of every route once with no cookie, no Authorization header and no `Accept: text/html`
 * (a browser navigation is redirected to /login instead of answered 401). Every answer must be 401,
 * except for a HARD-CODED allowlist. Deriving that list from resolveRequestPolicy would make the
 * test circular: widening the policy would widen the expectation with it.
 */
import { mkdtemp } from "node:fs/promises";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { AuthStore } from "../../src/auth/authStore.js";
import { TeamAuth } from "../../src/auth/teamAuth.js";
import { createConsoleLogger, type Logger } from "../../src/logging/logger.js";
import { getServerLogger, setServerLogger } from "../../src/logging/serverLogger.js";
import { createApp } from "../../src/server.js";
import { CaseStore } from "../../src/storage/caseStore.js";

/** Routes a stranger may reach in team mode. Adding one here is a deliberate, reviewable diff. */
const PUBLIC_ROUTES = new Set(["GET /health", "GET /login", "GET /js/safe-dom.js"]);

/**
 * The team-auth routes themselves (/login, /admin, /auth, /auth/*). Logging in is how a caller gets
 * a credential, so they cannot all answer 401; the role and token routes check auth inside their
 * handlers. They are pinned so that a new /auth/* route shows up as a visible change here.
 */
const TEAM_AUTH_ROUTES = [
  "GET /login",
  "GET /admin",
  "GET /auth/me",
  "GET /auth/oidc/start",
  "GET /auth/oidc/callback",
  "POST /auth/bootstrap",
  "POST /auth/local/login",
  "POST /auth/logout",
  "GET /auth/sessions",
  "DELETE /auth/sessions/others",
  "GET /auth/users",
  "GET /auth/directory",
  "POST /auth/users",
  "PATCH /auth/users/:identityId",
  "GET /auth/cases/:caseId/roles",
  "PUT /auth/cases/:caseId/roles/:identityId",
  "DELETE /auth/cases/:caseId/roles/:identityId",
  "GET /auth/service-tokens",
  "POST /auth/service-tokens",
  "DELETE /auth/service-tokens/:tokenId",
  "GET /auth/audit",
];

/** Team-auth routes that legitimately answer a stranger with success (the login page, "who am I"). */
const TEAM_AUTH_ANONYMOUS_OK = new Set(["GET /login", "GET /auth/me"]);

/** A floor, so a half-built app cannot pass vacuously (the probe for #2168 counted 766). */
const MIN_ROUTE_VERBS = 740;

interface RouteVerb {
  method: string;
  path: string;
  layerIndex: number;
}

interface StackLayer {
  name: string;
  route?: { path: unknown; methods: Record<string, boolean> };
  regexp?: RegExp & { fast_slash?: boolean };
}

function isTeamAuthPath(path: string): boolean {
  return path === "/login" || path === "/admin" || path === "/auth" || path.startsWith("/auth/");
}

function concreteUrl(path: string): string {
  return path
    .replace(/:id\??(?=\/|$)/g, "c1")
    .replace(/:[A-Za-z0-9_]+\??/g, "x1")
    .replace(/\*/g, "x");
}

function collectRouteVerbs(stack: StackLayer[]): RouteVerb[] {
  const verbs: RouteVerb[] = [];
  stack.forEach((layer, layerIndex) => {
    if (!layer.route) return;
    const raw = layer.route.path;
    const paths = Array.isArray(raw) ? raw : [raw];
    for (const path of paths) {
      if (typeof path !== "string") {
        throw new Error(
          `route at stack index ${layerIndex} has a non-string path (${String(path)}) — teach this sweep about it`,
        );
      }
      for (const method of Object.keys(layer.route.methods)) {
        if (method === "_all") continue;
        verbs.push({ method: method.toUpperCase(), path, layerIndex });
      }
    }
  });
  return verbs;
}

describe("team mode — every route refuses a caller with no credential (#2168)", () => {
  let stack: StackLayer[];
  let server: Server;
  let previousLogger: Logger;

  beforeAll(async () => {
    // ~770 requests would print ~770 "[req]" lines; keep the run quiet but still surface errors.
    previousLogger = getServerLogger();
    setServerLogger(createConsoleLogger("error"));
    const root = await mkdtemp(join(tmpdir(), "dfir-team-sweep-"));
    const teamAuth = new TeamAuth({
      store: new AuthStore(join(root, "auth.sqlite")),
      bootstrapToken: "test-bootstrap-token-with-enough-entropy",
      cookieSecure: false,
      sessionTtlMs: 60 * 60_000,
    });
    const app = createApp(new CaseStore(join(root, "cases")), { teamAuth });
    stack = (app as unknown as { _router: { stack: StackLayer[] } })._router.stack;
    server = createServer(app);
  });

  afterAll(() => {
    server?.close();
    setServerLogger(previousLogger);
  });

  it("mounts the credential gate above every route", () => {
    const gateIndex = stack.findIndex((l) => l.name === "preAuthBodyGate");
    expect(gateIndex, "preAuthBodyGate is missing from the team-mode stack").toBeGreaterThanOrEqual(0);

    const routesAbove = stack
      .slice(0, gateIndex)
      .filter((l) => l.route)
      .map((l) => String(l.route?.path));
    expect(routesAbove, "routes registered above preAuthBodyGate").toEqual([]);

    // teamAuth.middleware() is an anonymous, path-less layer; it must sit before the first route
    // that is not one of the team-auth routes (/login, /auth/*), which are mounted ahead of it.
    const firstAppRoute = stack.findIndex((l) => l.route && !isTeamAuthPath(String(l.route.path)));
    const middlewareIndex = stack.findIndex(
      (l, i) => i > gateIndex && !l.route && l.name === "<anonymous>" && l.regexp?.fast_slash === true,
    );
    expect(middlewareIndex, "teamAuth.middleware() is missing from the stack").toBeGreaterThan(gateIndex);
    expect(middlewareIndex).toBeLessThan(firstAppRoute);
  });

  it("pins the team-auth routes", () => {
    const found = collectRouteVerbs(stack)
      .filter((v) => isTeamAuthPath(v.path))
      .map((v) => `${v.method} ${v.path}`);
    expect([...new Set(found)].sort()).toEqual([...TEAM_AUTH_ROUTES].sort());
  });

  it("answers 401 to every other route verb", async () => {
    const verbs = collectRouteVerbs(stack);
    expect(verbs.length).toBeGreaterThanOrEqual(MIN_ROUTE_VERBS);

    const offenders: string[] = [];
    for (const { method, path } of verbs) {
      const key = `${method} ${path}`;
      const res = await request(server)[method.toLowerCase() as "get"](concreteUrl(path));
      if (isTeamAuthPath(path)) {
        const ok = res.status >= 200 && res.status < 300;
        if (ok && !TEAM_AUTH_ANONYMOUS_OK.has(key)) offenders.push(`${key} → ${res.status}`);
        continue;
      }
      if (PUBLIC_ROUTES.has(key)) continue;
      if (res.status !== 401) offenders.push(`${key} → ${res.status}`);
    }
    expect(
      offenders,
      `routes that did not refuse an unauthenticated caller:\n${offenders.join("\n")}`,
    ).toEqual([]);
  }, 120_000);
});
