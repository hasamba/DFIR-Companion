import { randomBytes } from "node:crypto";
import type { Express, Request, Response } from "express";
import { getLoginLimiter, getLoginIpLimiter, getOidcStartLimiter } from "../http/rateLimiter.js";
import { warnLine } from "../logging/serverLogger.js";
import { withNonce } from "../http/securityHeaders.js";
import { readPublicAsset } from "../serverAssets.js";
import type { TeamAuth } from "./teamAuth.js";
import { isValidCaseId, type CaseStore } from "../storage/caseStore.js";
import { isValidUsername } from "./authStore.js";
import { isCaseRole, isGlobalRole, isServicePermission, type RequestAuthentication } from "./types.js";

function bodyObject(req: Request): Record<string, unknown> {
  return req.body && typeof req.body === "object" && !Array.isArray(req.body)
    ? (req.body as Record<string, unknown>)
    : {};
}

function bodyString(body: Record<string, unknown>, key: string): string {
  return typeof body[key] === "string" ? body[key].trim() : "";
}

/**
 * Longest provider error this server will write to its log, before the escaping below expands it.
 * Long enough to carry a real message from an identity provider, short enough that a caller cannot
 * push anything else out of a scrolled log by sending a megabyte of it.
 */
const LOGGED_DETAIL_MAX = 300;

/**
 * Control characters, matching the class analysis/motwDownload.ts already uses: C0, DEL and C1.
 */
const CONTROL_CHARS = /[\u0000-\u001f\u007f-\u009f]/g;

/**
 * Make one line of untrusted text safe to write to a log.
 *
 * Moving the provider's error out of the browser and into the server log is only a fix if the log
 * is not itself a rendering surface, and it is two of them. The log sink appends `line + "\n"`
 * verbatim, so ONE newline inside the detail ends the entry and starts a second one the caller
 * wrote — a forged audit line in the operator's own session log. The same line goes to the console,
 * where an ANSI escape repaints whatever terminal is tailing it. The `?error=` on the OIDC callback
 * is public, unauthenticated, and handed over already percent-decoded by Express, so `%0a` is all
 * it takes.
 *
 * Escaped, not stripped: an operator diagnosing a real provider failure should still see that the
 * message contained a newline, rather than read a silently reflowed version of it.
 */
function logSafe(detail: string): string {
  const capped = detail.length > LOGGED_DETAIL_MAX ? `${detail.slice(0, LOGGED_DETAIL_MAX)}…` : detail;
  return capped.replace(CONTROL_CHARS, (c) => `\\x${(c.codePointAt(0) ?? 0).toString(16).padStart(2, "0")}`);
}

/**
 * Send a failed OIDC sign-in back to /login WITHOUT the underlying error text (#674).
 *
 * The three OIDC failure paths used to URL-encode the raw message straight into the redirect, and
 * login.html prints whatever arrives in `?error=` verbatim. Two of those messages are written by
 * the identity provider, not by us: discovery and token-exchange errors carry internal host names,
 * endpoint paths and configuration detail, and the `?error=` the provider hands to the callback is
 * attacker-reachable text reflected back into the page. None of it helps the person signing in —
 * they cannot act on it — while all of it helps someone mapping a team deployment.
 *
 * So the browser gets one fixed sentence plus a short random REFERENCE, and the full detail goes to
 * the server log under that same reference. The operator keeps everything they had for diagnosis;
 * they just have to look in the log, where only they can see it.
 *
 * `stage` is written as a completed failure ("callback failed"), because it is the subject of the
 * log line rather than a label appended to one. `detail` is untrusted on all three paths — two of
 * them carry the provider's own words — so it goes through {@link logSafe} on the way out.
 */
function oidcFailureRedirect(res: Response, stage: string, detail: string): void {
  const reference = randomBytes(4).toString("hex").toUpperCase();
  warnLine(`[oidc] ${stage} (reference ${reference}): ${logSafe(detail)}`);
  const message = `Sign-in with your identity provider failed (reference ${reference}). Ask your administrator to check the server log.`;
  res.redirect(`/login?error=${encodeURIComponent(message)}`);
}

function setSessionCookie(res: Response, auth: TeamAuth, token: string): void {
  res.append("Set-Cookie", auth.sessionCookie(token));
  res.setHeader("Cache-Control", "no-store");
}

function sessionPayload(auth: RequestAuthentication): Record<string, unknown> {
  if (auth.kind !== "session") return {};
  return {
    enabled: true,
    authenticated: true,
    identity: auth.identity,
    csrfToken: auth.session.csrfToken,
    sessionExpiresAt: auth.session.expiresAt,
  };
}

function requireSession(auth: TeamAuth, req: Request, res: Response): RequestAuthentication | null {
  const session = auth.requireSession(req);
  if (!session) {
    res.status(401).json({ error: "authentication required" });
    return null;
  }
  if (!auth.requestCsrfAllowed(req, session)) {
    res.status(403).json({ error: "missing or invalid CSRF token" });
    return null;
  }
  return session;
}

function requireGlobalAdmin(auth: TeamAuth, req: Request, res: Response): RequestAuthentication | null {
  const session = requireSession(auth, req, res);
  if (!session) return null;
  if (!auth.isGlobalAdministrator(session)) {
    res.status(403).json({ error: "global administrator permission required" });
    return null;
  }
  return session;
}

function requireCaseAdmin(
  auth: TeamAuth,
  req: Request,
  res: Response,
  caseId: string,
): RequestAuthentication | null {
  const session = requireSession(auth, req, res);
  if (!session) return null;
  if (!auth.canAdminCase(session, caseId)) {
    res.status(404).json({ error: "case not found or access denied" });
    return null;
  }
  return session;
}

async function serveHtml(asset: string, res: Response): Promise<void> {
  const html = await readPublicAsset(asset, "utf8");
  res.setHeader("Cache-Control", "no-store");
  res.type("html").send(withNonce(html, String(res.locals.cspNonce ?? "")));
}

async function existingCase(cases: CaseStore, caseId: string, res: Response): Promise<boolean> {
  if (isValidCaseId(caseId) && (await cases.caseExists(caseId))) return true;
  res.status(404).json({ error: "case not found or access denied" });
  return false;
}

/**
 * The paths registerTeamAuthRoutes mounts below, as a predicate.
 *
 * These routes are registered BEFORE teamAuth.middleware(), so the request policy never applies to
 * them — POST /auth/local/login and POST /auth/bootstrap are unauthenticated by definition, because
 * they are how a caller GETS a credential. The pre-parse gate in composition/httpStack.ts has to
 * know the same list: a path it lets through with no credential is a path whose body it must parse
 * itself, at the small unauthenticated limit (#681). Add a route here when you add one below.
 *
 * Express routing is neither case-sensitive nor strict, so /AUTH/local/login and /auth/local/login/
 * both reach the handler. Match the way the router matches, or the gate would 401 a spelling the
 * router still serves.
 */
export function isTeamAuthRoutePath(path: string): boolean {
  const normalized = (path.length > 1 ? path.replace(/\/+$/, "") : path).toLowerCase();
  return (
    normalized === "/login" ||
    normalized === "/admin" ||
    normalized === "/auth" ||
    normalized.startsWith("/auth/")
  );
}

export function registerTeamAuthRoutes(app: Express, auth: TeamAuth, cases: CaseStore): void {
  app.use("/auth", (_req, res, next) => {
    res.setHeader("Cache-Control", "no-store");
    next();
  });
  app.get("/login", async (_req, res) => serveHtml("login.html", res));

  app.get("/admin", async (req, res) => {
    const session = auth.requireSession(req);
    if (!session) {
      res.redirect(`/login?returnTo=${encodeURIComponent("/admin")}`);
      return;
    }
    await auth.withRequestIdentity(req, () => serveHtml("admin.html", res));
  });

  app.get("/auth/me", (req: Request, res: Response) => {
    const session = auth.requireSession(req);
    if (!session) {
      return res.status(200).json({
        enabled: true,
        authenticated: false,
        bootstrapRequired: auth.store.countIdentities() === 0,
        oidcEnabled: Boolean(auth.oidcClient),
      });
    }
    return auth.withRequestIdentity(req, () =>
      res.status(200).json({
        ...sessionPayload(session),
        caseRoles: auth.store.rolesForIdentity(session.identity.id),
        oidcEnabled: Boolean(auth.oidcClient),
      }),
    );
  });

  app.get("/auth/oidc/start", async (req: Request, res: Response) => {
    if (!auth.oidcClient) return res.status(404).json({ error: "OIDC is not configured" });
    // The only PUBLIC route that allocates server state: each call stores a state, nonce, verifier,
    // return path and expiry for ten minutes. Unlimited, an unauthenticated caller could allocate
    // memory as fast as it could issue requests. Gated before begin(), so a throttled request costs
    // nothing — no discovery fetch, no flow stored. The client's own hard flow ceiling is the
    // backstop for many clients at once; this bounds any single one.
    if (!getOidcStartLimiter().tryAcquire(req.ip ?? "unknown")) {
      res.setHeader("Retry-After", "60");
      return res.status(429).json({ error: "too many sign-in attempts, try again later" });
    }
    try {
      const started = await auth.oidcClient.begin(
        typeof req.query.returnTo === "string" ? req.query.returnTo : undefined,
      );
      res.setHeader("Set-Cookie", auth.oidcStateCookie(started.state));
      res.setHeader("Cache-Control", "no-store");
      return res.redirect(started.authorizationUrl);
    } catch (err) {
      return oidcFailureRedirect(res, "provider discovery failed", (err as Error).message);
    }
  });

  app.get("/auth/oidc/callback", async (req: Request, res: Response) => {
    if (!auth.oidcClient) return res.status(404).json({ error: "OIDC is not configured" });
    res.setHeader("Set-Cookie", auth.clearOidcStateCookie());
    res.setHeader("Cache-Control", "no-store");
    const providerError = typeof req.query.error === "string" ? req.query.error : "";
    if (providerError) {
      return oidcFailureRedirect(res, "identity provider refused sign-in", providerError);
    }
    const state = typeof req.query.state === "string" ? req.query.state : "";
    const code = typeof req.query.code === "string" ? req.query.code : "";
    if (!state || !code) return res.redirect("/login?error=OIDC%20callback%20is%20incomplete");
    try {
      const completed = await auth.oidcClient.complete({
        state,
        browserState: auth.oidcBrowserState(req.headers.cookie),
        code,
        ...(typeof req.query.iss === "string" ? { responseIssuer: req.query.iss } : {}),
      });
      const identity = auth.store.upsertOidcIdentity(
        completed.claims.issuer,
        completed.claims.subject,
        completed.claims.displayName,
        completed.claims.username,
      );
      if (identity.disabled) return res.redirect("/login?error=This%20account%20is%20disabled");
      const created = auth.store.createSession(identity, auth.sessionTtlMs, {
        ip: req.ip,
        userAgent: req.get("user-agent"),
      });
      setSessionCookie(res, auth, created.token);
      auth.store.addAudit(identity, "oidc-login", identity.id, undefined, "");
      return auth.withIdentity(identity, () => res.redirect(completed.returnTo));
    } catch (err) {
      return oidcFailureRedirect(res, "callback failed", (err as Error).message);
    }
  });

  app.post("/auth/bootstrap", async (req: Request, res: Response) => {
    if (auth.store.countIdentities() !== 0) {
      return res.status(409).json({ error: "authentication has already been bootstrapped" });
    }
    const body = bodyObject(req);
    const suppliedToken = bodyString(body, "bootstrapToken");
    const bootstrapAllowed = auth.bootstrapToken
      ? auth.bootstrapTokenMatches(suppliedToken)
      : auth.isLoopbackRequest(req);
    if (!bootstrapAllowed) return res.status(403).json({ error: "valid bootstrap token required" });
    try {
      const identity = await auth.store.bootstrapLocalAdministrator({
        username: bodyString(body, "username"),
        password: bodyString(body, "password"),
        displayName: bodyString(body, "displayName"),
      });
      const created = auth.store.createSession(identity, auth.sessionTtlMs, {
        ip: req.ip,
        userAgent: req.get("user-agent"),
      });
      setSessionCookie(res, auth, created.token);
      return auth.withIdentity(identity, () =>
        res.status(201).json({
          ...sessionPayload({ kind: "session", identity, session: created.record }),
        }),
      );
    } catch (err) {
      return res.status(400).json({ error: (err as Error).message });
    }
  });

  app.post("/auth/local/login", async (req: Request, res: Response) => {
    const body = bodyObject(req);
    const username = bodyString(body, "username");
    const ip = req.ip ?? "unknown";
    // Client-wide budget FIRST, and consumed by every attempt. The per-account key below is
    // `ip:username`, so rotating the username handed out a fresh bucket per request: the five-try
    // lockout still protected one named account, but an unauthenticated caller could run an
    // unbounded sequence of scrypt verifications, permanent audit rows and limiter Map entries
    // from a single client (#421).
    if (!getLoginIpLimiter().tryAcquire(ip)) {
      res.setHeader("Retry-After", "60");
      return res.status(429).json({ error: "too many attempts, try again later" });
    }
    // A username that could never name an account buys nothing: no lookup, no verification against
    // the dummy hash, no audit row. Same generic 401 as a wrong password — this must not become a
    // way to tell "no such user" from "wrong password".
    if (!isValidUsername(username)) {
      return res.status(401).json({ error: "invalid username or password" });
    }
    const loginLimiter = getLoginLimiter();
    const key = `${ip}:${username.toLowerCase()}`;
    const remaining = loginLimiter.remainingLockout(key);
    if (remaining > 0) {
      res.setHeader("Retry-After", String(Math.ceil(remaining / 1_000)));
      return res.status(429).json({ error: "too many attempts, try again later" });
    }
    const identity = await auth.store.verifyLocalCredentials(username, bodyString(body, "password"));
    if (!identity) {
      loginLimiter.recordFailure(key);
      // Bounded even though isValidUsername already caps it at 64 — the audit table is permanent,
      // and the detail column should never be the place a length assumption is first tested.
      auth.store.addAudit(
        undefined,
        "local-login-failed",
        undefined,
        undefined,
        `username=${username.slice(0, 64)}`,
      );
      return res.status(401).json({ error: "invalid username or password" });
    }
    loginLimiter.clear(key);
    const created = auth.store.createSession(identity, auth.sessionTtlMs, {
      ip: req.ip,
      userAgent: req.get("user-agent"),
    });
    setSessionCookie(res, auth, created.token);
    auth.auditLogin(identity, Boolean(auth.oidcClient));
    return auth.withIdentity(identity, () =>
      res.status(200).json({
        ...sessionPayload({ kind: "session", identity, session: created.record }),
      }),
    );
  });

  app.post("/auth/logout", (req: Request, res: Response) => {
    const session = requireSession(auth, req, res);
    if (!session || session.kind !== "session") return;
    const cookie = req.headers.cookie;
    const token = cookie
      ?.split(";")
      .map((part) => part.trim())
      .find((part) => part.startsWith("dfir_session="))
      ?.slice("dfir_session=".length);
    if (token) auth.store.deleteSessionByToken(decodeURIComponent(token));
    res.setHeader("Set-Cookie", auth.clearSessionCookie());
    res.status(204).end();
  });

  app.get("/auth/sessions", (req: Request, res: Response) => {
    const session = auth.requireSession(req);
    if (!session) return res.status(401).json({ error: "authentication required" });
    return res.status(200).json(
      auth.store.listSessions(session.identity.id).map((item) => ({
        ...item,
        csrfToken: undefined,
        current: session.kind === "session" && item.id === session.session.id,
      })),
    );
  });

  app.delete("/auth/sessions/others", (req: Request, res: Response) => {
    const session = requireSession(auth, req, res);
    if (!session || session.kind !== "session") return;
    const removed = auth.store.deleteOtherSessions(session.identity.id, session.session.id);
    res.status(200).json({ removed });
  });

  app.get("/auth/users", (req: Request, res: Response) => {
    if (!requireGlobalAdmin(auth, req, res)) return;
    res.status(200).json(auth.store.listIdentities().filter((identity) => identity.kind !== "service"));
  });

  app.get("/auth/directory", (req: Request, res: Response) => {
    if (!auth.requireSession(req)) return res.status(401).json({ error: "authentication required" });
    res.status(200).json(
      auth.store
        .listIdentities()
        .filter((identity) => identity.kind !== "service" && !identity.disabled)
        .map(({ id, kind, displayName }) => ({ id, kind, displayName })),
    );
  });

  app.post("/auth/users", async (req: Request, res: Response) => {
    const session = requireGlobalAdmin(auth, req, res);
    if (!session) return;
    const body = bodyObject(req);
    const globalRole = body.globalRole === undefined ? "member" : body.globalRole;
    if (!isGlobalRole(globalRole)) {
      return res.status(400).json({ error: "globalRole must be member or administrator" });
    }
    try {
      const identity = await auth.store.createLocalIdentity(
        {
          username: bodyString(body, "username"),
          password: bodyString(body, "password"),
          displayName: bodyString(body, "displayName"),
          globalRole,
        },
        session.identity,
      );
      return res.status(201).json(identity);
    } catch (err) {
      return res.status(400).json({ error: (err as Error).message });
    }
  });

  app.patch("/auth/users/:identityId", async (req: Request, res: Response) => {
    const session = requireGlobalAdmin(auth, req, res);
    if (!session) return;
    const body = bodyObject(req);
    if (body.globalRole !== undefined && !isGlobalRole(body.globalRole)) {
      return res.status(400).json({ error: "globalRole must be member or administrator" });
    }
    try {
      const updated = await auth.store.updateIdentity(
        req.params.identityId,
        {
          ...(typeof body.displayName === "string" ? { displayName: body.displayName } : {}),
          ...(isGlobalRole(body.globalRole) ? { globalRole: body.globalRole } : {}),
          ...(typeof body.disabled === "boolean" ? { disabled: body.disabled } : {}),
          ...(typeof body.password === "string" ? { password: body.password } : {}),
        },
        session.identity,
      );
      return res.status(200).json(updated);
    } catch (err) {
      return res.status(400).json({ error: (err as Error).message });
    }
  });

  app.get("/auth/cases/:caseId/roles", async (req: Request, res: Response) => {
    if (!(await existingCase(cases, req.params.caseId, res))) return;
    if (!requireCaseAdmin(auth, req, res, req.params.caseId)) return;
    res.status(200).json(
      auth.store.listCaseRoles(req.params.caseId).map((entry) => ({
        identityId: entry.identity.id,
        displayName: entry.identity.displayName,
        kind: entry.identity.kind,
        role: entry.role,
        changedAt: entry.changedAt,
      })),
    );
  });

  app.put("/auth/cases/:caseId/roles/:identityId", async (req: Request, res: Response) => {
    if (!(await existingCase(cases, req.params.caseId, res))) return;
    const session = requireCaseAdmin(auth, req, res, req.params.caseId);
    if (!session) return;
    const role = bodyObject(req).role;
    if (!isCaseRole(role)) {
      return res.status(400).json({ error: "role must be reader, investigator, reviewer, or administrator" });
    }
    if (
      session.identity.id === req.params.identityId &&
      auth.store.getCaseRole(session.identity.id, req.params.caseId) === "administrator" &&
      role !== "administrator" &&
      session.identity.globalRole !== "administrator"
    ) {
      return res.status(409).json({ error: "a case administrator cannot demote their own access" });
    }
    try {
      auth.store.setCaseRole(req.params.caseId, req.params.identityId, role, session.identity);
      return res.status(200).json({ identityId: req.params.identityId, caseId: req.params.caseId, role });
    } catch (err) {
      return res.status(400).json({ error: (err as Error).message });
    }
  });

  app.delete("/auth/cases/:caseId/roles/:identityId", async (req: Request, res: Response) => {
    if (!(await existingCase(cases, req.params.caseId, res))) return;
    const session = requireCaseAdmin(auth, req, res, req.params.caseId);
    if (!session) return;
    if (
      session.identity.id === req.params.identityId &&
      auth.store.getCaseRole(session.identity.id, req.params.caseId) === "administrator" &&
      session.identity.globalRole !== "administrator"
    ) {
      return res.status(409).json({ error: "a case administrator cannot remove their own access" });
    }
    const removed = auth.store.removeCaseRole(req.params.caseId, req.params.identityId, session.identity);
    return res.status(removed ? 204 : 404).end();
  });

  app.get("/auth/service-tokens", (req: Request, res: Response) => {
    const session = auth.requireSession(req);
    if (!session) return res.status(401).json({ error: "authentication required" });
    const tokens = auth.store.listServiceTokens().filter((token) => auth.canAdminCase(session, token.caseId));
    return res.status(200).json(tokens);
  });

  app.post("/auth/service-tokens", async (req: Request, res: Response) => {
    const body = bodyObject(req);
    const caseId = bodyString(body, "caseId");
    if (!(await existingCase(cases, caseId, res))) return;
    const session = requireCaseAdmin(auth, req, res, caseId);
    if (!session) return;
    const permissions = Array.isArray(body.permissions)
      ? [...new Set(body.permissions.filter(isServicePermission))]
      : [];
    try {
      const created = auth.store.createServiceToken(
        {
          name: bodyString(body, "name"),
          caseId,
          permissions,
          ...(typeof body.expiresAt === "string" ? { expiresAt: body.expiresAt } : {}),
        },
        session.identity,
      );
      return res.status(201).json({ ...created.record, token: created.token });
    } catch (err) {
      return res.status(400).json({ error: (err as Error).message });
    }
  });

  app.delete("/auth/service-tokens/:tokenId", (req: Request, res: Response) => {
    const token = auth.store.listServiceTokens().find((candidate) => candidate.id === req.params.tokenId);
    if (!token) return res.status(404).end();
    const session = requireCaseAdmin(auth, req, res, token.caseId);
    if (!session) return;
    const removed = auth.store.revokeServiceToken(req.params.tokenId, session.identity);
    return res.status(removed ? 204 : 404).end();
  });

  app.get("/auth/audit", (req: Request, res: Response) => {
    if (!requireGlobalAdmin(auth, req, res)) return;
    const limit = Number(req.query.limit);
    res.status(200).json(auth.store.listAudit(Number.isFinite(limit) ? limit : undefined));
  });
}
