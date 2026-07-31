import type { Express, Request, Response } from "express";
import { AttemptLimiter } from "../http/rateLimiter.js";
import { withNonce } from "../http/securityHeaders.js";
import { readPublicAsset } from "../serverAssets.js";
import type { TeamAuth } from "./teamAuth.js";
import { isValidCaseId, type CaseStore } from "../storage/caseStore.js";
import { isCaseRole, isGlobalRole, isServicePermission, type RequestAuthentication } from "./types.js";

const loginLimiter = new AttemptLimiter(5, 30_000);

function bodyObject(req: Request): Record<string, unknown> {
  return req.body && typeof req.body === "object" && !Array.isArray(req.body)
    ? (req.body as Record<string, unknown>)
    : {};
}

function bodyString(body: Record<string, unknown>, key: string): string {
  return typeof body[key] === "string" ? body[key].trim() : "";
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
    try {
      const started = await auth.oidcClient.begin(
        typeof req.query.returnTo === "string" ? req.query.returnTo : undefined,
      );
      res.setHeader("Set-Cookie", auth.oidcStateCookie(started.state));
      res.setHeader("Cache-Control", "no-store");
      return res.redirect(started.authorizationUrl);
    } catch (err) {
      return res.redirect(`/login?error=${encodeURIComponent((err as Error).message)}`);
    }
  });

  app.get("/auth/oidc/callback", async (req: Request, res: Response) => {
    if (!auth.oidcClient) return res.status(404).json({ error: "OIDC is not configured" });
    res.setHeader("Set-Cookie", auth.clearOidcStateCookie());
    res.setHeader("Cache-Control", "no-store");
    const providerError = typeof req.query.error === "string" ? req.query.error : "";
    if (providerError) {
      return res.redirect(
        `/login?error=${encodeURIComponent(`identity provider refused sign-in: ${providerError}`)}`,
      );
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
      return res.redirect(`/login?error=${encodeURIComponent((err as Error).message)}`);
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
    const key = `${req.ip}:${username.toLowerCase()}`;
    const remaining = loginLimiter.remainingLockout(key);
    if (remaining > 0) {
      res.setHeader("Retry-After", String(Math.ceil(remaining / 1_000)));
      return res.status(429).json({ error: "too many attempts, try again later" });
    }
    const identity = await auth.store.verifyLocalCredentials(username, bodyString(body, "password"));
    if (!identity) {
      loginLimiter.recordFailure(key);
      auth.store.addAudit(undefined, "local-login-failed", undefined, undefined, `username=${username}`);
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
