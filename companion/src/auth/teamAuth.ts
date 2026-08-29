import { timingSafeEqual } from "node:crypto";
import type { NextFunction, Request, RequestHandler, Response } from "express";
import { parseCookieHeader } from "../analysis/casePassword.js";
import { runWithIdentity } from "./identityContext.js";
import {
  caseRoleAllows,
  resolveRequestPolicy,
  servicePermissionAllows,
  type CasePermission,
  type RequestPolicy,
} from "./policy.js";
import type { AuthStore } from "./authStore.js";
import {
  requestAuthentication,
  setRequestAuthentication,
  type AuthIdentity,
  type RequestAuthentication,
} from "./types.js";
import type { OidcClient } from "./oidcClient.js";

export const SESSION_COOKIE = "dfir_session";
export const OIDC_STATE_COOKIE = "dfir_oidc_state";
const TOUCH_INTERVAL_MS = 5 * 60_000;

export interface TeamAuthOptions {
  store: AuthStore;
  bootstrapToken?: string;
  cookieSecure: boolean;
  sessionTtlMs: number;
  oidcClient?: OidcClient;
}

function safeStringEqual(left: string, right: string): boolean {
  const leftBytes = Buffer.from(left, "utf8");
  const rightBytes = Buffer.from(right, "utf8");
  return leftBytes.length === rightBytes.length && timingSafeEqual(leftBytes, rightBytes);
}

function acceptsHtml(req: Request): boolean {
  return req.method === "GET" && (req.headers.accept ?? "").includes("text/html");
}

function bearerToken(req: Request): string | undefined {
  const authorization = req.headers.authorization;
  if (!authorization) return undefined;
  const match = /^Bearer ([A-Za-z0-9_-]{20,})$/.exec(authorization.trim());
  return match?.[1];
}

export class TeamAuth {
  readonly store: AuthStore;
  readonly bootstrapToken?: string;
  readonly cookieSecure: boolean;
  readonly sessionTtlMs: number;
  readonly oidcClient?: OidcClient;

  constructor(options: TeamAuthOptions) {
    this.store = options.store;
    this.bootstrapToken = options.bootstrapToken;
    this.cookieSecure = options.cookieSecure;
    this.sessionTtlMs = options.sessionTtlMs;
    this.oidcClient = options.oidcClient;
  }

  sessionCookie(token: string): string {
    return [
      `${SESSION_COOKIE}=${encodeURIComponent(token)}`,
      "Path=/",
      "HttpOnly",
      "SameSite=Strict",
      this.cookieSecure ? "Secure" : "",
      `Max-Age=${Math.floor(this.sessionTtlMs / 1_000)}`,
    ]
      .filter(Boolean)
      .join("; ");
  }

  clearSessionCookie(): string {
    return [
      `${SESSION_COOKIE}=`,
      "Path=/",
      "HttpOnly",
      "SameSite=Strict",
      this.cookieSecure ? "Secure" : "",
      "Max-Age=0",
    ]
      .filter(Boolean)
      .join("; ");
  }

  oidcStateCookie(state: string): string {
    return [
      `${OIDC_STATE_COOKIE}=${encodeURIComponent(state)}`,
      "Path=/auth/oidc/callback",
      "HttpOnly",
      "SameSite=Lax",
      this.cookieSecure ? "Secure" : "",
      "Max-Age=600",
    ]
      .filter(Boolean)
      .join("; ");
  }

  clearOidcStateCookie(): string {
    return [
      `${OIDC_STATE_COOKIE}=`,
      "Path=/auth/oidc/callback",
      "HttpOnly",
      "SameSite=Lax",
      this.cookieSecure ? "Secure" : "",
      "Max-Age=0",
    ]
      .filter(Boolean)
      .join("; ");
  }

  oidcBrowserState(cookieHeader: string | undefined): string {
    return parseCookieHeader(cookieHeader)[OIDC_STATE_COOKIE] ?? "";
  }

  bootstrapTokenMatches(candidate: string): boolean {
    return this.bootstrapToken !== undefined && safeStringEqual(candidate, this.bootstrapToken);
  }

  isLoopbackRequest(req: Request): boolean {
    const address = req.socket.remoteAddress ?? "";
    return address === "127.0.0.1" || address === "::1" || address === "::ffff:127.0.0.1";
  }

  authenticateCookieHeader(cookieHeader: string | undefined): RequestAuthentication | null {
    const token = parseCookieHeader(cookieHeader)[SESSION_COOKIE];
    return token ? this.store.authenticateSession(token) : null;
  }

  authenticateRequest(req: Request): RequestAuthentication | null {
    const token = bearerToken(req);
    if (req.headers.authorization && !token) return null;
    const auth = token
      ? this.store.authenticateServiceToken(token)
      : this.authenticateCookieHeader(req.headers.cookie);
    if (auth?.kind === "session") {
      const seen = Date.parse(auth.session.lastSeenAt);
      if (!Number.isFinite(seen) || Date.now() - seen >= TOUCH_INTERVAL_MS) {
        const now = new Date().toISOString();
        this.store.touchSession(auth.session.id, now);
        auth.session = { ...auth.session, lastSeenAt: now };
      }
    }
    return auth;
  }

  private sessionCaseAllowed(
    auth: RequestAuthentication,
    caseId: string,
    permission: CasePermission,
  ): boolean {
    if (auth.kind !== "session") return false;
    if (auth.identity.globalRole === "administrator") return true;
    const role = this.store.getCaseRole(auth.identity.id, caseId);
    return role !== null && caseRoleAllows(role, permission);
  }

  private serviceCaseAllowed(
    auth: RequestAuthentication,
    caseId: string,
    permission: CasePermission,
  ): boolean {
    return (
      auth.kind === "service-token" &&
      auth.token.caseId === caseId &&
      servicePermissionAllows(auth.token.permissions, permission)
    );
  }

  canAccessCase(auth: RequestAuthentication, caseId: string, permission: CasePermission): boolean {
    return (
      this.sessionCaseAllowed(auth, caseId, permission) || this.serviceCaseAllowed(auth, caseId, permission)
    );
  }

  private authorized(auth: RequestAuthentication, policy: RequestPolicy, req: Request): boolean {
    if (policy.kind === "case-list") {
      return (
        auth.kind === "session" ||
        (auth.kind === "service-token" && servicePermissionAllows(auth.token.permissions, "read"))
      );
    }
    if (policy.kind === "authenticated") return auth.kind === "session";
    if (policy.kind === "global") {
      return auth.kind === "session" && auth.identity.globalRole === "administrator";
    }
    if (policy.kind === "case") {
      if (policy.permission === "export" && req.body?.removeFromList === true) {
        return this.sessionCaseAllowed(auth, policy.caseId, "admin");
      }
      return this.canAccessCase(auth, policy.caseId, policy.permission);
    }
    if (policy.kind === "capture") {
      const caseId = typeof req.body?.caseId === "string" ? req.body.caseId.trim() : "";
      if (!caseId) return false;
      return (
        this.sessionCaseAllowed(auth, caseId, "write") ||
        (auth.kind === "service-token" &&
          auth.token.caseId === caseId &&
          (auth.token.permissions.includes("capture") || auth.token.permissions.includes("write")))
      );
    }
    return true;
  }

  private knowsCase(auth: RequestAuthentication, caseId: string): boolean {
    if (auth.kind === "service-token") return auth.token.caseId === caseId;
    return (
      auth.identity.globalRole === "administrator" ||
      this.store.getCaseRole(auth.identity.id, caseId) !== null
    );
  }

  private csrfAllowed(auth: RequestAuthentication, req: Request): boolean {
    if (auth.kind === "service-token") return true;
    if (req.method === "GET" || req.method === "HEAD" || req.method === "OPTIONS") return true;
    const supplied = req.get("X-DFIR-CSRF") ?? "";
    return safeStringEqual(supplied, auth.session.csrfToken);
  }

  /**
   * The answer to a request that carries no usable credential: a login redirect for a browser
   * navigation, a 401 for everything else.
   *
   * Exported as a method because TWO layers now send it. composition/httpStack.ts runs a pre-parse
   * gate BEFORE the body parsers so an unauthenticated caller cannot make the process inflate,
   * allocate and JSON-parse hundreds of MB on its way to this same 401 (#681). The two must answer
   * identically — a client that used to be redirected to /login must still be redirected — so the
   * answer lives here once instead of being copied there.
   */
  rejectUnauthenticated(req: Request, res: Response): void {
    if (acceptsHtml(req)) {
      res.redirect(`/login?returnTo=${encodeURIComponent(req.originalUrl)}`);
      return;
    }
    res.status(401).json({ error: "authentication required" });
  }

  middleware(): RequestHandler {
    return (req: Request, res: Response, next: NextFunction): void => {
      const policy = resolveRequestPolicy(req.method, req.path);
      if (policy.kind === "public") {
        next();
        return;
      }
      const auth = this.authenticateRequest(req);
      if (!auth) {
        this.rejectUnauthenticated(req, res);
        return;
      }
      if (!this.authorized(auth, policy, req)) {
        if (policy.kind === "case") {
          const visible = this.knowsCase(auth, policy.caseId);
          res.status(visible ? 403 : 404).json({
            error: visible ? "case role does not permit this action" : "case not found or access denied",
          });
          return;
        }
        if (policy.kind === "capture") {
          const caseId = typeof req.body?.caseId === "string" ? req.body.caseId.trim() : "";
          const visible = Boolean(caseId) && this.knowsCase(auth, caseId);
          res.status(visible ? 403 : 404).json({
            error: visible ? "case role does not permit capture" : "case not found or access denied",
          });
          return;
        }
        res.status(403).json({ error: "administrator permission required" });
        return;
      }
      if (!this.csrfAllowed(auth, req)) {
        res.status(403).json({ error: "missing or invalid CSRF token" });
        return;
      }
      setRequestAuthentication(req, auth);
      runWithIdentity(auth.identity, next);
    };
  }

  requireSession(req: Request): RequestAuthentication | null {
    const auth = this.authenticateRequest(req);
    return auth?.kind === "session" ? auth : null;
  }

  requestCsrfAllowed(req: Request, auth: RequestAuthentication): boolean {
    return this.csrfAllowed(auth, req);
  }

  isGlobalAdministrator(auth: RequestAuthentication): boolean {
    return auth.kind === "session" && auth.identity.globalRole === "administrator";
  }

  canAdminCase(auth: RequestAuthentication, caseId: string): boolean {
    return this.sessionCaseAllowed(auth, caseId, "admin");
  }

  visibleCaseIds(req: Request): Set<string> | null {
    const auth = requestAuthentication(req) ?? this.authenticateRequest(req);
    if (!auth) return new Set();
    if (auth.kind === "service-token") return new Set([auth.token.caseId]);
    return this.store.visibleCaseIds(auth.identity);
  }

  grantCreator(req: Request, caseId: string): void {
    const auth = requestAuthentication(req);
    if (auth?.kind === "session") {
      this.store.setCaseRole(caseId, auth.identity.id, "administrator", auth.identity);
    }
  }

  canReadCase(req: Request, caseId: string): boolean {
    const auth = requestAuthentication(req) ?? this.authenticateRequest(req);
    return auth !== null && this.canAccessCase(auth, caseId, "read");
  }

  canWriteCase(req: Request, caseId: string): boolean {
    const auth = requestAuthentication(req) ?? this.authenticateRequest(req);
    return auth !== null && this.canAccessCase(auth, caseId, "write");
  }

  authorizeWebSocket(cookieHeader: string | undefined, caseId: string): boolean {
    const auth = this.authenticateCookieHeader(cookieHeader);
    return auth !== null && this.sessionCaseAllowed(auth, caseId, "read");
  }

  withRequestIdentity<T>(req: Request, fn: (auth: RequestAuthentication) => T): T | undefined {
    const auth = requestAuthentication(req) ?? this.authenticateRequest(req);
    if (!auth) return undefined;
    setRequestAuthentication(req, auth);
    return runWithIdentity(auth.identity, () => fn(auth));
  }

  withIdentity<T>(identity: AuthIdentity, fn: () => T): T {
    return runWithIdentity(identity, fn);
  }

  auditLogin(identity: AuthIdentity, emergency: boolean): void {
    this.store.addAudit(
      identity,
      emergency ? "emergency-local-login" : "local-login",
      identity.id,
      undefined,
      emergency ? "OIDC fallback account used" : "",
    );
  }
}
