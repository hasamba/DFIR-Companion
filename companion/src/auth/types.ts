import type { Request } from "express";

export const CASE_ROLES = ["reader", "investigator", "reviewer", "administrator"] as const;
export type CaseRole = (typeof CASE_ROLES)[number];

export const GLOBAL_ROLES = ["member", "administrator"] as const;
export type GlobalRole = (typeof GLOBAL_ROLES)[number];

export const IDENTITY_KINDS = ["local", "oidc", "service"] as const;
export type IdentityKind = (typeof IDENTITY_KINDS)[number];

export const SERVICE_PERMISSIONS = ["read", "write", "review", "export", "capture"] as const;
export type ServicePermission = (typeof SERVICE_PERMISSIONS)[number];

export interface AuthIdentity {
  id: string;
  kind: IdentityKind;
  username?: string;
  displayName: string;
  globalRole: GlobalRole;
  disabled: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface SessionRecord {
  id: string;
  identityId: string;
  csrfToken: string;
  createdAt: string;
  expiresAt: string;
  lastSeenAt: string;
  ip?: string;
  userAgent?: string;
}

/** One case (the default), or every case the owner can currently write to (#2474). */
export type ServiceTokenScope = "case" | "all-cases";

export interface ServiceTokenRecord {
  id: string;
  identityId: string;
  name: string;
  scope: ServiceTokenScope;
  /** The case for a "case" token; "" for an "all-cases" token. */
  caseId: string;
  /** The person an "all-cases" token acts for. Its access is that person's, read per request. */
  ownerIdentityId?: string;
  ownerDisplayName?: string;
  permissions: ServicePermission[];
  createdAt: string;
  expiresAt?: string;
  revokedAt?: string;
}

export type RequestAuthentication =
  | {
      kind: "session";
      identity: AuthIdentity;
      session: SessionRecord;
    }
  | {
      kind: "service-token";
      identity: AuthIdentity;
      token: ServiceTokenRecord;
    };

interface RequestWithAuthentication extends Request {
  dfirAuth?: RequestAuthentication;
}

export function requestAuthentication(req: Request): RequestAuthentication | undefined {
  return (req as RequestWithAuthentication).dfirAuth;
}

export function setRequestAuthentication(req: Request, auth: RequestAuthentication): void {
  (req as RequestWithAuthentication).dfirAuth = auth;
}

export function isCaseRole(value: unknown): value is CaseRole {
  return typeof value === "string" && (CASE_ROLES as readonly string[]).includes(value);
}

export function isGlobalRole(value: unknown): value is GlobalRole {
  return typeof value === "string" && (GLOBAL_ROLES as readonly string[]).includes(value);
}

export function isServicePermission(value: unknown): value is ServicePermission {
  return typeof value === "string" && (SERVICE_PERMISSIONS as readonly string[]).includes(value);
}
