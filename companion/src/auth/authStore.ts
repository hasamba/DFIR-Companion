import { createHash, randomBytes, randomUUID } from "node:crypto";
import { chmodSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import type { SqliteDatabase } from "../analysis/sqliteRuntime.js";
import { loadDatabaseSync } from "../analysis/sqliteRuntime.js";
import { hashLocalPassword, verifyLocalPassword } from "./password.js";
import {
  type AuthIdentity,
  type CaseRole,
  type GlobalRole,
  type RequestAuthentication,
  type ServicePermission,
  type ServiceTokenRecord,
  type SessionRecord,
  isCaseRole,
  isGlobalRole,
  isServicePermission,
} from "./types.js";

const DUMMY_PASSWORD_HASH =
  "scrypt-v1$16384$8$1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const DEFAULT_AUDIT_LIMIT = 200;
const MAX_AUDIT_LIMIT = 1_000;

export interface AuthAuditEvent {
  id: string;
  timestamp: string;
  actorId?: string;
  actorDisplayName?: string;
  action: string;
  targetId?: string;
  caseId?: string;
  detail: string;
}

export interface CreateLocalIdentityInput {
  username: string;
  password: string;
  displayName: string;
  globalRole?: GlobalRole;
}

export interface CreateServiceTokenInput {
  name: string;
  caseId: string;
  permissions: ServicePermission[];
  expiresAt?: string;
}

interface ServiceTokenCreated {
  record: ServiceTokenRecord;
  identity: AuthIdentity;
  token: string;
}

function row(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("authentication database returned an invalid row");
  }
  return value as Record<string, unknown>;
}

function text(value: unknown, field: string): string {
  if (typeof value !== "string") throw new Error(`authentication database field ${field} is invalid`);
  return value;
}

function optionalText(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function tokenHash(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

const USERNAME_SYNTAX = /^[A-Za-z0-9][A-Za-z0-9._@-]{2,63}$/;

/** The same rule account creation enforces, as a predicate. The login route needs it to reject a
 *  malformed username BEFORE the database lookup, the scrypt verification against the dummy hash,
 *  and the permanent audit row — none of which a string that could never name an account should
 *  ever be able to buy (#421). */
export function isValidUsername(value: string): boolean {
  return USERNAME_SYNTAX.test(value.trim());
}

function normalizeUsername(value: string): string {
  const username = value.trim();
  if (!isValidUsername(username)) {
    throw new Error("username must be 3-64 letters, numbers, dots, dashes, underscores, or @");
  }
  return username;
}

function normalizeDisplayName(value: string): string {
  const displayName = value.trim();
  if (!displayName || displayName.length > 120) {
    throw new Error("displayName must be 1-120 characters");
  }
  return displayName;
}

function identityFromRow(value: unknown): AuthIdentity {
  const source = row(value);
  const kind = text(source.kind, "kind");
  const globalRole = text(source.global_role, "global_role");
  if (kind !== "local" && kind !== "oidc" && kind !== "service") {
    throw new Error("authentication database identity kind is invalid");
  }
  if (!isGlobalRole(globalRole)) throw new Error("authentication database global role is invalid");
  return {
    id: text(source.id, "id"),
    kind,
    ...(optionalText(source.username) ? { username: optionalText(source.username) } : {}),
    displayName: text(source.display_name, "display_name"),
    globalRole,
    disabled: source.disabled === 1,
    createdAt: text(source.created_at, "created_at"),
    updatedAt: text(source.updated_at, "updated_at"),
  };
}

function sessionFromRow(value: unknown): SessionRecord {
  const source = row(value);
  return {
    id: text(source.session_id ?? source.id, "session_id"),
    identityId: text(source.identity_id, "identity_id"),
    csrfToken: text(source.csrf_token, "csrf_token"),
    createdAt: text(source.session_created_at ?? source.created_at, "session_created_at"),
    expiresAt: text(source.expires_at, "expires_at"),
    lastSeenAt: text(source.last_seen_at, "last_seen_at"),
    ...(optionalText(source.ip) ? { ip: optionalText(source.ip) } : {}),
    ...(optionalText(source.user_agent) ? { userAgent: optionalText(source.user_agent) } : {}),
  };
}

function permissionsFromJson(value: unknown): ServicePermission[] {
  if (typeof value !== "string") return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    return [];
  }
  return Array.isArray(parsed) ? [...new Set(parsed.filter(isServicePermission))] : [];
}

function serviceTokenFromRow(value: unknown): ServiceTokenRecord {
  const source = row(value);
  return {
    id: text(source.token_id ?? source.id, "token_id"),
    identityId: text(source.identity_id, "identity_id"),
    name: text(source.token_name ?? source.name, "token_name"),
    caseId: text(source.case_id, "case_id"),
    permissions: permissionsFromJson(source.permissions_json),
    createdAt: text(source.token_created_at ?? source.created_at, "token_created_at"),
    ...(optionalText(source.expires_at) ? { expiresAt: optionalText(source.expires_at) } : {}),
    ...(optionalText(source.revoked_at) ? { revokedAt: optionalText(source.revoked_at) } : {}),
  };
}

export class AuthStore {
  private readonly db: SqliteDatabase;

  constructor(path: string) {
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    const DatabaseSync = loadDatabaseSync();
    this.db = new DatabaseSync(path, { enableForeignKeyConstraints: true });
    chmodSync(path, 0o600);
    this.db.exec(
      "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=10000;",
    );
    this.db.exec(
      "CREATE TABLE IF NOT EXISTS auth_identities (" +
        "id TEXT PRIMARY KEY, kind TEXT NOT NULL, username TEXT, username_key TEXT UNIQUE, " +
        "display_name TEXT NOT NULL, global_role TEXT NOT NULL, disabled INTEGER NOT NULL DEFAULT 0, " +
        "password_hash TEXT, issuer TEXT, subject TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, " +
        "UNIQUE(issuer, subject)" +
        ");" +
        "CREATE TABLE IF NOT EXISTS auth_case_roles (" +
        "case_id TEXT NOT NULL, identity_id TEXT NOT NULL REFERENCES auth_identities(id) ON DELETE CASCADE, " +
        "role TEXT NOT NULL, changed_at TEXT NOT NULL, changed_by_id TEXT, PRIMARY KEY(case_id, identity_id)" +
        ");" +
        "CREATE INDEX IF NOT EXISTS auth_case_roles_identity_idx ON auth_case_roles(identity_id, case_id);" +
        "CREATE TABLE IF NOT EXISTS auth_sessions (" +
        "id TEXT PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE, identity_id TEXT NOT NULL " +
        "REFERENCES auth_identities(id) ON DELETE CASCADE, csrf_token TEXT NOT NULL, created_at TEXT NOT NULL, " +
        "expires_at TEXT NOT NULL, last_seen_at TEXT NOT NULL, ip TEXT, user_agent TEXT" +
        ");" +
        "CREATE INDEX IF NOT EXISTS auth_sessions_identity_idx ON auth_sessions(identity_id, expires_at);" +
        "CREATE TABLE IF NOT EXISTS auth_service_tokens (" +
        "id TEXT PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE, identity_id TEXT NOT NULL " +
        "REFERENCES auth_identities(id) ON DELETE CASCADE, name TEXT NOT NULL, case_id TEXT NOT NULL, " +
        "permissions_json TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT, revoked_at TEXT" +
        ");" +
        "CREATE INDEX IF NOT EXISTS auth_service_case_idx ON auth_service_tokens(case_id, revoked_at);" +
        "CREATE TABLE IF NOT EXISTS auth_audit (" +
        "id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, actor_id TEXT, actor_display_name TEXT, action TEXT NOT NULL, " +
        "target_id TEXT, case_id TEXT, detail TEXT NOT NULL" +
        ");" +
        "CREATE INDEX IF NOT EXISTS auth_audit_time_idx ON auth_audit(timestamp DESC);",
    );
  }

  close(): void {
    this.db.close();
  }

  countIdentities(): number {
    const source = row(this.db.prepare("SELECT COUNT(*) AS count FROM auth_identities").get());
    return typeof source.count === "number" ? source.count : Number(source.count);
  }

  private insertLocalIdentity(input: CreateLocalIdentityInput, passwordHash: string): AuthIdentity {
    const username = normalizeUsername(input.username);
    const displayName = normalizeDisplayName(input.displayName);
    const globalRole = input.globalRole ?? "member";
    const id = `local:${randomUUID()}`;
    const now = new Date().toISOString();
    this.db
      .prepare(
        "INSERT INTO auth_identities " +
          "(id, kind, username, username_key, display_name, global_role, password_hash, created_at, updated_at) " +
          "VALUES (?, 'local', ?, ?, ?, ?, ?, ?, ?)",
      )
      .run(id, username, username.toLowerCase(), displayName, globalRole, passwordHash, now, now);
    return this.getIdentity(id) as AuthIdentity;
  }

  async bootstrapLocalAdministrator(input: CreateLocalIdentityInput): Promise<AuthIdentity> {
    const passwordHash = await hashLocalPassword(input.password);
    this.db.exec("BEGIN IMMEDIATE");
    try {
      if (this.countIdentities() !== 0) throw new Error("authentication has already been bootstrapped");
      const identity = this.insertLocalIdentity({ ...input, globalRole: "administrator" }, passwordHash);
      this.addAudit(
        identity,
        "bootstrap-administrator",
        identity.id,
        undefined,
        "initial local administrator created",
      );
      this.db.exec("COMMIT");
      return identity;
    } catch (err) {
      this.db.exec("ROLLBACK");
      throw err;
    }
  }

  async createLocalIdentity(input: CreateLocalIdentityInput, actor: AuthIdentity): Promise<AuthIdentity> {
    const passwordHash = await hashLocalPassword(input.password);
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const identity = this.insertLocalIdentity(input, passwordHash);
      this.addAudit(actor, "local-user-created", identity.id, undefined, `created ${identity.displayName}`);
      this.db.exec("COMMIT");
      return identity;
    } catch (err) {
      this.db.exec("ROLLBACK");
      throw err;
    }
  }

  async verifyLocalCredentials(username: string, password: string): Promise<AuthIdentity | null> {
    const usernameKey = username.trim().toLowerCase();
    const value = this.db
      .prepare("SELECT * FROM auth_identities WHERE kind='local' AND username_key=?")
      .get(usernameKey);
    const source = value ? row(value) : undefined;
    const passwordHash = source ? text(source.password_hash, "password_hash") : DUMMY_PASSWORD_HASH;
    const valid = await verifyLocalPassword(password, passwordHash);
    if (!valid || !source) return null;
    const identity = identityFromRow(source);
    return identity.disabled ? null : identity;
  }

  getIdentity(id: string): AuthIdentity | null {
    const value = this.db.prepare("SELECT * FROM auth_identities WHERE id=?").get(id);
    return value ? identityFromRow(value) : null;
  }

  listIdentities(): AuthIdentity[] {
    return this.db
      .prepare("SELECT * FROM auth_identities ORDER BY display_name COLLATE NOCASE, created_at")
      .all()
      .map(identityFromRow);
  }

  updateIdentity(
    id: string,
    patch: { displayName?: string; globalRole?: GlobalRole; disabled?: boolean; password?: string },
    actor: AuthIdentity,
  ): Promise<AuthIdentity> {
    return this.updateIdentityAsync(id, patch, actor);
  }

  private async updateIdentityAsync(
    id: string,
    patch: { displayName?: string; globalRole?: GlobalRole; disabled?: boolean; password?: string },
    actor: AuthIdentity,
  ): Promise<AuthIdentity> {
    if (!this.getIdentity(id)) throw new Error("identity not found");
    const passwordHash = patch.password === undefined ? undefined : await hashLocalPassword(patch.password);
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const current = this.getIdentity(id);
      if (!current) throw new Error("identity not found");
      const displayName =
        patch.displayName === undefined ? current.displayName : normalizeDisplayName(patch.displayName);
      const globalRole = patch.globalRole ?? current.globalRole;
      const disabled = patch.disabled ?? current.disabled;
      if (
        current.globalRole === "administrator" &&
        !current.disabled &&
        (globalRole !== "administrator" || disabled)
      ) {
        const count = row(
          this.db
            .prepare(
              "SELECT COUNT(*) AS count FROM auth_identities " +
                "WHERE global_role='administrator' AND disabled=0",
            )
            .get(),
        ).count;
        if (Number(count) <= 1)
          throw new Error("the last active global administrator cannot be disabled or demoted");
      }
      this.db
        .prepare(
          "UPDATE auth_identities SET display_name=?, global_role=?, disabled=?, " +
            "password_hash=COALESCE(?, password_hash), updated_at=? WHERE id=?",
        )
        .run(displayName, globalRole, disabled ? 1 : 0, passwordHash ?? null, new Date().toISOString(), id);
      if (disabled) this.db.prepare("DELETE FROM auth_sessions WHERE identity_id=?").run(id);
      this.addAudit(actor, "identity-updated", id, undefined, `role=${globalRole}; disabled=${disabled}`);
      this.db.exec("COMMIT");
      return this.getIdentity(id) as AuthIdentity;
    } catch (err) {
      this.db.exec("ROLLBACK");
      throw err;
    }
  }

  upsertOidcIdentity(
    issuer: string,
    subject: string,
    displayNameInput: string,
    usernameInput?: string,
  ): AuthIdentity {
    const currentValue = this.db
      .prepare("SELECT * FROM auth_identities WHERE issuer=? AND subject=?")
      .get(issuer, subject);
    const displayName = normalizeDisplayName(displayNameInput);
    const username = usernameInput?.trim().slice(0, 120) || undefined;
    const now = new Date().toISOString();
    if (currentValue) {
      const current = identityFromRow(currentValue);
      this.db
        .prepare("UPDATE auth_identities SET display_name=?, username=?, updated_at=? WHERE id=?")
        .run(displayName, username ?? null, now, current.id);
      return this.getIdentity(current.id) as AuthIdentity;
    }
    const stable = createHash("sha256").update(`${issuer}\0${subject}`).digest("base64url");
    const id = `oidc:${stable}`;
    this.db
      .prepare(
        "INSERT INTO auth_identities " +
          "(id, kind, username, display_name, global_role, issuer, subject, created_at, updated_at) " +
          "VALUES (?, 'oidc', ?, ?, 'member', ?, ?, ?, ?)",
      )
      .run(id, username ?? null, displayName, issuer, subject, now, now);
    return this.getIdentity(id) as AuthIdentity;
  }

  createSession(
    identity: AuthIdentity,
    ttlMs: number,
    metadata: { ip?: string; userAgent?: string } = {},
  ): { record: SessionRecord; token: string } {
    const id = randomUUID();
    const token = randomBytes(32).toString("base64url");
    const csrfToken = randomBytes(32).toString("base64url");
    const nowMs = Date.now();
    const createdAt = new Date(nowMs).toISOString();
    const expiresAt = new Date(nowMs + ttlMs).toISOString();
    this.db
      .prepare(
        "INSERT INTO auth_sessions " +
          "(id, token_hash, identity_id, csrf_token, created_at, expires_at, last_seen_at, ip, user_agent) " +
          "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
      )
      .run(
        id,
        tokenHash(token),
        identity.id,
        csrfToken,
        createdAt,
        expiresAt,
        createdAt,
        metadata.ip ?? null,
        metadata.userAgent ?? null,
      );
    return {
      token,
      record: {
        id,
        identityId: identity.id,
        csrfToken,
        createdAt,
        expiresAt,
        lastSeenAt: createdAt,
        ...metadata,
      },
    };
  }

  authenticateSession(token: string): RequestAuthentication | null {
    const value = this.db
      .prepare(
        "SELECT s.id AS session_id, s.identity_id, s.csrf_token, " +
          "s.created_at AS session_created_at, s.expires_at, s.last_seen_at, s.ip, s.user_agent, i.* " +
          "FROM auth_sessions s JOIN auth_identities i ON i.id=s.identity_id WHERE s.token_hash=?",
      )
      .get(tokenHash(token));
    if (!value) return null;
    const source = row(value);
    if (source.disabled === 1 || Date.parse(text(source.expires_at, "expires_at")) <= Date.now()) {
      this.db.prepare("DELETE FROM auth_sessions WHERE id=?").run(text(source.session_id, "session_id"));
      return null;
    }
    return {
      kind: "session",
      identity: identityFromRow(source),
      session: sessionFromRow(source),
    };
  }

  touchSession(id: string, lastSeenAt: string): void {
    this.db.prepare("UPDATE auth_sessions SET last_seen_at=? WHERE id=?").run(lastSeenAt, id);
  }

  deleteSessionByToken(token: string): void {
    this.db.prepare("DELETE FROM auth_sessions WHERE token_hash=?").run(tokenHash(token));
  }

  deleteOtherSessions(identityId: string, currentSessionId: string): number {
    const result = this.db
      .prepare("DELETE FROM auth_sessions WHERE identity_id=? AND id<>?")
      .run(identityId, currentSessionId);
    return Number(result.changes);
  }

  /**
   * Drop every session whose expiry has passed. Returns how many rows went.
   *
   * authenticateSession already deletes an expired session, but only the one it was just handed —
   * a session whose owner never comes back with that cookie is never looked at again, so it sits in
   * the table for the life of the deployment. listSessions filters on expires_at, so nothing reads
   * stale rows; they simply accumulate, and the file grows with every sign-in that is not signed
   * out. Sweeping on a timer bounds that (#676). Row-shaped, not VACUUM: reclaiming pages is a
   * separate, far more expensive operation, and the point here is to stop the row count climbing.
   *
   * `expires_at` is a UTC ISO-8601 string, which sorts lexicographically in the same order it sorts
   * chronologically — the same comparison listSessions already makes.
   */
  deleteExpiredSessions(now: Date = new Date()): number {
    const result = this.db.prepare("DELETE FROM auth_sessions WHERE expires_at<=?").run(now.toISOString());
    return Number(result.changes);
  }

  listSessions(identityId: string): SessionRecord[] {
    return this.db
      .prepare(
        "SELECT id AS session_id, identity_id, csrf_token, created_at AS session_created_at, " +
          "expires_at, last_seen_at, ip, user_agent FROM auth_sessions " +
          "WHERE identity_id=? AND expires_at>? ORDER BY last_seen_at DESC",
      )
      .all(identityId, new Date().toISOString())
      .map(sessionFromRow);
  }

  getCaseRole(identityId: string, caseId: string): CaseRole | null {
    const value = this.db
      .prepare("SELECT role FROM auth_case_roles WHERE identity_id=? AND case_id=?")
      .get(identityId, caseId);
    if (!value) return null;
    const role = row(value).role;
    return isCaseRole(role) ? role : null;
  }

  listCaseRoles(caseId: string): Array<{ identity: AuthIdentity; role: CaseRole; changedAt: string }> {
    return this.db
      .prepare(
        "SELECT r.role, r.changed_at, i.* FROM auth_case_roles r " +
          "JOIN auth_identities i ON i.id=r.identity_id WHERE r.case_id=? " +
          "ORDER BY i.display_name COLLATE NOCASE",
      )
      .all(caseId)
      .flatMap((value) => {
        const source = row(value);
        if (!isCaseRole(source.role)) return [];
        return [
          {
            identity: identityFromRow(source),
            role: source.role,
            changedAt: text(source.changed_at, "changed_at"),
          },
        ];
      });
  }

  rolesForIdentity(identityId: string): Record<string, CaseRole> {
    const roles: Record<string, CaseRole> = {};
    for (const value of this.db
      .prepare("SELECT case_id, role FROM auth_case_roles WHERE identity_id=?")
      .all(identityId)) {
      const source = row(value);
      if (typeof source.case_id === "string" && isCaseRole(source.role)) {
        roles[source.case_id] = source.role;
      }
    }
    return roles;
  }

  setCaseRole(caseId: string, identityId: string, role: CaseRole, actor: AuthIdentity): void {
    const identity = this.getIdentity(identityId);
    if (!identity) throw new Error("identity not found");
    if (identity.disabled) throw new Error("disabled identities cannot receive case access");
    const now = new Date().toISOString();
    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.db
        .prepare(
          "INSERT INTO auth_case_roles (case_id, identity_id, role, changed_at, changed_by_id) " +
            "VALUES (?, ?, ?, ?, ?) ON CONFLICT(case_id, identity_id) DO UPDATE SET " +
            "role=excluded.role, changed_at=excluded.changed_at, changed_by_id=excluded.changed_by_id",
        )
        .run(caseId, identityId, role, now, actor.id);
      this.addAudit(actor, "case-role-set", identityId, caseId, `role=${role}`);
      this.db.exec("COMMIT");
    } catch (err) {
      this.db.exec("ROLLBACK");
      throw err;
    }
  }

  removeCaseRole(caseId: string, identityId: string, actor: AuthIdentity): boolean {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const result = this.db
        .prepare("DELETE FROM auth_case_roles WHERE case_id=? AND identity_id=?")
        .run(caseId, identityId);
      const removed = Number(result.changes) > 0;
      if (removed) this.addAudit(actor, "case-role-removed", identityId, caseId, "");
      this.db.exec("COMMIT");
      return removed;
    } catch (err) {
      this.db.exec("ROLLBACK");
      throw err;
    }
  }

  deleteCaseAccess(caseId: string, actor?: AuthIdentity): void {
    const now = new Date().toISOString();
    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.db
        .prepare(
          "UPDATE auth_identities SET disabled=1, updated_at=? WHERE id IN " +
            "(SELECT identity_id FROM auth_service_tokens WHERE case_id=?)",
        )
        .run(now, caseId);
      this.db
        .prepare("UPDATE auth_service_tokens SET revoked_at=COALESCE(revoked_at, ?) WHERE case_id=?")
        .run(now, caseId);
      this.db.prepare("DELETE FROM auth_case_roles WHERE case_id=?").run(caseId);
      this.addAudit(actor, "case-access-deleted", undefined, caseId, "roles and service tokens revoked");
      this.db.exec("COMMIT");
    } catch (err) {
      this.db.exec("ROLLBACK");
      throw err;
    }
  }

  visibleCaseIds(identity: AuthIdentity): Set<string> | null {
    if (identity.globalRole === "administrator") return null;
    return new Set(Object.keys(this.rolesForIdentity(identity.id)));
  }

  createServiceToken(input: CreateServiceTokenInput, actor: AuthIdentity): ServiceTokenCreated {
    const name = normalizeDisplayName(input.name);
    const permissions = [...new Set(input.permissions.filter(isServicePermission))];
    if (permissions.length === 0) throw new Error("at least one service-token permission is required");
    if (
      input.expiresAt &&
      (!Number.isFinite(Date.parse(input.expiresAt)) || Date.parse(input.expiresAt) <= Date.now())
    ) {
      throw new Error("expiresAt must be a future ISO timestamp");
    }
    const id = `service:${randomUUID()}`;
    const tokenId = randomUUID();
    const token = `dfirsvc_${randomBytes(32).toString("base64url")}`;
    const now = new Date().toISOString();
    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.db
        .prepare(
          "INSERT INTO auth_identities " +
            "(id, kind, display_name, global_role, created_at, updated_at) " +
            "VALUES (?, 'service', ?, 'member', ?, ?)",
        )
        .run(id, name, now, now);
      this.db
        .prepare(
          "INSERT INTO auth_service_tokens " +
            "(id, token_hash, identity_id, name, case_id, permissions_json, created_at, expires_at) " +
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .run(
          tokenId,
          tokenHash(token),
          id,
          name,
          input.caseId,
          JSON.stringify(permissions),
          now,
          input.expiresAt ?? null,
        );
      this.addAudit(actor, "service-token-created", id, input.caseId, `permissions=${permissions.join(",")}`);
      this.db.exec("COMMIT");
      const identity = this.getIdentity(id) as AuthIdentity;
      return {
        identity,
        token,
        record: {
          id: tokenId,
          identityId: id,
          name,
          caseId: input.caseId,
          permissions,
          createdAt: now,
          ...(input.expiresAt ? { expiresAt: input.expiresAt } : {}),
        },
      };
    } catch (err) {
      this.db.exec("ROLLBACK");
      throw err;
    }
  }

  authenticateServiceToken(token: string): RequestAuthentication | null {
    const value = this.db
      .prepare(
        "SELECT t.id AS token_id, t.identity_id, t.name AS token_name, t.case_id, " +
          "t.permissions_json, t.created_at AS token_created_at, t.expires_at, t.revoked_at, i.* " +
          "FROM auth_service_tokens t JOIN auth_identities i ON i.id=t.identity_id WHERE t.token_hash=?",
      )
      .get(tokenHash(token));
    if (!value) return null;
    const source = row(value);
    if (
      source.disabled === 1 ||
      source.revoked_at ||
      (typeof source.expires_at === "string" && Date.parse(source.expires_at) <= Date.now())
    ) {
      return null;
    }
    return {
      kind: "service-token",
      identity: identityFromRow(source),
      token: serviceTokenFromRow(source),
    };
  }

  listServiceTokens(): ServiceTokenRecord[] {
    return this.db
      .prepare(
        "SELECT id AS token_id, identity_id, name AS token_name, case_id, permissions_json, " +
          "created_at AS token_created_at, expires_at, revoked_at FROM auth_service_tokens " +
          "ORDER BY created_at DESC",
      )
      .all()
      .map(serviceTokenFromRow);
  }

  revokeServiceToken(id: string, actor: AuthIdentity): boolean {
    const tokenValue = this.db
      .prepare("SELECT identity_id, case_id FROM auth_service_tokens WHERE id=? AND revoked_at IS NULL")
      .get(id);
    if (!tokenValue) return false;
    const source = row(tokenValue);
    const now = new Date().toISOString();
    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.db.prepare("UPDATE auth_service_tokens SET revoked_at=? WHERE id=?").run(now, id);
      this.db
        .prepare("UPDATE auth_identities SET disabled=1, updated_at=? WHERE id=?")
        .run(now, text(source.identity_id, "identity_id"));
      this.addAudit(
        actor,
        "service-token-revoked",
        text(source.identity_id, "identity_id"),
        text(source.case_id, "case_id"),
        "",
      );
      this.db.exec("COMMIT");
      return true;
    } catch (err) {
      this.db.exec("ROLLBACK");
      throw err;
    }
  }

  addAudit(
    actor: AuthIdentity | undefined,
    action: string,
    targetId: string | undefined,
    caseId: string | undefined,
    detail: string,
  ): AuthAuditEvent {
    const event: AuthAuditEvent = {
      id: randomUUID(),
      timestamp: new Date().toISOString(),
      ...(actor ? { actorId: actor.id, actorDisplayName: actor.displayName } : {}),
      action,
      ...(targetId ? { targetId } : {}),
      ...(caseId ? { caseId } : {}),
      detail,
    };
    this.db
      .prepare(
        "INSERT INTO auth_audit " +
          "(id, timestamp, actor_id, actor_display_name, action, target_id, case_id, detail) " +
          "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      )
      .run(
        event.id,
        event.timestamp,
        event.actorId ?? null,
        event.actorDisplayName ?? null,
        event.action,
        event.targetId ?? null,
        event.caseId ?? null,
        event.detail,
      );
    return event;
  }

  listAudit(limit = DEFAULT_AUDIT_LIMIT): AuthAuditEvent[] {
    const bounded = Math.min(MAX_AUDIT_LIMIT, Math.max(1, Math.floor(limit)));
    return this.db
      .prepare("SELECT * FROM auth_audit ORDER BY timestamp DESC LIMIT ?")
      .all(bounded)
      .map((value) => {
        const source = row(value);
        return {
          id: text(source.id, "id"),
          timestamp: text(source.timestamp, "timestamp"),
          ...(optionalText(source.actor_id) ? { actorId: optionalText(source.actor_id) } : {}),
          ...(optionalText(source.actor_display_name)
            ? { actorDisplayName: optionalText(source.actor_display_name) }
            : {}),
          action: text(source.action, "action"),
          ...(optionalText(source.target_id) ? { targetId: optionalText(source.target_id) } : {}),
          ...(optionalText(source.case_id) ? { caseId: optionalText(source.case_id) } : {}),
          detail: text(source.detail, "detail"),
        };
      });
  }
}
