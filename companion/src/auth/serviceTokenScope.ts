/**
 * Service-token scopes (#2474) and the row mapping for stored tokens.
 *
 * A token is either pinned to ONE case (the original behaviour, still the default) or acts for its
 * OWNER on every case the owner can currently write to ("all-cases"). The all-cases scope carries no
 * access of its own: TeamAuth reads the owner's current case role on every request. The rules here
 * are the creation-time limits that keep it contained — permissions capped at capture + write, and a
 * required expiry no more than 90 days out.
 *
 * Kept out of authStore.ts, which sits at the file-size ceiling.
 */
import type { SqliteDatabase } from "../analysis/sqliteRuntime.js";
import {
  type ServicePermission,
  type ServiceTokenRecord,
  type ServiceTokenScope,
  isServicePermission,
} from "./types.js";

const DAY_MS = 24 * 60 * 60_000;
/** The UI pre-fills this; the server requires an explicit expiry. */
export const ALL_CASES_DEFAULT_EXPIRY_DAYS = 30;
export const ALL_CASES_MAX_EXPIRY_DAYS = 90;
/** Whatever is asked for, an all-cases token never holds more than these. */
export const ALL_CASES_PERMISSIONS: readonly ServicePermission[] = ["capture", "write"];
/** Stored in the NOT NULL case_id column for all-cases rows; never a valid case id. */
export const ALL_CASES_CASE_ID = "";

/**
 * Token lookup for authentication. Owner columns are aliased so they can never be mistaken for the
 * service identity's own `i.*` fields, whose revoked/disabled checks always still apply.
 */
export const AUTHENTICATE_TOKEN_SQL =
  "SELECT t.id AS token_id, t.identity_id, t.name AS token_name, t.case_id, " +
  "t.permissions_json, t.created_at AS token_created_at, t.expires_at, t.revoked_at, " +
  "t.scope, t.owner_identity_id, CASE WHEN o.id IS NULL THEN 0 ELSE 1 END AS owner_exists, " +
  "o.disabled AS owner_disabled, o.kind AS owner_kind, o.display_name AS owner_display_name, i.* " +
  "FROM auth_service_tokens t JOIN auth_identities i ON i.id=t.identity_id " +
  "LEFT JOIN auth_identities o ON o.id=t.owner_identity_id WHERE t.token_hash=?";

export const LIST_TOKENS_SQL =
  "SELECT t.id AS token_id, t.identity_id, t.name AS token_name, t.case_id, t.permissions_json, " +
  "t.created_at AS token_created_at, t.expires_at, t.revoked_at, t.scope, t.owner_identity_id, " +
  "o.display_name AS owner_display_name FROM auth_service_tokens t " +
  "LEFT JOIN auth_identities o ON o.id=t.owner_identity_id ORDER BY t.created_at DESC";

export const INSERT_TOKEN_SQL =
  "INSERT INTO auth_service_tokens (id, token_hash, identity_id, name, case_id, permissions_json, " +
  "created_at, expires_at, scope, owner_identity_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

/** Parses a requested scope. Absent means the legacy single-case scope; anything unknown is null. */
export function parseServiceTokenScope(value: unknown): ServiceTokenScope | null {
  if (value === undefined || value === null || value === "case") return "case";
  return value === "all-cases" ? "all-cases" : null;
}

/** The requested permissions cut down to capture + write; throws when nothing is left. */
export function capAllCasesPermissions(requested: readonly ServicePermission[]): ServicePermission[] {
  const capped = ALL_CASES_PERMISSIONS.filter((permission) => requested.includes(permission));
  if (capped.length === 0) {
    throw new Error("an all-cases token needs the capture or write permission");
  }
  return capped;
}

/** Throws unless `expiresAt` is a real timestamp in the future and within the 90-day maximum. */
export function assertAllCasesExpiry(expiresAt: string | undefined, now = Date.now()): string {
  if (!expiresAt) throw new Error("an all-cases token needs an expiry date");
  const at = Date.parse(expiresAt);
  if (!Number.isFinite(at) || at <= now) throw new Error("expiresAt must be a future ISO timestamp");
  if (at > now + ALL_CASES_MAX_EXPIRY_DAYS * DAY_MS) {
    throw new Error(`an all-cases token can last at most ${ALL_CASES_MAX_EXPIRY_DAYS} days`);
  }
  return new Date(at).toISOString();
}

/**
 * Whether a stored expiry still allows use. Fails closed: a value that is not a parseable timestamp
 * refuses the token rather than reading as "never expires" (NaN <= now is false).
 */
export function expiryAllowsUse(expiresAt: unknown, now = Date.now()): boolean {
  if (expiresAt === null || expiresAt === undefined) return true;
  if (typeof expiresAt !== "string") return false;
  const at = Date.parse(expiresAt);
  return Number.isFinite(at) && at > now;
}

/** SQL NULL is a record from before #2474 and means one case; any other unknown value is invalid. */
export function storedScope(value: unknown): ServiceTokenScope | null {
  if (value === null || value === undefined) return "case";
  return value === "case" || value === "all-cases" ? value : null;
}

/** Adds the scope and owner columns to a database created before #2474. Idempotent. */
export function migrateServiceTokenScope(db: SqliteDatabase): void {
  const columns = new Set(
    db
      .prepare("PRAGMA table_info(auth_service_tokens)")
      .all()
      .map((value) => (value as { name?: unknown }).name),
  );
  if (!columns.has("scope")) db.exec("ALTER TABLE auth_service_tokens ADD COLUMN scope TEXT");
  if (!columns.has("owner_identity_id")) {
    db.exec("ALTER TABLE auth_service_tokens ADD COLUMN owner_identity_id TEXT");
  }
}

function text(value: unknown, field: string): string {
  if (typeof value !== "string") throw new Error(`authentication database field ${field} is invalid`);
  return value;
}

function optionalText(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

export function permissionsFromJson(value: unknown): ServicePermission[] {
  if (typeof value !== "string") return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    return [];
  }
  return Array.isArray(parsed) ? [...new Set(parsed.filter(isServicePermission))] : [];
}

/** Maps a stored token row. An unknown scope is reported as an error, never as a case token. */
export function serviceTokenFromRow(source: Record<string, unknown>): ServiceTokenRecord {
  const scope = storedScope(source.scope);
  if (!scope) throw new Error("authentication database field scope is invalid");
  const owner = optionalText(source.owner_identity_id);
  const ownerName = optionalText(source.owner_display_name);
  return {
    id: text(source.token_id ?? source.id, "token_id"),
    identityId: text(source.identity_id, "identity_id"),
    name: text(source.token_name ?? source.name, "token_name"),
    scope,
    caseId: text(source.case_id, "case_id"),
    ...(owner ? { ownerIdentityId: owner } : {}),
    ...(ownerName ? { ownerDisplayName: ownerName } : {}),
    permissions: permissionsFromJson(source.permissions_json),
    createdAt: text(source.token_created_at ?? source.created_at, "token_created_at"),
    ...(optionalText(source.expires_at) ? { expiresAt: optionalText(source.expires_at) } : {}),
    ...(optionalText(source.revoked_at) ? { revokedAt: optionalText(source.revoked_at) } : {}),
  };
}

/**
 * Whether an all-cases row is well formed: a human owner who exists and is enabled, the empty case
 * sentinel, and an expiry. Checked on every authentication, so an owner disabled a moment ago stops
 * the token on its next request.
 */
export function allCasesRowUsable(source: Record<string, unknown>): boolean {
  return (
    source.case_id === ALL_CASES_CASE_ID &&
    typeof source.owner_identity_id === "string" &&
    source.owner_exists === 1 &&
    source.owner_disabled === 0 &&
    (source.owner_kind === "local" || source.owner_kind === "oidc") &&
    typeof source.expires_at === "string"
  );
}
