import type { AuthIdentity, SessionRecord } from "./types.js";
import { isGlobalRole } from "./types.js";

/** Row parsing for the authentication database: every column is checked, never trusted. */

export function row(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("authentication database returned an invalid row");
  }
  return value as Record<string, unknown>;
}

export function text(value: unknown, field: string): string {
  if (typeof value !== "string") throw new Error(`authentication database field ${field} is invalid`);
  return value;
}

export function optionalText(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

export function identityFromRow(value: unknown): AuthIdentity {
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

export function sessionFromRow(value: unknown): SessionRecord {
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
