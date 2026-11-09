import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { loadDatabaseSync } from "../../src/analysis/sqliteRuntime.js";
import { AuthStore } from "../../src/auth/authStore.js";
import {
  assertAllCasesExpiry,
  capAllCasesPermissions,
  expiryAllowsUse,
  parseServiceTokenScope,
} from "../../src/auth/serviceTokenScope.js";

/**
 * #2474 added a scope and an owner to stored service tokens. A database from before it must open,
 * gain the columns once, and keep every existing token working as a ONE-case token.
 */

const LEGACY_SCHEMA =
  "CREATE TABLE auth_identities (" +
  "id TEXT PRIMARY KEY, kind TEXT NOT NULL, username TEXT, username_key TEXT UNIQUE, " +
  "display_name TEXT NOT NULL, global_role TEXT NOT NULL, disabled INTEGER NOT NULL DEFAULT 0, " +
  "password_hash TEXT, issuer TEXT, subject TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, " +
  "UNIQUE(issuer, subject));" +
  "CREATE TABLE auth_service_tokens (" +
  "id TEXT PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE, identity_id TEXT NOT NULL " +
  "REFERENCES auth_identities(id) ON DELETE CASCADE, name TEXT NOT NULL, case_id TEXT NOT NULL, " +
  "permissions_json TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT, revoked_at TEXT);";

// sha256("dfirsvc_legacy-token-value-long-enough") — the store keeps only the hash.
async function legacyDatabase(expiresAt: string | null): Promise<{ path: string; token: string }> {
  const { createHash } = await import("node:crypto");
  const path = join(await mkdtemp(join(tmpdir(), "dfir-token-migration-")), "auth.sqlite");
  const token = "dfirsvc_legacy-token-value-long-enough";
  const DatabaseSync = loadDatabaseSync();
  const db = new DatabaseSync(path);
  db.exec(LEGACY_SCHEMA);
  const now = new Date().toISOString();
  db.prepare(
    "INSERT INTO auth_identities (id, kind, display_name, global_role, created_at, updated_at) " +
      "VALUES ('service:old', 'service', 'old collector', 'member', ?, ?)",
  ).run(now, now);
  db.prepare(
    "INSERT INTO auth_service_tokens (id, token_hash, identity_id, name, case_id, permissions_json, " +
      "created_at, expires_at) VALUES ('t1', ?, 'service:old', 'old collector', 'c1', '[\"write\"]', ?, ?)",
  ).run(createHash("sha256").update(token, "utf8").digest("hex"), now, expiresAt);
  db.close();
  return { path, token };
}

describe("service-token scope migration (#2474)", () => {
  it("keeps a token stored before the scope existed working as a one-case token", async () => {
    const { path, token } = await legacyDatabase(null);
    const store = new AuthStore(path);
    const auth = store.authenticateServiceToken(token);
    expect(auth?.kind).toBe("service-token");
    expect(auth?.kind === "service-token" && auth.token).toMatchObject({ scope: "case", caseId: "c1" });
    expect(store.listServiceTokens()).toEqual([expect.objectContaining({ id: "t1", scope: "case" })]);
    store.close();
    const reopened = new AuthStore(path); // the migration is idempotent
    expect(reopened.authenticateServiceToken(token)).not.toBeNull();
    reopened.close();
  });

  it("refuses a stored token whose expiry is not a real timestamp instead of treating it as no expiry", async () => {
    const { path, token } = await legacyDatabase("not-a-date");
    const store = new AuthStore(path);
    expect(store.authenticateServiceToken(token)).toBeNull();
    store.close();
  });

  it("refuses a stored token whose scope is unknown rather than reading it as one case", async () => {
    const { path, token } = await legacyDatabase(null);
    const store = new AuthStore(path);
    store.close();
    const DatabaseSync = loadDatabaseSync();
    const db = new DatabaseSync(path);
    db.exec("UPDATE auth_service_tokens SET scope='everything'");
    db.close();
    const reopened = new AuthStore(path);
    expect(reopened.authenticateServiceToken(token)).toBeNull();
    expect(reopened.listServiceTokens()).toEqual([]);
    reopened.close();
  });
});

describe("all-cases creation rules (#2474)", () => {
  const now = Date.parse("2026-11-09T00:00:00.000Z");
  const day = 24 * 60 * 60_000;

  it("parses scopes, treating absent as one case and anything unknown as invalid", () => {
    expect(parseServiceTokenScope(undefined)).toBe("case");
    expect(parseServiceTokenScope("case")).toBe("case");
    expect(parseServiceTokenScope("all-cases")).toBe("all-cases");
    expect(parseServiceTokenScope("ALL")).toBeNull();
    expect(parseServiceTokenScope(1)).toBeNull();
  });

  it("caps permissions at capture and write", () => {
    expect(capAllCasesPermissions(["read", "write", "export"])).toEqual(["write"]);
    expect(capAllCasesPermissions(["capture", "review"])).toEqual(["capture"]);
    expect(() => capAllCasesPermissions(["read"])).toThrow(/capture or write/);
  });

  it("requires a real future expiry within 90 days", () => {
    expect(() => assertAllCasesExpiry(undefined, now)).toThrow(/expiry/);
    expect(() => assertAllCasesExpiry("", now)).toThrow(/expiry/);
    expect(() => assertAllCasesExpiry("garbage", now)).toThrow(/future/);
    expect(() => assertAllCasesExpiry(new Date(now).toISOString(), now)).toThrow(/future/);
    expect(() => assertAllCasesExpiry(new Date(now + 90 * day + 1).toISOString(), now)).toThrow(/90 days/);
    expect(assertAllCasesExpiry(new Date(now + 90 * day).toISOString(), now)).toBe(
      new Date(now + 90 * day).toISOString(),
    );
  });

  it("fails closed on a stored expiry that is not a timestamp", () => {
    expect(expiryAllowsUse(null, now)).toBe(true);
    expect(expiryAllowsUse("nonsense", now)).toBe(false);
    expect(expiryAllowsUse(42, now)).toBe(false);
    expect(expiryAllowsUse(new Date(now - 1).toISOString(), now)).toBe(false);
    expect(expiryAllowsUse(new Date(now + day).toISOString(), now)).toBe(true);
  });
});
