import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AuthStore } from "../../src/auth/authStore.js";
import type { AuthIdentity } from "../../src/auth/types.js";

/**
 * The three readers on the per-request path hold their statement, instead of re-parsing the SQL
 * on every call (#1003).
 *
 * node:sqlite has no statement cache: every `db.prepare(sql)` parses and plans the query again.
 * Measured on a seeded store, that parse was 30 of the 38 µs an `authenticateSession` cost, and in
 * team mode the lookup runs for every authenticated request. Nothing here changes what the readers
 * return — a logout, a role change or a disable still takes effect on the very next request,
 * because the ROW is still read fresh each time. Only the parse is kept.
 *
 * The assertion is on `prepare` itself, over a second call: the first may prepare, the second
 * must not.
 */
let store: AuthStore;
let prepare: ReturnType<typeof vi.spyOn>;
let identity: AuthIdentity;
let actor: AuthIdentity;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-hot-statements-"));
  store = new AuthStore(join(root, "auth.sqlite"));
  actor = store.upsertOidcIdentity("https://idp.test", "admin", "Admin", "admin");
  identity = store.upsertOidcIdentity("https://idp.test", "sub-1", "Ada", "ada");
  store.setCaseRole("c1", identity.id, "investigator", actor);
  prepare = vi.spyOn((store as unknown as { db: { prepare: (sql: string) => unknown } }).db, "prepare");
});

afterEach(() => {
  prepare.mockRestore();
  store.close();
});

/** prepare() calls made by `fn` on its second invocation. */
function preparesOnSecondCall(fn: () => unknown): number {
  fn();
  prepare.mockClear();
  fn();
  return prepare.mock.calls.length;
}

describe("AuthStore hot readers keep their prepared statement", () => {
  it("authenticateSession prepares once, and still returns the live row", () => {
    const { token } = store.createSession(identity, 60 * 60_000);
    expect(preparesOnSecondCall(() => store.authenticateSession(token))).toBe(0);
    expect(store.authenticateSession(token)?.identity.id).toBe(identity.id);
    // The row is read fresh each time: a logout is visible on the very next call.
    store.deleteSessionByToken(token);
    expect(store.authenticateSession(token)).toBeNull();
  });

  it("authenticateServiceToken prepares once", () => {
    const { token } = store.createServiceToken({ caseId: "c1", name: "t", permissions: ["read"] }, actor);
    expect(preparesOnSecondCall(() => store.authenticateServiceToken(token))).toBe(0);
    expect(store.authenticateServiceToken(token)?.kind).toBe("service-token");
  });

  it("getCaseRole prepares once", () => {
    expect(preparesOnSecondCall(() => store.getCaseRole(identity.id, "c1"))).toBe(0);
    expect(store.getCaseRole(identity.id, "c1")).toBe("investigator");
  });
});
