import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Request } from "express";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { resolveTeamAuthConfig } from "../../src/auth/authConfig.js";
import { createTeamAuthRuntime } from "../../src/auth/authFactory.js";
import { AuthStore } from "../../src/auth/authStore.js";
import { TeamAuth } from "../../src/auth/teamAuth.js";

/** Sliding session expiry (#2717): activity extends, idle expires, the hard cap holds. */
const HOUR = 3_600_000;
const T0 = Date.parse("2026-01-01T00:00:00Z");
let store: AuthStore;

function reqFor(token: string): Request {
  return { headers: { cookie: `dfir_session=${token}` } } as unknown as Request;
}

function setup(ttl: number, max: number | undefined) {
  const auth = new TeamAuth({ store, cookieSecure: false, sessionTtlMs: ttl, sessionMaxMs: max });
  const identity = store.upsertOidcIdentity("https://idp.test", "sub-1", "Ada", "ada");
  const { token, record } = store.createSession(identity, ttl);
  return { auth, token, record, identity };
}

beforeEach(async () => {
  vi.useFakeTimers();
  vi.setSystemTime(T0);
  store = new AuthStore(join(await mkdtemp(join(tmpdir(), "dfir-sliding-")), "auth.sqlite"));
});
afterEach(() => {
  vi.useRealTimers();
  store.close();
});

describe("sliding session expiry", () => {
  it("extends an active session past its first expiry", () => {
    const { auth, token } = setup(12 * HOUR, 168 * HOUR);
    for (let h = 1; h <= 30; h++) {
      vi.setSystemTime(T0 + h * HOUR);
      expect(auth.authenticateRequest(reqFor(token))).not.toBeNull();
    }
    const me = auth.authenticateRequest(reqFor(token));
    expect(me?.kind).toBe("session");
    const expiresAt = me?.kind === "session" ? me.session.expiresAt : "";
    expect(Date.parse(expiresAt)).toBeGreaterThan(T0 + 30 * HOUR);
  });

  it("expires an idle session at its normal time", () => {
    const { auth, token } = setup(12 * HOUR, 168 * HOUR);
    vi.setSystemTime(T0 + 6 * HOUR);
    expect(auth.authenticateRequest(reqFor(token))).not.toBeNull();
    vi.setSystemTime(T0 + 6 * HOUR + 12 * HOUR + 1_000);
    expect(auth.authenticateRequest(reqFor(token))).toBeNull();
  });

  it("never extends past the hard maximum since sign-in", () => {
    const { auth, token, record } = setup(12 * HOUR, 48 * HOUR);
    for (let h = 1; h < 48; h++) {
      vi.setSystemTime(T0 + h * HOUR);
      auth.authenticateRequest(reqFor(token));
    }
    const rows = store.listSessions(record.identityId);
    expect(Date.parse(rows[0].expiresAt)).toBe(T0 + 48 * HOUR);
    vi.setSystemTime(T0 + 48 * HOUR + 1_000);
    expect(auth.authenticateRequest(reqFor(token))).toBeNull();
  });

  it("does not extend when no cap is configured", () => {
    const { auth, token, record } = setup(12 * HOUR, undefined);
    vi.setSystemTime(T0 + 6 * HOUR);
    auth.authenticateRequest(reqFor(token));
    expect(Date.parse(store.listSessions(record.identityId)[0].expiresAt)).toBe(T0 + 12 * HOUR);
  });

  it("keeps a short lifetime alive across the touch throttle", () => {
    const { auth, token } = setup(15 * 60_000, 168 * HOUR);
    for (let m = 1; m <= 60; m += 3) {
      vi.setSystemTime(T0 + m * 60_000);
      expect(auth.authenticateRequest(reqFor(token))).not.toBeNull();
    }
  });

  it("still rejects a disabled identity", () => {
    const { auth, token, identity } = setup(12 * HOUR, 168 * HOUR);
    (store as unknown as { db: { prepare(s: string): { run(...a: unknown[]): void } } }).db
      .prepare("UPDATE auth_identities SET disabled=1 WHERE id=?")
      .run(identity.id);
    expect(auth.authenticateRequest(reqFor(token))).toBeNull();
  });

  it("never shortens a session whose expiry is already later", () => {
    const { record } = setup(12 * HOUR, 168 * HOUR);
    store.touchSession(record.id, new Date().toISOString(), new Date(T0 + HOUR).toISOString());
    expect(Date.parse(store.listSessions(record.identityId)[0].expiresAt)).toBe(T0 + 12 * HOUR);
  });

  it("gives the cookie a lifetime that covers every extension", () => {
    const { auth } = setup(12 * HOUR, 168 * HOUR);
    expect(auth.sessionCookie("t")).toContain(`Max-Age=${(168 * HOUR) / 1000}`);
  });
});

describe("session cap configuration", () => {
  const team = { DFIR_AUTH_MODE: "team", DFIR_AUTH_BOOTSTRAP_TOKEN: "b".repeat(40) };
  it.each([
    [undefined, 168],
    ["", 168],
    ["  ", 168],
    ["abc", 168],
    ["0", 12],
    ["720", 720],
    ["9999", 720],
    ["48", 48],
  ])("DFIR_AUTH_SESSION_MAX_HOURS=%s -> %s h", (raw, hours) => {
    const cfg = resolveTeamAuthConfig({
      ...team,
      ...(raw === undefined ? {} : { DFIR_AUTH_SESSION_MAX_HOURS: raw }),
    });
    expect(cfg.sessionMaxMs).toBe(hours * HOUR);
  });

  it("never lets the cap undercut the idle lifetime", () => {
    const cfg = resolveTeamAuthConfig({
      ...team,
      DFIR_AUTH_SESSION_HOURS: "100",
      DFIR_AUTH_SESSION_MAX_HOURS: "24",
    });
    expect(cfg.sessionMaxMs).toBe(100 * HOUR);
  });

  it("is wired through the production factory", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-sliding-fac-"));
    const runtime = createTeamAuthRuntime(join(root, "cases"), "127.0.0.1", 4773, {
      ...team,
      DFIR_AUTH_COOKIE_SECURE: "false",
      DFIR_AUTH_DATA_DIR: join(root, "auth"),
    });
    expect(runtime.teamAuth?.sessionMaxMs).toBe(168 * HOUR);
    expect(runtime.teamAuth?.sessionCookie("t")).toContain(`Max-Age=${(168 * HOUR) / 1000}`);
    runtime.teamAuth?.store.close();
    runtime.writerGuard?.release();
  });
});
