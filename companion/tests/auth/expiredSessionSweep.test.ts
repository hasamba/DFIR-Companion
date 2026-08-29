import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AuthStore } from "../../src/auth/authStore.js";
import { loadDatabaseSync, type SqliteDatabase } from "../../src/analysis/sqliteRuntime.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import { startMaintenanceTasks } from "../../src/composition/maintenanceTasks.js";
import { CustodyStore } from "../../src/analysis/custody.js";
import type { Notifier } from "../../src/integrations/notify/notifyDispatch.js";

/**
 * Expired team-mode sessions must not accumulate forever (#676).
 *
 * authenticateSession deletes an expired session, but only the one it was just handed. A session
 * whose owner never returns with that cookie — the normal end of a shift — is never looked at
 * again. Nothing READS it either (listSessions filters on expires_at), which is what made this
 * invisible: the table just grows for the life of the deployment.
 *
 * So every assertion here counts RAW ROWS, over a second connection to the same file. Going through
 * listSessions would hide exactly the rows under test.
 */
let root: string;
let store: AuthStore;
let cases: CaseStore;
let probe: SqliteDatabase;

const silentNotifier = { dispatch: async () => {} } as unknown as Notifier;

async function freshStore(prefix: string): Promise<void> {
  root = await mkdtemp(join(tmpdir(), prefix));
  store = new AuthStore(join(root, "auth.sqlite"));
  cases = new CaseStore(join(root, "cases"));
  probe = new (loadDatabaseSync())(join(root, "auth.sqlite"));
}

const sessionRows = (): number =>
  Number((probe.prepare("SELECT COUNT(*) AS n FROM auth_sessions").get() as { n: number }).n);

/** One identity, with `live` unexpired sessions and `lapsed` already-expired ones. */
function seedSessions(live: number, lapsed: number): string {
  const identity = store.upsertOidcIdentity("https://idp.test", "sub-1", "Ada", "ada");
  for (let i = 0; i < live; i++) store.createSession(identity, 60 * 60_000);
  for (let i = 0; i < lapsed; i++) store.createSession(identity, -1_000);
  return identity.id;
}

function maintenance(authStore?: AuthStore): void {
  startMaintenanceTasks({
    store: cases,
    custodyStore: new CustodyStore(cases),
    notifier: silentNotifier,
    dashboardBaseUrl: "http://localhost:4773",
    ...(authStore ? { authStore } : {}),
  });
}

afterEach(() => {
  vi.useRealTimers();
  probe?.close();
  store?.close();
});

describe("AuthStore.deleteExpiredSessions", () => {
  beforeEach(async () => freshStore("dfir-session-sweep-"));

  it("deletes lapsed sessions and keeps live ones", () => {
    const identityId = seedSessions(2, 3);
    expect(sessionRows()).toBe(5);

    expect(store.deleteExpiredSessions()).toBe(3);
    expect(sessionRows()).toBe(2);
    // The two survivors are the ones a signed-in analyst is still holding.
    expect(store.listSessions(identityId)).toHaveLength(2);
  });

  it("is a no-op when nothing has lapsed", () => {
    seedSessions(2, 0);
    expect(store.deleteExpiredSessions()).toBe(0);
    expect(sessionRows()).toBe(2);
  });

  it("takes an explicit clock, so a session lapsing later is swept later", () => {
    const identityId = seedSessions(1, 0);
    const [live] = store.listSessions(identityId);

    expect(store.deleteExpiredSessions(new Date(Date.parse(live.expiresAt) - 1))).toBe(0);
    expect(store.deleteExpiredSessions(new Date(Date.parse(live.expiresAt) + 1))).toBe(1);
  });
});

describe("startMaintenanceTasks arms the session sweep", () => {
  const BACKUP_INTERVAL = "DFIR_STATE_BACKUP_INTERVAL_MS";
  let savedBackupInterval: string | undefined;

  beforeEach(async () => {
    await freshStore("dfir-session-sweep-timer-");
    // Disarm the backup timer: advancing six hours below would otherwise fire six rounds of
    // unrelated case I/O, none of which this test is about.
    savedBackupInterval = process.env[BACKUP_INTERVAL];
    process.env[BACKUP_INTERVAL] = "0";
    vi.useFakeTimers();
  });

  afterEach(() => {
    if (savedBackupInterval === undefined) delete process.env[BACKUP_INTERVAL];
    else process.env[BACKUP_INTERVAL] = savedBackupInterval;
  });

  it("sweeps at startup and again on its interval", () => {
    const identity = store.upsertOidcIdentity("https://idp.test", "sub-1", "Ada", "ada");
    // A day, not an hour: this session has to outlive the six hours of fake time advanced below,
    // or the sweep would be right to take it and the test would be measuring nothing.
    store.createSession(identity, 24 * 60 * 60_000);
    store.createSession(identity, -1_000);

    maintenance(store);
    expect(sessionRows()).toBe(1); // the startup sweep took the lapsed one

    // A session that lapses while the server keeps running is taken by the next tick, not left.
    store.createSession(identity, 60_000);
    vi.advanceTimersByTime(60_001);
    expect(sessionRows()).toBe(2);
    vi.advanceTimersByTime(6 * 60 * 60 * 1000);
    expect(sessionRows()).toBe(1);
  });

  it("leaves the table alone in solo mode, where there is no auth store to sweep", () => {
    seedSessions(1, 1);
    maintenance();
    vi.advanceTimersByTime(24 * 60 * 60 * 1000);
    expect(sessionRows()).toBe(2);
  });
});
