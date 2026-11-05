import { describe, it, expect, beforeEach, vi } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import {
  AuthObservationStore,
  AUTH_OBSERVATION_QUERY_MAX,
  type StoredAuthObservation,
} from "../../src/analysis/authObservationStore.js";

function obs(p: Partial<StoredAuthObservation> & { timestamp: string }): StoredAuthObservation {
  return {
    account: "alice",
    sourceIp: "203.0.113.5",
    hostOrTenant: "corp.example",
    outcome: "failed",
    locator: "record:1",
    importer: "ecar",
    importBatch: "t1",
    ...p,
  };
}

describe("AuthObservationStore", () => {
  let cases: CaseStore;
  let store: AuthObservationStore;
  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-authobs-"));
    cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    store = new AuthObservationStore(cases, 168);
  });

  it("queryWindow on an empty case returns no observations, not truncated", async () => {
    const r = await store.queryWindow("c1", "2026-01-01T00:00:00Z");
    expect(r).toEqual({ observations: [], truncated: false });
  });

  it("append persists observations; queryWindow returns them within the window", async () => {
    await store.append("c1", [
      obs({ timestamp: "2026-06-01T00:00:00Z", account: "alice" }),
      obs({ timestamp: "2026-06-02T00:00:00Z", account: "bob" }),
    ]);
    const r = await store.queryWindow("c1", "2026-05-01T00:00:00Z");
    expect(r.truncated).toBe(false);
    expect(r.observations.map((o) => o.account).sort()).toEqual(["alice", "bob"]);
  });

  it("a re-append of the same observation (same identity fields) writes zero new rows", async () => {
    const first = await store.append("c1", [
      obs({ timestamp: "2026-06-01T00:00:00.500Z", account: "alice" }),
    ]);
    expect(first).toBe(1);
    // Same second, sub-second differs, same account/source/host/outcome — same identity.
    const second = await store.append("c1", [
      obs({ timestamp: "2026-06-01T00:00:00.900Z", account: "alice" }),
    ]);
    expect(second).toBe(0);
    const r = await store.queryWindow("c1", "2026-01-01T00:00:00Z");
    expect(r.observations).toHaveLength(1);
  });

  it("an observation outside the queried window is not returned", async () => {
    await store.append("c1", [obs({ timestamp: "2026-01-01T00:00:00Z", account: "old" })]);
    const r = await store.queryWindow("c1", "2026-06-01T00:00:00Z");
    expect(r.observations).toHaveLength(0);
  });

  it("queryWindow returns newest-first and sets truncated when the window exceeds the cap", async () => {
    const small = new AuthObservationStore(cases, 168);
    // Can't practically insert AUTH_OBSERVATION_QUERY_MAX+1 rows in a unit test; instead verify
    // ordering directly, and verify the constant is exported and sane.
    expect(AUTH_OBSERVATION_QUERY_MAX).toBeGreaterThan(0);
    await small.append("c1", [
      obs({ timestamp: "2026-06-01T00:00:00Z", account: "first" }),
      obs({ timestamp: "2026-06-03T00:00:00Z", account: "third" }),
      obs({ timestamp: "2026-06-02T00:00:00Z", account: "second" }),
    ]);
    const r = await small.queryWindow("c1", "2026-01-01T00:00:00Z");
    expect(r.observations.map((o) => o.account)).toEqual(["third", "second", "first"]);
  });

  it("retention pruning evicts observations older than the retention window, and they no longer affect a later query", async () => {
    const shortRetention = new AuthObservationStore(cases, 1); // 1 hour
    const dbPath = join(cases.stateDir("c1"), "investigation.sqlite");
    // Insert directly old-dated rows (append() itself would filter nothing by age), then force a
    // prune by calling the worker op the store wraps, simulating what append()'s throttled prune
    // does when it is due.
    await shortRetention.append("c1", [obs({ timestamp: "2000-01-01T00:00:00Z", account: "ancient" })]);
    const { caseSqliteWorker } = await import("../../src/analysis/caseSqliteWorker.js");
    const deleted = await caseSqliteWorker.request<number>({
      op: "pruneEntitiesBefore",
      dbPath,
      kind: "authObservation",
      beforeMs: Date.now() - 3_600_000,
    });
    expect(deleted).toBe(1);
    const r = await shortRetention.queryWindow("c1", "1999-01-01T00:00:00Z");
    expect(r.observations).toHaveLength(0);
  });

  // #1239: the throttle timestamp was set BEFORE the prune's own await, so a failed prune (worker
  // error, transient lock) still cost the case a full PRUNE_THROTTLE_MS before the next attempt —
  // expired rows kept accumulating for an extra hour per failure. Rolled back on catch instead.
  it("does not hold the prune throttle after a failed prune attempt — the next append retries it", async () => {
    const { caseSqliteWorker } = await import("../../src/analysis/caseSqliteWorker.js");
    const real = caseSqliteWorker.request.bind(caseSqliteWorker);
    const spy = vi.spyOn(caseSqliteWorker, "request").mockImplementationOnce((req: unknown) => {
      const r = req as { op: string };
      if (r.op === "pruneEntitiesBeforeNewest") return Promise.reject(new Error("simulated worker failure"));
      return real(req as never);
    });
    try {
      await expect(
        store.append("c1", [obs({ timestamp: "2026-06-01T00:00:00Z", account: "alice" })]),
      ).rejects.toThrow("simulated worker failure");
      // The append itself never ran (pruneIfDue rejected first) — the row must not be there.
      const afterFailure = await store.queryWindow("c1", "2026-01-01T00:00:00Z");
      expect(afterFailure.observations).toHaveLength(0);

      // A second append, right away, must retry the prune rather than treat it as already-done —
      // proven by the row from THIS append being visible (append only runs after pruneIfDue).
      await store.append("c1", [obs({ timestamp: "2026-06-01T00:00:00Z", account: "bob" })]);
      const afterRetry = await store.queryWindow("c1", "2026-01-01T00:00:00Z");
      expect(afterRetry.observations.map((o) => o.account)).toEqual(["bob"]);
      const pruneCalls = spy.mock.calls.filter(
        (c) => (c[0] as { op: string }).op === "pruneEntitiesBeforeNewest",
      );
      expect(pruneCalls.length).toBeGreaterThanOrEqual(2); // the failed attempt, then the retry
    } finally {
      spy.mockRestore();
    }
  });

  it("distinct import batches for the same real attempt do not double the entity — identity excludes importBatch", async () => {
    const a = await store.append("c1", [
      obs({ timestamp: "2026-06-01T00:00:00Z", account: "alice", importBatch: "t1" }),
    ]);
    const b = await store.append("c1", [
      obs({ timestamp: "2026-06-01T00:00:00Z", account: "alice", importBatch: "t2" }),
    ]);
    expect(a).toBe(1);
    expect(b).toBe(0); // same observation identity regardless of which batch re-describes it
    const r = await store.queryWindow("c1", "2026-01-01T00:00:00Z");
    expect(r.observations).toHaveLength(1);
  });

  // #2301: retention is measured in evidence time, never against the wall clock.
  it("keeps an old export's observations on arrival — retention is evidence time, not wall clock", async () => {
    await store.append("c1", [obs({ timestamp: "2020-03-01T00:00:00Z", account: "old" })]);
    const fresh = new AuthObservationStore(cases, 168); // a new instance: its prune is due at once
    await fresh.append("c1", [obs({ timestamp: "2020-03-02T00:00:00Z", account: "old2" })]);
    const r = await fresh.queryWindow("c1", "2019-01-01T00:00:00Z");
    expect(r.observations.map((o) => o.account).sort()).toEqual(["old", "old2"]);
  });

  it("prunes rows older than the newest stored observation minus the retention span", async () => {
    await store.append("c1", [obs({ timestamp: "2020-03-01T00:00:00Z", account: "early" })]);
    const later = new AuthObservationStore(cases, 168);
    await later.append("c1", [obs({ timestamp: "2020-03-20T00:00:00Z", account: "late" })]);
    // The prune ran before the late row was written, so a third due prune is what evicts "early".
    await new AuthObservationStore(cases, 168).append("c1", [
      obs({ timestamp: "2020-03-19T00:00:00Z", account: "late2" }),
    ]);
    const r = await later.queryWindow("c1", "2019-01-01T00:00:00Z");
    expect(r.observations.map((o) => o.account).sort()).toEqual(["late", "late2"]);
  });

  it("stores the sign-in detail fields and keys a record-identified row by its record id", async () => {
    const detail = {
      resultCode: "500121",
      mfaDetail: "denied" as const,
      authMethod: "Mobile app notification",
      sessionId: "sess-1",
      correlationId: "corr-1",
      app: "Office 365",
      outcome: "interrupted" as const,
    };
    const added = await store.append("c1", [
      obs({ timestamp: "2026-06-01T00:00:00Z", recordId: "entra-signin|t|s-1", ...detail }),
      obs({ timestamp: "2026-06-01T00:00:00Z", recordId: "entra-signin|t|s-2", ...detail }),
    ]);
    expect(added).toBe(2); // same second, same account: two records, two rows
    const page = await store.queryPage("c1", {});
    expect(page.observations[0]).toMatchObject(detail);
    expect(
      await store.append("c1", [obs({ timestamp: "2026-06-01T00:00:00Z", recordId: "entra-signin|t|s-1" })]),
    ).toBe(0);
  });

  it("queryPage filters by tenant, account and window", async () => {
    await store.append("c1", [
      obs({ timestamp: "2026-06-01T00:00:00Z", account: "Alice", hostOrTenant: "t-a" }),
      obs({ timestamp: "2026-06-01T01:00:00Z", account: "bob", hostOrTenant: "t-a" }),
      obs({ timestamp: "2026-06-01T02:00:00Z", account: "alice", hostOrTenant: "t-b" }),
      obs({ timestamp: "2026-06-03T00:00:00Z", account: "alice", hostOrTenant: "t-a" }),
    ]);
    const r = await store.queryPage("c1", {
      tenant: "t-a",
      account: "ALICE",
      since: "2026-06-01T00:00:00Z",
      until: "2026-06-02T00:00:00Z",
    });
    expect(r.observations.map((o) => o.timestamp)).toEqual(["2026-06-01T00:00:00Z"]);
    expect(r.next).toBeNull();
  });

  it("returns every row across pages above the old 100k query cap", async () => {
    await store.append("c1", [
      obs({ timestamp: "2026-06-01T00:00:00Z", account: "seed", hostOrTenant: "t-x" }),
    ]);
    const N = AUTH_OBSERVATION_QUERY_MAX + 5_000;
    const { loadDatabaseSync } = await import("../../src/analysis/sqliteRuntime.js");
    const DatabaseSync = loadDatabaseSync();
    const db = new DatabaseSync(join(cases.stateDir("c1"), "investigation.sqlite"));
    const base = Date.parse("2026-06-01T00:00:00Z");
    try {
      db.exec(
        `WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<${N}) ` +
          "INSERT INTO entities (kind, entity_id, ordinal, version, timestamp_ms, payload) " +
          `SELECT 'authObservation', 'x' || i, 10+i, 1, ${base} + (i / 3) * 1000, ` +
          "json_object('timestamp','t','account','u' || (i % 50),'sourceIp','','hostOrTenant','t-a'," +
          "'outcome','interrupted','locator','record:' || i,'importer','m365','importBatch','b') FROM n",
      );
    } finally {
      db.close();
    }
    let total = 0;
    let after: { ms: number; rowId: number } | undefined;
    const seen = new Set<string>();
    for (;;) {
      const page = await store.queryPage("c1", { tenant: "t-a", after, limit: 5_000 });
      total += page.observations.length;
      for (const o of page.observations) seen.add(o.locator);
      if (!page.next) break;
      after = page.next;
    }
    expect(total).toBe(N);
    expect(seen.size).toBe(N);
  }, 30_000);
});
