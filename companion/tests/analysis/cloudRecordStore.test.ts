import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { CloudRecordStore, verdictsFor } from "../../src/analysis/cloudRecordStore.js";
import { cloudRecordIdentity } from "../../src/analysis/cloudRecordIdentity.js";
import { INVESTIGATION_DB_FILENAME } from "../../src/analysis/stateStore.js";
import { loadDatabaseSync } from "../../src/analysis/sqliteRuntime.js";

const ual = (id: string, op = "Send") =>
  cloudRecordIdentity("ual", { Id: id, OrganizationId: "t", Operation: op });

describe("verdictsFor (#2301)", () => {
  it("flags a record twice in one batch as a duplicate the second time", () => {
    const r = verdictsFor([ual("a"), ual("a")], new Map());
    expect(r.verdicts).toEqual(["new", "duplicate"]);
    expect(r.duplicates).toBe(1);
  });

  it("same id with a different payload in one batch is a conflict, not a duplicate", () => {
    const r = verdictsFor([ual("a", "Send"), ual("a", "Delete")], new Map());
    expect(r.verdicts).toEqual(["new", "conflict"]);
    expect(r.conflicts).toBe(1);
  });
});

describe("CloudRecordStore (#2301)", () => {
  let cases: CaseStore;
  let store: CloudRecordStore;
  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-cloudrec-"));
    cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    store = new CloudRecordStore(cases);
  });

  it("dedup round trip: a committed batch is all duplicates the second time", async () => {
    const batch = [ual("a"), ual("b"), ual("c")];
    const first = await store.classify("c1", batch);
    expect(first.verdicts).toEqual(["new", "new", "new"]);
    expect(await store.commit("c1", batch, first.verdicts, "m1")).toBe(3);
    const second = await store.classify("c1", batch);
    expect(second.verdicts).toEqual(["duplicate", "duplicate", "duplicate"]);
    expect(second.duplicates).toBe(3);
  });

  it("nothing is marked seen until commit — a failed import can be retried", async () => {
    const batch = [ual("a")];
    await store.classify("c1", batch);
    expect((await store.classify("c1", batch)).verdicts).toEqual(["new"]);
  });

  it("conflict: same id, different payload is kept, flagged, and then known", async () => {
    const original = [ual("a", "Send")];
    await store.commit("c1", original, (await store.classify("c1", original)).verdicts, "m1");
    const altered = [ual("a", "Delete")];
    const r = await store.classify("c1", altered);
    expect(r.verdicts).toEqual(["conflict"]);
    expect(r.conflicts).toBe(1);
    expect(await store.commit("c1", altered, r.verdicts, "m2")).toBe(1);
    // Both payloads are now known: re-uploading either is a duplicate.
    expect((await store.classify("c1", [ual("a", "Send"), ual("a", "Delete")])).verdicts).toEqual([
      "duplicate",
      "duplicate",
    ]);
  });

  it("commit never writes a duplicate verdict and never doubles an existing ledger row", async () => {
    const batch = [ual("a")];
    await store.commit("c1", batch, ["new"], "m1");
    expect(await store.commit("c1", batch, ["new"], "m2")).toBe(0);
    expect(await store.commit("c1", [ual("b")], ["duplicate"], "m2")).toBe(0);
  });

  it("pages members of one group in order and keeps groups apart", async () => {
    await store.recordMembers("c1", [
      { group: "g1", ref: "r1", locator: "record:0" },
      { group: "g2", ref: "x1" },
      { group: "g1", ref: "r2" },
      { group: "g1", ref: "r3" },
    ]);
    const p1 = await store.pageMembers("c1", "g1", { limit: 2 });
    expect(p1.total).toBe(3);
    expect(p1.members).toEqual([{ ref: "r1", locator: "record:0" }, { ref: "r2" }]);
    expect(p1.next).not.toBeNull();
    const p2 = await store.pageMembers("c1", "g1", { after: p1.next!, limit: 2 });
    expect(p2.members).toEqual([{ ref: "r3" }]);
    expect(p2.next).toBeNull();
    expect((await store.pageMembers("c1", "nope")).members).toEqual([]);
  });

  it("pages an aggregated event's 1M source records without loading them all", async () => {
    await store.recordMembers("c1", [{ group: "seed", ref: "seed" }]); // creates the database
    const N = 1_000_000;
    const DatabaseSync = loadDatabaseSync();
    const db = new DatabaseSync(join(cases.stateDir("c1"), INVESTIGATION_DB_FILENAME));
    try {
      db.exec(
        "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<" +
          N +
          ") " +
          "INSERT INTO entities (kind, entity_id, ordinal, version, host, payload) " +
          "SELECT 'cloudRecordMember', NULL, 1000+i, 1, 'big', " +
          '\'{"asset":"big","ref":"ual|t|r\' || i || \'"}\' FROM n',
      );
    } finally {
      db.close();
    }
    const first = await store.pageMembers("c1", "big", { limit: 1000 });
    expect(first.total).toBe(N);
    expect(first.members).toHaveLength(1000);
    expect(first.members[0].ref).toBe("ual|t|r1");
    let page = first;
    let seen = first.members.length;
    // Walk a few pages, then jump near the end through the keyset cursor.
    for (let i = 0; i < 3; i++) {
      page = await store.pageMembers("c1", "big", { after: page.next!, limit: 1000 });
      seen += page.members.length;
    }
    expect(seen).toBe(4000);
    expect(page.members[999].ref).toBe("ual|t|r4000");
    const tail = await store.pageMembers("c1", "big", { after: page.next! + (N - 4000 - 10), limit: 1000 });
    expect(tail.members).toHaveLength(10);
    expect(tail.members[9].ref).toBe(`ual|t|r${N}`);
    expect(tail.next).toBeNull();
  }, 30_000);
});
