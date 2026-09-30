import { describe, it, expect, beforeEach } from "vitest";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { INVESTIGATION_DB_FILENAME } from "../../src/analysis/stateStore.js";
import { loadDatabaseSync } from "../../src/analysis/sqliteRuntime.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";
import { TagsStore, type EventProtectionSink } from "../../src/analysis/tags.js";
import { BackupManager } from "../../src/storage/backupManager.js";
import { caseSqliteWorker } from "../../src/analysis/caseSqliteWorker.js";

// #958 — the cap bounds UNPROTECTED rows. A row the analyst starred or tagged is protected and is
// never evicted; the protection relation lives in the case database beside the rows it guards, so
// it can never name a row that is not there.
function ev(p: Partial<ForensicEvent> & { id: string; timestamp: string }): ForensicEvent {
  return {
    description: `event ${p.id}`,
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...p,
  };
}

const dated = (id: string, day: number) =>
  ev({ id, timestamp: `2026-06-${String(day).padStart(2, "0")}T00:00:00Z` });

describe("SuperTimelineStore protection (#958)", () => {
  let cases: CaseStore;
  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-super-protect-"));
    cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  });

  it("a protected row survives an append past the cap; the cap bounds the unprotected rows", async () => {
    const small = new SuperTimelineStore(cases, 2);
    await small.append("c1", [dated("row0", 1)]);
    expect(await small.protect("c1", "row0")).toBe(true);
    // Out of date order and past the cap: without protection row0 is the oldest insert and goes first.
    expect(await small.append("c1", [dated("r1", 9), dated("r2", 5), dated("r3", 7)])).toBe(2);
    const r = await small.query("c1", {});
    expect(new Set(r.events.map((e) => e.id))).toEqual(new Set(["row0", "r2", "r3"]));
    expect(r.total).toBe(3); // cap 2 unprotected + 1 protected
    expect((await small.get("c1", "row0"))?.id).toBe("row0");
  });

  it("protect refuses an unknown or evicted id and stores no orphan", async () => {
    const small = new SuperTimelineStore(cases, 1);
    expect(await small.protect("c1", "nope")).toBe(false);
    await small.append("c1", [dated("old", 1)]);
    await small.append("c1", [dated("new", 2)]); // evicts "old"
    expect(await small.protect("c1", "old")).toBe(false);
    expect(await small.protectedIds("c1")).toEqual([]);
  });

  it("unprotect makes the row evictable again", async () => {
    const small = new SuperTimelineStore(cases, 1);
    await small.append("c1", [dated("row0", 1)]);
    await small.protect("c1", "row0");
    await small.unprotect("c1", "row0");
    await small.append("c1", [dated("r1", 2)]);
    expect(await small.get("c1", "row0")).toBeNull();
    expect(await small.protectedIds("c1")).toEqual([]);
  });

  it("unprotect enforces the cap at once: the store never holds more unprotected rows than the cap", async () => {
    const small = new SuperTimelineStore(cases, 1);
    await small.append("c1", [dated("row0", 1)]);
    await small.protect("c1", "row0");
    await small.append("c1", [dated("r1", 2)]); // cap 1 unprotected + row0 protected = 2 rows
    expect((await small.query("c1", {})).total).toBe(2);
    await small.unprotect("c1", "row0");
    const r = await small.query("c1", {});
    expect(r.total).toBe(1);
    expect(r.events.map((e) => e.id)).toEqual(["r1"]); // row0 is the oldest unprotected row, so it goes
  });

  it("tags put back by a restore are reconciled on the next store call", async () => {
    // A restore can put a star in the tag table without the protection relation that goes with it
    // (a legacy investigation.json restore never touches the super rows). The tag table is the
    // authority: protection is re-derived from it whenever an analyst event tag came or went since
    // the last sync — and a dropped star releases the row to the cap.
    const small = new SuperTimelineStore(cases, 1);
    const tags = new TagsStore(cases, small);
    const backups = new BackupManager(cases, { retain: 24, preSynthRetain: 10, intervalMs: 0, maxBytes: 0 });
    await tags.add("c1", { targetType: "ioc", targetId: "i1", author: "analyst", label: "x" });
    await small.append("c1", [dated("row0", 1)]);
    const restore = async (filename: string, tagList: unknown[]) => {
      await writeFile(
        join(backups.backupDir("c1"), filename),
        JSON.stringify({ files: { "investigation.json": { caseId: "c1" }, "tags.json": tagList } }),
      );
      await backups.restoreBackup("c1", filename);
    };
    await mkdir(backups.backupDir("c1"), { recursive: true });
    await restore("2026-06-05T00-00-00-000Z_scheduled.json", [
      {
        id: "t1",
        targetType: "event",
        targetId: "row0",
        label: "starred",
        author: "analyst",
        createdAt: "2026-06-04T00:00:00Z",
      },
    ]);
    await small.append("c1", [dated("r1", 2)]);
    expect(await small.protectedIds("c1")).toEqual(["row0"]);
    expect((await small.get("c1", "row0"))?.id).toBe("row0");

    await restore("2026-06-06T00-00-00-000Z_scheduled.json", []);
    expect(await small.protectedIds("c1")).toEqual([]);
    expect((await small.query("c1", {})).total).toBe(1); // back within the cap
    expect(await small.get("c1", "row0")).toBeNull();
  });

  it("a tagger batch does not re-derive protection; an analyst event tag does", async () => {
    const small = new SuperTimelineStore(cases, 10);
    const tags = new TagsStore(cases, small);
    await small.append("c1", [dated("a", 1), dated("b", 2), dated("stray", 3)]);
    await tags.add("c1", { targetType: "event", targetId: "a", author: "analyst", label: "starred" });
    expect(await small.protectedIds("c1")).toEqual(["a"]);
    // A protected row no tag names: only a re-derive would release it, so it shows whether one ran.
    const db = new (loadDatabaseSync())(join(cases.stateDir("c1"), INVESTIGATION_DB_FILENAME));
    db.exec("INSERT INTO super_protected(event_id) VALUES('stray')");
    db.close();
    await tags.addMany("c1", [
      { targetType: "event", targetId: "b", author: "tagger:r1", label: "x" },
      { targetType: "event", targetId: "stray", author: "tagger:r1", label: "x" },
    ]);
    await tags.removeTaggerTagsFor("c1", ["b"]);
    await small.append("c1", [dated("c", 4)]);
    expect(await small.protectedIds("c1")).toEqual(["a", "stray"]);
    await tags.add("c1", { targetType: "event", targetId: "b", author: "analyst", label: "key-evidence" });
    await small.append("c1", [dated("d", 5)]);
    expect(await small.protectedIds("c1")).toEqual(["a", "b"]);
  });

  it("a crash after protect but before the tag row was written is released on the next store call", async () => {
    const small = new SuperTimelineStore(cases, 1);
    await small.append("c1", [dated("row0", 1)]);
    const dbPath = join(cases.stateDir("c1"), INVESTIGATION_DB_FILENAME);
    // The first half of TagsStore.add for an analyst event tag: the plan, then the protect call...
    const plan = await caseSqliteWorker.request<{ fresh: number[] }>({
      op: "tagsPlan",
      dbPath,
      tagsPath: join(cases.stateDir("c1"), "tags.json"),
      inputs: [{ targetType: "event", targetId: "row0", label: "starred", author: "analyst" }],
      protecting: true,
    });
    expect(plan.fresh).toEqual([0]);
    expect(await small.protect("c1", "row0")).toBe(true);
    // ...then the process died before the tag row was inserted. A new process has a new writer.
    const db = new (loadDatabaseSync())(dbPath);
    db.exec("UPDATE tags_protect_pending SET boot='a-process-that-died'");
    db.close();
    await small.append("c1", [dated("r1", 2)]);
    expect(await small.protectedIds("c1")).toEqual([]);
    expect(await small.get("c1", "row0")).toBeNull();
  });

  it("an in-flight analyst tag keeps its row protected while a concurrent store call reconciles", async () => {
    const small = new SuperTimelineStore(cases, 1);
    await small.append("c1", [dated("row0", 1)]);
    let appended = false;
    // The protect call returns, and before the tag row lands another store call runs a re-derive.
    const racing: EventProtectionSink = {
      protect: async (caseId, eventId) => {
        const ok = await small.protect(caseId, eventId);
        await small.append("c1", [dated("r1", 2)]);
        appended = true;
        return ok;
      },
      unprotect: (caseId, eventId) => small.unprotect(caseId, eventId),
    };
    await new TagsStore(cases, racing).add("c1", {
      targetType: "event",
      targetId: "row0",
      author: "analyst",
      label: "starred",
    });
    expect(appended).toBe(true);
    expect((await small.get("c1", "row0"))?.id).toBe("row0");
    expect(await small.protectedIds("c1")).toEqual(["row0"]);
  });

  it("setLabels reports false for an id that is not in the store", async () => {
    const store = new SuperTimelineStore(cases, 10);
    expect(await store.setLabels("c1", "ghost", ["key-evidence"])).toBe(false);
    await store.append("c1", [dated("e1", 1)]);
    expect(await store.setLabels("c1", "e1", ["key-evidence"])).toBe(true);
  });

  it("migration protects analyst-tagged legacy rows before the cap, and skips tagger tags", async () => {
    await writeFile(
      join(cases.stateDir("c1"), "super-timeline.json"),
      JSON.stringify([dated("oldest", 1), dated("mid", 2), dated("newest", 3)]),
    );
    await writeFile(
      join(cases.stateDir("c1"), "tags.json"),
      JSON.stringify([
        {
          id: "t1",
          targetType: "event",
          targetId: "oldest",
          label: "starred",
          author: "analyst",
          createdAt: "2026-06-04T00:00:00Z",
        },
        {
          id: "t2",
          targetType: "event",
          targetId: "mid",
          label: "persistence",
          author: "tagger:rule-1",
          createdAt: "2026-06-04T00:00:00Z",
        },
        {
          id: "t3",
          targetType: "finding",
          targetId: "newest",
          label: "starred",
          author: "analyst",
          createdAt: "2026-06-04T00:00:00Z",
        },
      ]),
    );
    const small = new SuperTimelineStore(cases, 1);
    const r = await small.query("c1", {});
    expect(new Set(r.events.map((e) => e.id))).toEqual(new Set(["oldest", "newest"]));
    expect(await small.protectedIds("c1")).toEqual(["oldest"]);
  });

  it("migration transfers protection from a tagged id that content-dedup aliases to the retained row", async () => {
    // "dup" has the same timestamp/description/host as "keep" so dedup drops it; the analyst's star
    // on "dup" must land on "keep", the row that now stands for that evidence.
    await writeFile(
      join(cases.stateDir("c1"), "super-timeline.json"),
      JSON.stringify([
        ev({ id: "keep", timestamp: "2026-06-01T00:00:00Z", description: "same" }),
        ev({ id: "dup", timestamp: "2026-06-01T00:00:00Z", description: "same" }),
        dated("later", 5),
      ]),
    );
    await writeFile(
      join(cases.stateDir("c1"), "tags.json"),
      JSON.stringify([
        {
          id: "t1",
          targetType: "event",
          targetId: "dup",
          label: "starred",
          author: "analyst",
          createdAt: "2026-06-04T00:00:00Z",
        },
      ]),
    );
    const small = new SuperTimelineStore(cases, 1);
    const r = await small.query("c1", {});
    expect(new Set(r.events.map((e) => e.id))).toEqual(new Set(["keep", "later"]));
    expect(await small.protectedIds("c1")).toEqual(["keep"]);
  });

  it("a case indexed before #958 backfills protection from its analyst tags once", async () => {
    const small = new SuperTimelineStore(cases, 2);
    await small.append("c1", [dated("a", 1), dated("b", 2)]);
    // Rewind the database to the pre-#958 shape: indexed, but never synced with the tags file.
    const db = new (loadDatabaseSync())(join(cases.stateDir("c1"), INVESTIGATION_DB_FILENAME));
    db.exec("DELETE FROM storage_meta WHERE key='super_protected_sync'");
    db.close();
    await writeFile(
      join(cases.stateDir("c1"), "tags.json"),
      JSON.stringify([
        {
          id: "t1",
          targetType: "event",
          targetId: "a",
          label: "starred",
          author: "analyst",
          createdAt: "2026-06-04T00:00:00Z",
        },
      ]),
    );
    const fresh = new SuperTimelineStore(cases, 2); // a restart: the store re-runs its migration check
    await fresh.append("c1", [dated("c", 3)]);
    expect(new Set((await fresh.query("c1", {})).events.map((e) => e.id))).toEqual(new Set(["a", "b", "c"]));
  });
});
