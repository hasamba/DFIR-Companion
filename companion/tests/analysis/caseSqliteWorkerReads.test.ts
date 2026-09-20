// #1454: case reads no longer queue behind a running import. The case SQLite client routes reads
// to a small pool of read-only workers and writes to one writer; the database runs in WAL mode so
// a reader never waits for a write transaction. This file pins the contracts that split depends
// on: a read on another case does not wait for a write in flight, a read posted after an
// un-awaited write still sees that write, a failed write blocks nothing, a reader never creates
// a file, and a restore (which renames a file over the live database) drains the readers and
// never replays a leftover WAL onto the restored file.
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { existsSync } from "node:fs";
import { copyFile, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { caseSqliteWorker } from "../../src/analysis/caseSqliteWorker.js";
import { loadDatabaseSync } from "../../src/analysis/sqliteRuntime.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

const KINDS = ["forensicTimeline"];

function events(count: number, prefix = "e"): ForensicEvent[] {
  return Array.from({ length: count }, (_, i) => ({
    id: `${prefix}-${i}`,
    timestamp: "2026-01-01T00:00:00Z",
    description: `event ${prefix} ${i} with some words so the term index has work to do`,
    severity: "Info",
    sources: ["test"],
    asset: `host-${i % 7}`,
  })) as ForensicEvent[];
}

function append(dbPath: string, batch: ForensicEvent[]): Promise<number> {
  return caseSqliteWorker.request<number>({
    op: "appendEntities",
    dbPath,
    kind: "forensicTimeline",
    entities: batch,
  });
}

function count(dbPath: string): Promise<Record<string, number> | null> {
  return caseSqliteWorker.request<Record<string, number> | null>({
    op: "entityCounts",
    dbPath,
    kinds: KINDS,
  });
}

function journalMode(dbPath: string): string {
  const DatabaseSync = loadDatabaseSync();
  const db = new DatabaseSync(dbPath, { readOnly: true });
  try {
    return String((db.prepare("PRAGMA journal_mode").get() as { journal_mode: string }).journal_mode);
  } finally {
    db.close();
  }
}

let dir: string;
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "dfir-sqlite-reads-"));
});
afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe("caseSqliteWorker — reads beside writes (#1454)", () => {
  it("runs the case database in WAL mode after the first write", async () => {
    const dbPath = join(dir, "a.sqlite");
    await append(dbPath, events(1));
    expect(journalMode(dbPath)).toBe("wal");
  });

  it("a read on another case settles before a large write in flight", async () => {
    const busy = join(dir, "busy.sqlite");
    const idle = join(dir, "idle.sqlite");
    await append(idle, events(1));
    const order: string[] = [];
    const write = append(busy, events(20000)).then(() => order.push("write"));
    const read = count(idle).then((counts) => {
      order.push("read");
      return counts;
    });
    const [, counts] = await Promise.all([write, read]);
    expect(counts).toEqual({ forensicTimeline: 1 });
    // Under the old single FIFO worker the read could only settle after the write.
    expect(order[0]).toBe("read");
  });

  it("a read posted after an un-awaited write to the same case sees that write", async () => {
    const dbPath = join(dir, "a.sqlite");
    await append(dbPath, events(2, "seed"));
    const write = append(dbPath, events(500, "late"));
    const counts = await count(dbPath);
    expect(counts).toEqual({ forensicTimeline: 502 });
    await write;
  });

  it("a failed write does not block later reads of that case", async () => {
    const dbPath = join(dir, "a.sqlite");
    await append(dbPath, events(3));
    const notADirectory = join(dir, "plain-file");
    await writeFile(notADirectory, "x");
    await expect(
      caseSqliteWorker.request({
        op: "backupDatabase",
        dbPath,
        targetPath: join(notADirectory, "snapshot.sqlite"),
      }),
    ).rejects.toThrow();
    expect(await count(dbPath)).toEqual({ forensicTimeline: 3 });
  });

  it("a reader never creates a database file", async () => {
    const dbPath = join(dir, "never.sqlite");
    expect(await count(dbPath)).toBeNull();
    expect(
      await caseSqliteWorker.request({ op: "queryEntities", dbPath, kind: "forensicTimeline", query: {} }),
    ).toEqual({ entities: [], nextCursor: null, total: 0 });
    expect(await caseSqliteWorker.request({ op: "superMeta", dbPath, hosts: 0 })).toEqual({
      rows: 0,
      generation: 0,
      hosts: [],
      hostsTruncated: false,
    });
    expect(existsSync(dbPath)).toBe(false);
    expect(existsSync(dbPath + "-wal")).toBe(false);
  });

  it("a restore installs the backup, drains the readers, and reads after it see the backup", async () => {
    const dbPath = join(dir, "a.sqlite");
    const backupPath = join(dir, "backup.sqlite");
    await append(dbPath, events(3, "kept"));
    await caseSqliteWorker.request({ op: "backupDatabase", dbPath, targetPath: backupPath });
    await append(dbPath, events(2, "after"));
    expect(await count(dbPath)).toEqual({ forensicTimeline: 5 });

    // A read-only connection held across a writer's close leaves the WAL behind — the shape of a
    // crash leftover. Those frames belong to the OLD database and must never land in the restored one.
    const DatabaseSync = loadDatabaseSync();
    const reader = new DatabaseSync(dbPath, { readOnly: true });
    reader.prepare("SELECT count(*) AS n FROM entities").get();
    await append(dbPath, events(4, "leftover"));
    reader.close();
    expect(existsSync(dbPath + "-wal")).toBe(true);

    const restore = caseSqliteWorker.request({
      op: "restoreDatabase",
      sourcePath: backupPath,
      targetPath: dbPath,
    });
    // Posted while the restore is pending: the exclusive gate holds it until the file swap is done.
    const readDuring = count(dbPath);
    await restore;
    expect(await readDuring).toEqual({ forensicTimeline: 3 });
    expect(await count(dbPath)).toEqual({ forensicTimeline: 3 });
    // The next write still finds a healthy WAL-mode database.
    await append(dbPath, events(1, "post"));
    expect(await count(dbPath)).toEqual({ forensicTimeline: 4 });
    expect(journalMode(dbPath)).toBe("wal");
  });

  it("a write posted after a restore lands in the restored database, never in the old one", async () => {
    const dbPath = join(dir, "a.sqlite");
    const backupPath = join(dir, "backup.sqlite");
    await append(dbPath, events(3, "kept"));
    await caseSqliteWorker.request({ op: "backupDatabase", dbPath, targetPath: backupPath });
    await append(dbPath, events(2, "after"));
    // A read in flight makes the restore wait; without the gate a write posted meanwhile would run
    // against the old file first and be thrown away by the rename.
    const readBefore = caseSqliteWorker.request({
      op: "queryEntities",
      dbPath,
      kind: "forensicTimeline",
      query: {},
    });
    const restore = caseSqliteWorker.request({
      op: "restoreDatabase",
      sourcePath: backupPath,
      targetPath: dbPath,
    });
    const writeAfter = append(dbPath, events(1, "late"));
    const readAfter = count(dbPath);
    await Promise.all([readBefore, restore, writeAfter]);
    expect(await readAfter).toEqual({ forensicTimeline: 4 });
    expect(await count(dbPath)).toEqual({ forensicTimeline: 4 });
  });

  it("a backup written while a read holds a snapshot is complete and standalone", async () => {
    const dbPath = join(dir, "a.sqlite");
    const backupPath = join(dir, "backup.sqlite");
    await append(dbPath, events(10));
    const read = caseSqliteWorker.request({
      op: "queryEntities",
      dbPath,
      kind: "forensicTimeline",
      query: {},
    });
    await caseSqliteWorker.request({ op: "backupDatabase", dbPath, targetPath: backupPath });
    await read;
    // Standalone: the file alone, copied away from any sidecar, holds every row.
    const copy = join(dir, "copy.sqlite");
    await copyFile(backupPath, copy);
    expect(await count(copy)).toEqual({ forensicTimeline: 10 });
  });
});
