// #1874: the case's tags moved from state/tags.json into the case database. A backup bundle still
// carries a "tags.json" entry (old bundles restore unchanged), and a restore must still put back the
// bundle's tags — through a binary database restore AND through a legacy investigation.json restore,
// which never touches the database's tag table. A bundle WITHOUT tags.json leaves the current tags
// alone, as it always has, even though the database under them is replaced.
import { describe, it, expect } from "vitest";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { BackupManager } from "../../src/storage/backupManager.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import { TagsStore, type Tag } from "../../src/analysis/tags.js";
import { loadDatabaseSync } from "../../src/analysis/sqliteRuntime.js";

async function setup() {
  const cases = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-backup-tags-")));
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const mgr = new BackupManager(cases, { retain: 24, preSynthRetain: 10, intervalMs: 0, maxBytes: 0 });
  const state = new StateStore(cases);
  await state.save({ ...emptyState("c1"), lastSummary: "s" });
  return { cases, mgr, state, tags: new TagsStore(cases) };
}

function tag(id: string, targetId: string, label: string): Tag {
  return { id, targetType: "ioc", targetId, label, author: "alice", createdAt: "2026-06-04T00:00:00.000Z" };
}

type Bundle = { files: Record<string, unknown>; binaryFiles?: Record<string, string> };

async function readBundle(mgr: BackupManager, filename: string): Promise<Bundle> {
  return JSON.parse(await readFile(join(mgr.backupDir("c1"), filename), "utf8")) as Bundle;
}

async function writeBundle(mgr: BackupManager, filename: string, bundle: Bundle): Promise<void> {
  await mkdir(mgr.backupDir("c1"), { recursive: true });
  await writeFile(join(mgr.backupDir("c1"), filename), JSON.stringify(bundle));
}

describe("BackupManager and the tag table (#1874)", () => {
  it("a case whose tags.json was never migrated backs up the raw file, malformed or not", async () => {
    const { cases, mgr } = await setup();
    const raw = [tag("t1", "i1", "x"), { weird: true }];
    await writeFile(join(cases.stateDir("c1"), "tags.json"), JSON.stringify(raw));
    const info = await mgr.createBackup("c1", "scheduled", "2026-07-01T00:00:00.000Z");
    expect((await readBundle(mgr, info.filename)).files["tags.json"]).toEqual(raw);
  });

  it("a migrated case backs up the database's list, not the stale file", async () => {
    const { cases, mgr, tags } = await setup();
    await writeFile(join(cases.stateDir("c1"), "tags.json"), JSON.stringify([tag("t1", "i1", "x")]));
    await tags.add("c1", { targetType: "ioc", targetId: "i2", author: "bob", label: "y" });
    const info = await mgr.createBackup("c1", "scheduled", "2026-07-01T00:00:00.000Z");
    expect((await readBundle(mgr, info.filename)).files["tags.json"]).toEqual(await tags.load("c1"));
    expect(await tags.load("c1")).toHaveLength(2);
  });

  it("a case with no tags at all has no tags.json entry", async () => {
    const { mgr } = await setup();
    const info = await mgr.createBackup("c1", "scheduled", "2026-07-01T00:00:00.000Z");
    expect((await readBundle(mgr, info.filename)).files).not.toHaveProperty("tags.json");
  });

  it("a backup racing the migration still carries the tags", async () => {
    const { cases, mgr, tags } = await setup();
    const rows = [tag("t1", "i1", "x"), tag("t2", "i2", "y")];
    await writeFile(join(cases.stateDir("c1"), "tags.json"), JSON.stringify(rows));
    const [, info] = await Promise.all([
      tags.load("c1"),
      mgr.createBackup("c1", "scheduled", "2026-07-01T00:00:00.000Z"),
    ]);
    expect((await readBundle(mgr, info.filename)).files["tags.json"]).toEqual(rows);
  });

  it("a binary restore puts back the bundle's tags.json over a migrated database", async () => {
    const { mgr, tags } = await setup();
    await tags.add("c1", { targetType: "ioc", targetId: "i1", author: "a", label: "x" });
    const info = await mgr.createBackup("c1", "scheduled", "2026-07-01T00:00:00.000Z");
    const bundle = await readBundle(mgr, info.filename);
    expect(bundle.binaryFiles).toBeDefined();
    const fromBundle = [tag("b1", "i7", "from-bundle"), tag("b1", "i8", "dup-id")];
    await writeBundle(mgr, info.filename, { ...bundle, files: { ...bundle.files, "tags.json": fromBundle } });
    await tags.add("c1", { targetType: "ioc", targetId: "i2", author: "a", label: "later" });
    await mgr.restoreBackup("c1", info.filename);
    expect(await tags.load("c1")).toEqual(fromBundle);
  });

  it("a legacy investigation.json restore puts back the bundle's tags over a migrated database", async () => {
    const { mgr, state, tags } = await setup();
    await tags.add("c1", { targetType: "ioc", targetId: "i1", author: "a", label: "current" });
    const filename = "2026-07-01T00-00-00-000Z_scheduled.json";
    const fromBundle = [tag("b1", "i7", "from-bundle")];
    await writeBundle(mgr, filename, {
      files: {
        "investigation.json": { ...emptyState("c1"), lastSummary: "legacy" },
        "tags.json": fromBundle,
      },
    });
    await mgr.restoreBackup("c1", filename);
    expect((await state.load("c1")).lastSummary).toBe("legacy");
    expect(await tags.load("c1")).toEqual(fromBundle);
  });

  it("a bundle without tags.json keeps the current tags across a binary restore", async () => {
    const { mgr, state, tags } = await setup();
    const info = await mgr.createBackup("c1", "scheduled", "2026-07-01T00:00:00.000Z");
    expect((await readBundle(mgr, info.filename)).files).not.toHaveProperty("tags.json");
    await tags.add("c1", { targetType: "ioc", targetId: "i1", author: "a", label: "kept" });
    await state.save({ ...emptyState("c1"), lastSummary: "newer" });
    await mgr.restoreBackup("c1", info.filename);
    expect((await state.load("c1")).lastSummary).toBe("s");
    expect((await tags.load("c1")).map((t) => t.label)).toEqual(["kept"]);
  });

  it("an old bundle (tags.json beside a database with no tag table) restores its tags", async () => {
    const { mgr, tags } = await setup();
    const info = await mgr.createBackup("c1", "scheduled", "2026-07-01T00:00:00.000Z");
    const bundle = await readBundle(mgr, info.filename);
    // Rewind the snapshot to a database written before #1874: no tag tables, no marker.
    const db = new (loadDatabaseSync())(
      join(mgr.backupDir("c1"), bundle.binaryFiles!["investigation.sqlite"]),
    );
    db.exec(
      "DROP TABLE tags; DROP TABLE tags_protect_gen; DELETE FROM storage_meta WHERE key='tags_migrated'",
    );
    db.close();
    const fromBundle = [tag("o1", "i1", "old")];
    await writeBundle(mgr, info.filename, { ...bundle, files: { ...bundle.files, "tags.json": fromBundle } });
    await tags.add("c1", { targetType: "ioc", targetId: "i2", author: "a", label: "current" });
    await mgr.restoreBackup("c1", info.filename);
    expect(await tags.load("c1")).toEqual(fromBundle);
  });
});
