// #2169 — restoreBackup must reject a tampered bundle before it replaces any live state file.
// Real fs in a tmp dir and the real SQLite worker; no stubs. Each test builds a genuine backup with
// createBackup, tampers with the manifest or sidecar on disk, and checks both the rejection and that
// the live case state is byte-for-byte / value-for-value unchanged.
import { describe, it, expect } from "vitest";
import { mkdtemp, writeFile, readFile, readdir, unlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRequire } from "node:module";
import { CaseStore } from "../../src/storage/caseStore.js";
import { BackupManager, type BackupConfig } from "../../src/storage/backupManager.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { emptyState, type InvestigationState } from "../../src/analysis/stateTypes.js";

interface Manifest {
  createdAt: string;
  trigger: string;
  files: Record<string, unknown>;
  binaryFiles?: Record<string, string>;
}

interface Fixture {
  mgr: BackupManager;
  store: CaseStore;
  root: string;
  caseId: string;
}

// Vite cannot resolve the node:sqlite builtin through an ESM import, so load it the CommonJS way.
const { DatabaseSync } = createRequire(import.meta.url)("node:sqlite") as typeof import("node:sqlite");

const NOW = "2026-10-12T10:00:00.000Z";

async function makeFixture(): Promise<Fixture> {
  const root = await mkdtemp(join(tmpdir(), "dfir-backup-tamper-"));
  const store = new CaseStore(root);
  const cfg: BackupConfig = { retain: 24, preSynthRetain: 10, intervalMs: 0, maxBytes: 0 };
  const mgr = new BackupManager(store, cfg);
  const caseId = `tamper-${Math.random().toString(36).slice(2, 8)}`;
  await store.createCase({ caseId, name: "Tamper", investigator: "Tester", aiProvider: null });
  return { mgr, store, root, caseId };
}

/** A pre-SQLite case: the backup carries investigation.json inside the manifest. */
async function makeLegacyFixture(): Promise<Fixture> {
  const fx = await makeFixture();
  await writeFile(
    join(fx.store.stateDir(fx.caseId), "investigation.json"),
    JSON.stringify({ caseId: fx.caseId, forensicTimeline: [], findings: [], iocs: [] }),
  );
  return fx;
}

/** A migrated case: the backup carries the database as a binary sidecar. */
async function makeSqliteFixture(): Promise<Fixture> {
  const fx = await makeFixture();
  const stateStore = new StateStore(fx.store);
  await stateStore.save({ ...emptyState(fx.caseId), lastSummary: "backed-up state" });
  return fx;
}

function manifestPath(fx: Fixture, filename: string): string {
  return join(fx.mgr.backupDir(fx.caseId), filename);
}

async function readManifest(fx: Fixture, filename: string): Promise<Manifest> {
  return JSON.parse(await readFile(manifestPath(fx, filename), "utf8")) as Manifest;
}

async function writeManifest(fx: Fixture, filename: string, manifest: Manifest): Promise<void> {
  await writeFile(manifestPath(fx, filename), JSON.stringify(manifest));
}

/** Moves the live SQLite state past the backup so a wrongful restore would be visible. */
async function advanceLiveState(fx: Fixture): Promise<InvestigationState> {
  const live = { ...emptyState(fx.caseId), lastSummary: "live state after backup" };
  await new StateStore(fx.store).save(live);
  return new StateStore(fx.store).load(fx.caseId);
}

function entitiesRootPage(dbPath: string): number {
  const db = new DatabaseSync(dbPath, { readOnly: true });
  try {
    const row = db
      .prepare("SELECT rootpage FROM sqlite_schema WHERE type = 'table' AND name = 'entities'")
      .get() as { rootpage: number } | undefined;
    return Number(row?.rootpage ?? 0);
  } finally {
    db.close();
  }
}

async function listRecursive(dir: string): Promise<string[]> {
  const entries = await readdir(dir, { recursive: true });
  return entries.map(String);
}

describe("restoreBackup rejects a tampered bundle (#2169)", () => {
  it.each(["../../evil.json", "config.json"])(
    "rejects a manifest naming the non-allowlisted state file %s and writes nothing",
    async (badName) => {
      const fx = await makeLegacyFixture();
      const info = await fx.mgr.createBackup(fx.caseId, "pre-synthesis", NOW);
      const manifest = await readManifest(fx, info.filename);
      await writeManifest(fx, info.filename, {
        ...manifest,
        files: { ...manifest.files, [badName]: { pwned: true } },
      });
      const livePath = join(fx.store.stateDir(fx.caseId), "investigation.json");
      await writeFile(livePath, JSON.stringify({ caseId: fx.caseId, marker: "live" }));
      const liveBytes = await readFile(livePath, "utf8");

      await expect(fx.mgr.restoreBackup(fx.caseId, info.filename)).rejects.toThrow(
        /invalid state file reference/,
      );

      expect(await readFile(livePath, "utf8")).toBe(liveBytes);
      const leaf = badName.split("/").pop() as string;
      const written = (await listRecursive(fx.root)).filter((p) => p.endsWith(leaf));
      expect(written).toEqual([]);
    },
  );

  it("rejects a binary sidecar reference that points outside the backup dir", async () => {
    const fx = await makeSqliteFixture();
    const info = await fx.mgr.createBackup(fx.caseId, "pre-synthesis", NOW);
    const manifest = await readManifest(fx, info.filename);
    expect(manifest.binaryFiles?.["investigation.sqlite"]).toBeDefined();
    await writeManifest(fx, info.filename, {
      ...manifest,
      binaryFiles: { "investigation.sqlite": "../../../outside.sqlite" },
    });
    const live = await advanceLiveState(fx);

    await expect(fx.mgr.restoreBackup(fx.caseId, info.filename)).rejects.toThrow(
      /invalid binary sidecar reference/,
    );
    expect(await new StateStore(fx.store).load(fx.caseId)).toEqual(live);
  });

  it("rejects a binary sidecar for a name that is not a known binary state file", async () => {
    const fx = await makeSqliteFixture();
    const info = await fx.mgr.createBackup(fx.caseId, "pre-synthesis", NOW);
    const manifest = await readManifest(fx, info.filename);
    const stem = info.filename.slice(0, -".json".length);
    await writeManifest(fx, info.filename, {
      ...manifest,
      binaryFiles: { ...manifest.binaryFiles, "evil.bin": `${stem}.evil.bin` },
    });
    const live = await advanceLiveState(fx);

    await expect(fx.mgr.restoreBackup(fx.caseId, info.filename)).rejects.toThrow(
      /invalid binary sidecar reference: evil\.bin/,
    );
    expect(await new StateStore(fx.store).load(fx.caseId)).toEqual(live);
  });

  it("rejects a database sidecar that fails integrity_check", async () => {
    const fx = await makeSqliteFixture();
    const info = await fx.mgr.createBackup(fx.caseId, "pre-synthesis", NOW);
    const manifest = await readManifest(fx, info.filename);
    const sidecarPath = join(
      fx.mgr.backupDir(fx.caseId),
      manifest.binaryFiles?.["investigation.sqlite"] as string,
    );
    // Zero the root b-tree page of the core events table. The database still opens, so the restore
    // reaches PRAGMA integrity_check, which reports the damaged page (the ok:false branch). Zeroing an
    // arbitrary page instead can make SQLite throw "malformed" before integrity_check reports.
    const rootPage = entitiesRootPage(sidecarPath);
    const db = await readFile(sidecarPath);
    // SQLite header bytes 16-17: page size, big-endian; 1 encodes 65536.
    const raw = db.readUInt16BE(16);
    const pageSize = raw === 1 ? 65536 : raw;
    expect(rootPage).toBeGreaterThan(1);
    const tampered = Buffer.from(db);
    tampered.fill(0, (rootPage - 1) * pageSize, rootPage * pageSize);
    await writeFile(sidecarPath, tampered);
    const live = await advanceLiveState(fx);

    await expect(fx.mgr.restoreBackup(fx.caseId, info.filename)).rejects.toThrow(/integrity_check/);
    expect(await new StateStore(fx.store).load(fx.caseId)).toEqual(live);
  });

  it("rejects a database sidecar replaced with non-SQLite bytes", async () => {
    const fx = await makeSqliteFixture();
    const info = await fx.mgr.createBackup(fx.caseId, "pre-synthesis", NOW);
    const manifest = await readManifest(fx, info.filename);
    const sidecarPath = join(
      fx.mgr.backupDir(fx.caseId),
      manifest.binaryFiles?.["investigation.sqlite"] as string,
    );
    await writeFile(sidecarPath, Buffer.alloc(8192, 0x41));
    const live = await advanceLiveState(fx);

    await expect(fx.mgr.restoreBackup(fx.caseId, info.filename)).rejects.toThrow(
      /not a database|integrity_check/,
    );
    expect(await new StateStore(fx.store).load(fx.caseId)).toEqual(live);
  });

  it("rejects a bundle whose referenced sidecar is missing", async () => {
    const fx = await makeSqliteFixture();
    const info = await fx.mgr.createBackup(fx.caseId, "pre-synthesis", NOW);
    const manifest = await readManifest(fx, info.filename);
    const sidecar = manifest.binaryFiles?.["investigation.sqlite"] as string;
    await unlink(join(fx.mgr.backupDir(fx.caseId), sidecar));
    const live = await advanceLiveState(fx);

    await expect(fx.mgr.restoreBackup(fx.caseId, info.filename)).rejects.toThrow(
      `backup is incomplete: missing ${sidecar}`,
    );
    expect(await new StateStore(fx.store).load(fx.caseId)).toEqual(live);
  });

  it("still lists a manifest whose sidecar reference is invalid", async () => {
    const fx = await makeSqliteFixture();
    const info = await fx.mgr.createBackup(fx.caseId, "pre-synthesis", NOW);
    const manifest = await readManifest(fx, info.filename);
    await writeManifest(fx, info.filename, {
      ...manifest,
      binaryFiles: { "investigation.sqlite": "../../../outside.sqlite" },
    });

    const list = await fx.mgr.listBackups(fx.caseId);
    expect(list.map((b) => b.filename)).toEqual([info.filename]);
  });
});
