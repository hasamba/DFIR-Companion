import { describe, it, expect } from "vitest";
import { mkdtemp, writeFile, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, sep } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { JobManager } from "../../src/analysis/jobManager.js";
import { StateLock } from "../../src/analysis/stateLock.js";
import { BackupManager, resolveBackupConfig, RETAIN_FALLBACK_CAP, DEFAULT_MAX_BYTES, type BackupConfig, type BackupManagerDeps, type BackupTrigger } from "../../src/storage/backupManager.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import { createApp } from "../../src/server.js";

// ── Pure unit tests ───────────────────────────────────────────────────────────

describe("resolveBackupConfig", () => {
  it("returns defaults when env is empty", () => {
    const cfg = resolveBackupConfig({});
    expect(cfg.retain).toBe(24);
    expect(cfg.preSynthRetain).toBe(10);
    expect(cfg.intervalMs).toBe(3_600_000);
  });

  it("reads DFIR_STATE_BACKUP_RETAIN", () => {
    expect(resolveBackupConfig({ DFIR_STATE_BACKUP_RETAIN: "5" }).retain).toBe(5);
  });

  it("reads DFIR_STATE_BACKUP_PRE_SYNTH_RETAIN", () => {
    expect(resolveBackupConfig({ DFIR_STATE_BACKUP_PRE_SYNTH_RETAIN: "3" }).preSynthRetain).toBe(3);
  });

  it("reads DFIR_STATE_BACKUP_INTERVAL_MS and 0 disables", () => {
    expect(resolveBackupConfig({ DFIR_STATE_BACKUP_INTERVAL_MS: "0" }).intervalMs).toBe(0);
    expect(resolveBackupConfig({ DFIR_STATE_BACKUP_INTERVAL_MS: "60000" }).intervalMs).toBe(60_000);
  });

  it("clamps negative values to 0", () => {
    const cfg = resolveBackupConfig({ DFIR_STATE_BACKUP_RETAIN: "-5", DFIR_STATE_BACKUP_PRE_SYNTH_RETAIN: "-1" });
    // A negative retain is an unlimited request, so it lands on the fallback cap, never 0 (#251).
    expect(cfg.retain).toBe(RETAIN_FALLBACK_CAP);
    expect(cfg.preSynthRetain).toBe(0);
  });

  it("resolves an unlimited retain request to the fallback cap (#251)", () => {
    expect(resolveBackupConfig({ DFIR_STATE_BACKUP_RETAIN: "0" }).retain).toBe(RETAIN_FALLBACK_CAP);
    expect(RETAIN_FALLBACK_CAP).toBeGreaterThan(0);
  });

  it("falls back to the default for blank or non-numeric retain", () => {
    expect(resolveBackupConfig({ DFIR_STATE_BACKUP_RETAIN: "" }).retain).toBe(24);
    // Must not resolve to NaN: `kept < NaN` is always false, which would delete every backup.
    expect(resolveBackupConfig({ DFIR_STATE_BACKUP_RETAIN: "abc" }).retain).toBe(24);
  });

  it("defaults maxBytes to DEFAULT_MAX_BYTES (#295)", () => {
    expect(resolveBackupConfig({}).maxBytes).toBe(DEFAULT_MAX_BYTES);
    expect(DEFAULT_MAX_BYTES).toBeGreaterThan(0);
  });

  it("reads DFIR_STATE_BACKUP_MAX_BYTES (#295)", () => {
    expect(resolveBackupConfig({ DFIR_STATE_BACKUP_MAX_BYTES: "1048576" }).maxBytes).toBe(1_048_576);
  });

  it("treats 0 and negative maxBytes as the cap being off (#295)", () => {
    expect(resolveBackupConfig({ DFIR_STATE_BACKUP_MAX_BYTES: "0" }).maxBytes).toBe(0);
    expect(resolveBackupConfig({ DFIR_STATE_BACKUP_MAX_BYTES: "-1" }).maxBytes).toBe(0);
  });

  it("falls back to the default for blank or non-numeric maxBytes (#295)", () => {
    // NaN would make every `totalBytes > maxBytes` comparison false — the cap silently off.
    expect(resolveBackupConfig({ DFIR_STATE_BACKUP_MAX_BYTES: "" }).maxBytes).toBe(DEFAULT_MAX_BYTES);
    expect(resolveBackupConfig({ DFIR_STATE_BACKUP_MAX_BYTES: "abc" }).maxBytes).toBe(DEFAULT_MAX_BYTES);
  });
});

// ── BackupManager with real temp dirs ────────────────────────────────────────

/**
 * A minimal in-memory stand-in for the fs calls BackupManager makes, for the one test whose cost
 * is dominated by disk churn rather than by what it asserts. Deliberately faithful on the two
 * behaviours the manager actually depends on: readFile raises ENOENT for a missing snapshot file
 * (createBackup skips those), and readdir lists only the immediate children of a directory.
 */
function memoryFs(): Required<BackupManagerDeps> {
  const files = new Map<string, string>();
  const enoent = (path: string): NodeJS.ErrnoException =>
    Object.assign(new Error(`ENOENT: no such file or directory, open '${path}'`), { code: "ENOENT" });
  return {
    mkdir: async () => undefined,
    atomicWrite: async (path, content) => { files.set(path, content); },
    readFile: async (path) => {
      const content = files.get(path);
      if (content === undefined) throw enoent(path);
      return content;
    },
    readdir: async (dir) => {
      const prefix = dir.endsWith(sep) ? dir : dir + sep;
      const names = new Set<string>();
      for (const path of files.keys()) {
        if (!path.startsWith(prefix)) continue;
        const rest = path.slice(prefix.length);
        if (!rest.includes(sep)) names.add(rest);   // immediate children only
      }
      return [...names];
    },
    stat: async (path) => {
      const content = files.get(path);
      if (content === undefined) throw enoent(path);
      return { size: Buffer.byteLength(content, "utf8"), mtimeMs: 0 };
    },
    unlink: async (path) => { files.delete(path); },
  };
}

const MB = 1024 * 1024;

/**
 * memoryFs with stat reporting a caller-chosen size per backup filename, so the byte-cap tests can
 * describe 500 MB snapshots without writing 500 MB. Delegates to the real stat first so a missing
 * file still raises ENOENT (listBackups skips those).
 */
function sizedFs(sizeOf: (filename: string) => number): Required<BackupManagerDeps> {
  const fs = memoryFs();
  return {
    ...fs,
    stat: async (path) => {
      const real = await fs.stat(path);
      return { size: sizeOf(path.slice(path.lastIndexOf(sep) + 1)), mtimeMs: real.mtimeMs };
    },
  };
}

/**
 * Write backup files straight through the injected fs rather than via createBackup, so seeding a
 * fixture never triggers the prune that is under test. Hours are 2-digit, newest = highest.
 */
async function seedBackups(
  fs: Required<BackupManagerDeps>,
  mgr: BackupManager,
  caseId: string,
  entries: Array<[hour: string, trigger: BackupTrigger]>,
): Promise<void> {
  for (const [hour, trigger] of entries) {
    await fs.atomicWrite(join(mgr.backupDir(caseId), `2026-06-28T${hour}-00-00-000Z_${trigger}.json`), "{}");
  }
}

async function makeByteCapManager(
  maxBytes: number,
  sizeOf: (filename: string) => number,
  config: Partial<BackupConfig> = {},
): Promise<{ mgr: BackupManager; fs: Required<BackupManagerDeps> }> {
  const root = await mkdtemp(join(tmpdir(), "dfir-backup-bytes-"));
  const fs = sizedFs(sizeOf);
  const cfg: BackupConfig = { retain: 24, preSynthRetain: 10, intervalMs: 0, maxBytes, ...config };
  return { mgr: new BackupManager(new CaseStore(root), cfg, fs), fs };
}

async function makeManager(config: Partial<BackupConfig> = {}): Promise<{ mgr: BackupManager; store: CaseStore; root: string }> {
  const root = await mkdtemp(join(tmpdir(), "dfir-backup-"));
  const store = new CaseStore(root);
  const cfg: BackupConfig = { retain: 24, preSynthRetain: 10, intervalMs: 3_600_000, maxBytes: 0, ...config };
  const mgr = new BackupManager(store, cfg);
  return { mgr, store, root };
}

async function makeCase(store: CaseStore): Promise<string> {
  const caseId = `test-${Math.random().toString(36).slice(2, 8)}`;
  await store.createCase({ caseId, name: "Test", investigator: "Tester", aiProvider: null });
  // Write a minimal investigation.json so the backup has something to snapshot.
  await writeFile(
    join(store.stateDir(caseId), "investigation.json"),
    JSON.stringify({ caseId, forensicTimeline: [], findings: [], iocs: [] }),
  );
  return caseId;
}

describe("BackupManager.createBackup", () => {
  it("creates a backup file and returns info", async () => {
    const { mgr, store } = await makeManager();
    const caseId = await makeCase(store);

    const now = "2026-06-28T10:00:00.000Z";
    const info = await mgr.createBackup(caseId, "pre-synthesis", now);

    expect(info.trigger).toBe("pre-synthesis");
    expect(info.createdAt).toBe(now);
    expect(info.filename).toBe("2026-06-28T10-00-00-000Z_pre-synthesis.json");
    expect(info.sizeBytes).toBeGreaterThan(0);
  });

  it("backup contains state files", async () => {
    const { mgr, store } = await makeManager();
    const caseId = await makeCase(store);

    const { readFile } = await import("node:fs/promises");
    await mgr.createBackup(caseId, "pre-synthesis", "2026-06-28T10:00:00.000Z");
    const dir = mgr.backupDir(caseId);
    const raw = await readFile(join(dir, "2026-06-28T10-00-00-000Z_pre-synthesis.json"), "utf8");
    const bundle = JSON.parse(raw) as { files: Record<string, unknown> };
    expect(bundle.files["investigation.json"]).toBeDefined();
  });

  it("silently skips missing state files", async () => {
    const { mgr, store } = await makeManager();
    const caseId = await makeCase(store);
    // No tags.json written — should not throw
    const info = await mgr.createBackup(caseId, "scheduled", "2026-06-28T11:00:00.000Z");
    expect(info.trigger).toBe("scheduled");
  });
});

describe("BackupManager.listBackups", () => {
  it("returns empty array when no backups exist", async () => {
    const { mgr, store } = await makeManager();
    const caseId = await makeCase(store);
    expect(await mgr.listBackups(caseId)).toEqual([]);
  });

  it("returns backups newest first", async () => {
    const { mgr, store } = await makeManager();
    const caseId = await makeCase(store);

    await mgr.createBackup(caseId, "pre-synthesis", "2026-06-28T10:00:00.000Z");
    await mgr.createBackup(caseId, "scheduled",     "2026-06-28T11:00:00.000Z");
    await mgr.createBackup(caseId, "pre-synthesis", "2026-06-28T12:00:00.000Z");

    const list = await mgr.listBackups(caseId);
    expect(list[0].createdAt).toBe("2026-06-28T12:00:00.000Z");
    expect(list[2].createdAt).toBe("2026-06-28T10:00:00.000Z");
  });
});

describe("BackupManager.restoreBackup", () => {
  it("restores state files from backup", async () => {
    const { mgr, store } = await makeManager();
    const caseId = await makeCase(store);

    const now = "2026-06-28T10:00:00.000Z";
    const info = await mgr.createBackup(caseId, "pre-synthesis", now);

    // Migrate and change the primary SQLite state, then also damage the retained legacy file.
    const stateStore = new StateStore(store);
    await stateStore.save({ ...emptyState(caseId), lastSummary: "newer SQLite state" });
    const stateDir = store.stateDir(caseId);
    await writeFile(join(stateDir, "investigation.json"), JSON.stringify({ caseId, corrupted: true }));

    const { restored } = await mgr.restoreBackup(caseId, info.filename);
    expect(restored).toContain("investigation.json");

    const { readFile } = await import("node:fs/promises");
    const after = JSON.parse(await readFile(join(stateDir, "investigation.json"), "utf8")) as Record<string, unknown>;
    expect(after["corrupted"]).toBeUndefined();
    expect(after["forensicTimeline"]).toBeDefined();
    expect((await stateStore.load(caseId)).lastSummary).toBe("");
  });

  it("throws on unknown backup filename", async () => {
    const { mgr, store } = await makeManager();
    const caseId = await makeCase(store);
    await expect(mgr.restoreBackup(caseId, "not-a-backup.json")).rejects.toThrow("invalid backup filename");
  });

  it("throws when backup file does not exist", async () => {
    const { mgr, store } = await makeManager();
    const caseId = await makeCase(store);
    await expect(mgr.restoreBackup(caseId, "2026-06-28T10-00-00-000Z_pre-synthesis.json")).rejects.toThrow("backup not found");
  });

  it("snapshots and restores the SQLite case store without base64-loading it into the manifest", async () => {
    const { mgr, store } = await makeManager();
    const caseId = await makeCase(store);
    const stateStore = new StateStore(store);
    const before = { ...emptyState(caseId), lastSummary: "before backup" };
    before.iocs = [{ id: "i1", type: "domain", value: "example.invalid", firstSeen: "2026-07-30T00:00:00Z" }];
    await stateStore.save(before);

    const info = await mgr.createBackup(caseId, "pre-synthesis", "2026-07-30T10:00:00.000Z");
    const manifest = JSON.parse(
      await readFile(join(mgr.backupDir(caseId), info.filename), "utf8"),
    ) as { files?: Record<string, unknown>; binaryFiles?: Record<string, string> };
    expect(manifest.binaryFiles?.["investigation.sqlite"]).toMatch(/investigation\.sqlite$/);
    expect(manifest.files?.["investigation.json"]).toBeUndefined();
    expect(JSON.stringify(manifest)).not.toContain("SQLite format 3");

    await stateStore.save({ ...before, lastSummary: "after backup", iocs: [] });
    const result = await mgr.restoreBackup(caseId, info.filename);
    expect(result.restored).toContain("investigation.sqlite");
    expect(await new StateStore(store).load(caseId)).toEqual(before);
  });
});

describe("BackupManager.pruneBackups", () => {
  it("prunes down to retain limit", async () => {
    const { mgr, store } = await makeManager({ retain: 3, preSynthRetain: 1 });
    const caseId = await makeCase(store);

    // Create 5 backups
    for (let i = 0; i < 5; i++) {
      await mgr.createBackup(caseId, "scheduled", `2026-06-28T${String(i).padStart(2, "0")}:00:00.000Z`);
    }

    const list = await mgr.listBackups(caseId);
    expect(list.length).toBeLessThanOrEqual(3);
  });

  it("protects newest preSynthRetain pre-synthesis backups", async () => {
    const { mgr, store } = await makeManager({ retain: 3, preSynthRetain: 2 });
    const caseId = await makeCase(store);

    // 2 pre-synth + 4 scheduled = 6 total; retain=3 means we prune 3
    await mgr.createBackup(caseId, "pre-synthesis", "2026-06-28T01:00:00.000Z");
    await mgr.createBackup(caseId, "pre-synthesis", "2026-06-28T02:00:00.000Z");
    await mgr.createBackup(caseId, "scheduled",     "2026-06-28T03:00:00.000Z");
    await mgr.createBackup(caseId, "scheduled",     "2026-06-28T04:00:00.000Z");
    await mgr.createBackup(caseId, "scheduled",     "2026-06-28T05:00:00.000Z");
    await mgr.createBackup(caseId, "scheduled",     "2026-06-28T06:00:00.000Z");

    const list = await mgr.listBackups(caseId);
    const preSynth = list.filter((b) => b.trigger === "pre-synthesis");
    // Both pre-synth backups must survive
    expect(preSynth.length).toBe(2);
    // Protected entries are kept on top of the retain cap, so the real ceiling is retain + preSynthRetain.
    expect(list.length).toBe(5);
  });

  it("still prunes when the operator asks for unlimited retention (#251)", async () => {
    // Built through resolveBackupConfig so the test covers the real env → config → prune path.
    const cfg = resolveBackupConfig({ DFIR_STATE_BACKUP_RETAIN: "0", DFIR_STATE_BACKUP_PRE_SYNTH_RETAIN: "0" });
    const root = await mkdtemp(join(tmpdir(), "dfir-backup-"));
    const store = new CaseStore(root);
    // In-memory fs for this one case. What is under test is the PRUNE ARITHMETIC over 105
    // backups — that an unlimited request still caps at RETAIN_FALLBACK_CAP — and none of that
    // is about disk semantics (the real-fs path is covered by every other test in this file).
    // Done against the real filesystem it costs ~4s of write+readdir+stat churn on an idle
    // machine, which left no headroom inside the 15s budget once other suites competed for the
    // disk, and the test timed out. The deps seam exists exactly for this.
    const mgr = new BackupManager(store, cfg, memoryFs());
    const caseId = "unlimited-retain-case";

    for (let i = 0; i < RETAIN_FALLBACK_CAP + 5; i++) {
      const hh = String(Math.floor(i / 60)).padStart(2, "0");
      const mm = String(i % 60).padStart(2, "0");
      await mgr.createBackup(caseId, "scheduled", `2026-06-28T${hh}:${mm}:00.000Z`);
    }
    const list = await mgr.listBackups(caseId);
    expect(list.length).toBe(RETAIN_FALLBACK_CAP);
  });
});

// The count cap bounds how MANY backups a case keeps; it says nothing about how much disk they
// occupy, and one bundle can approach the ~512 MB state-load ceiling. These cover the byte cap
// that bounds the total (#295).
describe("BackupManager.pruneBackups byte cap (#295)", () => {
  const CASE = "byte-cap-case";

  it("evicts oldest-first until the total fits the budget", async () => {
    const { mgr, fs } = await makeByteCapManager(250 * MB, () => 100 * MB);
    await seedBackups(fs, mgr, CASE, [
      ["01", "scheduled"], ["02", "scheduled"], ["03", "scheduled"],
      ["04", "scheduled"], ["05", "scheduled"],
    ]);

    const result = await mgr.pruneBackups(CASE);

    // 5 × 100 MB = 500 MB; dropping the three oldest lands on 200 MB, the first total under 250 MB.
    expect((await mgr.listBackups(CASE)).map((b) => b.createdAt)).toEqual([
      "2026-06-28T05:00:00.000Z",
      "2026-06-28T04:00:00.000Z",
    ]);
    expect(result.totalBytes).toBe(200 * MB);
    expect(result.overBudget).toBe(false);
  });

  it("enforces the budget even when the count is under the retain limit", async () => {
    // Regression guard: the count pass used to return early whenever list.length <= retain, which
    // would skip the byte pass entirely for exactly the case it exists to catch — few, huge backups.
    const { mgr, fs } = await makeByteCapManager(150 * MB, () => 100 * MB, { retain: 24 });
    await seedBackups(fs, mgr, CASE, [["01", "scheduled"], ["02", "scheduled"], ["03", "scheduled"]]);

    await mgr.pruneBackups(CASE);

    expect((await mgr.listBackups(CASE)).map((b) => b.createdAt)).toEqual(["2026-06-28T03:00:00.000Z"]);
  });

  it("keeps the newest backup even when it alone exceeds the budget, and reports overBudget", async () => {
    // Deleting it would leave the case with no recovery point at all, which is worse than the
    // overrun; the operator gets told instead.
    const { mgr, fs } = await makeByteCapManager(250 * MB, () => 500 * MB);
    await seedBackups(fs, mgr, CASE, [["01", "scheduled"], ["02", "scheduled"], ["03", "scheduled"]]);

    const result = await mgr.pruneBackups(CASE);

    expect((await mgr.listBackups(CASE)).map((b) => b.createdAt)).toEqual(["2026-06-28T03:00:00.000Z"]);
    expect(result.totalBytes).toBe(500 * MB);
    expect(result.overBudget).toBe(true);
  });

  it("never deletes the only backup a case has", async () => {
    const { mgr, fs } = await makeByteCapManager(1 * MB, () => 500 * MB);
    await seedBackups(fs, mgr, CASE, [["01", "scheduled"]]);

    const result = await mgr.pruneBackups(CASE);

    expect(await mgr.listBackups(CASE)).toHaveLength(1);
    expect(result.overBudget).toBe(true);
  });

  it("keeps the newest pre-synthesis backup but counts older ones against the budget", async () => {
    // preSynthRetain protects both pre-synth entries from the COUNT pass; the byte pass still
    // evicts the older one, otherwise 10 large pre-synth snapshots could blow the cap on their own.
    const { mgr, fs } = await makeByteCapManager(150 * MB, () => 100 * MB, { preSynthRetain: 10 });
    await seedBackups(fs, mgr, CASE, [
      ["01", "pre-synthesis"], ["02", "pre-synthesis"], ["03", "scheduled"],
    ]);

    const result = await mgr.pruneBackups(CASE);

    expect((await mgr.listBackups(CASE)).map((b) => b.createdAt)).toEqual([
      "2026-06-28T03:00:00.000Z", // newest overall — never evicted
      "2026-06-28T02:00:00.000Z", // newest pre-synthesis — the rollback point #267 guarantees
    ]);
    // Both survivors are exempt, so the budget is still blown and the operator is told.
    expect(result.overBudget).toBe(true);
  });

  it("leaves every backup in place when the byte cap is off", async () => {
    const { mgr, fs } = await makeByteCapManager(0, () => 500 * MB, { retain: 24 });
    await seedBackups(fs, mgr, CASE, [
      ["01", "scheduled"], ["02", "scheduled"], ["03", "scheduled"],
    ]);

    const result = await mgr.pruneBackups(CASE);

    expect(await mgr.listBackups(CASE)).toHaveLength(3);
    expect(result.overBudget).toBe(false);
  });
});

describe("BackupManager.summary", () => {
  it("returns zeros for a case with no backups", async () => {
    const { mgr, store } = await makeManager();
    const caseId = await makeCase(store);
    const s = await mgr.summary(caseId);
    expect(s).toEqual({ count: 0, oldestAt: null, newestAt: null, totalBytes: 0 });
  });

  it("returns correct counts", async () => {
    const { mgr, store } = await makeManager();
    const caseId = await makeCase(store);
    await mgr.createBackup(caseId, "pre-synthesis", "2026-06-28T10:00:00.000Z");
    await mgr.createBackup(caseId, "scheduled",     "2026-06-28T11:00:00.000Z");
    const s = await mgr.summary(caseId);
    expect(s.count).toBe(2);
    expect(s.newestAt).toBe("2026-06-28T11:00:00.000Z");
    expect(s.oldestAt).toBe("2026-06-28T10:00:00.000Z");
    expect(s.totalBytes).toBeGreaterThan(0);
  });
});

// ── Route-level integration tests ─────────────────────────────────────────────

async function makeAppWithBackup(
  config: Partial<BackupConfig> = {},
  extra: { jobManager?: JobManager; stateLock?: StateLock } = {},
): Promise<{ app: ReturnType<typeof createApp>; store: CaseStore }> {
  const root = await mkdtemp(join(tmpdir(), "dfir-backup-route-"));
  const store = new CaseStore(root);
  const cfg: BackupConfig = { retain: 24, preSynthRetain: 10, intervalMs: 0, maxBytes: 0, ...config };
  const backupManager = new BackupManager(store, cfg);
  const app = createApp(store, { backupManager, ...extra });
  return { app, store };
}

// Seed a case with a backup, then corrupt the live state so a successful restore is observable.
async function seedRestorable(store: CaseStore): Promise<{ caseId: string; filename: string }> {
  const caseId = await makeCase(store);
  const mgr = new BackupManager(store, { retain: 24, preSynthRetain: 10, intervalMs: 0, maxBytes: 0 });
  const info = await mgr.createBackup(caseId, "pre-synthesis", "2026-06-28T10:00:00.000Z");
  await writeFile(join(store.stateDir(caseId), "investigation.json"), '{"corrupted":true}');
  return { caseId, filename: info.filename };
}

async function readState(store: CaseStore, caseId: string): Promise<Record<string, unknown>> {
  return JSON.parse(await readFile(join(store.stateDir(caseId), "investigation.json"), "utf8")) as Record<string, unknown>;
}

describe("GET /cases/:id/backups", () => {
  it("returns 404 for unknown case", async () => {
    const { app } = await makeAppWithBackup();
    const res = await request(app).get("/cases/nonexistent/backups");
    expect(res.status).toBe(404);
  });

  it("returns empty list for a new case", async () => {
    const { app, store } = await makeAppWithBackup();
    const caseId = await makeCase(store);
    const res = await request(app).get(`/cases/${caseId}/backups`);
    expect(res.status).toBe(200);
    expect(res.body.backups).toEqual([]);
  });
});

describe("POST /cases/:id/restore-backup", () => {
  it("returns 404 for unknown case", async () => {
    const { app } = await makeAppWithBackup();
    const res = await request(app).post("/cases/nonexistent/restore-backup").send({ filename: "x" });
    expect(res.status).toBe(404);
  });

  it("returns 400 for missing filename", async () => {
    const { app, store } = await makeAppWithBackup();
    const caseId = await makeCase(store);
    const res = await request(app).post(`/cases/${caseId}/restore-backup`).send({});
    expect(res.status).toBe(400);
  });

  it("returns 404 for non-existent backup file", async () => {
    const { app, store } = await makeAppWithBackup();
    const caseId = await makeCase(store);
    const res = await request(app)
      .post(`/cases/${caseId}/restore-backup`)
      .send({ filename: "2026-06-28T10-00-00-000Z_pre-synthesis.json" });
    expect(res.status).toBe(404);
  });

  it("restores a backup end-to-end", async () => {
    const { app, store } = await makeAppWithBackup();
    const caseId = await makeCase(store);

    // Create a backup via the manager directly
    const cfg: BackupConfig = { retain: 24, preSynthRetain: 10, intervalMs: 0, maxBytes: 0 };
    const mgr = new BackupManager(store, cfg);
    const info = await mgr.createBackup(caseId, "pre-synthesis", "2026-06-28T10:00:00.000Z");

    // Corrupt the state
    await writeFile(join(store.stateDir(caseId), "investigation.json"), '{"corrupted":true}');

    const res = await request(app)
      .post(`/cases/${caseId}/restore-backup`)
      .send({ filename: info.filename });
    expect(res.status).toBe(200);
    expect(res.body.restored).toContain("investigation.json");
  });

  // #251: a restore rewrites investigation.json wholesale, so it must not race an active writer.
  it("refuses with 409 while a job is in flight for the case", async () => {
    const jobManager = new JobManager();
    const { app, store } = await makeAppWithBackup({}, { jobManager });
    const { caseId, filename } = await seedRestorable(store);

    const { jobId } = jobManager.register({ caseId, kind: "synthesis", label: "re-synthesis", cancellable: true });

    const res = await request(app).post(`/cases/${caseId}/restore-backup`).send({ filename });
    expect(res.status).toBe(409);
    expect(res.body.kind).toBe("synthesis");
    expect(res.body.jobId).toBe(jobId);
    // The live state must be untouched — a rejected restore that half-wrote would be worse than none.
    expect((await readState(store, caseId)).corrupted).toBe(true);
  });

  it("refuses for any job kind, not just synthesis", async () => {
    const jobManager = new JobManager();
    const { app, store } = await makeAppWithBackup({}, { jobManager });
    const { caseId, filename } = await seedRestorable(store);

    jobManager.register({ caseId, kind: "import", label: "evtx import" });

    const res = await request(app).post(`/cases/${caseId}/restore-backup`).send({ filename });
    expect(res.status).toBe(409);
    expect(res.body.kind).toBe("import");
  });

  it("allows the restore once the job reaches a terminal state", async () => {
    const jobManager = new JobManager();
    const { app, store } = await makeAppWithBackup({}, { jobManager });
    const { caseId, filename } = await seedRestorable(store);

    const { jobId } = jobManager.register({ caseId, kind: "synthesis", cancellable: true });
    jobManager.finish(jobId);

    const res = await request(app).post(`/cases/${caseId}/restore-backup`).send({ filename });
    expect(res.status).toBe(200);
    expect((await readState(store, caseId)).corrupted).toBeUndefined();
  });

  it("is not blocked by a job belonging to a different case", async () => {
    const jobManager = new JobManager();
    const { app, store } = await makeAppWithBackup({}, { jobManager });
    const { caseId, filename } = await seedRestorable(store);
    const otherCase = await makeCase(store);

    jobManager.register({ caseId: otherCase, kind: "synthesis" });

    const res = await request(app).post(`/cases/${caseId}/restore-backup`).send({ filename });
    expect(res.status).toBe(200);
  });

  it("waits for an in-flight state-lock critical section instead of interleaving with it", async () => {
    const stateLock = new StateLock();
    const { app, store } = await makeAppWithBackup({}, { stateLock });
    const { caseId, filename } = await seedRestorable(store);

    // Hold the case's lock the way a manual event/IOC add does, and don't let go yet.
    let release!: () => void;
    const held = new Promise<void>((r) => { release = r; });
    const critical = stateLock.runExclusive(caseId, () => held);

    const pending = request(app).post(`/cases/${caseId}/restore-backup`).send({ filename });
    // While the lock is held the restore can never complete, however long we wait — so this races
    // against a generous timeout rather than draining a fixed number of event-loop turns, which an
    // unguarded restore (~20ms end to end) would also survive, passing the test for the wrong reason.
    const raced = await Promise.race([
      pending.then(() => "completed" as const),
      new Promise<"blocked">((r) => setTimeout(() => r("blocked"), 250)),
    ]);
    expect(raced).toBe("blocked");
    expect((await readState(store, caseId)).corrupted).toBe(true);

    release();
    await critical;
    const res = await pending;
    expect(res.status).toBe(200);
    expect((await readState(store, caseId)).corrupted).toBeUndefined();
  });
});
