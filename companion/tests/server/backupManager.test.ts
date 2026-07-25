import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, mkdir, writeFile, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { JobManager } from "../../src/analysis/jobManager.js";
import { StateLock } from "../../src/analysis/stateLock.js";
import { BackupManager, resolveBackupConfig, RETAIN_FALLBACK_CAP, type BackupConfig, type BackupManagerDeps } from "../../src/storage/backupManager.js";
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
});

// ── BackupManager with real temp dirs ────────────────────────────────────────

async function makeManager(config: Partial<BackupConfig> = {}): Promise<{ mgr: BackupManager; store: CaseStore; root: string }> {
  const root = await mkdtemp(join(tmpdir(), "dfir-backup-"));
  const store = new CaseStore(root);
  const cfg: BackupConfig = { retain: 24, preSynthRetain: 10, intervalMs: 3_600_000, ...config };
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

    // Overwrite investigation.json with different content
    const stateDir = store.stateDir(caseId);
    await writeFile(join(stateDir, "investigation.json"), JSON.stringify({ caseId, corrupted: true }));

    const { restored } = await mgr.restoreBackup(caseId, info.filename);
    expect(restored).toContain("investigation.json");

    const { readFile } = await import("node:fs/promises");
    const after = JSON.parse(await readFile(join(stateDir, "investigation.json"), "utf8")) as Record<string, unknown>;
    expect(after["corrupted"]).toBeUndefined();
    expect(after["forensicTimeline"]).toBeDefined();
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
    const mgr = new BackupManager(store, cfg);
    const caseId = await makeCase(store);

    for (let i = 0; i < RETAIN_FALLBACK_CAP + 5; i++) {
      const hh = String(Math.floor(i / 60)).padStart(2, "0");
      const mm = String(i % 60).padStart(2, "0");
      await mgr.createBackup(caseId, "scheduled", `2026-06-28T${hh}:${mm}:00.000Z`);
    }
    const list = await mgr.listBackups(caseId);
    expect(list.length).toBe(RETAIN_FALLBACK_CAP);
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
  const cfg: BackupConfig = { retain: 24, preSynthRetain: 10, intervalMs: 0, ...config };
  const backupManager = new BackupManager(store, cfg);
  const app = createApp(store, { backupManager, ...extra });
  return { app, store };
}

// Seed a case with a backup, then corrupt the live state so a successful restore is observable.
async function seedRestorable(store: CaseStore): Promise<{ caseId: string; filename: string }> {
  const caseId = await makeCase(store);
  const mgr = new BackupManager(store, { retain: 24, preSynthRetain: 10, intervalMs: 0 });
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
    const cfg: BackupConfig = { retain: 24, preSynthRetain: 10, intervalMs: 0 };
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
