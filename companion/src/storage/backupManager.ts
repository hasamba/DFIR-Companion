import { mkdir, readdir, stat, readFile, unlink } from "node:fs/promises";
import { join } from "node:path";
import { atomicWrite } from "./atomicWrite.js";
import { SNAPSHOT_STATE_FILES } from "../analysis/investigationStateFiles.js";
import type { CaseStore } from "./caseStore.js";

export type BackupTrigger = "pre-synthesis" | "pre-import" | "scheduled" | "shutdown";

export interface BackupInfo {
  filename: string;
  createdAt: string;
  trigger: BackupTrigger;
  sizeBytes: number;
}

export interface BackupSummary {
  count: number;
  oldestAt: string | null;
  newestAt: string | null;
  totalBytes: number;
}

export interface BackupConfig {
  /** Max total backups to keep per case (DFIR_STATE_BACKUP_RETAIN, default 24). 0 = unlimited. */
  retain: number;
  /** How many pre-synthesis backups to preserve within the total cap (DFIR_STATE_BACKUP_PRE_SYNTH_RETAIN, default 10). */
  preSynthRetain: number;
  /** Time-based backup interval in ms (DFIR_STATE_BACKUP_INTERVAL_MS, default 3 600 000 = 1 h). 0 = disabled. */
  intervalMs: number;
}

export function resolveBackupConfig(env: NodeJS.ProcessEnv = process.env): BackupConfig {
  const retain = Math.max(0, Number(env.DFIR_STATE_BACKUP_RETAIN) || 24);
  const preSynthRetain = Math.max(0, Number(env.DFIR_STATE_BACKUP_PRE_SYNTH_RETAIN) || 10);
  const rawInterval = env.DFIR_STATE_BACKUP_INTERVAL_MS;
  const intervalMs = Math.max(
    0,
    rawInterval != null && rawInterval !== "" ? Number(rawInterval) : 3_600_000,
  );
  return { retain, preSynthRetain, intervalMs };
}

// Replace colons + dots with dashes so timestamps are safe on Windows filenames.
function safeTimestamp(iso: string): string {
  return iso.replace(/[:.]/g, "-");
}

// Reverse safeTimestamp: "2026-06-28T10-30-00-000Z" → "2026-06-28T10:30:00.000Z"
function unsafeTimestamp(safe: string): string {
  const tIdx = safe.indexOf("T");
  if (tIdx < 0) return safe;
  const after = safe.slice(tIdx + 1);
  const parts = after.split("-");
  if (parts.length < 4) return safe;
  return safe.slice(0, tIdx + 1) + parts[0] + ":" + parts[1] + ":" + parts[2] + "." + parts[3];
}

function backupFilename(createdAt: string, trigger: BackupTrigger): string {
  return `${safeTimestamp(createdAt)}_${trigger}.json`;
}

// Returns null if the name does not match the expected pattern.
function parseBackupFilename(filename: string): { createdAt: string; trigger: BackupTrigger } | null {
  const m = filename.match(/^(\d{4}-\d{2}-\d{2}T[\d-]+Z)_([a-z-]+)\.json$/);
  if (!m) return null;
  return { createdAt: unsafeTimestamp(m[1]), trigger: m[2] as BackupTrigger };
}

// Dependency injection surface so tests can swap out disk I/O.
export interface BackupManagerDeps {
  mkdir?: (path: string, opts: { recursive: boolean }) => Promise<unknown>;
  readdir?: (path: string) => Promise<string[]>;
  stat?: (path: string) => Promise<{ size: number; mtimeMs: number }>;
  readFile?: (path: string, enc: "utf8") => Promise<string>;
  unlink?: (path: string) => Promise<void>;
  atomicWrite?: (path: string, content: string) => Promise<void>;
}

export class BackupManager {
  private readonly deps: Required<BackupManagerDeps>;

  constructor(
    private readonly cases: CaseStore,
    readonly config: BackupConfig,
    deps: BackupManagerDeps = {},
  ) {
    this.deps = {
      mkdir: deps.mkdir ?? ((p, o) => mkdir(p, o)),
      readdir: deps.readdir ?? ((p) => readdir(p)),
      stat: deps.stat ?? ((p) => stat(p)),
      readFile: deps.readFile ?? ((p, e) => readFile(p, e)),
      unlink: deps.unlink ?? ((p) => unlink(p)),
      atomicWrite: deps.atomicWrite ?? atomicWrite,
    };
  }

  backupDir(caseId: string): string {
    return join(this.cases.stateDir(caseId), "backups");
  }

  /**
   * Snapshot all present SNAPSHOT_STATE_FILES into a single bundle and write it to the backup dir.
   * Prunes the backup dir afterwards according to the configured retention policy.
   */
  async createBackup(
    caseId: string,
    trigger: BackupTrigger,
    now: string = new Date().toISOString(),
  ): Promise<BackupInfo> {
    const dir = this.backupDir(caseId);
    await this.deps.mkdir(dir, { recursive: true });

    const stateDir = this.cases.stateDir(caseId);
    const files: Record<string, unknown> = {};
    for (const name of SNAPSHOT_STATE_FILES) {
      try {
        const content = await this.deps.readFile(join(stateDir, name), "utf8");
        files[name] = JSON.parse(content) as unknown;
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
        // File absent for this case — skip
      }
    }

    const bundle = { createdAt: now, trigger, files };
    const filename = backupFilename(now, trigger);
    const json = JSON.stringify(bundle);
    await this.deps.atomicWrite(join(dir, filename), json);

    const sizeBytes = Buffer.byteLength(json, "utf8");
    const info: BackupInfo = { filename, createdAt: now, trigger, sizeBytes };

    await this.pruneBackups(caseId);
    return info;
  }

  /** List all backups for a case, newest first. */
  async listBackups(caseId: string): Promise<BackupInfo[]> {
    const dir = this.backupDir(caseId);
    let entries: string[];
    try {
      entries = await this.deps.readdir(dir);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }

    const infos: BackupInfo[] = [];
    for (const name of entries) {
      const parsed = parseBackupFilename(name);
      if (!parsed) continue;
      try {
        const s = await this.deps.stat(join(dir, name));
        infos.push({ filename: name, ...parsed, sizeBytes: s.size });
      } catch {
        // File disappeared between readdir and stat — skip
      }
    }

    infos.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
    return infos;
  }

  /**
   * Restore a backup: write each bundled state file back to the case's state dir via atomicWrite
   * so partial restores never leave a corrupt file. Returns the list of restored filenames.
   */
  async restoreBackup(caseId: string, filename: string): Promise<{ restored: string[] }> {
    if (!parseBackupFilename(filename)) throw new Error(`invalid backup filename: ${filename}`);

    const backupPath = join(this.backupDir(caseId), filename);
    let bundle: { createdAt: string; trigger: BackupTrigger; files: Record<string, unknown> };
    try {
      const raw = await this.deps.readFile(backupPath, "utf8");
      bundle = JSON.parse(raw) as typeof bundle;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") throw new Error(`backup not found: ${filename}`);
      throw err;
    }

    const stateDir = this.cases.stateDir(caseId);
    const restored: string[] = [];
    for (const [name, content] of Object.entries(bundle.files ?? {})) {
      await this.deps.atomicWrite(join(stateDir, name), JSON.stringify(content, null, 2));
      restored.push(name);
    }
    return { restored };
  }

  /** Aggregate backup count + disk usage for a case. */
  async summary(caseId: string): Promise<BackupSummary> {
    const list = await this.listBackups(caseId);
    const totalBytes = list.reduce((s, b) => s + b.sizeBytes, 0);
    return {
      count: list.length,
      oldestAt: list.length > 0 ? list[list.length - 1].createdAt : null,
      newestAt: list.length > 0 ? list[0].createdAt : null,
      totalBytes,
    };
  }

  /**
   * Prune the backup dir: keep at most `retain` backups per case. Within that cap, always
   * preserve the newest `preSynthRetain` pre-synthesis backups so they are never crowded out
   * by frequent scheduled or pre-import backups. If `retain` is 0, nothing is deleted.
   */
  async pruneBackups(caseId: string): Promise<void> {
    if (this.config.retain === 0) return;
    const list = await this.listBackups(caseId); // newest first
    if (list.length <= this.config.retain) return;

    // Always keep the newest preSynthRetain pre-synthesis backups.
    const preSynth = list.filter((b) => b.trigger === "pre-synthesis");
    const protectedSet = new Set(preSynth.slice(0, this.config.preSynthRetain).map((b) => b.filename));

    // Walk newest → oldest: fill retain slots, skipping protected entries (they're kept regardless).
    let kept = 0;
    for (const b of list) {
      if (protectedSet.has(b.filename)) continue;
      if (kept < this.config.retain) {
        kept++;
      } else {
        try {
          await this.deps.unlink(join(this.backupDir(caseId), b.filename));
        } catch {
          // Best-effort: a file that's already gone is not an error
        }
      }
    }
  }
}
