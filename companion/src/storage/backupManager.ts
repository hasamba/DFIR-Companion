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

// Backups are full copies of investigation.json (hundreds of MB on large cases) and fire on every
// synthesis plus an hourly timer, so "keep everything" fills the disk. When the operator asks for
// unlimited (retain=0) we substitute this cap instead — raise DFIR_STATE_BACKUP_RETAIN for more.
export const RETAIN_FALLBACK_CAP = 100;

// A count cap does not bound disk: at the ~512 MB state-load ceiling a single bundle is huge, so
// retain + preSynthRetain entries can still run to tens of GB per case (#295). 10 GiB is far above
// what a normal case ever reaches — it binds only on the runaway shape the cap exists to catch.
export const DEFAULT_MAX_BYTES = 10 * 1024 * 1024 * 1024;

export interface BackupConfig {
  /**
   * Max total backups to keep per case (DFIR_STATE_BACKUP_RETAIN, default 24). Always > 0: an
   * unlimited request (0, or a negative value clamped to 0) resolves to RETAIN_FALLBACK_CAP so
   * backups can never grow without bound.
   */
  retain: number;
  /** How many pre-synthesis backups to preserve on top of the total cap (DFIR_STATE_BACKUP_PRE_SYNTH_RETAIN, default 10). */
  preSynthRetain: number;
  /** Time-based backup interval in ms (DFIR_STATE_BACKUP_INTERVAL_MS, default 3 600 000 = 1 h). 0 = disabled. */
  intervalMs: number;
  /**
   * Max total bytes of backups to keep per case (DFIR_STATE_BACKUP_MAX_BYTES, default
   * DEFAULT_MAX_BYTES). 0 = no byte cap. Enforced per case rather than host-wide on purpose:
   * a global budget would delete one case's snapshots because a different case grew, which is
   * not a trade-off an investigator can predict. Host-level pressure is reported instead —
   * see the /diagnostics backups block and the DFIR_DISK_WARN_PCT check.
   */
  maxBytes: number;
}

/** What a prune pass did, so callers can log an overrun and diagnostics can report it. */
export interface BackupPruneResult {
  /** Backups actually unlinked by this pass. */
  deleted: number;
  /** Bytes remaining after the pass. */
  totalBytes: number;
  /** True when the survivors still exceed maxBytes because every one of them is exempt. */
  overBudget: boolean;
}

export function resolveBackupConfig(env: NodeJS.ProcessEnv = process.env): BackupConfig {
  // Parse retain explicitly (as intervalMs does below) instead of leaning on `|| 24`, which swallows
  // a literal "0" as falsy. 0 — and any negative value, which clamps to 0 — is the operator asking
  // for unlimited; that resolves to the fallback cap. Blank or non-numeric still falls back to 24.
  const rawRetain = env.DFIR_STATE_BACKUP_RETAIN;
  const parsedRetain = rawRetain != null && rawRetain !== "" ? Number(rawRetain) : 24;
  const requestedRetain = Math.max(0, Number.isFinite(parsedRetain) ? parsedRetain : 24);
  // Normalise here, not at prune time, so config.retain is the effective cap everywhere it is read
  // — including the /diagnostics report, which would otherwise show 0 while 100 were being kept.
  const retain = requestedRetain === 0 ? RETAIN_FALLBACK_CAP : requestedRetain;
  const preSynthRetain = Math.max(0, Number(env.DFIR_STATE_BACKUP_PRE_SYNTH_RETAIN) || 10);
  const rawInterval = env.DFIR_STATE_BACKUP_INTERVAL_MS;
  const intervalMs = Math.max(
    0,
    rawInterval != null && rawInterval !== "" ? Number(rawInterval) : 3_600_000,
  );
  // Parsed explicitly like retain above: a literal "0" is the operator turning the byte cap off,
  // while blank or non-numeric must land on the default rather than NaN — every `total > NaN`
  // comparison is false, which would leave the cap silently disabled.
  const rawMaxBytes = env.DFIR_STATE_BACKUP_MAX_BYTES;
  const parsedMaxBytes = rawMaxBytes != null && rawMaxBytes !== "" ? Number(rawMaxBytes) : DEFAULT_MAX_BYTES;
  const maxBytes = Math.max(0, Number.isFinite(parsedMaxBytes) ? parsedMaxBytes : DEFAULT_MAX_BYTES);
  return { retain, preSynthRetain, intervalMs, maxBytes };
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
   * Prunes the backup dir afterwards according to the configured retention policy; the prune's
   * outcome rides along on the result so the caller can log a byte-budget overrun.
   */
  async createBackup(
    caseId: string,
    trigger: BackupTrigger,
    now: string = new Date().toISOString(),
  ): Promise<BackupInfo & { prune: BackupPruneResult }> {
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
    const prune = await this.pruneBackups(caseId);
    return { filename, createdAt: now, trigger, sizeBytes, prune };
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
      // Compact, matching how StateStore writes investigation.json. Pretty-printing here would
      // re-inflate a restored state file by ~35% — and restoring a backup is exactly the recovery
      // path for a case that grew past the ~512 MB load ceiling, so it must not push it back over.
      await this.deps.atomicWrite(join(stateDir, name), JSON.stringify(content));
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
   * Prune the backup dir in two passes.
   *
   * Count pass: keep the newest `retain` backups, plus the newest `preSynthRetain` pre-synthesis
   * backups, which are preserved on top of that cap so frequent scheduled or pre-import backups
   * can never crowd them out. The ceiling is `retain + preSynthRetain`; `retain` is always > 0
   * (see resolveBackupConfig), so the entry count is always bounded.
   *
   * Byte pass (#295): a bounded count is not a bounded size — 34 bundles of a few hundred MB is
   * still tens of GB. Whatever survived the count pass is walked oldest → newest, deleting until
   * the total fits `maxBytes`. Two entries are exempt: the newest backup overall (deleting it
   * would leave the case with no recovery point) and the newest pre-synthesis backup (the
   * rollback point the count pass exists to guarantee). Older pre-synthesis backups are NOT
   * exempt — if they were, `preSynthRetain` large snapshots could blow the budget on their own
   * and the cap would not be a cap. When only exempt entries remain and the total is still over,
   * nothing more is deleted and the result reports `overBudget` for the caller to surface.
   */
  async pruneBackups(caseId: string): Promise<BackupPruneResult> {
    const list = await this.listBackups(caseId); // newest first
    const doomed = new Set<string>();

    // ── Count pass ──
    // retain <= 0 is defensive: hand-built configs bypass resolveBackupConfig's normalisation.
    if (this.config.retain > 0 && list.length > this.config.retain) {
      const preSynth = list.filter((b) => b.trigger === "pre-synthesis");
      const protectedSet = new Set(preSynth.slice(0, this.config.preSynthRetain).map((b) => b.filename));

      // Walk newest → oldest: fill retain slots, skipping protected entries (they're kept regardless).
      let kept = 0;
      for (const b of list) {
        if (protectedSet.has(b.filename)) continue;
        if (kept < this.config.retain) kept++;
        else doomed.add(b.filename);
      }
    }

    // ── Byte pass ──
    const survivors = list.filter((b) => !doomed.has(b.filename)); // still newest first
    let totalBytes = survivors.reduce((s, b) => s + b.sizeBytes, 0);
    let overBudget = false;

    if (this.config.maxBytes > 0 && totalBytes > this.config.maxBytes) {
      const exempt = new Set<string>();
      if (survivors.length > 0) exempt.add(survivors[0].filename); // newest overall
      const newestPreSynth = survivors.find((b) => b.trigger === "pre-synthesis");
      if (newestPreSynth) exempt.add(newestPreSynth.filename);

      for (let i = survivors.length - 1; i >= 0 && totalBytes > this.config.maxBytes; i--) {
        const b = survivors[i];
        if (exempt.has(b.filename)) continue;
        doomed.add(b.filename);
        totalBytes -= b.sizeBytes;
      }
      overBudget = totalBytes > this.config.maxBytes;
    }

    let deleted = 0;
    for (const filename of doomed) {
      try {
        await this.deps.unlink(join(this.backupDir(caseId), filename));
        deleted++;
      } catch {
        // Best-effort: a file that's already gone is not an error
      }
    }
    return { deleted, totalBytes, overBudget };
  }
}
