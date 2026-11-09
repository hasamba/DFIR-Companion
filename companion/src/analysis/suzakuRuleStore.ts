// Installed Suzaku CloudTrail rules (#2508): which version is active (the bundled copy or a commit
// downloaded from GitHub), and check / preview / install / roll back. Nothing installs on its own.
//
//   <dataRoot>/sigma/suzaku/installs/<id>/  one immutable folder per install, laid out like the
//                                           bundled data/sigma-suzaku (release.json + rules/aws/cloudtrail)
//   <dataRoot>/sigma/suzaku/staging/<token>/ the one previewed-but-not-installed commit
//   <dataRoot>/sigma/suzaku/active.json     { active, previous, generation } — "bundled" is a value
//
// Folders are written under a temporary name and renamed into place, and the manifest is replaced
// atomically, so a crash never leaves the active rules pointing at a half-written folder. Every
// install writes a fresh folder; an old one is never reused. An install that cannot be read falls
// back to the bundled copy, and EVERYTHING then describes the bundled copy (Codex plan review).
//
// Reads are synchronous (every import takes a grading snapshot first); mutations are serialized.

import { randomBytes } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import { mkdir, rename } from "node:fs/promises";
import { join } from "node:path";
import { pruneExcept, writeAtomic, writeReleaseDir, type InstalledReleaseMeta } from "./sigmaReleaseFiles.js";
import { diffSigmaReleases, type SigmaReleaseDiff } from "./sigmaReleaseArchive.js";
import type { SigmaRuleFile } from "./sigmaRuleSet.js";
import {
  readSuzakuMeta,
  SUZAKU_ORIGIN_KEY,
  SUZAKU_PATH_PREFIX,
  suzakuRuleFiles,
  type SuzakuActive,
  type SuzakuSource,
} from "./sigmaSuzakuRules.js";
import {
  downloadSuzakuRules,
  latestSuzakuCommit,
  SUZAKU_MAX_RULE_FILES,
  SUZAKU_REPO,
  SUZAKU_WATCH_PATH,
  type SuzakuCommit,
} from "./suzakuReleaseClient.js";
import type { ReleaseAssetFetch } from "./githubReleaseDownload.js";

const BUNDLED = "bundled";
const PREVIEW_TTL_MS = 60 * 60 * 1000;
const RULES_SUBDIR = join("rules", "aws", "cloudtrail");

/** A refusal the route turns into an HTTP status and a plain sentence. */
export class SuzakuStoreError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

export interface SuzakuVersionInfo {
  id: string;
  release: string;
  commit: string;
  date?: string;
  source: "bundled" | "github";
  installedAt?: string;
}

export interface SuzakuCheck {
  checkedAt: string;
  installed: string;
  installedCommit: string;
  latest?: string;
  latestCommit?: string;
  latestDate?: string;
  updateAvailable: boolean;
  error?: string;
}

/** Counts measured against the CURRENT SigmaHQ rules and settings (Codex plan review). */
export interface SuzakuMeasure {
  /** Suzaku rules that would load. */
  loads: number;
  /** Of those, how many sit at or above the Suzaku minimum level, so can raise severity. */
  raises: number;
}

export interface SuzakuPreview {
  token: string;
  release: SuzakuVersionInfo;
  diff: SigmaReleaseDiff;
  measure: SuzakuMeasure;
  usable: boolean;
}

interface Manifest {
  active: string;
  previous: string | null;
  generation: number;
}

interface Pending {
  token: string;
  dir: string;
  info: SuzakuVersionInfo;
  files: SigmaRuleFile[];
  generation: number;
  createdAt: number;
}

const paths = (dataRoot: string) => {
  const root = join(dataRoot, "sigma", "suzaku");
  return {
    installs: join(root, "installs"),
    staging: join(root, "staging"),
    manifest: join(root, "active.json"),
  };
};

const releaseLabel = (c: SuzakuCommit): string => `suzaku-${c.date}-${c.sha.slice(0, 7)}`;

/** Loader paths (suzaku/aws/cloudtrail/<name>): what the rule set sees. */
const loaderFiles = (files: readonly { name: string; text: string }[]): SigmaRuleFile[] =>
  files.map((f) => ({
    path: `${SUZAKU_PATH_PREFIX}aws/cloudtrail/${f.name}`,
    text: f.text,
    origin: SUZAKU_ORIGIN_KEY,
  }));

/** Disk paths (rules/aws/cloudtrail/<name>): what writeReleaseDir lays out under a folder. */
const diskFiles = (files: readonly { name: string; text: string }[]): SigmaRuleFile[] =>
  files.map((f) => ({ path: `rules/aws/cloudtrail/${f.name}`, text: f.text }));

function readManifest(file: string): Manifest {
  try {
    const raw = JSON.parse(readFileSync(file, "utf8")) as Record<string, unknown>;
    return {
      active: typeof raw.active === "string" && raw.active ? raw.active : BUNDLED,
      previous: typeof raw.previous === "string" && raw.previous ? raw.previous : null,
      generation: typeof raw.generation === "number" && Number.isFinite(raw.generation) ? raw.generation : 0,
    };
  } catch {
    return { active: BUNDLED, previous: null, generation: 0 };
  }
}

export class SuzakuRuleStore implements SuzakuSource {
  private manifest: Manifest = { active: BUNDLED, previous: null, generation: 0 };
  private resolved?: { manifestKey: string; active: SuzakuActive; info: SuzakuVersionInfo };
  private pending?: Pending;
  private chain: Promise<unknown> = Promise.resolve();
  lastCheck?: SuzakuCheck;

  constructor(
    private readonly dataRoot: string,
    private readonly bundledDir: string | undefined,
  ) {}

  /** Read the manifest synchronously. Never throws. */
  load(): void {
    this.manifest = readManifest(paths(this.dataRoot).manifest);
    this.resolved = undefined;
  }

  /** load(), then drop staging leftovers and installs the manifest does not name. */
  async init(): Promise<void> {
    this.load();
    const p = paths(this.dataRoot);
    await pruneExcept(p.staging, new Set());
    const keep = [this.manifest.active, this.manifest.previous].filter((x): x is string => !!x);
    await pruneExcept(p.installs, new Set(keep));
  }

  // ── Reads ──────────────────────────────────────────────────────────────────────────────────

  private bundledInfo(): SuzakuVersionInfo {
    const meta = this.bundledDir ? readSuzakuMeta(this.bundledDir) : { release: "none", commit: "main" };
    return { id: BUNDLED, release: meta.release, commit: meta.commit, source: "bundled" };
  }

  /** An install folder's info, or undefined when it is not complete (metadata + at least one rule). */
  private installInfo(id: string): SuzakuVersionInfo | undefined {
    const dir = join(paths(this.dataRoot).installs, id);
    try {
      const meta = JSON.parse(readFileSync(join(dir, "release.json"), "utf8")) as Record<string, unknown>;
      if (typeof meta.commit !== "string" || !/^[0-9a-f]{40}$/.test(meta.commit)) return undefined;
      if (!statSync(join(dir, RULES_SUBDIR)).isDirectory()) return undefined;
      // Read EVERY rule, not a sample: a later unreadable file must send the store to the bundled
      // copy rather than leave an install that loads nothing (Codex review).
      const read = suzakuRuleFiles(dir, SUZAKU_MAX_RULE_FILES);
      if (read.files.length === 0 || read.overflow) return undefined;
      return {
        id,
        release: typeof meta.release === "string" ? meta.release : id,
        commit: meta.commit,
        ...(typeof meta.date === "string" ? { date: meta.date } : {}),
        source: "github",
        ...(typeof meta.installedAt === "string" ? { installedAt: meta.installedAt } : {}),
      };
    } catch {
      return undefined;
    }
  }

  /** Files, problems, cache identity and version info, resolved together (fallback included). */
  private resolve(): { active: SuzakuActive; info: SuzakuVersionInfo } {
    const manifestKey = `${this.manifest.active}|${this.manifest.generation}`;
    if (this.resolved?.manifestKey === manifestKey) return this.resolved;
    const id = this.manifest.active;
    const info = id === BUNDLED ? undefined : this.installInfo(id);
    const out =
      id === BUNDLED
        ? { active: { key: BUNDLED, dir: this.bundledDir, problems: [] }, info: this.bundledInfo() }
        : info
          ? { active: { key: id, dir: join(paths(this.dataRoot).installs, id), problems: [] }, info }
          : {
              active: {
                key: `${BUNDLED}(fallback:${id})`,
                dir: this.bundledDir,
                problems: [
                  `the installed Suzaku rules ${id} could not be read — using the bundled Suzaku rules`,
                ],
              },
              info: this.bundledInfo(),
            };
    this.resolved = { manifestKey, ...out };
    return this.resolved;
  }

  activeSource(): SuzakuActive {
    return this.resolve().active;
  }

  /** The version in effect — the bundled copy when an install could not be read. */
  active(): SuzakuVersionInfo {
    return this.resolve().info;
  }

  previous(): SuzakuVersionInfo | null {
    const prev = this.manifest.previous;
    if (!prev) return null;
    return prev === BUNDLED ? this.bundledInfo() : (this.installInfo(prev) ?? null);
  }

  /** The last check, recomputed against the version in effect NOW (after an install or roll back). */
  checkAsOfNow(): SuzakuCheck | undefined {
    const c = this.lastCheck;
    if (!c) return undefined;
    const now = this.active();
    return {
      ...c,
      installed: now.release,
      installedCommit: now.commit,
      updateAvailable: !c.error && !!c.latestCommit && c.latestCommit !== now.commit,
    };
  }

  private activeFiles(): SigmaRuleFile[] {
    const dir = this.activeSource().dir;
    return dir ? suzakuRuleFiles(dir, SUZAKU_MAX_RULE_FILES).files : [];
  }

  // ── Mutations (serialized) ─────────────────────────────────────────────────────────────────

  private serial<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.chain.then(fn, fn);
    this.chain = run.catch(() => undefined);
    return run;
  }

  /** Ask GitHub for the newest commit touching the Suzaku CloudTrail folder. Never throws. */
  async checkLatest(fetchFn: typeof fetch): Promise<SuzakuCheck> {
    const now = this.active();
    const base = { checkedAt: new Date().toISOString(), installed: now.release, installedCommit: now.commit };
    try {
      const latest = await latestSuzakuCommit(fetchFn);
      this.lastCheck = {
        ...base,
        latest: releaseLabel(latest),
        latestCommit: latest.sha,
        latestDate: latest.date,
        updateAvailable: latest.sha !== now.commit,
      };
    } catch (error) {
      this.lastCheck = { ...base, updateAvailable: false, error: (error as Error).message };
    }
    return this.lastCheck;
  }

  /**
   * Download and verify the commit the check found (pinned — never a second "latest" lookup), stage
   * it, and measure it with `measure` against the current SigmaHQ rules and settings.
   */
  preview(
    commit: SuzakuCommit,
    fetchFn: typeof fetch,
    fetchAsset: ReleaseAssetFetch,
    measure: (files: SigmaRuleFile[]) => SuzakuMeasure,
  ): Promise<SuzakuPreview> {
    return this.serial(async () => {
      const download = await downloadSuzakuRules(commit, fetchFn, fetchAsset);
      const files = loaderFiles(download.files);
      const token = `${commit.sha.slice(0, 12)}-${randomBytes(6).toString("hex")}`;
      const info: SuzakuVersionInfo = {
        id: `suzaku-${commit.date}-${commit.sha.slice(0, 12)}-${randomBytes(3).toString("hex")}`,
        release: releaseLabel(commit),
        commit: commit.sha,
        date: commit.date,
        source: "github",
      };
      const p = paths(this.dataRoot);
      await pruneExcept(p.staging, new Set());
      await mkdir(p.staging, { recursive: true });
      const dir = join(p.staging, token);
      const meta = this.releaseMeta(info) as unknown as InstalledReleaseMeta;
      await writeReleaseDir(dir, diskFiles(download.files), meta);
      this.pending = { token, dir, info, files, generation: this.manifest.generation, createdAt: Date.now() };
      const m = measure(files);
      const diff = diffSigmaReleases(this.activeFiles(), files);
      return { token, release: info, diff, measure: m, usable: m.loads > 0 };
    });
  }

  private releaseMeta(info: SuzakuVersionInfo): Record<string, unknown> {
    return {
      origin: "Suzaku",
      repo: SUZAKU_REPO,
      path: SUZAKU_WATCH_PATH,
      release: info.release,
      commit: info.commit,
      date: info.date,
      verified: "every file matched its git blob SHA at this commit",
      installedAt: new Date().toISOString(),
    };
  }

  private livePending(token: string): Pending {
    const p = this.pending;
    if (!p || p.token !== token)
      throw new SuzakuStoreError(404, "that preview is gone — check for updates again");
    if (Date.now() - p.createdAt > PREVIEW_TTL_MS)
      throw new SuzakuStoreError(409, "that preview is more than an hour old — check for updates again");
    if (p.generation !== this.manifest.generation)
      throw new SuzakuStoreError(409, "the installed Suzaku rules changed since this preview — check again");
    return p;
  }

  /**
   * Make the previewed commit active. Re-measured first with the CURRENT settings and SigmaHQ rules:
   * a commit none of whose rules would load now is refused (Codex plan review).
   */
  install(token: string, measure: (files: SigmaRuleFile[]) => SuzakuMeasure): Promise<SuzakuVersionInfo> {
    return this.serial(async () => {
      const p = this.livePending(token);
      if (measure(p.files).loads === 0)
        throw new SuzakuStoreError(
          409,
          "none of these Suzaku rules would load with the current settings — nothing was installed",
        );
      const dirs = paths(this.dataRoot);
      await mkdir(dirs.installs, { recursive: true });
      await rename(p.dir, join(dirs.installs, p.info.id));
      // The rollback target is what was IN EFFECT — the bundled copy after a fallback.
      const effective = this.active().id;
      await this.writeManifest({
        active: p.info.id,
        previous: effective,
        generation: this.manifest.generation + 1,
      });
      this.pending = undefined;
      await pruneExcept(dirs.installs, new Set([p.info.id, effective]));
      return this.active();
    });
  }

  /** Swap back to the previous version (the bundled copy is always a valid target). */
  rollback(): Promise<SuzakuVersionInfo> {
    return this.serial(async () => {
      const prev = this.manifest.previous;
      if (!prev) throw new SuzakuStoreError(409, "there is no previous Suzaku version to roll back to");
      if (prev !== BUNDLED && !this.installInfo(prev))
        throw new SuzakuStoreError(409, "the previous Suzaku version can no longer be read");
      const effective = this.active().id;
      await this.writeManifest({
        active: prev,
        previous: effective,
        generation: this.manifest.generation + 1,
      });
      this.pending = undefined;
      return this.active();
    });
  }

  private async writeManifest(m: Manifest): Promise<void> {
    await writeAtomic(paths(this.dataRoot).manifest, `${JSON.stringify(m, null, 2)}\n`);
    this.manifest = m;
    this.resolved = undefined;
  }
}
