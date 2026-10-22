// The installed Sigma rules and everything an analyst does to them (#2204): which release is
// active, preview / install / roll back a release, switch single rules off or back on, and keep a
// rule on while skipping known-benign values (exclusions, #2218).
//
// Reads are synchronous and served from memory, because every import takes a grading snapshot
// before it parses. Mutations are serialized and persisted crash-safely (sigmaReleaseFiles.ts).
// Nothing here downloads; the route hands in fetchers so the network stays behind the SSRF guard.

import { createHash, randomBytes } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import { mkdir, rename, rm } from "node:fs/promises";
import { join } from "node:path";
import { parse as parseYaml, stringify as stringifyYaml } from "yaml";
import { readDisabledList, readMeta, ruleFiles, SIGMA_MAX_RULE_FILES } from "./sigmaBundledRules.js";
import { diffSigmaReleases, readSigmaReleaseZip, type SigmaReleaseDiff } from "./sigmaReleaseArchive.js";
import { downloadSigmaRelease, latestSigmaRelease, type SigmaAssetFetch } from "./sigmaReleaseClient.js";
import {
  checkSigmaExclusion,
  exclusionsByRule,
  parseSigmaExclusions,
  SIGMA_EXCLUSION_LIMITS,
  sigmaExclusionKey,
  sigmaExclusionsHash,
  stringifySigmaExclusions,
  type SigmaExclusion,
} from "./sigmaExclusions.js";
import { fieldResolvers, SIGMA_LOG_SOURCES } from "./sigmaLogSources.js";
import {
  buildSigmaRuleSet,
  type SigmaInventoryEntry,
  type SigmaRuleFile,
  type SigmaRuleSet,
} from "./sigmaRuleSet.js";
import {
  BUNDLED,
  pruneExcept,
  readManifestSync,
  readReleaseMeta,
  readReleaseMetaSync,
  sigmaPaths,
  writeAtomic,
  writeManifest,
  writeReleaseDir,
  type InstalledReleaseMeta,
  type SigmaManifest,
} from "./sigmaReleaseFiles.js";
import { sigmaStatusesFromEnv } from "./sigmaSettings.js";

const PREVIEW_TTL_MS = 60 * 60 * 1000;

export interface SigmaOverrides {
  disabled: { id: string; reason: string }[];
  enabled: string[];
}

export interface SigmaReleaseInfo {
  id: string;
  release: string;
  commit: string;
  source: "bundled" | "github" | "file";
  verified: boolean;
  sha256?: string;
  installedAt?: string;
  fileName?: string;
  versionLabel?: string;
}

export interface SigmaPreview {
  token: string;
  release: SigmaReleaseInfo;
  diff: SigmaReleaseDiff;
  /** Rules that would load per graded log source, with the current settings. */
  loads: Record<string, number>;
  usable: boolean;
  problems: string[];
}

export interface SigmaLatestCheck {
  checkedAt: string;
  latest?: string;
  publishedAt?: string;
  installed: string;
  updateAvailable: boolean;
  error?: string;
}

interface Pending {
  token: string;
  dir: string;
  info: SigmaReleaseInfo;
  generation: number;
  createdAt: number;
  usable: boolean;
}

const tokenPart = (s: string) => s.replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 60) || "release";

export function loadsPerSource(set: SigmaRuleSet): Record<string, number> {
  const out: Record<string, number> = {};
  for (const e of set.inventory)
    if (e.outcome === "loaded" && e.source) out[e.source] = (out[e.source] ?? 0) + 1;
  return out;
}

export class SigmaRuleStore {
  private manifest: SigmaManifest = { active: BUNDLED, previous: null, generation: 0 };
  private activeInfo: SigmaReleaseInfo;
  private overrides: SigmaOverrides = { disabled: [], enabled: [] };
  private overridesVersion = 0;
  private exclusions: SigmaExclusion[] = [];
  /** The exclusions' hash, kept in the rule-set cache key (#2218). */
  private exclusionsKey = "none";
  private startupProblems: string[] = [];
  private cache?: { key: string; set: SigmaRuleSet; files: SigmaRuleFile[] };
  private pending?: Pending;
  private chain: Promise<unknown> = Promise.resolve();
  lastCheck?: SigmaLatestCheck;

  constructor(
    private readonly dataRoot: string,
    private readonly bundledDir: string | undefined,
    private readonly env: NodeJS.ProcessEnv = process.env,
  ) {
    this.activeInfo = this.bundledInfo();
  }

  // ── Startup ────────────────────────────────────────────────────────────────────────────────

  /** Read the manifest and overrides synchronously. Never throws: problems are reported instead. */
  load(): void {
    try {
      this.manifest = readManifestSync(this.dataRoot);
    } catch (error) {
      this.startupProblems.push(`${(error as Error).message} — using the bundled rules`);
    }
    this.activeInfo = this.infoFor(this.manifest.active);
    this.overrides = this.readOverrides();
    this.setExclusions(this.readExclusions());
  }

  /** load(), then drop staging leftovers and releases the manifest does not name. */
  async init(): Promise<void> {
    this.load();
    const paths = sigmaPaths(this.dataRoot);
    await pruneExcept(paths.staging, new Set());
    const keep = new Set([this.manifest.active, this.manifest.previous].filter((x): x is string => !!x));
    await pruneExcept(paths.releases, keep);
  }

  private bundledInfo(): SigmaReleaseInfo {
    const meta = this.bundledDir ? readMeta(this.bundledDir) : { release: "none", commit: "master" };
    return { id: BUNDLED, release: meta.release, commit: meta.commit, source: "bundled", verified: true };
  }

  /** A release folder counts only with readable metadata AND its rules/ folder (Codex review). */
  private intactMeta(id: string): InstalledReleaseMeta | undefined {
    const dir = join(sigmaPaths(this.dataRoot).releases, id);
    const meta = readReleaseMetaSync(dir);
    try {
      return meta && statSync(join(dir, "rules")).isDirectory() ? meta : undefined;
    } catch {
      return undefined;
    }
  }

  private infoFor(id: string): SigmaReleaseInfo {
    if (id === BUNDLED) return this.bundledInfo();
    const meta = this.intactMeta(id);
    if (!meta) {
      this.startupProblems.push(
        `the installed Sigma release ${id} could not be read — using the bundled rules`,
      );
      return this.bundledInfo();
    }
    return { id, ...this.metaInfo(meta) };
  }

  private metaInfo(meta: InstalledReleaseMeta): Omit<SigmaReleaseInfo, "id"> {
    return {
      release: meta.release,
      commit: meta.commit,
      source: meta.source,
      verified: meta.verified,
      sha256: meta.sha256,
      installedAt: meta.installedAt,
      ...(meta.fileName ? { fileName: meta.fileName } : {}),
      ...(meta.versionLabel ? { versionLabel: meta.versionLabel } : {}),
    };
  }

  // ── Reads (synchronous, cached) ────────────────────────────────────────────────────────────

  private activeDir(): string | undefined {
    return this.activeInfo.id === BUNDLED
      ? this.bundledDir
      : join(sigmaPaths(this.dataRoot).releases, this.activeInfo.id);
  }

  /** Shipped defaults − analyst re-enables + analyst disables (the latest action wins). */
  effectiveDisabled(): Map<string, string> {
    const shipped = this.shippedDisabled();
    const enabled = new Set(this.overrides.enabled);
    const out = new Map([...shipped].filter(([id]) => !enabled.has(id)));
    for (const d of this.overrides.disabled) out.set(d.id, d.reason);
    return out;
  }

  shippedDisabled(): Map<string, string> {
    if (!this.bundledDir) return new Map();
    try {
      return readDisabledList(readFileSync(join(this.bundledDir, "disabled.yml"), "utf8"));
    } catch {
      return new Map();
    }
  }

  private build(files: readonly SigmaRuleFile[], release: SigmaReleaseInfo): SigmaRuleSet {
    return buildSigmaRuleSet(
      files,
      { release: release.release, commit: release.commit },
      {
        statuses: sigmaStatusesFromEnv(this.env).statuses,
        disabled: this.effectiveDisabled(),
        exclusions: exclusionsByRule(this.exclusions),
      },
    );
  }

  private readFiles(dir: string | undefined): { files: SigmaRuleFile[]; problems: string[] } {
    if (!dir) return { files: [], problems: ["no bundled Sigma rules folder (data/sigma/rules) was found"] };
    const { files, overflow } = ruleFiles(dir);
    return {
      files,
      problems: overflow ? [`more than ${SIGMA_MAX_RULE_FILES} rule files; the rest were not read`] : [],
    };
  }

  /**
   * The active release's files. An installed release that cannot be read, or holds no rules, falls
   * back to the bundled rules with a problem sentence — imports never run on zero rules, and a read
   * error never reaches an import (Codex review of #2204).
   */
  private activeFiles(): { files: SigmaRuleFile[]; problems: string[] } {
    if (this.activeInfo.id === BUNDLED) return this.readFiles(this.bundledDir);
    let read: { files: SigmaRuleFile[]; problems: string[] } | undefined;
    let why = "it holds no rules";
    try {
      read = this.readFiles(this.activeDir());
    } catch (error) {
      why = (error as Error).message;
    }
    if (read && read.files.length > 0) return read;
    const failed = this.activeInfo.id;
    this.activeInfo = this.bundledInfo();
    this.startupProblems.push(
      `the installed Sigma release ${failed} could not be read (${why}) — using the bundled rules`,
    );
    return this.readFiles(this.bundledDir);
  }

  /** The rule set imports are graded with: the active release, current statuses and disabled list. */
  activeRuleSet(): SigmaRuleSet {
    const statuses = sigmaStatusesFromEnv(this.env).statuses.join(",");
    const key = `${this.activeInfo.id}|${statuses}|${this.overridesVersion}|${this.exclusionsKey}`;
    if (this.cache?.key === key) return this.cache.set;
    const files =
      this.cache && this.cache.key.split("|")[0] === this.activeInfo.id
        ? { files: this.cache.files, problems: [] }
        : this.activeFiles();
    const built = this.build(files.files, this.activeInfo);
    const set = { ...built, problems: [...this.startupProblems, ...files.problems, ...built.problems] };
    this.cache = { key, set, files: files.files };
    return set;
  }

  active(): SigmaReleaseInfo {
    return this.activeInfo;
  }

  previous(): SigmaReleaseInfo | null {
    if (!this.manifest.previous) return null;
    const meta =
      this.manifest.previous === BUNDLED
        ? undefined
        : readReleaseMetaSync(join(sigmaPaths(this.dataRoot).releases, this.manifest.previous));
    return this.manifest.previous === BUNDLED
      ? this.bundledInfo()
      : meta
        ? { id: this.manifest.previous, ...this.metaInfo(meta) }
        : null;
  }

  inventory(): SigmaStoreInventoryEntry[] {
    const shipped = this.shippedDisabled();
    const analyst = new Set(this.overrides.disabled.map((d) => d.id));
    return this.activeRuleSet().inventory.map((e) => {
      const excl = this.exclusions
        .filter((x) => x.id === e.id)
        .map(({ field, value, reason }) => ({ field, value, reason }));
      const withExcl = excl.length ? { ...e, exclusions: excl } : e;
      return e.outcome === "disabled"
        ? { ...withExcl, disabledBy: analyst.has(e.id) || !shipped.has(e.id) ? "analyst" : "shipped" }
        : withExcl;
    });
  }

  // ── Mutations (serialized) ─────────────────────────────────────────────────────────────────

  private serial<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.chain.then(fn, fn);
    this.chain = run.catch(() => undefined);
    return run;
  }

  private readOverrides(): SigmaOverrides {
    try {
      const doc = parseYaml(readFileSync(sigmaPaths(this.dataRoot).overrides, "utf8")) as Record<
        string,
        unknown
      > | null;
      const disabled = (Array.isArray(doc?.disabled) ? doc.disabled : [])
        .filter((d): d is { id: string; reason?: unknown } => typeof d?.id === "string" && d.id.trim() !== "")
        .map((d) => ({
          id: d.id.trim(),
          reason:
            typeof d.reason === "string" && d.reason.trim() ? d.reason.trim() : "disabled by the analyst",
        }));
      const enabled = (Array.isArray(doc?.enabled) ? doc.enabled : []).filter(
        (x): x is string => typeof x === "string",
      );
      return { disabled, enabled };
    } catch {
      return { disabled: [], enabled: [] };
    }
  }

  /** Switch one rule off (with a reason) or back on — shipped defaults included. */
  setRuleDisabled(id: string, disabled: boolean, reason = ""): Promise<void> {
    return this.serial(async () => {
      const clean = id.trim();
      if (!clean) throw new Error("a rule id is required");
      const without = this.overrides.disabled.filter((d) => d.id !== clean);
      const enabled = this.overrides.enabled.filter((e) => e !== clean);
      const next: SigmaOverrides = disabled
        ? {
            disabled: [...without, { id: clean, reason: reason.trim() || "disabled by the analyst" }],
            enabled,
          }
        : { disabled: without, enabled: this.shippedDisabled().has(clean) ? [...enabled, clean] : enabled };
      await writeAtomic(sigmaPaths(this.dataRoot).overrides, stringifyYaml(next));
      this.overrides = next;
      this.overridesVersion++;
    });
  }

  // ── Exclusions (#2218) ─────────────────────────────────────────────────────────────────────

  private readExclusions(): SigmaExclusion[] {
    try {
      return parseSigmaExclusions(readFileSync(sigmaPaths(this.dataRoot).exclusions, "utf8"));
    } catch {
      return [];
    }
  }

  private setExclusions(next: SigmaExclusion[]): void {
    this.exclusions = next;
    this.exclusionsKey = sigmaExclusionsHash(exclusionsByRule(next));
  }

  private async writeExclusions(next: SigmaExclusion[]): Promise<void> {
    await writeAtomic(sigmaPaths(this.dataRoot).exclusions, stringifySigmaExclusions(next));
    this.setExclusions(next);
  }

  /**
   * Keep rule `id` on but skip records whose `field` holds `value` (Sigma exact match, wildcards
   * allowed). The same rule, field and value again replaces the reason. A field the rule's log
   * source cannot read is refused: it resolves to nothing, so the exclusion would never fire.
   */
  setRuleExclusion(id: string, field: string, value: string, reason = ""): Promise<void> {
    return this.serial(async () => {
      const entry = checkedExclusion(id, field, value, reason);
      const rule = this.activeRuleSet().inventory.find((e) => e.id === entry.id && e.source);
      if (!rule) throw new SigmaStoreError(404, `no rule ${entry.id} for a log source the Companion grades`);
      const def = SIGMA_LOG_SOURCES.find((s) => s.id === rule.source);
      const resolvers = def ? fieldResolvers(def, entry.field) : { refused: "unknown log source" };
      if (!Array.isArray(resolvers)) throw new SigmaStoreError(422, resolvers.refused);
      const key = sigmaExclusionKey(entry);
      const others = this.exclusions.filter((x) => sigmaExclusionKey(x) !== key);
      if (others.length >= SIGMA_EXCLUSION_LIMITS.count)
        throw new SigmaStoreError(422, `at most ${SIGMA_EXCLUSION_LIMITS.count} exclusions can be kept`);
      await this.writeExclusions([...others, entry]);
    });
  }

  /** Drop one exclusion. Removing one that is not there changes nothing. */
  removeRuleExclusion(id: string, field: string, value: string): Promise<void> {
    return this.serial(async () => {
      const key = sigmaExclusionKey({ id: id.trim(), field: field.trim(), value: value.trim() });
      const next = this.exclusions.filter((x) => sigmaExclusionKey(x) !== key);
      if (next.length !== this.exclusions.length) await this.writeExclusions(next);
    });
  }

  /** Stage a release for review. Nothing becomes active. Replaces any earlier preview. */
  preview(
    bytes: Buffer,
    provenance: { source: "github" | "file"; tag?: string; fileName?: string; verified: boolean },
  ): Promise<SigmaPreview> {
    return this.serial(async () => {
      const contents = readSigmaReleaseZip(bytes);
      const sha256 = createHash("sha256").update(bytes).digest("hex");
      const release =
        provenance.source === "github" && provenance.tag
          ? provenance.tag
          : `file ${provenance.fileName ?? "upload.zip"}`;
      const meta: InstalledReleaseMeta = {
        release,
        commit: contents.commit ?? "master",
        sha256,
        source: provenance.source,
        verified: provenance.verified,
        installedAt: new Date().toISOString(),
        ...(provenance.fileName ? { fileName: provenance.fileName } : {}),
        ...(contents.versionLabel ? { versionLabel: contents.versionLabel } : {}),
      };
      const id = `${tokenPart(release)}-${sha256.slice(0, 12)}`;
      const info: SigmaReleaseInfo = { id, ...this.metaInfo(meta) };
      const set = this.build(contents.files, info);
      const loads = loadsPerSource(set);
      const usable = Object.values(loads).some((n) => n > 0);
      const token = `${sha256.slice(0, 16)}-${randomBytes(6).toString("hex")}`;
      const paths = sigmaPaths(this.dataRoot);
      await pruneExcept(paths.staging, new Set());
      const dir = join(paths.staging, token);
      await writeReleaseDir(dir, contents.files, meta);
      this.pending = {
        token,
        dir,
        info,
        generation: this.manifest.generation,
        createdAt: Date.now(),
        usable,
      };
      return {
        token,
        release: info,
        diff: diffSigmaReleases(this.activeFiles().files, contents.files),
        loads,
        usable,
        problems: [
          ...set.problems,
          ...(usable
            ? []
            : [
                "no rule in this release loads for a log source the Companion grades, so it cannot be installed",
              ]),
        ],
      };
    });
  }

  /** Make the previewed release active. The release it replaces becomes the rollback target. */
  install(token: string): Promise<SigmaReleaseInfo> {
    return this.serial(async () => {
      const p = this.pending;
      if (!p || p.token !== token)
        throw new SigmaStoreError(404, "that preview is gone — preview the release again");
      if (Date.now() - p.createdAt > PREVIEW_TTL_MS)
        throw new SigmaStoreError(409, "that preview is more than an hour old — preview the release again");
      if (p.generation !== this.manifest.generation)
        throw new SigmaStoreError(
          409,
          "the installed rules changed since this preview — preview the release again",
        );
      if (!p.usable)
        throw new SigmaStoreError(422, "no rule in this release loads for a log source the Companion grades");
      const paths = sigmaPaths(this.dataRoot);
      const target = join(paths.releases, p.info.id);
      if (p.info.id === this.manifest.active)
        throw new SigmaStoreError(409, "this release is already the active one");
      const existing = await readReleaseMeta(target);
      if (existing) await rm(p.dir, { recursive: true, force: true });
      else {
        await pruneExcept(paths.releases, new Set([this.manifest.active, this.manifest.previous ?? ""]));
        await mkdir(paths.releases, { recursive: true });
        await rename(p.dir, target).catch(async (error) => {
          if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
          throw new SigmaStoreError(404, "that preview is gone — preview the release again");
        });
      }
      await this.activate({
        active: p.info.id,
        previous: this.manifest.active,
        generation: this.manifest.generation + 1,
      });
      this.pending = undefined;
      return this.activeInfo;
    });
  }

  /** Swap back to the release that was active before the last install or rollback. */
  rollback(): Promise<SigmaReleaseInfo> {
    return this.serial(async () => {
      const prev = this.manifest.previous;
      if (!prev) throw new SigmaStoreError(409, "there is no earlier release to roll back to");
      if (prev !== BUNDLED && !this.intactMeta(prev))
        throw new SigmaStoreError(409, `the earlier release ${prev} can no longer be read`);
      await this.activate({
        active: prev,
        previous: this.manifest.active,
        generation: this.manifest.generation + 1,
      });
      return this.activeInfo;
    });
  }

  private async activate(next: SigmaManifest): Promise<void> {
    await writeManifest(this.dataRoot, next);
    this.manifest = next;
    this.startupProblems = [];
    this.activeInfo = this.infoFor(next.active);
    this.cache = undefined;
    const keep = new Set([next.active, next.previous].filter((x): x is string => !!x));
    await pruneExcept(sigmaPaths(this.dataRoot).releases, keep);
  }

  // ── GitHub ─────────────────────────────────────────────────────────────────────────────────

  async checkLatest(fetchFn: typeof fetch): Promise<SigmaLatestCheck> {
    const installed = this.activeInfo.release;
    try {
      const latest = await latestSigmaRelease(fetchFn);
      this.lastCheck = {
        checkedAt: new Date().toISOString(),
        latest: latest.tag,
        ...(latest.publishedAt ? { publishedAt: latest.publishedAt } : {}),
        installed,
        updateAvailable: latest.tag !== installed,
      };
    } catch (error) {
      this.lastCheck = {
        checkedAt: new Date().toISOString(),
        installed,
        updateAvailable: false,
        error: (error as Error).message,
      };
    }
    return this.lastCheck;
  }

  async previewLatest(fetchFn: typeof fetch, fetchAsset: SigmaAssetFetch): Promise<SigmaPreview> {
    const latest = await latestSigmaRelease(fetchFn);
    const bytes = await downloadSigmaRelease(latest, fetchAsset);
    return this.preview(bytes, { source: "github", tag: latest.tag, verified: true });
  }
}

export type SigmaStoreInventoryEntry = SigmaInventoryEntry & {
  disabledBy?: "shipped" | "analyst";
  exclusions?: { field: string; value: string; reason: string }[];
};

function checkedExclusion(id: string, field: string, value: string, reason: string): SigmaExclusion {
  const entry = checkSigmaExclusion({ id, field, value, reason });
  if (!entry)
    throw new SigmaStoreError(
      422,
      `an exclusion needs a rule id, a field (at most ${SIGMA_EXCLUSION_LIMITS.field} characters) ` +
        `and a value (at most ${SIGMA_EXCLUSION_LIMITS.value} characters)`,
    );
  return entry;
}

/** A refusal the route turns into an HTTP status with the sentence as the error. */
export class SigmaStoreError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}
