// On-disk layout of installed Sigma releases (#2204), crash-safe by construction (Codex plan review):
//
//   <dataRoot>/sigma/releases/<id>/   one immutable folder per installed release (release.json + rules)
//   <dataRoot>/sigma/staging/<token>/ the one previewed-but-not-installed release
//   <dataRoot>/sigma/active.json      { active, previous, generation } — "bundled" is a valid value
//   <dataRoot>/sigma/disabled.yml     the analyst's overrides of the shipped disabled list
//
// A release folder is written under a temporary name and renamed into place; the manifest is
// written to a temporary file and renamed over the old one. A crash at any point leaves the old
// manifest naming a complete folder, so the active rules never become "none".

import { readFileSync } from "node:fs";
import { mkdir, readdir, rename, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { randomBytes } from "node:crypto";
import type { SigmaRuleFile } from "./sigmaRuleSet.js";

export const BUNDLED = "bundled";

export interface SigmaManifest {
  active: string;
  previous: string | null;
  generation: number;
}

export interface InstalledReleaseMeta {
  /** The release name the analyst sees: the GitHub tag, or "file <name>". */
  release: string;
  commit: string;
  sha256: string;
  source: "github" | "file";
  /** True only for a download whose bytes matched GitHub's published digest. */
  verified: boolean;
  installedAt: string;
  fileName?: string;
  /** version.txt's own label — SigmaHQ's build label, recorded as stated, not verified. */
  versionLabel?: string;
}

export const sigmaPaths = (dataRoot: string) => {
  const root = join(dataRoot, "sigma");
  return {
    root,
    releases: join(root, "releases"),
    staging: join(root, "staging"),
    manifest: join(root, "active.json"),
    overrides: join(root, "disabled.yml"),
  };
};

const tmpName = (path: string) => `${path}.tmp-${randomBytes(6).toString("hex")}`;

/** Write `text` to `path` atomically (temp file + rename). */
export async function writeAtomic(path: string, text: string): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const tmp = tmpName(path);
  try {
    await writeFile(tmp, text, "utf8");
    await rename(tmp, path);
  } catch (error) {
    await rm(tmp, { force: true });
    throw error;
  }
}

export async function readManifest(dataRoot: string): Promise<SigmaManifest> {
  return readManifestSync(dataRoot);
}

/** Synchronous, so the store knows the active release before the first import can run. */
export function readManifestSync(dataRoot: string): SigmaManifest {
  try {
    const raw = JSON.parse(readFileSync(sigmaPaths(dataRoot).manifest, "utf8")) as Record<string, unknown>;
    return {
      active: typeof raw.active === "string" && raw.active ? raw.active : BUNDLED,
      previous: typeof raw.previous === "string" && raw.previous ? raw.previous : null,
      generation: typeof raw.generation === "number" && Number.isFinite(raw.generation) ? raw.generation : 0,
    };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT")
      return { active: BUNDLED, previous: null, generation: 0 };
    throw new Error(`the Sigma manifest (active.json) cannot be read: ${(error as Error).message}`);
  }
}

export const writeManifest = (dataRoot: string, m: SigmaManifest): Promise<void> =>
  writeAtomic(sigmaPaths(dataRoot).manifest, `${JSON.stringify(m, null, 2)}\n`);

/** Write a complete release folder at `dir` (temp folder + rename). `dir` must not exist. */
export async function writeReleaseDir(
  dir: string,
  files: readonly SigmaRuleFile[],
  meta: InstalledReleaseMeta,
): Promise<void> {
  const tmp = tmpName(dir);
  try {
    await mkdir(tmp, { recursive: true });
    await writeFile(join(tmp, "release.json"), `${JSON.stringify(meta, null, 2)}\n`, "utf8");
    const dirs = new Set(files.map((f) => dirname(join(tmp, f.path))));
    for (const d of dirs) await mkdir(d, { recursive: true });
    for (const f of files) await writeFile(join(tmp, f.path), f.text, "utf8");
    await rename(tmp, dir);
  } catch (error) {
    await rm(tmp, { recursive: true, force: true });
    throw error;
  }
}

export async function readReleaseMeta(dir: string): Promise<InstalledReleaseMeta | undefined> {
  return readReleaseMetaSync(dir);
}

export function readReleaseMetaSync(dir: string): InstalledReleaseMeta | undefined {
  try {
    return JSON.parse(readFileSync(join(dir, "release.json"), "utf8")) as InstalledReleaseMeta;
  } catch {
    return undefined;
  }
}

/** Remove every entry of `parent` not in `keep` (temporary leftovers included). */
export async function pruneExcept(parent: string, keep: ReadonlySet<string>): Promise<void> {
  let names: string[];
  try {
    names = await readdir(parent);
  } catch {
    return;
  }
  for (const name of names)
    if (!keep.has(name)) await rm(join(parent, name), { recursive: true, force: true });
}
