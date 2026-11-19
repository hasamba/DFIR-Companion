// AI Agent Forensics (#2690, §7, §14.1): the SEPARATE AI-agent rule pack — check → review → install →
// roll back, the same trust as the detection rule pack (rulePackClient.ts), in its own tag family.
//
//   - Releases are listed from this repository only, and only `aiagent-rules-YYYY.MM.DD[.N]` tags count.
//     Older apps' tagger pack check matches `^rules-YYYY…` only, so they never see these.
//   - Both assets come from GitHub's release hosts only, size-capped, each matching the SHA-256 GitHub
//     publishes (githubReleaseDownload.ts); the bundle must also match the manifest's SHA-256, and every
//     file in it must match the manifest's per-file list.
//   - A pack that needs a newer app is refused with a sentence saying so.
//   - A downloaded pack is written to a staging folder and LOADED (aiAgentRuleSet.ts) before it can be
//     installed: a set that does not load never becomes active.
//   - Install switches the live rule set (aiAgentActiveRules.ts) for the NEXT run. Past runs keep the
//     version they ran with, and existing case events are never regraded.

import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, normalize, relative, sep } from "node:path";
import { parseReleaseAssets } from "./velociraptorRelease.js";
import { DEFAULT_UPDATE_REPO } from "./updateCheck.js";
import { downloadVerifiedAsset, sha256Hex, type ReleaseAssetFetch } from "./githubReleaseDownload.js";
import { githubErrorMessage } from "./githubHttpError.js";
import { comparePackVersions, packFit, needsNewerAppMessage } from "./rulePackManifest.js";
import { loadAiAgentRuleSet, type AiAgentRuleSet } from "./aiAgentRuleSet.js";
import { setActiveAiAgentRulesDir, activeAiAgentRuleSet } from "./aiAgentActiveRules.js";
import { atomicWrite } from "../storage/atomicWrite.js";

export const AI_PACK_TAG = /^aiagent-rules-(\d{4})\.(\d{2})\.(\d{2})(?:\.(\d{1,4}))?$/;
export const AI_PACK_BUNDLE_ASSET = "ai-agent-rules.json";
export const AI_PACK_MANIFEST_ASSET = "ai-agent-pack-manifest.json";
const AI_PACK_KIND = "dfir-companion-ai-agent-rule-pack";
const MAX_MANIFEST_BYTES = 256 * 1024;
const MAX_BUNDLE_BYTES = 8 * 1024 * 1024;
const ASSET_TIMEOUT_MS = 60_000;

export class AiAgentPackError extends Error {
  constructor(
    message: string,
    readonly status = 400,
  ) {
    super(message);
  }
}

export interface AiAgentPackManifest {
  version: string;
  minAppVersion: string;
  createdAt: string;
  upstream: { name: string; commit: string; date: string };
  ruleCount: number;
  bundleSha256: string;
  contents: { path: string; sha256: string }[];
}

export interface AiAgentPackRelease {
  tag: string;
  htmlUrl?: string;
  bundle: { url: string; sha256?: string };
  manifest: { url: string; sha256?: string };
}

export const isAiPackTag = (tag: string): boolean => AI_PACK_TAG.test(tag.trim());
// The tag family is ordered like the detection packs' (same date shape); reuse that comparison.
const compareTags = (a: string, b: string): number =>
  comparePackVersions(a.replace(/^aiagent-/, ""), b.replace(/^aiagent-/, ""));

/** Validate a manifest's shape; throws AiAgentPackError naming what is wrong. */
export function parseAiPackManifest(text: string): AiAgentPackManifest {
  let o: Record<string, unknown>;
  try {
    o = JSON.parse(text) as Record<string, unknown>;
  } catch {
    throw new AiAgentPackError("the AI-agent pack manifest is not JSON");
  }
  const files = Array.isArray(o.files) ? (o.files as Record<string, unknown>[]) : [];
  const bundle = files.find((f) => f?.name === AI_PACK_BUNDLE_ASSET);
  const up = (o.upstream ?? {}) as Record<string, unknown>;
  const contents = Array.isArray(o.contents) ? (o.contents as Record<string, unknown>[]) : [];
  if (
    o.kind !== AI_PACK_KIND ||
    typeof o.version !== "string" ||
    !isAiPackTag(o.version) ||
    typeof o.minAppVersion !== "string" ||
    typeof bundle?.sha256 !== "string" ||
    typeof up.commit !== "string" ||
    !contents.every((c) => typeof c.path === "string" && typeof c.sha256 === "string")
  )
    throw new AiAgentPackError("the AI-agent pack manifest is missing a required field");
  return {
    version: o.version,
    minAppVersion: o.minAppVersion,
    createdAt: typeof o.createdAt === "string" ? o.createdAt : "",
    upstream: { name: String(up.name ?? ""), commit: up.commit, date: String(up.date ?? "") },
    ruleCount: Number(o.ruleCount) || 0,
    bundleSha256: bundle.sha256.toLowerCase(),
    contents: contents.map((c) => ({ path: String(c.path), sha256: String(c.sha256).toLowerCase() })),
  };
}

/** The pack's files, each checked against the manifest. Paths may not leave the pack folder. */
export function verifyAiPackBundle(
  text: string,
  manifest: AiAgentPackManifest,
): { path: string; text: string }[] {
  if (sha256Hex(text) !== manifest.bundleSha256)
    throw new AiAgentPackError(
      "the AI-agent pack does not match its manifest's SHA-256; nothing was installed",
    );
  const parsed = JSON.parse(text) as { files?: { path?: unknown; text?: unknown }[] };
  const files = (parsed.files ?? []).map((f) => ({ path: String(f.path ?? ""), text: String(f.text ?? "") }));
  const want = new Map(manifest.contents.map((c) => [c.path, c.sha256]));
  for (const f of files) {
    const p = normalize(f.path);
    if (!f.path || p.startsWith("..") || p.startsWith(sep) || /^[A-Za-z]:/.test(p) || f.path.includes("\0"))
      throw new AiAgentPackError(`the AI-agent pack names an unsafe path: ${f.path}`);
    if (want.get(f.path) !== sha256Hex(f.text))
      throw new AiAgentPackError(
        `the AI-agent pack file ${f.path} does not match its manifest; nothing was installed`,
      );
  }
  if (files.length !== want.size)
    throw new AiAgentPackError("the AI-agent pack's file list does not match its manifest");
  return files;
}

/** The AI-agent pack releases of this repository, newest first. */
export async function listAiPackReleases(
  fetchFn: typeof fetch,
  repo = DEFAULT_UPDATE_REPO,
): Promise<AiAgentPackRelease[]> {
  const resp = await fetchFn(`https://api.github.com/repos/${repo}/releases?per_page=100`, {
    headers: { Accept: "application/vnd.github+json", "User-Agent": "dfir-companion" },
    signal: AbortSignal.timeout(10_000),
  });
  if (!resp.ok) throw new Error(githubErrorMessage(resp, "listing AI-agent rule pack releases"));
  const json: unknown = await resp.json();
  if (!Array.isArray(json)) throw new Error("could not read the release list from GitHub");
  const out: AiAgentPackRelease[] = [];
  for (const item of json as Record<string, unknown>[]) {
    if (!item || item.draft === true || item.prerelease === true) continue;
    const tag = typeof item.tag_name === "string" ? item.tag_name.trim() : "";
    const parsed = parseReleaseAssets(item);
    if (!parsed || !isAiPackTag(tag)) continue;
    const ref = (name: string) => {
      const a = parsed.assets.find((x) => x.name === name);
      const sha256 = a?.digest?.replace(/^sha256:/i, "").toLowerCase();
      return a ? { url: a.browser_download_url, ...(sha256 ? { sha256 } : {}) } : undefined;
    };
    const bundle = ref(AI_PACK_BUNDLE_ASSET);
    const manifest = ref(AI_PACK_MANIFEST_ASSET);
    if (!bundle || !manifest) continue;
    const htmlUrl =
      typeof item.html_url === "string" && item.html_url.startsWith("https://") ? item.html_url : undefined;
    out.push({ tag, bundle, manifest, ...(htmlUrl ? { htmlUrl } : {}) });
  }
  return out.sort((a, b) => compareTags(b.tag, a.tag));
}

export interface AiPackDiff {
  added: string[]; // rules new in the pack ("yara:<name>" / "sigma:<title>")
  removed: string[]; // rules the pack no longer has
  changedFiles: string[]; // any file whose content differs: rules, grades/scopes, paths, disabled list
  addedFiles: string[];
  removedFiles: string[];
}

function ruleNames(set: AiAgentRuleSet): Set<string> {
  return new Set([
    ...set.yara.flatMap((f) => f.rules.map((r) => `yara:${r.name}`)),
    ...set.sigma.map((d) => `sigma:${d.title}`),
  ]);
}

/** Every file of a rule folder (path → LF text). */
function folderFiles(dir: string): Map<string, string> {
  const out = new Map<string, string>();
  const walk = (d: string): void => {
    for (const name of readdirSync(d).sort()) {
      const full = join(d, name);
      if (statSync(full).isDirectory()) walk(full);
      else
        out.set(relative(dir, full).split(sep).join("/"), readFileSync(full, "utf8").replace(/\r\n/g, "\n"));
    }
  };
  walk(dir);
  return out;
}

/**
 * What installing `incoming` changes against the rule set in use: rules added and removed, and every
 * file added, removed or changed — so a re-sync that only moves a grade, a scope, a path or the
 * disabled list still shows up in the review.
 */
export function diffAiAgentRuleSets(current: AiAgentRuleSet, incoming: AiAgentRuleSet): AiPackDiff {
  const a = ruleNames(current);
  const b = ruleNames(incoming);
  const fa = folderFiles(current.dir);
  const fb = folderFiles(incoming.dir);
  return {
    added: [...b].filter((x) => !a.has(x)).sort(),
    removed: [...a].filter((x) => !b.has(x)).sort(),
    changedFiles: [...fb]
      .filter(([p, t]) => fa.has(p) && fa.get(p) !== t)
      .map(([p]) => p)
      .sort(),
    addedFiles: [...fb.keys()].filter((p) => !fa.has(p)).sort(),
    removedFiles: [...fa.keys()].filter((p) => !fb.has(p)).sort(),
  };
}

interface PointerFile {
  active: string | null;
  previous: string | null;
}

/** Installed AI-agent packs under `<root>/packs/<version>`, and the pointer naming the active one. */
export class AiAgentPackStore {
  constructor(
    private readonly root: string,
    private readonly appVersion: string,
  ) {}

  private pointerPath(): string {
    return join(this.root, "active.json");
  }
  packDir(version: string): string {
    return join(this.root, "packs", version);
  }

  async pointer(): Promise<PointerFile> {
    try {
      const p = JSON.parse(await readFile(this.pointerPath(), "utf8")) as Partial<PointerFile>;
      const ok = (v: unknown) => (typeof v === "string" && isAiPackTag(v) ? v : null);
      return { active: ok(p.active), previous: ok(p.previous) };
    } catch {
      return { active: null, previous: null };
    }
  }

  /** Point the live rule set at the installed pack (startup). A pack that no longer loads is ignored. */
  async restore(): Promise<string | null> {
    const { active } = await this.pointer();
    if (!active) return null;
    setActiveAiAgentRulesDir(this.packDir(active));
    activeAiAgentRuleSet(); // falls back to the bundled set, with a problem sentence, if it no longer loads
    return active;
  }

  /** Download, verify, stage and LOAD the newest pack this app can take. Nothing is installed. */
  async check(
    fetchFn: typeof fetch,
    fetchAsset: ReleaseAssetFetch,
  ): Promise<{
    status: "found" | "current" | "none";
    version?: string;
    manifest?: AiAgentPackManifest;
    diff?: AiPackDiff;
    message?: string;
  }> {
    const releases = await listAiPackReleases(fetchFn);
    const { active } = await this.pointer();
    let needsApp = "";
    for (const rel of releases.slice(0, 5)) {
      const manifestText = (
        await downloadVerifiedAsset(
          {
            ...rel.manifest,
            maxBytes: MAX_MANIFEST_BYTES,
            label: "AI-agent pack manifest",
            timeoutMs: ASSET_TIMEOUT_MS,
          },
          fetchAsset,
        )
      ).toString("utf8");
      const manifest = parseAiPackManifest(manifestText);
      if (packFit(manifest.minAppVersion, this.appVersion) === "needs-newer-app") {
        needsApp ||= needsNewerAppMessage(manifest.version, manifest.minAppVersion, this.appVersion);
        continue; // try an older pack this app can load
      }
      if (manifest.version === active) return { status: "current", version: active };
      const bundle = (
        await downloadVerifiedAsset(
          {
            ...rel.bundle,
            maxBytes: MAX_BUNDLE_BYTES,
            label: "AI-agent rule pack",
            timeoutMs: ASSET_TIMEOUT_MS,
          },
          fetchAsset,
        )
      ).toString("utf8");
      const files = verifyAiPackBundle(bundle, manifest);
      const staged = await this.stage(manifest.version, files);
      const diff = diffAiAgentRuleSets(activeAiAgentRuleSet(), staged);
      return { status: "found", version: manifest.version, manifest, diff };
    }
    return { status: "none", message: needsApp || "no AI-agent rule pack has been published yet" };
  }

  /** Write the files to `packs/<version>.staging` and load them; throws when the set does not load. */
  async stage(version: string, files: { path: string; text: string }[]): Promise<AiAgentRuleSet> {
    if (!isAiPackTag(version)) throw new AiAgentPackError(`not an AI-agent pack version: ${version}`);
    const dir = `${this.packDir(version)}.staging`;
    await rm(dir, { recursive: true, force: true });
    for (const f of files) {
      const target = join(dir, f.path);
      await mkdir(dirname(target), { recursive: true });
      await writeFile(target, f.text, "utf8");
    }
    try {
      return loadAiAgentRuleSet(dir);
    } catch (e) {
      await rm(dir, { recursive: true, force: true });
      throw new AiAgentPackError(`the AI-agent pack ${version} does not load: ${(e as Error).message}`);
    }
  }

  /** Make a staged pack the live rule set for the next run. */
  async install(version: string): Promise<string> {
    const staging = `${this.packDir(version)}.staging`;
    loadAiAgentRuleSet(staging); // still loads?
    await rm(this.packDir(version), { recursive: true, force: true });
    await rename(staging, this.packDir(version));
    const { active } = await this.pointer();
    await mkdir(this.root, { recursive: true });
    await atomicWrite(this.pointerPath(), JSON.stringify({ active: version, previous: active }, null, 2), {
      caseGuard: false,
    });
    setActiveAiAgentRulesDir(this.packDir(version));
    return version;
  }

  /** Back to the previous pack, or to the rules bundled with the app. */
  async rollback(to: "previous" | "bundled"): Promise<string | null> {
    const { active, previous } = await this.pointer();
    const next = to === "previous" ? previous : null;
    if (to === "previous" && !previous)
      throw new AiAgentPackError("there is no previous AI-agent pack to go back to", 409);
    await mkdir(this.root, { recursive: true });
    await atomicWrite(this.pointerPath(), JSON.stringify({ active: next, previous: active }, null, 2), {
      caseGuard: false,
    });
    setActiveAiAgentRulesDir(next ? this.packDir(next) : null);
    return next;
  }
}
