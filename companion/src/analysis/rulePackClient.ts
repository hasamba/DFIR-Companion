// The detection-rule pack client (#2349): find the newest `rules-*` release of THIS project that the
// running app can load, and download it. Trust is the Sigma updater's (#2204), by owner decision:
//
//   - releases are listed from this repository only, and only `rules-*` tags count — app releases
//     (`v*`) and anything else are skipped. /releases/latest is not used: packs are published
//     not-latest, so it would never name one;
//   - both files come from GitHub's release hosts only, size-capped, and each must match the
//     SHA-256 GitHub publishes for the asset (githubReleaseDownload.ts, shared with Sigma);
//   - the rules file must ALSO match the SHA-256 the pack's own manifest lists;
//   - a pack that needs a newer app is refused with a sentence saying so.
//
// Nothing here installs anything: the store stages what this returns for a review, and only the
// analyst's Install click makes it active. Network calls are injected, so this is testable offline.

import { parseReleaseAssets } from "./velociraptorRelease.js";
import { DEFAULT_UPDATE_REPO } from "./updateCheck.js";
import { downloadVerifiedAsset, sha256Hex, type ReleaseAssetFetch } from "./githubReleaseDownload.js";
import {
  RULE_PACK_MANIFEST_ASSET,
  RULE_PACK_MAX_MANIFEST_BYTES,
  RULE_PACK_MAX_RULES_BYTES,
  RULE_PACK_RULES_ASSET,
  comparePackVersions,
  isRulePackTag,
  needsNewerAppMessage,
  packFit,
  parseRulePackManifest,
  verifyRulesAgainstManifest,
  type RulePackManifest,
} from "./rulePackManifest.js";
import { githubErrorMessage } from "./githubHttpError.js";

export const RULE_PACK_REPO = DEFAULT_UPDATE_REPO;
const ASSET_TIMEOUT_MS = 60_000;
/** How many of the newest packs are looked at for one this app can load. */
const MAX_CANDIDATES = 5;

interface AssetRef {
  url: string;
  sha256?: string;
}

export interface RulePackReleaseRef {
  tag: string;
  publishedAt?: string;
  htmlUrl?: string;
  rules: AssetRef;
  manifest: AssetRef;
}

export interface DownloadedRulePack {
  tag: string;
  manifest: RulePackManifest;
  rulesText: string;
  rulesSha256: string;
  htmlUrl?: string;
}

export interface RulePackSearch {
  /** "found": `pack` is the newest this app can load. "superseded": the newest loadable pack is
   *  older than this app's bundled rules. "none": no loadable pack. */
  status: "found" | "superseded" | "none";
  pack?: DownloadedRulePack;
  /** The newest pack, when it needs a newer app than this one — named even when an older one fits. */
  newerNeedsApp?: { tag: string; minAppVersion: string; message: string };
  /** The newest loadable pack's tag, when it is superseded. */
  supersededTag?: string;
}

const asset = (assets: ReturnType<typeof parseReleaseAssets>, name: string): AssetRef | undefined => {
  const a = assets?.assets.find((x) => x.name === name);
  if (!a) return undefined;
  const sha256 = a.digest?.replace(/^sha256:/i, "").toLowerCase();
  return { url: a.browser_download_url, ...(sha256 ? { sha256 } : {}) };
};

/** This project's `rules-*` releases that carry both pack files, newest first. */
export async function listRulePackReleases(
  fetchFn: typeof fetch,
  repo = RULE_PACK_REPO,
  timeoutMs = 10_000,
): Promise<RulePackReleaseRef[]> {
  const resp = await fetchFn(`https://api.github.com/repos/${repo}/releases?per_page=100`, {
    headers: { Accept: "application/vnd.github+json", "User-Agent": "dfir-companion" },
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!resp.ok) throw new Error(githubErrorMessage(resp, "listing rule pack releases"));
  const json: unknown = await resp.json();
  if (!Array.isArray(json)) throw new Error("could not read the release list from GitHub");
  const refs: RulePackReleaseRef[] = [];
  for (const item of json) {
    if (!item || typeof item !== "object") continue;
    const o = item as Record<string, unknown>;
    if (o.draft === true || o.prerelease === true) continue;
    const parsed = parseReleaseAssets(o);
    const tag = typeof o.tag_name === "string" ? o.tag_name.trim() : "";
    if (!parsed || !isRulePackTag(tag)) continue;
    const rules = asset(parsed, RULE_PACK_RULES_ASSET);
    const manifest = asset(parsed, RULE_PACK_MANIFEST_ASSET);
    if (!rules || !manifest) continue;
    refs.push({
      tag,
      rules,
      manifest,
      ...(typeof o.published_at === "string" ? { publishedAt: o.published_at } : {}),
      ...(typeof o.html_url === "string" && o.html_url.startsWith("https://") ? { htmlUrl: o.html_url } : {}),
    });
  }
  return refs.sort((a, b) => comparePackVersions(b.tag, a.tag));
}

async function fetchManifest(
  ref: RulePackReleaseRef,
  fetchAsset: ReleaseAssetFetch,
): Promise<RulePackManifest> {
  const bytes = await downloadVerifiedAsset(
    {
      ...ref.manifest,
      maxBytes: RULE_PACK_MAX_MANIFEST_BYTES,
      label: "rule pack manifest",
      timeoutMs: ASSET_TIMEOUT_MS,
    },
    fetchAsset,
  );
  const manifest = parseRulePackManifest(bytes.toString("utf8"));
  if (manifest.version !== ref.tag)
    throw new Error(`the manifest of release ${ref.tag} names version ${manifest.version}; refusing it`);
  return manifest;
}

/** The pack's rules file, verified against GitHub's digest and the manifest. */
export async function downloadRulePack(
  ref: RulePackReleaseRef,
  manifest: RulePackManifest,
  fetchAsset: ReleaseAssetFetch,
): Promise<DownloadedRulePack> {
  const bytes = await downloadVerifiedAsset(
    { ...ref.rules, maxBytes: RULE_PACK_MAX_RULES_BYTES, label: "rule pack", timeoutMs: ASSET_TIMEOUT_MS },
    fetchAsset,
  );
  const rulesText = bytes.toString("utf8");
  verifyRulesAgainstManifest(manifest, rulesText);
  return {
    tag: ref.tag,
    manifest,
    rulesText,
    rulesSha256: sha256Hex(bytes),
    ...(ref.htmlUrl ? { htmlUrl: ref.htmlUrl } : {}),
  };
}

/** Find (and download, verified) the newest pack this app can load. Installs nothing. */
export async function findLatestRulePack(opts: {
  fetchFn: typeof fetch;
  fetchAsset: ReleaseAssetFetch;
  appVersion: string;
  repo?: string;
}): Promise<RulePackSearch> {
  const refs = (await listRulePackReleases(opts.fetchFn, opts.repo)).slice(0, MAX_CANDIDATES);
  let newerNeedsApp: RulePackSearch["newerNeedsApp"];
  for (const ref of refs) {
    const manifest = await fetchManifest(ref, opts.fetchAsset);
    const fit = packFit(manifest.minAppVersion, opts.appVersion);
    if (fit === "needs-newer-app") {
      newerNeedsApp ??= {
        tag: ref.tag,
        minAppVersion: manifest.minAppVersion,
        message: needsNewerAppMessage(ref.tag, manifest.minAppVersion, opts.appVersion),
      };
      continue;
    }
    if (fit === "superseded") return { status: "superseded", supersededTag: ref.tag, newerNeedsApp };
    return { status: "found", pack: await downloadRulePack(ref, manifest, opts.fetchAsset), newerNeedsApp };
  }
  return { status: "none", newerNeedsApp };
}
