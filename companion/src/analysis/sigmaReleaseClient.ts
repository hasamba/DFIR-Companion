// The SigmaHQ release client for the Sigma rule updater (#2204): find the latest release's
// `sigma_all_rules.zip` and download it — only from GitHub's release hosts, only up to the size
// cap, and only when its bytes match the SHA-256 digest GitHub publishes for the asset. A release
// without a digest is refused: the analyst can download it and use Install from file instead.
//
// The download rules live in githubReleaseDownload.ts, shared with the detection-rule pack updater
// (#2349). The network calls are injected (the route passes the SSRF-guarded fetchOutbound), so
// this file is testable without the network and never decides how a connection is made.

import { parseReleaseAssets } from "./velociraptorRelease.js";
import { SIGMA_RELEASE_MAX_ZIP_BYTES } from "./sigmaReleaseArchive.js";
import { downloadVerifiedAsset, type ReleaseAssetFetch } from "./githubReleaseDownload.js";

export const SIGMA_REPO = "SigmaHQ/sigma";
export const SIGMA_RELEASE_ASSET = "sigma_all_rules.zip";
const LATEST_URL = `https://api.github.com/repos/${SIGMA_REPO}/releases/latest`;
const ASSET_TIMEOUT_MS = 120_000;

export interface SigmaLatestRelease {
  tag: string;
  publishedAt?: string;
  url: string;
  /** Lower-case hex SHA-256 GitHub published for the asset. */
  sha256?: string;
}

/** The shape of fetchOutbound's result that the download needs. */
export type SigmaAssetFetch = ReleaseAssetFetch;

export async function latestSigmaRelease(
  fetchFn: typeof fetch,
  timeoutMs = 10_000,
): Promise<SigmaLatestRelease> {
  const resp = await fetchFn(LATEST_URL, {
    headers: { Accept: "application/vnd.github+json", "User-Agent": "dfir-companion" },
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!resp.ok) throw new Error(`GitHub returned ${resp.status} listing SigmaHQ releases`);
  const json = (await resp.json()) as Record<string, unknown>;
  const parsed = parseReleaseAssets(json);
  if (!parsed) throw new Error("could not read the latest SigmaHQ release from GitHub");
  const asset = parsed.assets.find((a) => a.name === SIGMA_RELEASE_ASSET);
  if (!asset) throw new Error(`the latest SigmaHQ release (${parsed.version}) has no ${SIGMA_RELEASE_ASSET}`);
  const sha256 = asset.digest?.replace(/^sha256:/i, "").toLowerCase();
  return {
    tag: typeof json.tag_name === "string" ? json.tag_name.trim() : parsed.version,
    ...(typeof json.published_at === "string" ? { publishedAt: json.published_at } : {}),
    url: asset.browser_download_url,
    ...(sha256 ? { sha256 } : {}),
  };
}

/** The release zip's bytes, verified against GitHub's digest. */
export async function downloadSigmaRelease(
  release: SigmaLatestRelease,
  fetchAsset: SigmaAssetFetch,
): Promise<Buffer> {
  return downloadVerifiedAsset(
    {
      url: release.url,
      sha256: release.sha256,
      maxBytes: SIGMA_RELEASE_MAX_ZIP_BYTES,
      label: "Sigma release",
      timeoutMs: ASSET_TIMEOUT_MS,
    },
    fetchAsset,
  );
}
