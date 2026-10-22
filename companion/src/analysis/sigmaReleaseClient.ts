// The SigmaHQ release client for the Sigma rule updater (#2204): find the latest release's
// `sigma_all_rules.zip` and download it — only from GitHub's release hosts, only up to the size
// cap, and only when its bytes match the SHA-256 digest GitHub publishes for the asset. A release
// without a digest is refused: the analyst can download it and use Install from file instead.
//
// The network calls are injected (the route passes the SSRF-guarded fetchOutbound), so this file
// is testable without the network and never decides how a connection is made.

import { createHash } from "node:crypto";
import { isAllowedAssetUrl, parseReleaseAssets } from "./velociraptorRelease.js";
import { SIGMA_RELEASE_MAX_ZIP_BYTES } from "./sigmaReleaseArchive.js";

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
export type SigmaAssetFetch = (
  url: string,
  timeoutMs: number,
) => Promise<{ response: Response; url: URL; dispose: () => Promise<void> }>;

const unexpectedHost = (where: string) =>
  new Error(
    `refusing the Sigma release from an unexpected host (${where}); only GitHub's release hosts are accepted`,
  );

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

async function readCapped(body: ReadableStream<Uint8Array>): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let total = 0;
  const reader = body.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > SIGMA_RELEASE_MAX_ZIP_BYTES) {
      await reader.cancel().catch(() => {});
      throw new Error(
        `the Sigma release download is larger than ${SIGMA_RELEASE_MAX_ZIP_BYTES / (1024 * 1024)} MB`,
      );
    }
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks);
}

/** The release zip's bytes, verified against GitHub's digest. */
export async function downloadSigmaRelease(
  release: SigmaLatestRelease,
  fetchAsset: SigmaAssetFetch,
): Promise<Buffer> {
  if (!release.sha256)
    throw new Error(
      "GitHub published no SHA-256 for this release, so it cannot be verified; download it yourself and use Install from file",
    );
  if (!isAllowedAssetUrl(release.url)) throw unexpectedHost("as listed by the release");
  const fetched = await fetchAsset(release.url, ASSET_TIMEOUT_MS);
  try {
    if (!isAllowedAssetUrl(fetched.url.href)) {
      await fetched.response.body?.cancel().catch(() => {});
      throw unexpectedHost("after redirect");
    }
    if (!fetched.response.ok || !fetched.response.body)
      throw new Error(`GitHub returned ${fetched.response.status} downloading the Sigma release`);
    const bytes = await readCapped(fetched.response.body);
    if (createHash("sha256").update(bytes).digest("hex") !== release.sha256)
      throw new Error(
        "the downloaded Sigma release does not match GitHub's published SHA-256; nothing was installed",
      );
    return bytes;
  } finally {
    await fetched.dispose();
  }
}
