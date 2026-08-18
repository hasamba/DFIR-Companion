// companion/src/analysis/velociraptorDownload.ts
// I/O half of the Settings "Download latest release" button for the Velociraptor binary path.
// This is analyst-triggered, never automatic — see toolConfig.ts's "the Companion NEVER bundles
// or downloads a binary" policy. That policy is about the app shipping/auto-fetching tooling on
// its own; clicking this button is the analyst explicitly asking, this once, to fetch the current
// official release from the project's own GitHub releases, same as they'd do by hand in a browser.
import { createWriteStream } from "node:fs";
import { chmod, mkdir, rename, unlink } from "node:fs/promises";
import { join } from "node:path";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { githubLatestUrl } from "./updateCheck.js";
import { VELOCIRAPTOR_REPO, parseReleaseAssets, pickVelociraptorAsset } from "./velociraptorRelease.js";

export type FetchLike = typeof fetch;

export interface DownloadLatestOptions {
  destDir: string;
  fetchFn: FetchLike;
  platform: string;
  arch: string;
  timeoutMs?: number;
}

export interface DownloadLatestResult {
  path: string;
  version: string;
  assetName: string;
}

export async function downloadLatestVelociraptor(opts: DownloadLatestOptions): Promise<DownloadLatestResult> {
  const { destDir, fetchFn, platform, arch, timeoutMs = 10000 } = opts;
  const releaseResp = await fetchFn(githubLatestUrl(VELOCIRAPTOR_REPO), {
    headers: { Accept: "application/vnd.github+json", "User-Agent": "dfir-companion" },
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!releaseResp.ok) throw new Error(`GitHub returned ${releaseResp.status} listing releases`);
  const parsed = parseReleaseAssets(await releaseResp.json());
  if (!parsed) throw new Error("could not parse the latest release");
  const picked = pickVelociraptorAsset(parsed.assets, platform, arch);
  if (!picked) throw new Error(`no release asset matches this server's OS/arch (${platform}/${arch})`);

  await mkdir(destDir, { recursive: true });
  const finalPath = join(destDir, picked.name);
  const tmpPath = `${finalPath}.download`;

  // 2-minute budget for the binary itself (tens of MB) vs. the 10s default for the small JSON call above.
  const assetResp = await fetchFn(picked.url, {
    headers: { "User-Agent": "dfir-companion" },
    signal: AbortSignal.timeout(120000),
  });
  if (!assetResp.ok || !assetResp.body) {
    throw new Error(`GitHub returned ${assetResp.status} downloading the release asset`);
  }
  try {
    await pipeline(
      Readable.fromWeb(assetResp.body as unknown as Parameters<typeof Readable.fromWeb>[0]),
      createWriteStream(tmpPath),
    );
    if (platform !== "win32") await chmod(tmpPath, 0o755); // POSIX exec bit; meaningless on Windows.
    await rename(tmpPath, finalPath);
  } catch (err) {
    await unlink(tmpPath).catch(() => {});
    throw err;
  }
  return { path: finalPath, version: parsed.version, assetName: picked.name };
}
