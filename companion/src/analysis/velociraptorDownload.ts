// companion/src/analysis/velociraptorDownload.ts
// I/O half of the Settings "Download latest release" button for the Velociraptor binary path.
// This is analyst-triggered, never automatic — see toolConfig.ts's "the Companion NEVER bundles
// or downloads a binary" policy. That policy is about the app shipping/auto-fetching tooling on
// its own; clicking this button is the analyst explicitly asking, this once, to fetch the current
// official release from the project's own GitHub releases, same as they'd do by hand in a browser.
//
// Supply-chain guard (#2133). The asset URL is copied verbatim out of the GitHub API JSON and the
// bytes it serves are written executable, so: the URL must be https on a GitHub release host (both
// as named AND at the last redirect hop), the fetch goes through the injected `fetchAsset` (the
// route supplies the SSRF-guarded, connection-pinned fetchOutbound), and when GitHub publishes a
// SHA-256 digest for the asset the downloaded bytes must match it before anything is made runnable.
import { createHash } from "node:crypto";
import { createWriteStream } from "node:fs";
import { chmod, mkdir, rename, unlink } from "node:fs/promises";
import { join } from "node:path";
import { Readable, Transform } from "node:stream";
import { pipeline } from "node:stream/promises";
import { createGunzip } from "node:zlib";
import { githubLatestUrl } from "./updateCheck.js";
import {
  VELOCIRAPTOR_REPO,
  isAllowedAssetUrl,
  parseReleaseAssets,
  pickVelociraptorAsset,
  type PickedAsset,
} from "./velociraptorRelease.js";

export type FetchLike = typeof fetch;

/** Fetches the release asset. Same shape as routes/outboundFetchGuard's fetchOutbound result, which
 *  the route injects — kept as a type here so analysis/ never imports up into routes/. */
export interface AssetFetchResult {
  response: Response;
  /** The URL the bytes actually came from — the last redirect hop. */
  url: URL;
  dispose: () => Promise<void>;
}
export type AssetFetcher = (url: string, timeoutMs: number) => Promise<AssetFetchResult>;

export interface DownloadLatestOptions {
  destDir: string;
  /** Used only for the constant GitHub API call that lists the latest release. */
  fetchFn: FetchLike;
  /** Used for the release asset itself (the bytes that become an executable). */
  fetchAsset: AssetFetcher;
  platform: string;
  arch: string;
  timeoutMs?: number;
}

export interface DownloadLatestResult {
  path: string;
  version: string;
  assetName: string;
}

// 2-minute budget for the binary itself (tens of MB) vs. the 10s default for the small JSON call.
const ASSET_TIMEOUT_MS = 120000;

function refuseHost(where: string): Error {
  return new Error(
    `refusing release asset from an unexpected host (${where}) — only https downloads from GitHub's release hosts are accepted`,
  );
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
  if (!isAllowedAssetUrl(picked.url)) throw refuseHost("as listed by the release");

  await mkdir(destDir, { recursive: true });
  // A compressed asset (`….gz`, the only packaging current releases publish — #2118) is gunzipped
  // on the way to disk, so the saved file is the runnable binary without the `.gz` suffix.
  const finalPath = join(destDir, picked.compressed ? picked.name.replace(/\.gz$/i, "") : picked.name);
  await fetchAndInstall(picked, finalPath, opts);
  return { path: finalPath, version: parsed.version, assetName: picked.name };
}

async function fetchAndInstall(
  picked: PickedAsset,
  finalPath: string,
  opts: DownloadLatestOptions,
): Promise<void> {
  const fetched = await opts.fetchAsset(picked.url, ASSET_TIMEOUT_MS);
  try {
    const { response } = fetched;
    // Final-hop check before any byte is written: fetchOutbound guarantees the hop was public and
    // https, but not that it is still GitHub.
    if (!isAllowedAssetUrl(fetched.url.href)) {
      await response.body?.cancel().catch(() => {});
      throw refuseHost("after redirect");
    }
    if (!response.ok || !response.body) {
      throw new Error(`GitHub returned ${response.status} downloading the release asset`);
    }
    await writeVerified(response.body, picked, finalPath, opts.platform);
  } finally {
    await fetched.dispose();
  }
}

// Streams the body to a temp file (gunzipping a compressed asset), hashing the RAW published bytes
// on the way — GitHub's digest is of the asset as published, i.e. the .gz. Only a verified file is
// chmodded and renamed into place; every failure removes the temp file.
async function writeVerified(
  body: ReadableStream<Uint8Array>,
  picked: PickedAsset,
  finalPath: string,
  platform: string,
): Promise<void> {
  const tmpPath = `${finalPath}.download`;
  const hash = createHash("sha256");
  const tap = new Transform({
    transform(chunk: Buffer, _enc, cb) {
      hash.update(chunk);
      cb(null, chunk);
    },
  });
  try {
    const source = Readable.fromWeb(body as unknown as Parameters<typeof Readable.fromWeb>[0]);
    // A corrupt gzip body rejects here and lands in the catch below, which removes the temp file.
    if (picked.compressed) await pipeline(source, tap, createGunzip(), createWriteStream(tmpPath));
    else await pipeline(source, tap, createWriteStream(tmpPath));
    if (picked.sha256 && hash.digest("hex") !== picked.sha256) {
      throw new Error(
        "checksum mismatch: the downloaded release asset does not match GitHub's published SHA-256",
      );
    }
    if (platform !== "win32") await chmod(tmpPath, 0o755); // POSIX exec bit; meaningless on Windows.
    await rename(tmpPath, finalPath);
  } catch (err) {
    await unlink(tmpPath).catch(() => {});
    throw err;
  }
}
