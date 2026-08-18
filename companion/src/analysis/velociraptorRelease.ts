// companion/src/analysis/velociraptorRelease.ts
// Pure logic for picking the right Velociraptor release asset for this server's OS/arch.
// No I/O — the network fetch + download-to-disk lives in velociraptorDownload.ts.

export const VELOCIRAPTOR_REPO = "Velocidex/velociraptor";

export interface ReleaseAsset {
  name: string;
  browser_download_url: string;
}

export interface PickedAsset {
  name: string;
  url: string;
}

export interface ParsedRelease {
  version: string;
  assets: ReleaseAsset[];
}

// Tolerant parse of GitHub's GET /repos/:owner/:repo/releases/latest body for the fields this
// downloader needs: the version tag and the asset list (name + direct download URL).
export function parseReleaseAssets(json: unknown): ParsedRelease | null {
  if (!json || typeof json !== "object") return null;
  const o = json as Record<string, unknown>;
  const tag = typeof o.tag_name === "string" ? o.tag_name.trim() : "";
  if (!tag) return null;
  const rawAssets = Array.isArray(o.assets) ? o.assets : [];
  const assets: ReleaseAsset[] = rawAssets
    .filter((a): a is Record<string, unknown> => !!a && typeof a === "object")
    .map((a) => ({
      name: typeof a.name === "string" ? a.name : "",
      browser_download_url: typeof a.browser_download_url === "string" ? a.browser_download_url : "",
    }))
    .filter((a) => a.name && a.browser_download_url);
  return { version: tag.replace(/^v/i, ""), assets };
}

// Velociraptor publishes one plain binary per OS/arch (velociraptor-vX.Y.Z-<os>-<arch>[.exe]),
// alongside .msi/.deb/.rpm/.sig/musl variants this must NOT match — the trailing `$` anchor
// excludes all of those, since they carry extra suffix text after the arch tag.
export function pickVelociraptorAsset(
  assets: ReleaseAsset[],
  platform: string,
  arch: string,
): PickedAsset | null {
  const platformTag = platform === "win32" ? "windows" : platform === "darwin" ? "darwin" : "linux";
  const archTag = arch === "arm64" ? "arm64" : "amd64";
  const suffix = platformTag === "windows" ? "\\.exe" : "";
  const pattern = new RegExp(`^velociraptor-v[0-9][0-9a-zA-Z.\\-]*-${platformTag}-${archTag}${suffix}$`, "i");
  const match = assets.find((a) => pattern.test(a.name));
  return match ? { name: match.name, url: match.browser_download_url } : null;
}
