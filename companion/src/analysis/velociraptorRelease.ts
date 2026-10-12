// companion/src/analysis/velociraptorRelease.ts
// Pure logic for picking the right Velociraptor release asset for this server's OS/arch.
// No I/O — the network fetch + download-to-disk lives in velociraptorDownload.ts.

export const VELOCIRAPTOR_REPO = "Velocidex/velociraptor";

// The only hosts a release asset may come from (#2133). The asset URL is copied verbatim out of the
// GitHub API JSON and its bytes become an executable the companion later spawns, so a response that
// names any other host — or plain http — is refused. `release-assets.githubusercontent.com` is
// GitHub's current redirect target for release downloads; `objects.githubusercontent.com` the older
// one. Leaving either out would break the button rather than harden it.
export const VELOCIRAPTOR_ASSET_HOSTS = [
  "github.com",
  "objects.githubusercontent.com",
  "release-assets.githubusercontent.com",
] as const;

const SHA256_DIGEST = /^sha256:([0-9a-f]{64})$/i;

export interface ReleaseAsset {
  name: string;
  browser_download_url: string;
  // GitHub's per-asset digest ("sha256:<hex>"), kept only when well-formed. Absent on releases
  // GitHub did not digest — the downloader then relies on host pinning alone.
  digest?: string;
}

export interface PickedAsset {
  name: string;
  url: string;
  // True when the asset is the gzip-compressed binary (`….gz`); the downloader gunzips it.
  compressed: boolean;
  // Lower-case hex SHA-256 of the asset AS PUBLISHED (the compressed bytes), when GitHub supplied one.
  sha256?: string;
}

// https, an exact host from VELOCIRAPTOR_ASSET_HOSTS, the default port, and no userinfo. Pure, so it
// is applied both to the URL the API named and to the last hop a redirect chain landed on.
export function isAllowedAssetUrl(raw: string): boolean {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return false;
  }
  if (url.protocol !== "https:" || url.port !== "" || url.username !== "" || url.password !== "")
    return false;
  return (VELOCIRAPTOR_ASSET_HOSTS as readonly string[]).includes(url.hostname.toLowerCase());
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
      ...(typeof a.digest === "string" && SHA256_DIGEST.test(a.digest) ? { digest: a.digest } : {}),
    }))
    .filter((a) => a.name && a.browser_download_url);
  return { version: tag.replace(/^v/i, ""), assets };
}

// Velociraptor publishes one binary per OS/arch (velociraptor-vX.Y.Z-<os>-<arch>[.exe]). Current
// releases ship it gzip-compressed only (`….gz`, #2118); older ones shipped it plain. A plain match
// wins when both exist. Alongside sit .msi/.deb/.rpm/.sig/musl/sumo-musl/legacy variants this must
// NOT match — the trailing `$` anchor excludes all of those, since they carry extra suffix text
// after the arch tag (or after `.gz`, for `.gz.sig`).
export function pickVelociraptorAsset(
  assets: ReleaseAsset[],
  platform: string,
  arch: string,
): PickedAsset | null {
  const platformTag = platform === "win32" ? "windows" : platform === "darwin" ? "darwin" : "linux";
  const archTag = arch === "arm64" ? "arm64" : "amd64";
  const suffix = platformTag === "windows" ? "\\.exe" : "";
  const pattern = new RegExp(
    `^velociraptor-v[0-9][0-9a-zA-Z.\\-]*-${platformTag}-${archTag}${suffix}(\\.gz)?$`,
    "i",
  );
  const candidates = assets.filter((a) => pattern.test(a.name));
  const match = candidates.find((a) => !isGzipName(a.name)) ?? candidates[0];
  if (!match) return null;
  const sha256 = match.digest ? SHA256_DIGEST.exec(match.digest)?.[1]?.toLowerCase() : undefined;
  return {
    name: match.name,
    url: match.browser_download_url,
    compressed: isGzipName(match.name),
    ...(sha256 ? { sha256 } : {}),
  };
}

function isGzipName(name: string): boolean {
  return /\.gz$/i.test(name);
}
