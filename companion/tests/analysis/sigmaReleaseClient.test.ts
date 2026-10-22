import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  downloadSigmaRelease,
  latestSigmaRelease,
  SIGMA_RELEASE_ASSET,
  type SigmaAssetFetch,
} from "../../src/analysis/sigmaReleaseClient.js";
import { SIGMA_RELEASE_MAX_ZIP_BYTES } from "../../src/analysis/sigmaReleaseArchive.js";

// The SigmaHQ release client (#2204): find the latest release's rule zip and download it only when
// it matches GitHub's published SHA-256. No network: fetch is injected.

const BODY = Buffer.from("PK fake zip bytes");
const SHA = createHash("sha256").update(BODY).digest("hex");
const ASSET_URL = `https://github.com/SigmaHQ/sigma/releases/download/r2026-10-01/${SIGMA_RELEASE_ASSET}`;

const releaseJson = (asset: Record<string, unknown> = {}) => ({
  tag_name: "r2026-10-01",
  published_at: "2026-10-01T10:00:00Z",
  assets: [
    {
      name: "sigma_core.zip",
      browser_download_url: "https://github.com/x/core.zip",
      digest: `sha256:${"0".repeat(64)}`,
    },
    { name: SIGMA_RELEASE_ASSET, browser_download_url: ASSET_URL, digest: `sha256:${SHA}`, ...asset },
  ],
});

const fetchJson =
  (json: unknown, status = 200): typeof fetch =>
  async () =>
    new Response(JSON.stringify(json), { status });

const asset =
  (body: Buffer | Uint8Array, url = ASSET_URL): SigmaAssetFetch =>
  async () => ({
    response: new Response(new Blob([new Uint8Array(body)])),
    url: new URL(url),
    dispose: async () => {},
  });

describe("latestSigmaRelease", () => {
  it("picks the all-rules zip and its digest", async () => {
    const r = await latestSigmaRelease(fetchJson(releaseJson()));
    expect(r).toEqual({
      tag: "r2026-10-01",
      publishedAt: "2026-10-01T10:00:00Z",
      url: ASSET_URL,
      sha256: SHA,
    });
  });

  it("fails with a sentence when GitHub answers an error or the asset is missing", async () => {
    await expect(latestSigmaRelease(fetchJson({}, 403))).rejects.toThrow(/GitHub returned 403/);
    await expect(latestSigmaRelease(fetchJson({ tag_name: "r1", assets: [] }))).rejects.toThrow(
      /sigma_all_rules\.zip/,
    );
  });
});

describe("downloadSigmaRelease", () => {
  const release = { tag: "r2026-10-01", url: ASSET_URL, sha256: SHA };

  it("returns the bytes when they match the published digest", async () => {
    expect((await downloadSigmaRelease(release, asset(BODY))).equals(BODY)).toBe(true);
  });

  it("refuses bytes that do not match the digest", async () => {
    await expect(downloadSigmaRelease(release, asset(Buffer.from("tampered")))).rejects.toThrow(
      /does not match/,
    );
  });

  it("refuses a release GitHub published no digest for", async () => {
    await expect(downloadSigmaRelease({ tag: "r", url: ASSET_URL }, asset(BODY))).rejects.toThrow(
      /no SHA-256/,
    );
  });

  it("refuses an asset served from an unexpected host", async () => {
    await expect(downloadSigmaRelease(release, asset(BODY, "https://evil.example/x.zip"))).rejects.toThrow(
      /unexpected host/,
    );
    await expect(
      downloadSigmaRelease({ ...release, url: "https://evil.example/x.zip" }, asset(BODY)),
    ).rejects.toThrow(/unexpected host/);
  });

  it("stops reading past the size cap", async () => {
    const big = new Uint8Array(SIGMA_RELEASE_MAX_ZIP_BYTES + 10);
    await expect(downloadSigmaRelease(release, asset(big))).rejects.toThrow(/larger than/);
  });
});
