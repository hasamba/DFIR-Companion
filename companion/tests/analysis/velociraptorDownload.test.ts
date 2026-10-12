// companion/tests/analysis/velociraptorDownload.test.ts
// The Settings "Download latest release" action, end to end against a stubbed fetch (no network).
// Current official releases publish every binary gzip-compressed (#2118), so the downloader must
// decompress it into a usable executable; older plain binaries must still be written as-is.
// #2133: the asset URL is attacker-shaped (it comes verbatim from the GitHub API JSON) and its bytes
// become an executable, so only GitHub's release hosts over https are fetched, the final redirect hop
// is re-checked, and GitHub's published SHA-256 digest is enforced when the release carries one.
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { createHash } from "node:crypto";
import { mkdtemp, readdir, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import {
  downloadLatestVelociraptor,
  type AssetFetcher,
  type FetchLike,
} from "../../src/analysis/velociraptorDownload.js";
import { OutboundUrlBlockedError } from "../../src/routes/outboundFetchGuard.js";

const RELEASE_URL = "https://api.github.com/repos/Velocidex/velociraptor/releases/latest";
const DL_BASE = "https://github.com/Velocidex/velociraptor/releases/download/v0.77.3/";

interface AssetSpec {
  name: string;
  url?: string;
  digest?: string;
}

function releaseJson(assets: (string | AssetSpec)[]) {
  return {
    tag_name: "v0.77.3",
    assets: assets.map((a) => {
      const spec = typeof a === "string" ? { name: a } : a;
      return {
        name: spec.name,
        browser_download_url: spec.url ?? `${DL_BASE}${spec.name}`,
        ...(spec.digest ? { digest: spec.digest } : {}),
      };
    }),
  };
}

// Serves only the release JSON — the asset itself must go through the injected fetchAsset.
function stubReleaseFetch(assets: (string | AssetSpec)[]): FetchLike {
  return async (input: string | URL | Request) => {
    if (String(input) === RELEASE_URL) {
      return new Response(JSON.stringify(releaseJson(assets)), { status: 200 });
    }
    throw new Error(`plain fetch must not be used for ${String(input)}`);
  };
}

interface AssetStub {
  fetchAsset: AssetFetcher;
  calls: string[];
  disposed: () => number;
}

// One body per asset name; `finalUrl` simulates where a redirect chain landed.
function stubAssetFetch(bodies: Record<string, Buffer>, finalUrl?: string): AssetStub {
  const calls: string[] = [];
  let disposed = 0;
  const fetchAsset: AssetFetcher = async (url) => {
    calls.push(url);
    const name = url.replace(DL_BASE, "");
    const body = bodies[name];
    return {
      response: body
        ? new Response(new Uint8Array(body), { status: 200 })
        : new Response("nope", { status: 404 }),
      url: new URL(finalUrl ?? url),
      dispose: async () => {
        disposed += 1;
      },
    };
  };
  return { fetchAsset, calls, disposed: () => disposed };
}

const sha256 = (b: Buffer): string => createHash("sha256").update(b).digest("hex");

describe("downloadLatestVelociraptor", () => {
  let destDir: string;

  beforeEach(async () => {
    destDir = await mkdtemp(join(tmpdir(), "velo-dl-"));
  });

  afterEach(async () => {
    await rm(destDir, { recursive: true, force: true });
  });

  it("decompresses a .gz release asset into an executable without the .gz suffix", async () => {
    const gzName = "velociraptor-v0.77.3-linux-amd64.gz";
    const asset = stubAssetFetch({ [gzName]: gzipSync(Buffer.from("FAKEBIN")) });
    const result = await downloadLatestVelociraptor({
      destDir,
      fetchFn: stubReleaseFetch([gzName, `${gzName}.sig`, "velociraptor-v0.77.3-linux-amd64-musl.gz"]),
      fetchAsset: asset.fetchAsset,
      platform: "linux",
      arch: "x64",
    });

    const expectedPath = join(destDir, "velociraptor-v0.77.3-linux-amd64");
    expect(result).toEqual({ path: expectedPath, version: "0.77.3", assetName: gzName });
    expect((await readFile(expectedPath)).toString()).toBe("FAKEBIN");
    if (process.platform !== "win32") {
      expect((await stat(expectedPath)).mode & 0o755).toBe(0o755);
    }
    expect(await readdir(destDir)).toEqual(["velociraptor-v0.77.3-linux-amd64"]);
    expect(asset.disposed()).toBe(1);
  });

  it("strips .gz from the Windows .exe.gz asset so the saved file is a runnable .exe", async () => {
    const gzName = "velociraptor-v0.77.3-windows-amd64.exe.gz";
    const result = await downloadLatestVelociraptor({
      destDir,
      fetchFn: stubReleaseFetch([gzName, "velociraptor-v0.77.3-windows-amd64.msi"]),
      fetchAsset: stubAssetFetch({ [gzName]: gzipSync(Buffer.from("FAKEEXE")) }).fetchAsset,
      platform: "win32",
      arch: "x64",
    });
    expect(result.path).toBe(join(destDir, "velociraptor-v0.77.3-windows-amd64.exe"));
    expect((await readFile(result.path)).toString()).toBe("FAKEEXE");
  });

  it("rejects a corrupt gzip body and leaves no temp or partial file behind", async () => {
    const gzName = "velociraptor-v0.77.3-linux-amd64.gz";
    await expect(
      downloadLatestVelociraptor({
        destDir,
        fetchFn: stubReleaseFetch([gzName]),
        fetchAsset: stubAssetFetch({ [gzName]: Buffer.from("this is not gzip data at all") }).fetchAsset,
        platform: "linux",
        arch: "x64",
      }),
    ).rejects.toThrow();
    expect(await readdir(destDir)).toEqual([]);
  });

  it("still writes a plain (uncompressed) release asset as-is", async () => {
    const name = "velociraptor-v0.77.3-linux-amd64";
    const result = await downloadLatestVelociraptor({
      destDir,
      fetchFn: stubReleaseFetch([name]),
      fetchAsset: stubAssetFetch({ [name]: Buffer.from("PLAINBIN") }).fetchAsset,
      platform: "linux",
      arch: "x64",
    });
    expect(result).toEqual({ path: join(destDir, name), version: "0.77.3", assetName: name });
    expect((await readFile(result.path)).toString()).toBe("PLAINBIN");
    expect(await readdir(destDir)).toEqual([name]);
  });

  it("throws a clear error when no asset matches this OS/arch", async () => {
    await expect(
      downloadLatestVelociraptor({
        destDir,
        fetchFn: stubReleaseFetch(["velociraptor-v0.77.3-windows-amd64.exe.gz"]),
        fetchAsset: stubAssetFetch({}).fetchAsset,
        platform: "linux",
        arch: "x64",
      }),
    ).rejects.toThrow("no release asset matches this server's OS/arch (linux/x64)");
  });

  describe("asset host pinning (#2133)", () => {
    const gzName = "velociraptor-v0.77.3-linux-amd64.gz";

    for (const [label, url] of [
      ["a cloud metadata address over http", "http://169.254.169.254/latest/meta-data"],
      ["a non-GitHub host", `https://evil.example/${gzName}`],
      [
        "GitHub over plain http",
        `http://github.com/Velocidex/velociraptor/releases/download/v0.77.3/${gzName}`,
      ],
    ] as const) {
      it(`refuses ${label} before fetching and writes nothing`, async () => {
        const asset = stubAssetFetch({ [gzName]: gzipSync(Buffer.from("EVIL")) });
        await expect(
          downloadLatestVelociraptor({
            destDir,
            fetchFn: stubReleaseFetch([{ name: gzName, url }]),
            fetchAsset: asset.fetchAsset,
            platform: "linux",
            arch: "x64",
          }),
        ).rejects.toThrow(/unexpected host/);
        expect(asset.calls).toEqual([]);
        expect(await readdir(destDir)).toEqual([]);
      });
    }

    it("refuses when the redirect chain lands off the GitHub host list, and still disposes", async () => {
      const asset = stubAssetFetch({ [gzName]: gzipSync(Buffer.from("EVIL")) }, "https://evil.example/x");
      await expect(
        downloadLatestVelociraptor({
          destDir,
          fetchFn: stubReleaseFetch([gzName]),
          fetchAsset: asset.fetchAsset,
          platform: "linux",
          arch: "x64",
        }),
      ).rejects.toThrow(/unexpected host/);
      expect(asset.disposed()).toBe(1);
      expect(await readdir(destDir)).toEqual([]);
    });

    it("accepts GitHub's release-assets redirect target as the final hop", async () => {
      const asset = stubAssetFetch(
        { [gzName]: gzipSync(Buffer.from("FAKEBIN")) },
        "https://release-assets.githubusercontent.com/github-production-release-asset/1/abc",
      );
      const result = await downloadLatestVelociraptor({
        destDir,
        fetchFn: stubReleaseFetch([gzName]),
        fetchAsset: asset.fetchAsset,
        platform: "linux",
        arch: "x64",
      });
      expect((await readFile(result.path)).toString()).toBe("FAKEBIN");
    });

    it("propagates the outbound guard's own refusal and writes nothing", async () => {
      const fetchAsset: AssetFetcher = async () => {
        throw new OutboundUrlBlockedError("the host resolves to a non-public address");
      };
      await expect(
        downloadLatestVelociraptor({
          destDir,
          fetchFn: stubReleaseFetch([gzName]),
          fetchAsset,
          platform: "linux",
          arch: "x64",
        }),
      ).rejects.toBeInstanceOf(OutboundUrlBlockedError);
      expect(await readdir(destDir)).toEqual([]);
    });
  });

  describe("published SHA-256 digest (#2133)", () => {
    const gzName = "velociraptor-v0.77.3-linux-amd64.gz";
    const gzBytes = gzipSync(Buffer.from("FAKEBIN"));

    it("writes the executable when the compressed bytes match GitHub's digest", async () => {
      const result = await downloadLatestVelociraptor({
        destDir,
        fetchFn: stubReleaseFetch([{ name: gzName, digest: `sha256:${sha256(gzBytes)}` }]),
        fetchAsset: stubAssetFetch({ [gzName]: gzBytes }).fetchAsset,
        platform: "linux",
        arch: "x64",
      });
      expect((await readFile(result.path)).toString()).toBe("FAKEBIN");
      expect(await readdir(destDir)).toEqual(["velociraptor-v0.77.3-linux-amd64"]);
    });

    it("refuses on a digest mismatch and leaves neither the final file nor the temp file", async () => {
      const asset = stubAssetFetch({ [gzName]: gzBytes });
      await expect(
        downloadLatestVelociraptor({
          destDir,
          fetchFn: stubReleaseFetch([{ name: gzName, digest: `sha256:${"0".repeat(64)}` }]),
          fetchAsset: asset.fetchAsset,
          platform: "linux",
          arch: "x64",
        }),
      ).rejects.toThrow(/checksum mismatch/);
      expect(await readdir(destDir)).toEqual([]);
      expect(asset.disposed()).toBe(1);
    });
  });
});
