// companion/tests/analysis/velociraptorDownload.test.ts
// The Settings "Download latest release" action, end to end against a stubbed fetch (no network).
// Current official releases publish every binary gzip-compressed (#2118), so the downloader must
// decompress it into a usable executable; older plain binaries must still be written as-is.
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, readdir, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { downloadLatestVelociraptor, type FetchLike } from "../../src/analysis/velociraptorDownload.js";

const RELEASE_URL = "https://api.github.com/repos/Velocidex/velociraptor/releases/latest";

function releaseJson(names: string[]) {
  return {
    tag_name: "v0.77.3",
    assets: names.map((name) => ({ name, browser_download_url: `https://example.com/dl/${name}` })),
  };
}

// Serves the release JSON and one body per asset URL; anything else is a 404.
function stubFetch(names: string[], bodies: Record<string, Buffer>): FetchLike {
  return (async (input: string | URL | Request) => {
    const url = String(input);
    if (url === RELEASE_URL) return new Response(JSON.stringify(releaseJson(names)), { status: 200 });
    const name = url.replace("https://example.com/dl/", "");
    const body = bodies[name];
    return body ? new Response(new Uint8Array(body), { status: 200 }) : new Response("nope", { status: 404 });
  }) as FetchLike;
}

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
    const result = await downloadLatestVelociraptor({
      destDir,
      fetchFn: stubFetch([gzName, `${gzName}.sig`, "velociraptor-v0.77.3-linux-amd64-musl.gz"], {
        [gzName]: gzipSync(Buffer.from("FAKEBIN")),
      }),
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
  });

  it("strips .gz from the Windows .exe.gz asset so the saved file is a runnable .exe", async () => {
    const gzName = "velociraptor-v0.77.3-windows-amd64.exe.gz";
    const result = await downloadLatestVelociraptor({
      destDir,
      fetchFn: stubFetch([gzName, "velociraptor-v0.77.3-windows-amd64.msi"], {
        [gzName]: gzipSync(Buffer.from("FAKEEXE")),
      }),
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
        fetchFn: stubFetch([gzName], { [gzName]: Buffer.from("this is not gzip data at all") }),
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
      fetchFn: stubFetch([name], { [name]: Buffer.from("PLAINBIN") }),
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
        fetchFn: stubFetch(["velociraptor-v0.77.3-windows-amd64.exe.gz"], {}),
        platform: "linux",
        arch: "x64",
      }),
    ).rejects.toThrow("no release asset matches this server's OS/arch (linux/x64)");
  });
});
