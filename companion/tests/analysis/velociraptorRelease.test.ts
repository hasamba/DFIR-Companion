// companion/tests/analysis/velociraptorRelease.test.ts
import { describe, it, expect } from "vitest";
import { parseReleaseAssets, pickVelociraptorAsset } from "../../src/analysis/velociraptorRelease.js";

// Older releases published plain (uncompressed) binaries. Kept so the picker stays backward
// compatible and still prefers a plain binary when one exists.
const PLAIN_RELEASE_ASSET_NAMES = [
  "velociraptor-v0.77.2-linux-amd64",
  "velociraptor-v0.77.2-linux-arm64",
  "velociraptor-v0.77.2-linux-musl-amd64",
  "velociraptor-v0.77.2-darwin-amd64",
  "velociraptor-v0.77.2-darwin-arm64",
  "velociraptor-v0.77.2-windows-amd64.exe",
  "velociraptor-v0.77.2-windows-arm64.exe",
  "velociraptor-v0.77.2-windows-amd64.msi",
  "velociraptor-v0.77.2-linux-amd64.deb",
  "velociraptor-v0.77.2-linux-amd64.rpm",
  "velociraptor-v0.77.2-linux-amd64.sig",
  "SHA256SUMS",
];

// Asset names as the official v0.77.3 release publishes them (#2118): every OS/arch binary is
// gzip-compressed, with .sig signatures, musl/sumo-musl/legacy variants, an .msi and a collector.
const REAL_RELEASE_ASSET_NAMES = [
  "velociraptor-v0.77.3-linux-amd64.gz",
  "velociraptor-v0.77.3-linux-amd64.gz.sig",
  "velociraptor-v0.77.3-linux-amd64-musl.gz",
  "velociraptor-v0.77.3-linux-amd64-musl.gz.sig",
  "velociraptor-v0.77.3-linux-amd64-sumo-musl.gz",
  "velociraptor-v0.77.3-linux-arm64.gz",
  "velociraptor-v0.77.3-linux-arm64.gz.sig",
  "velociraptor-v0.77.3-darwin-amd64.gz",
  "velociraptor-v0.77.3-darwin-arm64.gz",
  "velociraptor-v0.77.3-windows-amd64-legacy.exe.gz",
  "velociraptor-v0.77.3-windows-amd64.exe.gz",
  "velociraptor-v0.77.3-windows-amd64.exe.gz.sig",
  "velociraptor-v0.77.3-windows-amd64.msi",
  "velociraptor-v0.77.3-windows-arm64.exe.gz",
  "velociraptor-collector",
];

function assetsFor(names: string[]) {
  return names.map((name) => ({ name, browser_download_url: `https://example.com/${name}` }));
}

describe("parseReleaseAssets", () => {
  it("extracts the version and asset list, dropping malformed entries", () => {
    const parsed = parseReleaseAssets({
      tag_name: "v0.77.2",
      assets: [
        { name: "velociraptor-v0.77.2-linux-amd64", browser_download_url: "https://x/velo" },
        { name: "", browser_download_url: "https://x/empty-name" },
        { browser_download_url: "https://x/no-name" },
        "not-an-object",
      ],
    });
    expect(parsed).toEqual({
      version: "0.77.2",
      assets: [{ name: "velociraptor-v0.77.2-linux-amd64", browser_download_url: "https://x/velo" }],
    });
  });

  it("returns null when tag_name is missing", () => {
    expect(parseReleaseAssets({ assets: [] })).toBeNull();
    expect(parseReleaseAssets(null)).toBeNull();
  });
});

describe("pickVelociraptorAsset (plain binaries, older releases)", () => {
  const assets = assetsFor(PLAIN_RELEASE_ASSET_NAMES);

  it("picks the plain linux/amd64 binary, not the musl or packaged variants", () => {
    const picked = pickVelociraptorAsset(assets, "linux", "x64");
    expect(picked?.name).toBe("velociraptor-v0.77.2-linux-amd64");
  });

  it("picks linux/arm64", () => {
    expect(pickVelociraptorAsset(assets, "linux", "arm64")?.name).toBe("velociraptor-v0.77.2-linux-arm64");
  });

  it("picks darwin/amd64 and darwin/arm64", () => {
    expect(pickVelociraptorAsset(assets, "darwin", "x64")?.name).toBe("velociraptor-v0.77.2-darwin-amd64");
    expect(pickVelociraptorAsset(assets, "darwin", "arm64")?.name).toBe("velociraptor-v0.77.2-darwin-arm64");
  });

  it("picks the .exe for windows, not the .msi", () => {
    expect(pickVelociraptorAsset(assets, "win32", "x64")?.name).toBe(
      "velociraptor-v0.77.2-windows-amd64.exe",
    );
  });

  it("treats any unrecognized arch as amd64", () => {
    expect(pickVelociraptorAsset(assets, "linux", "ia32")?.name).toBe("velociraptor-v0.77.2-linux-amd64");
  });

  it("returns null when no asset matches", () => {
    expect(
      pickVelociraptorAsset(assetsFor(["velociraptor-v0.77.2-windows-amd64.exe"]), "linux", "x64"),
    ).toBeNull();
  });
});

describe("pickVelociraptorAsset (gzip-compressed binaries, current releases — #2118)", () => {
  const assets = assetsFor(REAL_RELEASE_ASSET_NAMES);

  it("picks the compressed linux/amd64 binary, not the musl or sumo-musl variant", () => {
    const picked = pickVelociraptorAsset(assets, "linux", "x64");
    expect(picked).toEqual({
      name: "velociraptor-v0.77.3-linux-amd64.gz",
      url: "https://example.com/velociraptor-v0.77.3-linux-amd64.gz",
      compressed: true,
    });
  });

  it("picks linux/arm64", () => {
    expect(pickVelociraptorAsset(assets, "linux", "arm64")?.name).toBe("velociraptor-v0.77.3-linux-arm64.gz");
  });

  it("picks darwin/amd64 and darwin/arm64", () => {
    expect(pickVelociraptorAsset(assets, "darwin", "x64")?.name).toBe("velociraptor-v0.77.3-darwin-amd64.gz");
    expect(pickVelociraptorAsset(assets, "darwin", "arm64")?.name).toBe(
      "velociraptor-v0.77.3-darwin-arm64.gz",
    );
  });

  it("picks the compressed .exe for windows, not the .msi or the legacy build", () => {
    expect(pickVelociraptorAsset(assets, "win32", "x64")?.name).toBe(
      "velociraptor-v0.77.3-windows-amd64.exe.gz",
    );
  });

  it("never picks a .sig signature file", () => {
    for (const [platform, arch] of [
      ["linux", "x64"],
      ["linux", "arm64"],
      ["win32", "x64"],
    ]) {
      expect(pickVelociraptorAsset(assets, platform, arch)?.name).not.toMatch(/\.sig$/);
    }
    expect(
      pickVelociraptorAsset(assetsFor(["velociraptor-v0.77.3-linux-amd64.gz.sig"]), "linux", "x64"),
    ).toBeNull();
  });

  it("prefers a plain binary over a compressed one when both are published", () => {
    const both = assetsFor(["velociraptor-v0.77.3-linux-amd64.gz", "velociraptor-v0.77.3-linux-amd64"]);
    expect(pickVelociraptorAsset(both, "linux", "x64")).toEqual({
      name: "velociraptor-v0.77.3-linux-amd64",
      url: "https://example.com/velociraptor-v0.77.3-linux-amd64",
      compressed: false,
    });
  });
});
