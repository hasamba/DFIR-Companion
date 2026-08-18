// companion/tests/analysis/velociraptorRelease.test.ts
import { describe, it, expect } from "vitest";
import { parseReleaseAssets, pickVelociraptorAsset } from "../../src/analysis/velociraptorRelease.js";

const REAL_RELEASE_ASSET_NAMES = [
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

describe("pickVelociraptorAsset", () => {
  const assets = assetsFor(REAL_RELEASE_ASSET_NAMES);

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
