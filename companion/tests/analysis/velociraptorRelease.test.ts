// companion/tests/analysis/velociraptorRelease.test.ts
import { describe, it, expect } from "vitest";
import {
  isAllowedAssetUrl,
  parseReleaseAssets,
  pickVelociraptorAsset,
  VELOCIRAPTOR_ASSET_HOSTS,
} from "../../src/analysis/velociraptorRelease.js";

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

// #2133: the asset URL comes verbatim from the GitHub API JSON, and its bytes become an executable
// the companion later spawns. Only GitHub's own release hosts over https are accepted.
describe("isAllowedAssetUrl (#2133)", () => {
  it("accepts every pinned GitHub release host over https", () => {
    for (const host of VELOCIRAPTOR_ASSET_HOSTS) {
      expect(isAllowedAssetUrl(`https://${host}/Velocidex/velociraptor/releases/download/v0.77.3/x.gz`)).toBe(
        true,
      );
    }
    expect(isAllowedAssetUrl("https://GitHub.com/Velocidex/velociraptor/releases/download/v1/x")).toBe(true);
  });

  it("refuses http, other hosts, look-alike hosts, userinfo tricks, ports and non-URLs", () => {
    for (const raw of [
      "http://github.com/Velocidex/velociraptor/releases/download/v1/x",
      "http://169.254.169.254/latest/meta-data",
      "https://evil.example/velociraptor-v0.77.3-linux-amd64.gz",
      "https://github.com.evil.example/x",
      "https://evil.example/github.com",
      "https://github.com@evil.example/",
      "https://user:pass@github.com/x",
      "https://github.com:8443/x",
      "https://api.github.com/x",
      "ftp://github.com/x",
      "not a url",
      "",
    ]) {
      expect(isAllowedAssetUrl(raw), raw).toBe(false);
    }
  });
});

describe("parseReleaseAssets digest (#2133)", () => {
  const hex = "a".repeat(64);

  it("keeps a well-formed sha256 digest and carries it to the picked asset as lower-case hex", () => {
    const parsed = parseReleaseAssets({
      tag_name: "v0.77.3",
      assets: [
        {
          name: "velociraptor-v0.77.3-linux-amd64.gz",
          browser_download_url: "https://github.com/x.gz",
          digest: `sha256:${hex.toUpperCase()}`,
        },
      ],
    });
    expect(parsed?.assets[0].digest).toBe(`sha256:${hex.toUpperCase()}`);
    expect(pickVelociraptorAsset(parsed!.assets, "linux", "x64")?.sha256).toBe(hex);
  });

  it("drops a malformed or non-sha256 digest", () => {
    for (const digest of ["sha256:xyz", `sha1:${hex}`, `sha256:${hex}0`, 42, null]) {
      const parsed = parseReleaseAssets({
        tag_name: "v0.77.3",
        assets: [
          { name: "velociraptor-v0.77.3-linux-amd64", browser_download_url: "https://github.com/x", digest },
        ],
      });
      expect("digest" in parsed!.assets[0]).toBe(false);
      expect(pickVelociraptorAsset(parsed!.assets, "linux", "x64")?.sha256).toBeUndefined();
    }
  });
});
