import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

// EVERY FILE THAT CARRIES THE RELEASE VERSION MUST CARRY THE SAME ONE.
//
// The release ritual bumps the version by hand in five files. docker-compose.yml is a sixth, and
// nobody knew it: its `image:` tag sat at 0.34.0 through the entire 0.35.x line. That tag is not
// cosmetic. The compose file ships with `build:` enabled, so the tag names BOTH the image built
// from local source and the image `docker compose pull` fetches from GHCR — a stale pin silently
// hands a user a release-old container and labels a fresh source build with the wrong version.
//
// It surfaced only when a user watched `docker compose pull` download 0.34.0 on a 0.35.1 checkout.
// Nothing compared the files, so the drift was invisible for two releases.
//
// A checklist line would not have caught it — the checklist already lists five files and the sixth
// was never on it. This gate derives the truth from companion/package.json instead, so ANY new
// version-bearing file is one entry away from being covered, and a partial bump fails by name.
const root = new URL("../../../", import.meta.url);
const read = (p: string): string => readFileSync(new URL(p, root), "utf8");
const json = (p: string): Record<string, unknown> => JSON.parse(read(p));

const EXPECTED = json("companion/package.json").version as string;

/** Each source is a file plus how the version is spelled inside it. */
const SOURCES: ReadonlyArray<{ file: string; label: string; read: () => string | undefined }> = [
  {
    file: "extension/package.json",
    label: '"version"',
    read: () => json("extension/package.json").version as string | undefined,
  },
  {
    file: "extension/manifest.json",
    label: '"version"',
    read: () => json("extension/manifest.json").version as string | undefined,
  },
  {
    file: "companion/package-lock.json",
    label: 'top-level "version"',
    read: () => json("companion/package-lock.json").version as string | undefined,
  },
  {
    file: "companion/package-lock.json",
    label: 'packages[""].version',
    read: () => lockRootVersion("companion/package-lock.json"),
  },
  {
    file: "extension/package-lock.json",
    label: 'top-level "version"',
    read: () => json("extension/package-lock.json").version as string | undefined,
  },
  {
    file: "extension/package-lock.json",
    label: 'packages[""].version',
    read: () => lockRootVersion("extension/package-lock.json"),
  },
  {
    file: "docker-compose.yml",
    label: "the ghcr.io image tag",
    read: () => /image:\s*ghcr\.io\/[^:\s]+:(\S+)/.exec(read("docker-compose.yml"))?.[1],
  },
];

/** A lockfile records its own version twice; the `packages[""]` copy is the one npm rewrites. */
function lockRootVersion(p: string): string | undefined {
  const packages = json(p).packages as Record<string, { version?: string }> | undefined;
  return packages?.[""]?.version;
}

describe("release version sync", () => {
  it("companion/package.json carries a plain semver version", () => {
    expect(EXPECTED).toMatch(/^\d+\.\d+\.\d+$/);
  });

  it.each(SOURCES)("$file — $label matches companion/package.json", ({ file, label, read }) => {
    const found = read();
    expect(found, `${file}: could not find ${label} — did the file's shape change?`).toBeDefined();
    expect(
      found,
      `${file} declares ${found} but companion/package.json declares ${EXPECTED}. ` +
        `Bump ${label} in ${file} to ${EXPECTED}.`,
    ).toBe(EXPECTED);
  });
});
