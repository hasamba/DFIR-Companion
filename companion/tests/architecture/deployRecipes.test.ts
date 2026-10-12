import { readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

// A RECIPE THAT CLAIMS LOOPBACK-ONLY EXPOSURE MUST ACTUALLY PUBLISH TO LOOPBACK (#2137).
//
// DFIR_ALLOW_UNAUTHENTICATED_REMOTE=container-loopback-proxy tells the server "the port is
// published to host loopback only — the exposure is not real". The Killercoda lab reused that value
// behind `-p 4773:4773` and a public per-session hostname, asserting a topology it did not have.
// `public-demo` (#535) is the spelling for a real public exposure.
//
// Every `docker run` shipped in the lab or the manual, and the Compose file, is scanned here, so a
// new recipe that pairs the loopback value with a non-loopback publish fails by name.
const root = new URL("../../../", import.meta.url);
const read = (p: string): string => readFileSync(new URL(p, root), "utf8");

const LOOPBACK_VALUE = "container-loopback-proxy";

/** Every `docker run` invocation in a text, with `\`-continued lines joined. */
function dockerRunCommands(text: string): string[] {
  const joined = text.replace(/\\\r?\n/g, " ");
  return joined
    .split(/\r?\n/)
    .filter((line) => /\bdocker run\b/.test(line))
    .map((line) => line.replace(/\s+/g, " ").trim());
}

/** The published-port arguments of one `docker run` command. */
function publishedPorts(cmd: string): string[] {
  return [...cmd.matchAll(/(?:^|\s)(?:-p|--publish)(?:\s+|=)(\S+)/g)].map((m) => m[1]);
}

/** True when a command claims loopback-only exposure but publishes beyond host loopback. */
function claimsLoopbackFalsely(cmd: string): boolean {
  if (!cmd.includes(`DFIR_ALLOW_UNAUTHENTICATED_REMOTE=${LOOPBACK_VALUE}`)) return false;
  return publishedPorts(cmd).some((p) => !p.startsWith("127.0.0.1:"));
}

const rootDir = fileURLToPath(root);

/** Repo-relative paths of every file under `dir` whose name matches `pattern`. */
function filesUnder(dir: string, pattern: RegExp): string[] {
  return readdirSync(join(rootDir, dir), { recursive: true, withFileTypes: true })
    .filter((d) => d.isFile() && pattern.test(d.name))
    .map((d) => relative(rootDir, join(d.parentPath, d.name)).split("\\").join("/"));
}

const recipeFiles = [...filesUnder("killercoda", /\.(sh|md)$/), ...filesUnder("mkdocs-docs", /\.md$/)];

describe("deploy recipe exposure claims (#2137)", () => {
  it("flags the loopback value behind a non-loopback publish, and accepts a loopback publish", () => {
    const bad = `docker run -p 4773:4773 -e DFIR_ALLOW_UNAUTHENTICATED_REMOTE=${LOOPBACK_VALUE} img`;
    const good = `docker run -p 127.0.0.1:4773:4773 -e DFIR_ALLOW_UNAUTHENTICATED_REMOTE=${LOOPBACK_VALUE} img`;
    const continued = `docker run -d \\\n  -p 4773:4773 \\\n  -e DFIR_ALLOW_UNAUTHENTICATED_REMOTE=${LOOPBACK_VALUE} \\\n  img`;
    expect(claimsLoopbackFalsely(bad)).toBe(true);
    expect(claimsLoopbackFalsely(good)).toBe(false);
    expect(dockerRunCommands(continued).map(claimsLoopbackFalsely)).toEqual([true]);
  });

  it("finds the recipes it is meant to scan", () => {
    const all = recipeFiles.flatMap((f) => dockerRunCommands(read(f)));
    expect(all.some((c) => c.includes(LOOPBACK_VALUE))).toBe(true);
    expect(dockerRunCommands(read("killercoda/background.sh"))).toHaveLength(1);
  });

  it.each(recipeFiles)("%s never pairs the loopback value with a non-loopback publish", (file) => {
    const offenders = dockerRunCommands(read(file)).filter(claimsLoopbackFalsely);
    expect(offenders).toEqual([]);
  });

  it("runs the public Killercoda lab with the public-demo value", () => {
    const [cmd] = dockerRunCommands(read("killercoda/background.sh"));
    expect(cmd).toContain("DFIR_ALLOW_UNAUTHENTICATED_REMOTE=public-demo");
    expect(cmd).not.toContain(LOOPBACK_VALUE);
  });

  it("keeps the Compose file's loopback value next to a loopback-only publish", () => {
    const compose = read("docker-compose.yml");
    expect(compose).toContain(`DFIR_ALLOW_UNAUTHENTICATED_REMOTE: "${LOOPBACK_VALUE}"`);
    const ports = [...compose.matchAll(/^\s*-\s*"(\d[^"]*:\d+)"\s*$/gm)].map((m) => m[1]);
    expect(ports.length).toBeGreaterThan(0);
    expect(ports.every((p) => p.startsWith("127.0.0.1:"))).toBe(true);
  });
});
