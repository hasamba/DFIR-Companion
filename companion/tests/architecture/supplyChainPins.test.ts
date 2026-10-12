import { readdirSync, readFileSync } from "node:fs";
import { parse as parseYaml } from "yaml";
import { describe, expect, it } from "vitest";

// EVERY THIRD-PARTY DOWNLOAD IN CI AND THE BUILD SCRIPTS IS PINNED AND VERIFIED (#2157).
//
// Three places fetched code that then ran on a runner holding a write-scoped token:
//   - pages.yml ran a bare `pip install mkdocs-material` on a job with `pages: write` +
//     `id-token: write` — a hijacked release would publish on the project's docs domain.
//   - build-appimage.mjs downloaded appimagetool from the moving `continuous` tag and executed
//     it with no checksum, inside the release job that builds the shipped AppImage.
//   - betterleaks-scan.yml piped a release tarball into `sudo mv` with no hash check.
//
// The rules below are checked against every workflow file (readdirSync), so a new workflow that
// adds a bare `pip install` or an unverified release download fails here the moment it lands.
const repoRoot = new URL("../../../", import.meta.url);
const workflowsDir = new URL(".github/workflows/", repoRoot);

const workflowFiles = readdirSync(workflowsDir)
  .filter((name) => /\.ya?ml$/i.test(name))
  .sort();

interface Step {
  run?: unknown;
}
interface Workflow {
  jobs?: Record<string, { steps?: Step[] } | null>;
}

function runScripts(name: string): string[] {
  const wf = (parseYaml(readFileSync(new URL(name, workflowsDir), "utf8")) ?? {}) as Workflow;
  return Object.values(wf.jobs ?? {}).flatMap((job) =>
    (job?.steps ?? []).flatMap((step) => (typeof step.run === "string" ? [step.run] : [])),
  );
}

const allRuns = workflowFiles.flatMap((name) => runScripts(name).map((run) => ({ name, run })));

// A pip install is pinned when it installs from a requirements file, or every package arg has `==`.
function isPinnedPipInstall(cmd: string): boolean {
  const args = cmd
    .replace(/^.*?pip3?\s+install\s*/, "")
    .split(/\s+/)
    .filter(Boolean);
  if (args.includes("-r") || args.some((a) => a.startsWith("--requirement"))) return true;
  const packages = args.filter((a) => !a.startsWith("-"));
  return packages.length > 0 && packages.every((p) => /==\S+/.test(p));
}

function pipInstallLines(run: string): string[] {
  return run.split("\n").filter((line) => /\bpip3?\s+install\b/.test(line));
}

const PIN_LINE = /^[A-Za-z0-9_.\-[\]]+==[^\s;]+(\s*;\s*[^#]+)?(\s+--hash=sha256:[0-9a-f]{64})*$/;

describe("supply-chain pins (#2157)", () => {
  it("finds the workflow files to check", () => {
    expect(workflowFiles.length).toBeGreaterThan(0);
  });

  it("every pip install in a workflow is pinned (requirements file or exact == versions)", () => {
    const unpinned = allRuns.flatMap(({ name, run }) =>
      pipInstallLines(run)
        .filter((line) => !isPinnedPipInstall(line))
        .map((line) => `${name}: ${line.trim()}`),
    );
    expect(unpinned).toEqual([]);
  });

  it("every release-asset download in a workflow is followed by a sha256sum -c check", () => {
    const unverified = allRuns
      .filter(({ run }) => /\b(curl|wget)\b[^\n]*\/releases\/download\//.test(run))
      .filter(({ run }) => !/sha256sum\s+(-c|--check)\b/.test(run))
      .map(({ name }) => name);
    expect(unverified).toEqual([]);
  });

  it("the release-asset hash is committed, not fetched from the same release at runtime", () => {
    const fetchesChecksums = allRuns
      .filter(({ run }) => /\/releases\/download\/[^\s]*checksums/i.test(run))
      .map(({ name }) => name);
    expect(fetchesChecksums).toEqual([]);
  });

  describe("pages.yml builds the manual from requirements-docs.txt", () => {
    const pagesRuns = runScripts("pages.yml").join("\n");
    const requirements = readFileSync(new URL("requirements-docs.txt", repoRoot), "utf8");
    const pinLines = requirements
      .split("\n")
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith("#"));

    it("installs with pip install -r requirements-docs.txt", () => {
      expect(pagesRuns).toMatch(/pip3?\s+install\s+(--require-hashes\s+)?-r\s+requirements-docs\.txt/);
    });

    it("pins every line of requirements-docs.txt with an exact == version", () => {
      expect(pinLines.length).toBeGreaterThan(0);
      expect(pinLines.filter((l) => !PIN_LINE.test(l))).toEqual([]);
    });

    it("pins mkdocs-material and mkdocs themselves", () => {
      expect(pinLines.some((l) => /^mkdocs-material==/i.test(l))).toBe(true);
      expect(pinLines.some((l) => /^mkdocs==/i.test(l))).toBe(true);
    });

    it("redeploys when requirements-docs.txt changes", () => {
      const raw = readFileSync(new URL("pages.yml", workflowsDir), "utf8");
      const wf = parseYaml(raw) as { on?: { push?: { paths?: string[] } } };
      expect(wf.on?.push?.paths ?? []).toContain("requirements-docs.txt");
    });
  });

  describe("build-appimage.mjs pins and verifies appimagetool", () => {
    const src = readFileSync(new URL("companion/scripts/build-appimage.mjs", repoRoot), "utf8");
    const url = /const APPIMAGETOOL_URL\s*=\s*"([^"]+)"/.exec(src)?.[1] ?? "";

    it("downloads a fixed release, never the moving continuous tag", () => {
      expect(url).toMatch(/\/releases\/download\/\d+\.\d+(\.\d+)?\/appimagetool-x86_64\.AppImage$/);
      expect(url).not.toContain("/continuous/");
    });

    it("commits a 64-hex SHA-256 for that release", () => {
      expect(src).toMatch(/const APPIMAGETOOL_SHA256\s*=\s*"[0-9a-f]{64}"/);
    });

    it("checks the hash before the binary is written, chmodded or executed", () => {
      expect(src).toMatch(/createHash\(\s*"sha256"\s*\)/);
      expect(src).toMatch(/checksum mismatch/);
    });
  });
});
