import { readFileSync } from "node:fs";
import { parse as parseYaml } from "yaml";
import { describe, expect, it } from "vitest";

// RELEASE INTEGRITY SIGNALS (#2158).
//
// The Windows EXE and the Linux AppImage are not code-signed, so an analyst downloading a forensic
// tool for live incident work gets no OS trust signal. Two cheap things close part of that gap,
// and both live only in the tag-gated `release` job, where a branch run never exercises them:
//
//   1. A SHA256SUMS.txt asset on every GitHub Release, built from exactly the files the
//      "Decide what to publish" step picked, so `sha256sum -c` works against the download.
//   2. A release-page disclosure that the binaries are unsigned. The README alone is not enough:
//      the release page is where people download from.
const root = new URL("../../../", import.meta.url);
const read = (rel: string): string => readFileSync(new URL(rel, root), "utf8");

type Step = {
  name?: string;
  id?: string;
  uses?: string;
  run?: string;
  env?: Record<string, unknown>;
  with?: Record<string, unknown>;
};
const workflow = parseYaml(read(".github/workflows/release-artifacts.yml")) as {
  jobs: Record<string, { steps: Step[] }>;
};
const steps = workflow.jobs.release.steps;
const indexOf = (pred: (s: Step) => boolean): number => steps.findIndex(pred);

const pickIdx = indexOf((s) => s.id === "pick");
const sumsIdx = indexOf((s) => /sha256sum/.test(s.run ?? "") && /SHA256SUMS\.txt/.test(s.run ?? ""));
const uploadIdx = indexOf((s) => (s.uses ?? "").startsWith("softprops/action-gh-release@"));
const notesIdx = indexOf((s) => s.id === "changelog");

describe("release job publishes SHA256SUMS.txt (#2158)", () => {
  it("has a step that runs sha256sum and writes SHA256SUMS.txt", () => {
    expect(sumsIdx).toBeGreaterThanOrEqual(0);
  });

  it("checksums after the pick step and before the upload", () => {
    expect(pickIdx).toBeGreaterThanOrEqual(0);
    expect(uploadIdx).toBeGreaterThanOrEqual(0);
    expect(sumsIdx).toBeGreaterThan(pickIdx);
    expect(sumsIdx).toBeLessThan(uploadIdx);
  });

  it("hashes exactly the picked files, by basename, and fails on an empty sums file", () => {
    const run = steps[sumsIdx].run ?? "";
    // The pick output reaches the script through env (never interpolated into the shell body).
    expect(JSON.stringify(steps[sumsIdx].env ?? {})).toContain("steps.pick.outputs.files");
    // Bare basenames: the line must be checkable next to the downloaded asset.
    expect(run).toMatch(/basename|cd "\$\(dirname|sed .*#/);
    expect(run).toMatch(/\[ ! -s SHA256SUMS\.txt \]/);
    expect(run).toMatch(/exit 1/);
  });

  it("uploads SHA256SUMS.txt alongside the picked files", () => {
    const files = String(steps[uploadIdx].with?.files ?? "");
    expect(files).toContain("steps.pick.outputs.files");
    expect(files).toContain("SHA256SUMS.txt");
  });
});

describe("release notes disclose that the binaries are unsigned (#2158)", () => {
  const run = (): string => steps[notesIdx].run ?? "";

  it("appends the disclosure after the fallback, so both branches carry it", () => {
    const body = run();
    const fallbackAt = body.indexOf("See CHANGELOG.md for details.");
    const disclosureAt = body.indexOf("not code-signed");
    expect(fallbackAt).toBeGreaterThanOrEqual(0);
    expect(disclosureAt).toBeGreaterThan(fallbackAt);
    // The fallback `if` must be closed before the disclosure, or only one branch gets it.
    expect(body.slice(fallbackAt, disclosureAt)).toMatch(/\bfi\b/);
  });

  it("tells the reader how to verify against SHA256SUMS.txt on Linux and Windows", () => {
    const body = run();
    expect(body).toContain("sha256sum -c SHA256SUMS.txt --ignore-missing");
    expect(body).toContain("Get-FileHash");
    expect(body).toContain("SmartScreen");
  });
});

describe("user docs disclose unsigned binaries and point to SHA256SUMS.txt (#2158)", () => {
  it.each(["README.md", "mkdocs-docs/getting-started.md"])("%s", (rel) => {
    const text = read(rel);
    expect(text).toContain("SHA256SUMS.txt");
    expect(text).toMatch(/not code-signed/);
    expect(text).toContain("SmartScreen");
  });
});
