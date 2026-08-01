import { mkdtempSync, mkdirSync, rmSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { assertTempCasesRoot } from "./isolation.js";

const REPO_ROOT = realpathSync(join(import.meta.dirname, "..", "..", ".."));
const made: string[] = [];

afterAll(() => {
  for (const d of made) rmSync(d, { recursive: true, force: true });
});

describe("assertTempCasesRoot", () => {
  it("accepts a directory under the OS temp dir", () => {
    const root = mkdtempSync(join(tmpdir(), "dfir-e2e-guard-"));
    made.push(root);
    expect(assertTempCasesRoot(root, REPO_ROOT)).toBe(realpathSync(root));
  });

  it("rejects a directory outside the OS temp dir", () => {
    expect(() => assertTempCasesRoot(join(REPO_ROOT, "cases"), REPO_ROOT)).toThrow(/refusing to start/);
  });

  it("rejects a path inside the repository even if it is also under tmp", () => {
    // A worktree living under /tmp is a real configuration; the repo check must still fire.
    const fakeRepo = mkdtempSync(join(tmpdir(), "dfir-e2e-repo-"));
    made.push(fakeRepo);
    const inside = join(fakeRepo, "cases");
    mkdirSync(inside, { recursive: true });
    expect(() => assertTempCasesRoot(inside, fakeRepo)).toThrow(/inside the repository/);
  });

  it("rejects a path that does not exist", () => {
    expect(() => assertTempCasesRoot(join(tmpdir(), "definitely-not-here-12345"), REPO_ROOT)).toThrow(
      /refusing to start/,
    );
  });

  it("does not treat a sibling with a shared prefix as being inside the repo", () => {
    // /tmp/repo-extra must not count as inside /tmp/repo. A naive startsWith() says it does.
    const repo = mkdtempSync(join(tmpdir(), "dfir-e2e-prefix-"));
    made.push(repo);
    const sibling = `${repo}-extra`;
    mkdirSync(sibling, { recursive: true });
    made.push(sibling);
    expect(assertTempCasesRoot(sibling, repo)).toBe(realpathSync(sibling));
  });
});
