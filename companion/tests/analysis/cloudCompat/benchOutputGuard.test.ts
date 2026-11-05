import { describe, it, expect } from "vitest";
import { mkdirSync, mkdtempSync, realpathSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { assertNotSymlink, safeOutputDir } from "../../../scripts/benchOutputGuard.js";

// The scale-baseline generator writes gigabytes of synthetic evidence (#2300). Its destination is
// judged by its REAL absolute path, so no spelling of the argument can put that output in a case.
function fakeRepo() {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "dfir-guard-")));
  const cases = join(root, "cases");
  mkdirSync(join(cases, "CASE-1"), { recursive: true });
  return { root, cases };
}

describe("benchmark output guard (#2300)", () => {
  it("refuses `cases` and `cases/bench` relative to the working directory", () => {
    const { root, cases } = fakeRepo();
    expect(() => safeOutputDir("cases", root, [cases])).toThrow(/cases folder/);
    expect(() => safeOutputDir("cases/bench", root, [cases])).toThrow(/cases folder/);
  });

  it("refuses `.` run from inside a case folder", () => {
    const { cases } = fakeRepo();
    expect(() => safeOutputDir(".", join(cases, "CASE-1"), [cases])).toThrow(/cases folder/);
  });

  it("refuses a symlink alias whose real target is a cases root", () => {
    const { root, cases } = fakeRepo();
    symlinkSync(cases, join(root, "innocent-name"), "dir");
    expect(() => safeOutputDir("innocent-name/out", root, [cases])).toThrow(/cases folder/);
    // Even when the configured root list misses it, a real path through a folder named cases is refused.
    expect(() => safeOutputDir("innocent-name/out", root, [])).toThrow(/cases folder/);
  });

  it("refuses a cases root that is not named cases (DFIR_CASES_ROOT elsewhere)", () => {
    const { root } = fakeRepo();
    const evidence = join(root, "evidence-store");
    mkdirSync(evidence);
    expect(() => safeOutputDir("evidence-store/bench", root, [evidence])).toThrow(/cases root/);
  });

  it("accepts a scratch folder and returns its real absolute path", () => {
    const { root, cases } = fakeRepo();
    expect(safeOutputDir("scratch/bench-2300", root, [cases])).toBe(join(root, "scratch", "bench-2300"));
  });

  it("refuses to write through a symlinked output file, dangling or not", () => {
    const { root } = fakeRepo();
    const target = join(root, "elsewhere.json");
    writeFileSync(target, "{}");
    symlinkSync(target, join(root, "manifest.json"));
    symlinkSync(join(root, "missing.json"), join(root, "dangling.json"));
    expect(() => assertNotSymlink(join(root, "manifest.json"))).toThrow(/symlink/);
    expect(() => assertNotSymlink(join(root, "dangling.json"))).toThrow(/symlink/);
    expect(() => assertNotSymlink(join(root, "fresh.json"))).not.toThrow();
  });
});
