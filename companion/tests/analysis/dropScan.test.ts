import { describe, it, expect } from "vitest";
import {
  classifyDropFile,
  shouldIgnoreDropFile,
  selectReadyFiles,
  isOversize,
  DROP_PROCESSED,
  DROP_FAILED,
  type DropFileStat,
} from "../../src/analysis/dropScan.js";

const f = (relpath: string, size = 10, mtimeMs = 1000): DropFileStat => ({ relpath, size, mtimeMs });

describe("dropScan — classification", () => {
  it("routes image extensions to the capture pipeline", () => {
    for (const p of ["a.png", "sub/b.JPG", "c.jpeg", "shot.webp", "anim.gif", "x.tiff"]) {
      expect(classifyDropFile(p)).toBe("image");
    }
  });
  it("routes everything else to artifact import", () => {
    for (const p of ["log.csv", "events.json", "auth.log", "export.xml", "mail.eml", "noext"]) {
      expect(classifyDropFile(p)).toBe("artifact");
    }
  });
});

describe("dropScan — ignore rules", () => {
  it("ignores the reserved subtrees (both separators)", () => {
    expect(shouldIgnoreDropFile(`${DROP_PROCESSED}/a.csv`)).toBe(true);
    expect(shouldIgnoreDropFile(`${DROP_FAILED}\\nested\\b.csv`)).toBe(true);
  });
  it("ignores README, dotfiles, and OS/sync junk", () => {
    expect(shouldIgnoreDropFile("README.txt")).toBe(true);
    expect(shouldIgnoreDropFile(".hidden")).toBe(true);
    expect(shouldIgnoreDropFile("sub/.DS_Store")).toBe(true);
    expect(shouldIgnoreDropFile("Thumbs.db")).toBe(true);
    expect(shouldIgnoreDropFile("desktop.ini")).toBe(true);
  });
  it("does not ignore a real evidence file", () => {
    expect(shouldIgnoreDropFile("triage/prefetch.csv")).toBe(false);
  });
});

describe("dropScan — settle gating", () => {
  it("does not mark a brand-new file ready, but records it for next poll", () => {
    const r = selectReadyFiles([f("a.csv")], new Map());
    expect(r.ready).toEqual([]);
    expect(r.nextSeen.get("a.csv")).toEqual({ size: 10, mtimeMs: 1000 });
  });

  it("marks a file ready once size+mtime are unchanged across a poll", () => {
    const first = selectReadyFiles([f("a.csv")], new Map());
    const second = selectReadyFiles([f("a.csv")], first.nextSeen);
    expect(second.ready.map((x) => x.relpath)).toEqual(["a.csv"]);
  });

  it("withholds a file that is still growing (size changed)", () => {
    const first = selectReadyFiles([f("a.csv", 10)], new Map());
    const second = selectReadyFiles([f("a.csv", 20)], first.nextSeen);
    expect(second.ready).toEqual([]);
    // still tracked at its new size, so the NEXT stable poll releases it
    const third = selectReadyFiles([f("a.csv", 20)], second.nextSeen);
    expect(third.ready.map((x) => x.relpath)).toEqual(["a.csv"]);
  });

  it("withholds a file whose mtime changed", () => {
    const first = selectReadyFiles([f("a.csv", 10, 1000)], new Map());
    const second = selectReadyFiles([f("a.csv", 10, 2000)], first.nextSeen);
    expect(second.ready).toEqual([]);
  });

  it("excludes ignored files from ready and nextSeen", () => {
    const first = selectReadyFiles([f(`${DROP_PROCESSED}/done.csv`), f("README.txt")], new Map());
    const second = selectReadyFiles([f(`${DROP_PROCESSED}/done.csv`), f("README.txt")], first.nextSeen);
    expect(second.ready).toEqual([]);
    expect(second.nextSeen.size).toBe(0);
  });
});

describe("dropScan — oversize", () => {
  it("flags files over the cap and respects a disabled (0) cap", () => {
    expect(isOversize(100, 50)).toBe(true);
    expect(isOversize(40, 50)).toBe(false);
    expect(isOversize(1e9, 0)).toBe(false);
  });
});
