import { describe, it, expect } from "vitest";
import {
  classifyDropFile,
  looksBinary,
  rawToolInputExt,
  shouldIgnoreDropFile,
  selectReadyFiles,
  excludeStuck,
  stuckMoveNote,
  moveFailureNote,
  type StuckDropFile,
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
  it("routes raw EVTX/PCAP to the external-tool run path", () => {
    for (const p of ["Security.evtx", "sub/a.evt", "capture.pcap", "b.PCAPNG"]) {
      expect(classifyDropFile(p)).toBe("raw-tool-input");
    }
  });
  it("routes everything else to artifact import", () => {
    for (const p of ["log.csv", "events.json", "auth.log", "export.xml", "mail.eml", "noext"]) {
      expect(classifyDropFile(p)).toBe("artifact");
    }
  });
  it("rawToolInputExt returns the lowercased ext only for raw inputs", () => {
    expect(rawToolInputExt("Security.EVTX")).toBe(".evtx");
    expect(rawToolInputExt("cap.pcapng")).toBe(".pcapng");
    expect(rawToolInputExt("log.csv")).toBe("");
    expect(rawToolInputExt("shot.png")).toBe("");
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
    expect(shouldIgnoreDropFile("drop-log.txt")).toBe(true);
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

describe("looksBinary", () => {
  it("is false for plain ASCII text", () => {
    expect(looksBinary(Buffer.from("2026-07-29 login succeeded for alice\n"))).toBe(false);
  });

  it("is false for UTF-8 text with accents and CJK", () => {
    expect(looksBinary(Buffer.from("café — 日本語のログ\n", "utf8"))).toBe(false);
  });

  it("is true for a PE header", () => {
    const pe = Buffer.concat([Buffer.from("MZ"), Buffer.alloc(64), Buffer.from("PE\0\0")]);
    expect(looksBinary(pe)).toBe(true);
  });

  it("is true for an ELF header", () => {
    expect(looksBinary(Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0, 0, 0]))).toBe(true);
  });

  it("is false for an empty buffer", () => {
    // Nothing to go on — do not claim an empty file is a malware sample.
    expect(looksBinary(Buffer.alloc(0))).toBe(false);
  });
});

describe("classifyDropFile with a content sample", () => {
  it("still routes by extension when there is one", () => {
    expect(classifyDropFile("Security.evtx")).toBe("raw-tool-input");
    expect(classifyDropFile("shot.png")).toBe("image");
    expect(classifyDropFile("auth.log")).toBe("artifact");
  });

  it("routes an extensionless binary sample to the tool path", () => {
    const pe = Buffer.concat([Buffer.from("MZ"), Buffer.alloc(64)]);
    expect(classifyDropFile("a1b2c3d4e5f6", pe)).toBe("raw-tool-input");
  });

  it("leaves an extensionless text file as an artifact", () => {
    expect(classifyDropFile("notes", Buffer.from("just some text\n"))).toBe("artifact");
  });

  it("never lets the sniff override a known text extension", () => {
    // A .csv with an odd byte is still a csv for the native importer, not a malware sample.
    expect(classifyDropFile("data.csv", Buffer.from([0x00, 0x41, 0x42]))).toBe("artifact");
  });
});

// #2281: a file whose move to _processed/ or _failed/ failed stays in drop/. The sweep must not
// import it again while it is unchanged, but changed bytes are new evidence.
describe("excludeStuck", () => {
  const stuckOf = (entries: [string, StuckDropFile][]) => new Map(entries);

  it("removes an unchanged stuck file from the ready list and keeps its entry", () => {
    const listing = [f("a.csv", 10, 1000), f("b.csv", 20, 2000)];
    const prev = stuckOf([["a.csv", { size: 10, mtimeMs: 1000, ok: true }]]);
    const { ready, nextStuck } = excludeStuck(listing, listing, prev);
    expect(ready.map((x) => x.relpath)).toEqual(["b.csv"]);
    expect(nextStuck.get("a.csv")).toEqual({ size: 10, mtimeMs: 1000, ok: true });
  });

  it("keeps the entry of an unchanged stuck file that is not ready this sweep", () => {
    const listing = [f("a.csv", 10, 1000)];
    const prev = stuckOf([["a.csv", { size: 10, mtimeMs: 1000, ok: false }]]);
    const { ready, nextStuck } = excludeStuck([], listing, prev);
    expect(ready).toEqual([]);
    expect(nextStuck.has("a.csv")).toBe(true);
  });

  it("lets a stuck file whose size or mtime changed through, and drops its entry", () => {
    const listing = [f("a.csv", 11, 1000), f("b.csv", 20, 2500)];
    const prev = stuckOf([
      ["a.csv", { size: 10, mtimeMs: 1000, ok: true }],
      ["b.csv", { size: 20, mtimeMs: 2000, ok: true }],
    ]);
    const { ready, nextStuck } = excludeStuck(listing, listing, prev);
    expect(ready.map((x) => x.relpath)).toEqual(["a.csv", "b.csv"]);
    expect(nextStuck.size).toBe(0);
  });

  it("drops the entry of a stuck file that has vanished", () => {
    const prev = stuckOf([["gone.csv", { size: 10, mtimeMs: 1000, ok: true }]]);
    expect(excludeStuck([], [], prev).nextStuck.size).toBe(0);
  });

  it("does not mutate its inputs", () => {
    const listing = [f("a.csv", 10, 1000)];
    const ready = [...listing];
    const prev = stuckOf([
      ["a.csv", { size: 10, mtimeMs: 1000, ok: true }],
      ["gone.csv", { size: 1, mtimeMs: 1, ok: true }],
    ]);
    const res = excludeStuck(ready, listing, prev);
    expect(ready).toHaveLength(1);
    expect(prev.size).toBe(2);
    expect(res.nextStuck).not.toBe(prev);
  });
});

describe("stuckMoveNote", () => {
  it("names the destination, the error and the no-re-import promise", () => {
    expect(stuckMoveNote(true, "EPERM: denied")).toMatch(/_processed\/.*EPERM: denied.*left in drop\//);
    expect(stuckMoveNote(false, "EBUSY")).toMatch(/_failed\/.*EBUSY/);
  });
});

describe("moveFailureNote", () => {
  it("is empty when the move succeeded and a '; '-prefixed caveat when it failed", async () => {
    expect(await moveFailureNote(Promise.resolve(), true)).toBe("");
    const note = await moveFailureNote(Promise.reject(new Error("EBUSY: locked")), false);
    expect(note).toMatch(/^; could not be moved to _failed\/ \(EBUSY: locked\)/);
  });
});
