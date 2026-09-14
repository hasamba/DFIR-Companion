import { describe, expect, it } from "vitest";
import {
  decodeFileAccessMask,
  normaliseId,
  normalisePid,
  normaliseWinPath,
} from "../../src/analysis/canonicalObjectAccess.js";

// #930 item 7: the rights a 4663 carries, by bit, as an UNSIGNED 32-bit value; `0x1` is read OR
// listing; ids and paths normalised for comparison, or said as not normalisable.

describe("decodeFileAccessMask", () => {
  it("each bit maps to its right and class; several bits carry several classes; unknown bits are said", () => {
    expect(decodeFileAccessMask("0x1")).toMatchObject({
      state: "value",
      rights: ["ReadData/ListDirectory"],
      classes: ["read-or-listing"],
    });
    expect(decodeFileAccessMask("0x80")).toMatchObject({ rights: ["ReadAttributes"], classes: ["metadata"] });
    expect(decodeFileAccessMask("0x10000")).toMatchObject({ classes: ["delete"] });
    expect(decodeFileAccessMask("0x6")).toMatchObject({
      rights: ["WriteData/AddFile", "AppendData/AddSubdirectory"],
      classes: ["data-write"],
    });
    expect(decodeFileAccessMask("0x120089")).toMatchObject({ classes: ["read-or-listing", "metadata"] });
    expect(decodeFileAccessMask("0x20")).toMatchObject({ classes: ["execute-or-traverse"] });
    expect(decodeFileAccessMask("0x200001")).toMatchObject({
      classes: ["read-or-listing", "unknown"],
      unknown: "0x200000",
    });
    expect(decodeFileAccessMask("1")).toMatchObject({ bits: 1, classes: ["read-or-listing"] });
  });
  it("is an unsigned 32-bit decode: the high bit, all ones, 4294967295 read; 4294967296, negatives, garbage and a missing field are said", () => {
    expect(decodeFileAccessMask("0x80000000")).toMatchObject({
      state: "value",
      bits: 0x80000000,
      classes: ["unknown"],
      unknown: "0x80000000",
    });
    expect(decodeFileAccessMask("0xffffffff")).toMatchObject({
      state: "value",
      bits: 0xffffffff,
      unknown: "0xffe0fe00",
    });
    expect(decodeFileAccessMask("4294967295").bits).toBe(0xffffffff);
    expect(decodeFileAccessMask("0x80000001").classes).toEqual(["read-or-listing", "unknown"]);
    expect(decodeFileAccessMask("4294967296").state).toBe("unreadable");
    expect(decodeFileAccessMask("-1").state).toBe("unreadable");
    expect(decodeFileAccessMask("0x123456789").state).toBe("unreadable");
    expect(decodeFileAccessMask("lots").state).toBe("unreadable");
    expect(decodeFileAccessMask(undefined).state).toBe("absent");
  });
});

describe("ids and paths", () => {
  it("pids: Security hex and Sysmon decimal read alike; ids canonical hex; garbage null", () => {
    expect(normalisePid("0x1a4")).toBe(420);
    expect(normalisePid("420")).toBe(420);
    expect(normalisePid("-")).toBeNull();
    expect(normalisePid("0x")).toBeNull();
    expect(normaliseId("0x3E7")).toBe("0x3e7");
    expect(normaliseId("0x0003e7")).toBe("0x3e7");
    expect(normaliseId("999")).toBe("0x3e7");
    expect(normaliseId("x")).toBeNull();
  });
  it("paths: case, separators and \\\\?\\ fold; device and 8.3 paths are said, not folded", () => {
    expect(normaliseWinPath("\\\\?\\C:\\Finance\\Board\\minutes.docx")).toEqual({
      key: "c:\\finance\\board\\minutes.docx",
    });
    expect(normaliseWinPath("C:/Finance/Board/MINUTES.DOCX")).toEqual({
      key: "c:\\finance\\board\\minutes.docx",
    });
    expect(normaliseWinPath("\\Device\\HarddiskVolume3\\Finance\\x.docx")).toEqual({
      unmappable: "device path",
    });
    expect(normaliseWinPath("C:\\FINANC~1\\x.docx")).toEqual({ unmappable: "short (8.3) name" });
    expect(normaliseWinPath("")).toBeNull();
    expect(normaliseWinPath("\\\\?\\UNC\\FS01\\Finance\\x.docx")).toEqual({
      key: "\\\\fs01\\finance\\x.docx",
    });
    expect(normaliseWinPath("\\\\fs01\\finance\\x.docx\\")).toEqual({ key: "\\\\fs01\\finance\\x.docx" });
  });
});
