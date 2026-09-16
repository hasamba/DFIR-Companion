import { describe, it, expect } from "vitest";
import {
  looksLikeMacBtmFilename,
  isBplistMagic,
  detectBinaryImportKind,
} from "../../src/analysis/macBinaryDetect.js";

const REAL_MAGIC = Buffer.from("62706c69737430303f", "hex"); // real "bplist00" + one byte

describe("looksLikeMacBtmFilename", () => {
  it("recognizes the real legacy filename", () => {
    expect(looksLikeMacBtmFilename("backgrounditems.btm")).toBe(true);
    expect(looksLikeMacBtmFilename("0007_backgrounditems.btm")).toBe(true);
  });

  it("recognizes the real modern filename pattern", () => {
    expect(looksLikeMacBtmFilename("BackgroundItems-v4.btm")).toBe(true);
    expect(looksLikeMacBtmFilename("BackgroundItems-v13.btm")).toBe(true);
  });

  it("rejects an unrelated filename", () => {
    expect(looksLikeMacBtmFilename("backgrounditems.plist")).toBe(false);
    expect(looksLikeMacBtmFilename("BackgroundItems-vX.btm")).toBe(false); // not a real version number
  });
});

describe("isBplistMagic", () => {
  it("recognizes the real bplist00 magic", () => {
    expect(isBplistMagic(REAL_MAGIC)).toBe(true);
  });

  it("rejects a buffer with a different magic", () => {
    expect(isBplistMagic(Buffer.from("not-a-bplist-at-all"))).toBe(false);
  });

  it("rejects a buffer shorter than the magic itself", () => {
    expect(isBplistMagic(Buffer.from("bplist"))).toBe(false);
  });
});

describe("detectBinaryImportKind — both filename AND real magic required", () => {
  it("matches when both the filename and the magic are real", () => {
    expect(detectBinaryImportKind("backgrounditems.btm", REAL_MAGIC)).toBe("macloginitem");
  });

  it("rejects a matching filename with a mismatched magic, never coerces it", () => {
    expect(detectBinaryImportKind("backgrounditems.btm", Buffer.from("not-bplist"))).toBeNull();
  });

  it("rejects real bplist magic under an unrelated filename", () => {
    expect(detectBinaryImportKind("Spotlight.bplist", REAL_MAGIC)).toBeNull();
  });
});
