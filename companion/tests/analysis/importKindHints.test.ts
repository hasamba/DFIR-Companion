import { describe, expect, it } from "vitest";
import { binaryArtifactHintFor, unknownImportHintFor } from "../../src/analysis/importKindHints.js";
import {
  detectBinaryImportKind,
  looksLikeMacLoginItemFilename,
  looksLikeUndecodedMacLoginItemFilename,
} from "../../src/analysis/macBinaryDetect.js";

// #1360: the v1 SessionLoginItems.sfl (macOS 10.11–10.12) is a login-item container this codebase
// knows by name but does not decode — a maintainer decision, the format is end-of-life and no real
// capture exists to build a reader against. Before this, the text path did not gate the name, so a
// text-read of the bplist was sniffed as a BINARY LAUNCHD PLIST and minted as a Medium "not read,
// run plutil -convert xml1" row: the wrong artifact, and advice that leads nowhere. The name is now
// refused with the honest sentence — and stays OUT of the byte-native accept list, so the binary
// routes do not start accepting a file they cannot decode either.

const SFL_V1 = "com.apple.LSSharedFileList.SessionLoginItems.sfl";
const BPLIST_AS_TEXT = "bplist00Ô\u0001\u0002\u0003\u0004\u0005\u0006$archiver";

describe("looksLikeUndecodedMacLoginItemFilename (#1360)", () => {
  it("names the v1 .sfl list, case-insensitively, and nothing else", () => {
    expect(looksLikeUndecodedMacLoginItemFilename(SFL_V1)).toBe(true);
    expect(looksLikeUndecodedMacLoginItemFilename(SFL_V1.toUpperCase())).toBe(true);
    expect(looksLikeUndecodedMacLoginItemFilename("com.apple.LSSharedFileList.SessionLoginItems.sfl2")).toBe(
      false,
    );
    expect(looksLikeUndecodedMacLoginItemFilename("com.apple.LSSharedFileList.RecentDocuments.sfl")).toBe(
      false,
    );
    expect(looksLikeUndecodedMacLoginItemFilename("backgrounditems.btm")).toBe(false);
  });

  it("is a separate list from the accept gate — the v1 name is still not decoded byte-native", () => {
    expect(looksLikeMacLoginItemFilename(SFL_V1)).toBe(false);
    expect(detectBinaryImportKind(SFL_V1, Buffer.from("bplist00"))).toBeNull();
  });
});

describe("binaryArtifactHintFor (#1360)", () => {
  it("tells the analyst the v1 .sfl is not decoded and that .sfl2 is — not to upload it byte-native", () => {
    const hint = binaryArtifactHintFor(SFL_V1);
    expect(hint).toMatch(/SessionLoginItems\.sfl \(v1, macOS 10\.11–10\.12\) is not decoded/);
    expect(hint).toMatch(/\.sfl2/);
    expect(hint).not.toMatch(/import-binary/);
    expect(hint).not.toMatch(/plutil/);
  });

  it("still gives the decoded containers the byte-native hint", () => {
    expect(binaryArtifactHintFor("com.apple.LSSharedFileList.SessionLoginItems.sfl2")).toMatch(
      /import-binary/,
    );
    expect(binaryArtifactHintFor("com.apple.LSSharedFileList.RecentDocuments.sfl2")).toBeUndefined();
  });

  it("reaches the unified route's unknown-kind message for a text-read of the v1 bplist", () => {
    expect(unknownImportHintFor(SFL_V1, BPLIST_AS_TEXT)).toMatch(/v1, macOS 10\.11–10\.12/);
  });
});
