import { describe, expect, it } from "vitest";
import {
  binaryArtifactHintFor,
  binaryPlistImportHint,
  IMPORT_FILE_UNKNOWN_MESSAGE,
  UNIFIED_IMPORT_UNKNOWN_MESSAGE,
  unknownImportHintFor,
  unknownImportResponse,
} from "../../src/analysis/importKindHints.js";
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

// #1392: #1360 gated ONE name. Every other binary plist — an MRU .sfl2, an arbitrary app's .plist,
// a .bookmark — still reached the text path, where the macOS-persistence sniffer claimed the
// `bplist0` magic and minted the same wrong launchd row. The magic itself is now refused, and the
// hint names both ways forward: the byte-native route for a login-item container, and the plutil
// conversion BEFORE upload for everything else.
describe("binaryPlistImportHint (#1392)", () => {
  const RECENT_DOCS = "com.apple.LSSharedFileList.RecentDocuments.sfl2";

  it("refuses any bplist0 body under a name the login-item gate does not take", () => {
    for (const name of [RECENT_DOCS, "com.evil.agent.plist", "Safari.bookmark", "export.txt"]) {
      const hint = binaryPlistImportHint(name, BPLIST_AS_TEXT);
      expect(hint, name).toMatch(/binary property list/);
      expect(hint, name).toContain(`"${name}"`);
      expect(hint, name).toMatch(/plutil -convert xml1/);
      expect(hint, name).toMatch(/import-binary/);
      expect(hint, name).not.toMatch(/launchd/);
    }
  });

  it("is silent for text, for an XML plist, and for a bplist mentioned past the first bytes", () => {
    expect(
      binaryPlistImportHint("a.plist", '<?xml version="1.0"?><plist version="1.0"><dict/></plist>'),
    ).toBeUndefined();
    expect(binaryPlistImportHint("a.log", "2026-01-01 the file was bplist00")).toBeUndefined();
    expect(binaryPlistImportHint("a.log", "")).toBeUndefined();
  });

  it("reaches the unified route's unknown-kind message, after the name-gated hints", () => {
    expect(unknownImportHintFor(RECENT_DOCS, BPLIST_AS_TEXT)).toMatch(/plutil -convert xml1/);
    expect(unknownImportHintFor("com.evil.agent.plist", BPLIST_AS_TEXT)).toMatch(/plutil -convert xml1/);
    // The v1 .sfl keeps its own sentence (#1360): no reader exists, so plutil is not the way forward.
    expect(unknownImportHintFor(SFL_V1, BPLIST_AS_TEXT)).not.toMatch(/plutil/);
    // A decoded container keeps the byte-native sentence (#1301), which already says how to upload it.
    expect(unknownImportHintFor("backgrounditems.btm", BPLIST_AS_TEXT)).toMatch(
      /binary macOS login-item container/,
    );
  });
});

describe("unknownImportResponse (#1392)", () => {
  it("marks a file-specific hint `refused` so the dashboard shows the sentence, and leaves the generic one unmarked", () => {
    const specific = unknownImportResponse(
      "com.evil.agent.plist",
      BPLIST_AS_TEXT,
      UNIFIED_IMPORT_UNKNOWN_MESSAGE,
    );
    expect(specific).toEqual({ error: expect.stringMatching(/plutil -convert xml1/), refused: true });
    const generic = unknownImportResponse(
      "notes.bin",
      "\u0000\u0001 nothing recognizable",
      IMPORT_FILE_UNKNOWN_MESSAGE,
    );
    expect(generic).toEqual({ error: IMPORT_FILE_UNKNOWN_MESSAGE });
    expect("refused" in generic).toBe(false);
  });
});
