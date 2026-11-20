import { describe, it, expect } from "vitest";
import {
  approvalMatch,
  itemVerdict,
  notAllowedMatch,
  pathPatternMatches,
  type MatchItem,
} from "../../src/analysis/huntApprovalMatch.js";
import { EMPTY_BASELINE, type BaselineMark } from "../../src/analysis/clientProfile.js";

const H1 = "a".repeat(64);
const H2 = "b".repeat(64);
const NOW = "2026-06-01T00:00:00.000Z";

const mark = (p: Partial<BaselineMark>): BaselineMark => ({
  id: "m",
  verdict: "approved",
  family: "program",
  program: "chrome.exe",
  pathPattern: "\\program files\\google\\chrome\\application",
  sha256: [H1],
  note: "",
  source: "client email",
  recordedBy: "admin",
  recordedAt: "2026-01-01T00:00:00Z",
  ...p,
});

const item = (p: Partial<MatchItem>): MatchItem => ({
  family: "program",
  program: "chrome.exe",
  pathPattern: "\\program files\\google\\chrome\\application",
  sha256: [H1],
  unhashedHosts: [],
  hashesCapped: false,
  ...p,
});

describe("strict baseline matching (#2670)", () => {
  it("an attacker-named binary in Temp is NOT covered by an approval for Program Files", () => {
    expect(approvalMatch(mark({}), item({ pathPattern: "\\users\\*\\appdata\\local\\temp" }), NOW)).toBe(
      "no-match",
    );
  });

  it("a missing hash gives Unknown, never a weaker match", () => {
    expect(approvalMatch(mark({}), item({ sha256: [] }), NOW)).toBe("unknown");
  });

  it("publisher text alone never approves: no signer and no hash on the mark is Unknown", () => {
    expect(approvalMatch(mark({ sha256: [] }), item({}), NOW)).toBe("unknown");
  });

  it("a signer-only approval is Unknown without a VERIFIED signer on the item", () => {
    expect(approvalMatch(mark({ sha256: [], signer: "Google LLC" }), item({}), NOW)).toBe("unknown");
    const signed = { signers: ["Google LLC"], unsignedHosts: [], signersCapped: false };
    expect(approvalMatch(mark({ sha256: [], signer: "Google LLC" }), item(signed), NOW)).toBe("match");
  });

  it("a changed hash on any host is not covered", () => {
    expect(approvalMatch(mark({}), item({ sha256: [H1, H2] }), NOW)).toBe("no-match");
    expect(approvalMatch(mark({ sha256: [H1, H2] }), item({ sha256: [H1, H2] }), NOW)).toBe("match");
  });

  it("an expired approval no longer applies", () => {
    expect(approvalMatch(mark({ expiresAt: "2026-05-01T00:00:00.000Z" }), item({}), NOW)).toBe("no-match");
  });

  it("path and wildcard boundaries are whole segments", () => {
    expect(pathPatternMatches("\\program files\\*\\app", "\\program files\\vendor\\app")).toBe(true);
    expect(pathPatternMatches("\\program files\\*\\app", "\\program files\\a\\b\\app")).toBe(false);
    expect(pathPatternMatches("\\program files\\**\\app", "\\program files\\a\\b\\app")).toBe(true);
    expect(pathPatternMatches("\\program files", "\\program files2")).toBe(false);
    expect(pathPatternMatches("\\users\\*\\appdata", "\\users\\*\\appdata")).toBe(true);
  });

  it("a mark saved from a device-path Prefetch item still matches the re-keyed item (#2749)", () => {
    const dev = "\\device\\harddiskvolume3\\program files\\google\\chrome\\application";
    expect(pathPatternMatches(dev, "\\program files\\google\\chrome\\application")).toBe(true);
    expect(pathPatternMatches("\\program files\\google\\chrome\\application", dev)).toBe(true);
    expect(approvalMatch(mark({ pathPattern: dev }), item({}), NOW)).toBe("match");
    expect(notAllowedMatch(mark({ verdict: "not-allowed", pathPattern: dev }), item({}))).toBe(true);
    expect(approvalMatch(mark({ pathPattern: dev }), item({ pathPattern: "\\users\\*\\appdata" }), NOW)).toBe(
      "no-match",
    );
  });

  it("Not allowed beats Approved", () => {
    const baseline = {
      ...EMPTY_BASELINE,
      marks: [mark({ id: "ok" }), mark({ id: "no", verdict: "not-allowed", pathPattern: "", sha256: [] })],
    };
    expect(itemVerdict(baseline, item({}), NOW)).toMatchObject({ verdict: "not-allowed", markId: "no" });
  });

  it("names why an item that an approval nearly covers is still Unknown", () => {
    const v = itemVerdict({ ...EMPTY_BASELINE, marks: [mark({})] }, item({ sha256: [] }), NOW);
    expect(v.verdict).toBe("unknown");
    expect(v.reason).toMatch(/verified signer or an approved hash is missing/);
  });
});

describe("items with no path can never be approved, and say why (#2747)", () => {
  const installed = item({ family: "installed", program: "7-zip 23.01 (x64)", pathPattern: "", sha256: [] });
  const NO_PATH =
    /cannot be approved: no file path or hash; approve the program's files instead, or mark it Not allowed/;

  it("gives the plain reason before any mark exists", () => {
    const v = itemVerdict(EMPTY_BASELINE, installed, NOW);
    expect(v.verdict).toBe("unknown");
    expect(v.reason).toMatch(NO_PATH);
    expect(v.reason).not.toMatch(/not in the reviewed baseline/);
  });

  it("gives the same reason when an old empty-path approval names it, never the hash hint", () => {
    const old = mark({ family: "installed", program: "7-zip 23.01 (x64)", pathPattern: "", sha256: [] });
    const v = itemVerdict({ ...EMPTY_BASELINE, marks: [old] }, installed, NOW);
    expect(v.verdict).toBe("unknown");
    expect(v.reason).toMatch(NO_PATH);
    expect(v.reason).not.toMatch(/verified signer or an approved hash is missing/);
  });

  it("Not allowed with no path still matches an installed item by name", () => {
    const block = mark({
      id: "no",
      verdict: "not-allowed",
      family: "installed",
      program: "7-zip 23.01 (x64)",
      pathPattern: "",
      sha256: [],
    });
    expect(itemVerdict({ ...EMPTY_BASELINE, marks: [block] }, installed, NOW)).toMatchObject({
      verdict: "not-allowed",
      markId: "no",
    });
  });
});
