import { describe, expect, it } from "vitest";
import { parse as parseYaml } from "yaml";
import {
  exclusionsByRule,
  parseSigmaExclusions,
  SIGMA_EXCLUSION_LIMITS,
  sigmaExclusionsHash,
  stringifySigmaExclusions,
} from "../../src/analysis/sigmaExclusions.js";

// <dataRoot>/sigma/exclusions.yml (#2218). The analyst can edit the file by hand: every entry is
// checked on load, a bad entry is dropped, and a broken file loads as empty — it never stops the
// server.

const ARN = "arn:aws:iam::111122223333:role/BackupService";

describe("parseSigmaExclusions", () => {
  it("reads valid entries, trimming and defaulting the reason", () => {
    const text = [
      "exclusions:",
      `  - { id: " r1 ", field: " userIdentity.arn ", value: "${ARN}", reason: " backup job " }`,
      "  - { id: r2, field: eventName, value: ListBuckets }",
    ].join("\n");
    expect(parseSigmaExclusions(text)).toEqual([
      { id: "r1", field: "userIdentity.arn", value: ARN, reason: "backup job" },
      { id: "r2", field: "eventName", value: "ListBuckets", reason: "excluded by the analyst" },
    ]);
  });

  it("drops entries with a missing, empty, non-string or over-long part", () => {
    const long = "x".repeat(SIGMA_EXCLUSION_LIMITS.value + 1);
    const text = [
      "exclusions:",
      "  - { id: '', field: f, value: v }",
      "  - { id: r, field: '  ', value: v }",
      "  - { id: r, field: f, value: 12 }",
      "  - { id: r, field: f }",
      `  - { id: r, field: f, value: ${long} }`,
      "  - just a string",
      "  - { id: ok, field: f, value: v }",
    ].join("\n");
    expect(parseSigmaExclusions(text).map((e) => e.id)).toEqual(["ok"]);
  });

  it("loads a broken or empty file as no exclusions, without throwing", () => {
    expect(parseSigmaExclusions("exclusions: [unclosed")).toEqual([]);
    expect(parseSigmaExclusions("")).toEqual([]);
    expect(parseSigmaExclusions("exclusions: 5")).toEqual([]);
  });

  it("keeps one entry per rule, field and value (letter case ignored, as matching does)", () => {
    const text =
      "exclusions:\n  - { id: r, field: F, value: V, reason: a }\n  - { id: r, field: f, value: v, reason: b }";
    expect(parseSigmaExclusions(text)).toEqual([{ id: "r", field: "F", value: "V", reason: "a" }]);
  });

  it("keeps at most SIGMA_EXCLUSION_LIMITS.count entries", () => {
    const lines = Array.from(
      { length: SIGMA_EXCLUSION_LIMITS.count + 5 },
      (_, i) => `  - { id: r, field: f, value: v${i} }`,
    );
    expect(parseSigmaExclusions(["exclusions:", ...lines].join("\n"))).toHaveLength(
      SIGMA_EXCLUSION_LIMITS.count,
    );
  });

  it("round-trips through stringifySigmaExclusions", () => {
    const list = [{ id: "r1", field: "userIdentity.arn", value: ARN, reason: "backup: nightly # job" }];
    const text = stringifySigmaExclusions(list);
    expect(parseYaml(text)).toEqual({ exclusions: list });
    expect(parseSigmaExclusions(text)).toEqual(list);
  });
});

describe("exclusionsByRule and sigmaExclusionsHash", () => {
  it("groups by rule id and hashes independent of order", () => {
    const a = { id: "r1", field: "f", value: "v1", reason: "x" };
    const b = { id: "r1", field: "f", value: "v2", reason: "y" };
    const c = { id: "r2", field: "g", value: "w", reason: "z" };
    const map = exclusionsByRule([a, b, c]);
    expect(map.get("r1")).toEqual([
      { field: "f", value: "v1" },
      { field: "f", value: "v2" },
    ]);
    expect(sigmaExclusionsHash(map)).toBe(sigmaExclusionsHash(exclusionsByRule([c, b, a])));
    expect(sigmaExclusionsHash(new Map())).toBe("none");
  });

  it("ignores the reason in the hash: only what changes matching changes the token", () => {
    const one = exclusionsByRule([{ id: "r", field: "f", value: "v", reason: "a" }]);
    const two = exclusionsByRule([{ id: "r", field: "f", value: "v", reason: "b" }]);
    expect(sigmaExclusionsHash(one)).toBe(sigmaExclusionsHash(two));
  });
});
