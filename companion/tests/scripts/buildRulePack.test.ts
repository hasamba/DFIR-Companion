import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  MANIFEST_ASSET,
  RULES_ASSET,
  buildManifest,
  countRules,
  isUnchanged,
  nextPackVersion,
  parseUpstreamSources,
} from "../../scripts/buildRulePack.mjs";

// The rule-pack builder (#2349): what the publish workflow releases. Pure functions only; the
// workflow's I/O is a few gh calls around them.

const SHA_A = "a".repeat(40);
const YAML = [
  "# header",
  `# Example-Suite upstream commit: ${SHA_A} (2026-10-26)`,
  "rule_one:",
  "  any:",
  "    - { field: message, contains: 'x' }",
  "rule_two:",
  "  any:",
  "    - { field: message, contains: 'y' }",
  "",
].join("\n");

const build = (tagsYaml = YAML, version = "rules-2026.11.06") =>
  buildManifest({
    tagsYaml,
    appVersion: "0.45.0",
    version,
    createdAt: "2026-11-06T00:00:00.000Z",
    commit: "c0ffee",
  });

describe("buildRulePack", () => {
  it("records the SHA-256 and size of the rules file, the app version and the rule count", () => {
    const m = build();
    expect(m.files).toEqual([
      {
        name: RULES_ASSET,
        sha256: createHash("sha256").update(YAML).digest("hex"),
        bytes: Buffer.byteLength(YAML),
      },
    ]);
    expect(m.minAppVersion).toBe("0.45.0");
    expect(m.ruleCount).toBe(2);
    expect(m.version).toBe("rules-2026.11.06");
    expect(m.commit).toBe("c0ffee");
    expect(MANIFEST_ASSET).toBe("rule-pack-manifest.json");
  });

  it("names every upstream source with its recorded commit", () => {
    expect(parseUpstreamSources(YAML)).toEqual([
      { name: "Example-Suite", commit: SHA_A, date: "2026-10-26" },
    ]);
  });

  it("reads the real tags.yaml: rules counted, the Analyzer-Suite source found", () => {
    const real = readFileSync(new URL("../../data/tags.yaml", import.meta.url), "utf8");
    expect(countRules(real)).toBeGreaterThan(50);
    expect(parseUpstreamSources(real).map((s) => s.name)).toContain("Microsoft-Analyzer-Suite");
  });

  it("dates the pack and adds .N when the day already has one", () => {
    expect(nextPackVersion("2026-11-06")).toBe("rules-2026.11.06");
    expect(nextPackVersion("2026-11-06", ["rules-2026.11.06"])).toBe("rules-2026.11.06.2");
    expect(nextPackVersion("2026-11-06", ["rules-2026.11.06", "rules-2026.11.06.2"])).toBe(
      "rules-2026.11.06.3",
    );
    expect(() => nextPackVersion("06/11/2026")).toThrow(/YYYY-MM-DD/);
  });

  it("refuses an empty rules file or a bad app version", () => {
    expect(() => build("# only comments\n")).toThrow(/no rules/);
    expect(() =>
      buildManifest({ tagsYaml: YAML, appVersion: "dev", version: "rules-2026.11.06", createdAt: "x" }),
    ).toThrow(/app version/);
  });

  it("an unchanged rules file and sources publish nothing; any change does", () => {
    const prev = build();
    expect(isUnchanged(prev, build(YAML, "rules-2026.11.07"))).toBe(true);
    expect(isUnchanged(prev, build(YAML + "rule_three:\n  any: []\n"))).toBe(false);
    expect(isUnchanged(prev, build(YAML.replace(SHA_A, "b".repeat(40))))).toBe(false);
    expect(isUnchanged(null, prev)).toBe(false);
  });
});
