import { describe, expect, it } from "vitest";
import {
  applySigmaMatches,
  createSigmaImportGrader,
  sigmaImportNote,
  sigmaMatchesFor,
  sigmaProvenanceToken,
} from "../../src/analysis/sigmaImportGrade.js";
import { buildSigmaRuleSet, type SigmaRuleRef } from "../../src/analysis/sigmaRuleSet.js";
import type { MappedEvent } from "../../src/analysis/siemImport.js";

// The overlay that writes Sigma verdicts onto an imported event (#2202): grade at or above the
// minimum level, tag below it, never mutate the input, never add "Sigma" as a corroborating source.

const ref = (id: string, level: SigmaRuleRef["level"], mitre: string[] = []): SigmaRuleRef => ({
  id,
  title: `Rule ${id}`,
  level,
  status: "test",
  author: "Example Author",
  path: `rules/${id}.yml`,
  url: `https://github.com/SigmaHQ/sigma/blob/abc/rules/${id}.yml`,
  release: "r-test",
  mitre,
  huntingOnly: false,
});

const SNAP = { minLevel: "high" as const, token: "sigma:r-test:abc:stable+test:high:none" };

const base = (): MappedEvent => ({
  timestamp: "2026-01-01T00:00:00Z",
  description: "AWS cloudtrail StopLogging by alice",
  severity: "Info",
  mitre: ["T1078.004"],
  aggKey: "aws|key",
  sources: ["AWS CloudTrail"],
});

describe("applySigmaMatches", () => {
  it("returns the same event when nothing matched and there is no canonical envelope", () => {
    const ev = base();
    expect(applySigmaMatches(ev, [], SNAP)).toBe(ev);
  });

  it("grades to the rule level at or above the minimum, and records the rule", () => {
    const ev = base();
    const out = applySigmaMatches(ev, [ref("a", "high", ["T1562.008"])], SNAP);
    expect(out.severity).toBe("High");
    expect(out.description).toBe("Sigma: Rule a - AWS cloudtrail StopLogging by alice");
    expect(out.mitre).toEqual(["T1078.004", "T1562.008"]);
    expect(out.aggKey).toBe("aws|key|sigma:a");
    expect(out.message).toContain("Sigma rule: Rule a [a]");
    expect(out.message).toContain("author Example Author");
    expect(out.message).toContain("https://github.com/SigmaHQ/sigma/blob/abc/rules/a.yml");
    expect(out.sources).toEqual(["AWS CloudTrail"]);
    expect(ev.severity).toBe("Info");
    expect(ev.description).toBe("AWS cloudtrail StopLogging by alice");
  });

  it("never lowers a hand-graded severity", () => {
    const out = applySigmaMatches({ ...base(), severity: "Critical" }, [ref("a", "high")], SNAP);
    expect(out.severity).toBe("Critical");
  });

  it("tags without grading below the minimum level", () => {
    const out = applySigmaMatches(base(), [ref("m", "medium", ["T1098"])], SNAP);
    expect(out.severity).toBe("Info");
    expect(out.description).toBe("Sigma (medium, tag only): Rule m - AWS cloudtrail StopLogging by alice");
    expect(out.mitre).toContain("T1098");
  });

  it("never grades on a threat-hunting rule, whatever its level", () => {
    const out = applySigmaMatches(base(), [{ ...ref("t", "critical"), huntingOnly: true }], SNAP);
    expect(out.severity).toBe("Info");
    expect(out.description).toMatch(/^Sigma \(critical, tag only\): Rule t - /);
    expect(out.message).toContain("threat-hunting rule (tag only)");
  });

  it("leads with a graded rule and counts the rest", () => {
    const out = applySigmaMatches(base(), [ref("m", "medium"), ref("c", "critical"), ref("h", "high")], SNAP);
    expect(out.severity).toBe("Critical");
    expect(out.description.startsWith("Sigma: Rule c (+2 more) - ")).toBe(true);
    expect(out.aggKey).toBe("aws|key|sigma:c,h,m");
  });

  it("stamps the snapshot token on the canonical producer once", () => {
    const ev: MappedEvent = {
      ...base(),
      canonical: {
        producer: {
          importer: "aws-cloudtrail",
          parserVersion: "1",
          mappingVersion: "v1",
          ruleVersions: ["x"],
        },
      } as unknown as MappedEvent["canonical"],
    };
    const out = applySigmaMatches(ev, [ref("a", "high"), ref("b", "high")], SNAP);
    expect(out.canonical?.producer.ruleVersions).toEqual(["x", SNAP.token]);
    expect(applySigmaMatches(out, [], SNAP).canonical?.producer.ruleVersions).toEqual(["x", SNAP.token]);
  });

  it("appends an attribution note to the message", () => {
    const out = applySigmaMatches(
      base(),
      [ref("a", "high")],
      SNAP,
      "matched the whole audit record (3 rows)",
    );
    expect(out.message).toContain("matched the whole audit record (3 rows)");
  });
});

describe("createSigmaImportGrader / sigmaMatchesFor", () => {
  const STOP_TEXT =
    "title: Stop\nid: stop\nstatus: test\nlogsource:\n  product: aws\n  service: cloudtrail\ndetection:\n  sel:\n    eventName: StopLogging\n  condition: sel\nlevel: high\n";
  const set = buildSigmaRuleSet([{ path: "r.yml", text: STOP_TEXT }], { release: "r-test", commit: "abc" });

  it("matches through the grader while enabled", () => {
    const grader = createSigmaImportGrader(set);
    expect(
      sigmaMatchesFor(grader.snapshot(), "aws-cloudtrail", { eventName: "StopLogging" }).map((r) => r.id),
    ).toEqual(["stop"]);
  });

  it("matches nothing when there is no grader or it is switched off", () => {
    let on = false;
    const grader = createSigmaImportGrader(set, { enabled: () => on });
    expect(sigmaMatchesFor(undefined, "aws-cloudtrail", { eventName: "StopLogging" })).toEqual([]);
    expect(grader.snapshot()).toBeUndefined();
    expect(sigmaMatchesFor(grader.snapshot(), "aws-cloudtrail", { eventName: "StopLogging" })).toEqual([]);
    on = true;
    expect(sigmaMatchesFor(grader.snapshot(), "aws-cloudtrail", { eventName: "StopLogging" })).toHaveLength(
      1,
    );
  });

  // #2218: two imports graded under different exclusions must not carry the same token.
  it("puts the exclusions hash last in the provenance token", () => {
    const plain = sigmaProvenanceToken(set, "high");
    expect(plain).toMatch(/:none:none$/);
    const excluded = buildSigmaRuleSet(
      [{ path: "r.yml", text: STOP_TEXT }],
      { release: "r-test", commit: "abc" },
      { exclusions: new Map([["stop", [{ field: "eventSource", value: "backup.example.com" }]]]) },
    );
    const token = sigmaProvenanceToken(excluded, "high");
    expect(token).toMatch(/^sigma:r-test:[0-9a-f]{12}:stable\+test:high:none:[0-9a-f]{8}$/);
    expect(token).not.toBe(plain);
    expect(sigmaImportNote({ ruleSet: excluded, minLevel: "high", token }, 2)).toMatch(
      /disabled list none, exclusions [0-9a-f]{8}, 2 row\(s\) matched$/,
    );
  });
});
