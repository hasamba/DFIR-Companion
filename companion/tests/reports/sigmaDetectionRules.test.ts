import { describe, expect, it } from "vitest";
import {
  detectionRulesHtml,
  detectionRulesMarkdown,
  sigmaGradingsInCase,
} from "../../src/reports/detectionRules.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// Report integrity for import-time Sigma grading (#2204): a report names the rule release, content,
// statuses, minimum level and disabled list that graded the case, read from the structured token
// every graded event carries — never parsed back out of prose.

const TOKEN_A = "sigma:r2026-07-01:0123456789ab:stable+test:high:none";
const TOKEN_B = "sigma:file_rules.zip:ba9876543210:stable+test+experimental:medium:1a2b3c4d";
const TOKEN_EXCL = "sigma:r2026-07-01:0123456789ab:stable+test:high:none:9f8e7d6c";

const ev = (id: string, ruleVersions?: string[]): ForensicEvent =>
  ({
    id,
    timestamp: "2026-01-01T00:00:00Z",
    description: "d",
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...(ruleVersions
      ? { canonical: { producer: { importer: "x", parserVersion: "1", mappingVersion: "1", ruleVersions } } }
      : {}),
  }) as unknown as ForensicEvent;

describe("sigmaGradingsInCase", () => {
  it("collects each distinct grading once, in first-seen order", () => {
    const g = sigmaGradingsInCase([ev("1", ["x", TOKEN_A]), ev("2", [TOKEN_A]), ev("3", [TOKEN_B]), ev("4")]);
    expect(g).toEqual([
      {
        release: "r2026-07-01",
        contentSha: "0123456789ab",
        statuses: ["stable", "test"],
        minLevel: "high",
        disabledHash: "none",
      },
      {
        release: "file_rules.zip",
        contentSha: "ba9876543210",
        statuses: ["stable", "test", "experimental"],
        minLevel: "medium",
        disabledHash: "1a2b3c4d",
      },
    ]);
  });

  it("reads an older event envelope that has no producer (CI found this on #2204)", () => {
    const legacy = { ...ev("1"), canonical: { evidence: { rawRecords: [] } } } as unknown as ForensicEvent;
    expect(sigmaGradingsInCase([legacy])).toEqual([]);
  });

  it("ignores malformed tokens", () => {
    expect(sigmaGradingsInCase([ev("1", ["sigma:only:three"])])).toEqual([]);
    expect(sigmaGradingsInCase([ev("1", [`${TOKEN_A}:NOTHEX!!`])])).toEqual([]);
  });

  // #2218: the token gained the exclusions hash. Older tokens (six parts) still read.
  it("reads the exclusions hash from a seven-part token", () => {
    expect(sigmaGradingsInCase([ev("1", [TOKEN_EXCL])])).toEqual([
      {
        release: "r2026-07-01",
        contentSha: "0123456789ab",
        statuses: ["stable", "test"],
        minLevel: "high",
        disabledHash: "none",
        exclusionsHash: "9f8e7d6c",
      },
    ]);
  });
});

describe("report output", () => {
  it("writes a Markdown sub-section only when the case was graded", () => {
    const lines: string[] = [];
    detectionRulesMarkdown([ev("1")], lines);
    expect(lines).toEqual([]);
    detectionRulesMarkdown([ev("1", [TOKEN_A])], lines);
    expect(lines.join("\n")).toContain("### Detection rules");
    expect(lines.join("\n")).toContain(
      "SigmaHQ `r2026-07-01` (content `0123456789ab`) — statuses stable, test; raises severity at high and above; disabled list `none`",
    );
  });

  it("writes one escaped HTML line, or nothing", () => {
    expect(detectionRulesHtml([ev("1")])).toBe("");
    expect(detectionRulesHtml([ev("1", ["sigma:<b>:0123456789ab:stable:high:none"])])).toBe("");
    expect(detectionRulesHtml([ev("1", [TOKEN_A])])).toBe(
      '<p class="meta">Detection rules: SigmaHQ r2026-07-01 (content 0123456789ab), statuses stable, test, raises at high+, disabled list none</p>',
    );
  });

  it("names the exclusions when the token carries them (#2218)", () => {
    const lines: string[] = [];
    detectionRulesMarkdown([ev("1", [TOKEN_EXCL])], lines);
    expect(lines.join("\n")).toContain("disabled list `none`; exclusions `9f8e7d6c`");
    expect(detectionRulesHtml([ev("1", [TOKEN_EXCL])])).toContain(
      "disabled list none, exclusions 9f8e7d6c</p>",
    );
  });
});
