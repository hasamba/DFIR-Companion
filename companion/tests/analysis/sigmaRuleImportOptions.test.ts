import { describe, expect, it } from "vitest";
import { parseSigmaRule } from "../../src/analysis/sigmaRule.js";

// The import-time engine (#2202) reads more of a rule than the hunt compiler does: the status that
// picks which rules load, the author the DRL requires on every match, the dates that version a
// match, and `field: null`, which CloudTrail rules use for "this key is absent". The hunt compiler
// parses without the option, so nothing it sees changes.

const WITH_META = `
title: Meta
id: 11111111-2222-3333-4444-555555555555
status: test
author: Jane Example, John Example
date: 2021-08-19
modified: 2024-01-02
logsource:
  product: aws
  service: cloudtrail
detection:
  sel:
    eventName: StopLogging
  condition: sel
level: high
`;

const WITH_NULL = `
title: Absent MFA flag
logsource:
  product: aws
  service: cloudtrail
detection:
  sel:
    eventName: ConsoleLogin
    additionalEventData.MFAUsed: null
  condition: sel
`;

describe("parseSigmaRule metadata for import-time grading", () => {
  it("reads status, author, date and modified", () => {
    const r = parseSigmaRule(WITH_META);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.rule.status).toBe("test");
    expect(r.rule.author).toBe("Jane Example, John Example");
    expect(r.rule.date).toBe("2021-08-19");
    expect(r.rule.modified).toBe("2024-01-02");
  });

  it("reads a slash date as its written text", () => {
    const r = parseSigmaRule(WITH_META.replace("date: 2021-08-19", "date: 2021/08/19"));
    expect(r.ok && r.rule.date).toBe("2021/08/19");
  });
});

describe("parseSigmaRule null values", () => {
  it("still refuses `field: null` without the option (the hunt compiler's view)", () => {
    const r = parseSigmaRule(WITH_NULL);
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.refusals).toEqual([
      { path: "detection.sel.additionalEventData.MFAUsed", message: expect.stringMatching(/null/i) },
    ]);
  });

  it("parses `field: null` as a null match with allowNull", () => {
    const r = parseSigmaRule(WITH_NULL, { allowNull: true });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const sel = r.rule.detection.selections[0];
    expect(sel.kind).toBe("map");
    if (sel.kind !== "map") return;
    expect(sel.fields[1]).toEqual({
      field: "additionalEventData.MFAUsed",
      modifiers: [],
      values: [],
      nullValue: true,
    });
  });

  it("refuses a null inside a value list even with allowNull", () => {
    const r = parseSigmaRule(WITH_NULL.replace("MFAUsed: null", "MFAUsed: [null, 'No']"), {
      allowNull: true,
    });
    expect(r.ok).toBe(false);
  });

  it("refuses a modifier on a null value even with allowNull", () => {
    const r = parseSigmaRule(WITH_NULL.replace("MFAUsed: null", "MFAUsed|contains: null"), {
      allowNull: true,
    });
    expect(r.ok).toBe(false);
  });
});
