import { describe, expect, it } from "vitest";
import { parseSigmaRule } from "../../src/analysis/sigmaRule.js";
import {
  compileSigmaRule,
  lookupPath,
  SIGMA_LOOKUP_MAX_LEAVES,
  SIGMA_LOOKUP_MAX_JSON_CHARS,
  type SigmaTri,
} from "../../src/analysis/sigmaMatch.js";

// The import-time Sigma evaluator (#2202): one parsed rule against one raw record. These tests pin
// the Sigma semantics the engine promises — case-insensitive strings, wildcards and their escapes,
// the modifiers, null, keywords, arrays, and the three-valued result that stops a truncated field
// from turning `not filter` into a false match.

type Row = Record<string, unknown>;

function rule(detection: string, condition = "sel"): ReturnType<typeof compileSigmaRule> {
  const r = parseSigmaRule(
    `title: T\nlogsource:\n  product: test\ndetection:\n${detection}\n  condition: ${condition}\n`,
    { allowNull: true },
  );
  if (!r.ok) throw new Error(r.refusals.map((x) => `${x.path}: ${x.message}`).join("\n"));
  return compileSigmaRule(r.rule);
}
const evalOn = (detection: string, rec: Row, condition?: string): SigmaTri =>
  rule(detection, condition).evaluate(rec, (r, f) => lookupPath(r, f));

describe("string matching", () => {
  it("is case-insensitive and exact by default", () => {
    const d = "  sel:\n    eventName: StopLogging";
    expect(evalOn(d, { eventName: "stoplogging" })).toBe(true);
    expect(evalOn(d, { eventName: "StopLoggingNow" })).toBe(false);
  });

  it("supports contains / startswith / endswith", () => {
    expect(evalOn("  sel:\n    ua|contains: boto", { ua: "Boto3/1.2" })).toBe(true);
    expect(evalOn("  sel:\n    ua|startswith: aws-cli", { ua: "aws-cli/2.0" })).toBe(true);
    expect(evalOn("  sel:\n    ua|endswith: .exe", { ua: "C:\\x\\S3 Browser.EXE" })).toBe(true);
    expect(evalOn("  sel:\n    ua|startswith: cli", { ua: "aws-cli/2.0" })).toBe(false);
  });

  it("treats * and ? as wildcards and honours their escapes", () => {
    expect(evalOn("  sel:\n    n: 'Delete*'", { n: "DeleteTrail" })).toBe(true);
    expect(evalOn("  sel:\n    n: 'Get?ecret'", { n: "GetSecret" })).toBe(true);
    expect(evalOn("  sel:\n    n: 'a\\*b'", { n: "a*b" })).toBe(true);
    expect(evalOn("  sel:\n    n: 'a\\*b'", { n: "axxb" })).toBe(false);
    expect(evalOn("  sel:\n    n: 'a\\?b'", { n: "axb" })).toBe(false);
  });

  it("keeps a lone backslash literal and reads \\\\ as one backslash", () => {
    expect(evalOn("  sel:\n    p: 'C:\\Temp'", { p: "c:\\temp" })).toBe(true);
    expect(evalOn("  sel:\n    p: 'a\\\\*'", { p: "a\\xyz" })).toBe(true);
  });

  it("escapes regex metacharacters in plain values", () => {
    expect(evalOn("  sel:\n    n: 'a.b'", { n: "axb" })).toBe(false);
    expect(evalOn("  sel:\n    n: '(x)'", { n: "(X)" })).toBe(true);
  });

  it("ORs a value list, and ANDs it with |all", () => {
    expect(evalOn("  sel:\n    n:\n      - A\n      - B", { n: "b" })).toBe(true);
    expect(evalOn("  sel:\n    n|contains|all:\n      - x\n      - y", { n: "x..y" })).toBe(true);
    expect(evalOn("  sel:\n    n|contains|all:\n      - x\n      - y", { n: "x" })).toBe(false);
  });

  it("compares numbers and booleans by their text", () => {
    expect(evalOn("  sel:\n    code: '50126'", { code: 50126 })).toBe(true);
    expect(evalOn("  sel:\n    code: 50126", { code: "50126" })).toBe(true);
    expect(evalOn("  sel:\n    flag: true", { flag: "True" })).toBe(true);
    expect(evalOn("  sel:\n    flag: false", { flag: true })).toBe(false);
  });
});

describe("modifiers", () => {
  it("runs re case-sensitively unless the pattern opts in with (?i)", () => {
    expect(evalOn("  sel:\n    n|re: '^Get.*Value$'", { n: "GetSecretValue" })).toBe(true);
    expect(evalOn("  sel:\n    n|re: '^get'", { n: "GetSecretValue" })).toBe(false);
    expect(evalOn("  sel:\n    n|re: '(?i)^get'", { n: "GetSecretValue" })).toBe(true);
  });

  it("matches cidr for IPv4 and IPv6", () => {
    expect(evalOn("  sel:\n    ip|cidr: 10.0.0.0/8", { ip: "10.2.3.4" })).toBe(true);
    expect(evalOn("  sel:\n    ip|cidr: 10.0.0.0/8", { ip: "192.0.2.4" })).toBe(false);
    expect(evalOn("  sel:\n    ip|cidr: '2001:db8::/32'", { ip: "2001:db8::1" })).toBe(true);
    expect(evalOn("  sel:\n    ip|cidr: 10.0.0.0/8", { ip: "not-an-ip" })).toBe(false);
  });

  it("compares numerically with gt / gte / lt / lte", () => {
    expect(evalOn("  sel:\n    n|gt: 5", { n: "6" })).toBe(true);
    expect(evalOn("  sel:\n    n|gte: 5", { n: 5 })).toBe(true);
    expect(evalOn("  sel:\n    n|lt: 5", { n: 5 })).toBe(false);
    expect(evalOn("  sel:\n    n|lte: 5", { n: "x" })).toBe(false);
  });
});

describe("null, empty and absent", () => {
  const d = "  sel:\n    mfa: null";
  it("matches null for an absent key or JSON null only", () => {
    expect(evalOn(d, {})).toBe(true);
    expect(evalOn(d, { mfa: null })).toBe(true);
    expect(evalOn(d, { mfa: "" })).toBe(false);
    expect(evalOn(d, { mfa: [] })).toBe(false);
    expect(evalOn(d, { mfa: "No" })).toBe(false);
  });

  it("matches '' against the empty string only", () => {
    const e = "  sel:\n    mfa: ''";
    expect(evalOn(e, { mfa: "" })).toBe(true);
    expect(evalOn(e, {})).toBe(false);
    expect(evalOn(e, { mfa: null })).toBe(false);
  });

  it("never matches a string value against an absent field", () => {
    expect(evalOn("  sel:\n    n|contains: x", {})).toBe(false);
  });
});

describe("field lookup", () => {
  it("walks dotted paths case-insensitively", () => {
    expect(evalOn("  sel:\n    userIdentity.type: Root", { UserIdentity: { Type: "Root" } })).toBe(true);
  });

  it("reads a flattened dotted key (CSV export) as well as a nested one", () => {
    expect(evalOn("  sel:\n    userIdentity.type: Root", { "userIdentity.type": "Root" })).toBe(true);
  });

  it("walks arrays and matches when any element matches", () => {
    const rec = { targetResources: [{ type: "User" }, { type: "Group" }] };
    expect(evalOn("  sel:\n    targetResources.type: Group", rec)).toBe(true);
    expect(evalOn("  sel:\n    targetResources.type: Device", rec)).toBe(false);
  });

  it("parses a JSON string when the path continues into it", () => {
    const rec = { Status: '{"errorCode":50126,"failureReason":"Invalid password"}' };
    expect(evalOn("  sel:\n    Status.errorCode: 50126", rec)).toBe(true);
  });

  it("compares an object leaf as its JSON text", () => {
    const rec = { requestParameters: { policyDocument: { Effect: "Allow", Action: "s3:GetObject" } } };
    expect(evalOn("  sel:\n    requestParameters|contains: 's3:GetObject'", rec)).toBe(true);
  });
});

describe("keywords", () => {
  it("searches the whole record case-insensitively", () => {
    expect(evalOn("  sel:\n    - 'stoplogging'", { a: { b: "StopLogging" } })).toBe(true);
    expect(evalOn("  sel:\n    - 'nothing'", { a: "StopLogging" })).toBe(false);
  });
});

describe("conditions", () => {
  const two = "  sel:\n    a: x\n  filter:\n    b: y";
  it("evaluates and / or / not", () => {
    expect(evalOn(two, { a: "x", b: "z" }, "sel and not filter")).toBe(true);
    expect(evalOn(two, { a: "x", b: "y" }, "sel and not filter")).toBe(false);
    expect(evalOn(two, { a: "q", b: "y" }, "sel or filter")).toBe(true);
  });

  it("evaluates 1 of / all of", () => {
    const d = "  sel_a:\n    a: x\n  sel_b:\n    b: y";
    expect(evalOn(d, { a: "x" }, "1 of sel_*")).toBe(true);
    expect(evalOn(d, { a: "x" }, "all of sel_*")).toBe(false);
    expect(evalOn(d, { a: "x", b: "y" }, "all of them")).toBe(true);
  });

  it("ORs the maps of a list selection", () => {
    const d = "  sel:\n    - a: x\n    - b: y";
    expect(evalOn(d, { b: "y" })).toBe(true);
    expect(evalOn(d, { c: "y" })).toBe(false);
  });
});

describe("incomplete evaluation (three-valued)", () => {
  const many = (n: number, last: string) => ({
    a: "x",
    list: [...Array.from({ length: n }, (_, i) => `v${i}`), last],
  });

  it("reports incomplete, not false, when a field overflows the leaf budget", () => {
    const rec = many(SIGMA_LOOKUP_MAX_LEAVES + 5, "needle");
    expect(evalOn("  sel:\n    list: needle", rec)).toBe("incomplete");
  });

  it("never turns an overflowed filter under `not` into a match", () => {
    const rec = many(SIGMA_LOOKUP_MAX_LEAVES + 5, "needle");
    const d = "  sel:\n    a: x\n  filter:\n    list: needle";
    expect(evalOn(d, rec, "sel and not filter")).toBe("incomplete");
  });

  it("never calls a truncated field absent (null) — Codex review", () => {
    const big = JSON.stringify({ trustType: "AzureAD", pad: "x".repeat(SIGMA_LOOKUP_MAX_JSON_CHARS + 10) });
    expect(evalOn("  sel:\n    deviceDetail.trustType: null", { deviceDetail: big })).toBe("incomplete");
    const nulls = { list: [...Array.from({ length: SIGMA_LOOKUP_MAX_LEAVES + 5 }, () => null), "set"] };
    expect(evalOn("  sel:\n    list: null", nulls)).toBe("incomplete");
    expect(
      evalOn("  sel:\n    a: x\n  filter:\n    list: null", { a: "x", ...nulls }, "sel and not filter"),
    ).toBe("incomplete");
  });

  it("still calls a field non-null when a retained value is set, even if truncated", () => {
    const rec = { list: ["set", ...Array.from({ length: SIGMA_LOOKUP_MAX_LEAVES + 5 }, () => null)] };
    expect(evalOn("  sel:\n    list: null", rec)).toBe(false);
  });

  it("still answers definitely when the overflowed part cannot change the result", () => {
    const rec = many(SIGMA_LOOKUP_MAX_LEAVES + 5, "needle");
    const d = "  sel:\n    a: nope\n  filter:\n    list: needle";
    expect(evalOn(d, rec, "sel and not filter")).toBe(false);
    expect(evalOn("  sel:\n    list: v1", rec)).toBe(true);
  });
});
