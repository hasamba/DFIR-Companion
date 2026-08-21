import { describe, expect, it } from "vitest";
import {
  HuntQuerySyntaxError,
  explainHuntQuery,
  parseHuntQuery,
  validateHuntRegex,
} from "../../src/analysis/huntQueryParser.js";

describe("hunt query parser", () => {
  it("parses the documented authentication hunt with an aggregation pipeline", () => {
    const parsed = parseHuntQuery(
      [
        "event.category=authentication",
        'AND user.name="jdoe"',
        "AND event.outcome=failed",
        'AND timestamp during "last 2h"',
        "| group by source.ip",
        "| count",
        "| sort count desc",
      ].join("\n"),
    );

    expect(parsed.pipeline.map((stage) => stage.kind)).toEqual(["group", "count", "sort"]);
    expect(parsed.parameters).toEqual([]);
    expect(parsed.filter).toMatchObject({ kind: "boolean", operator: "and" });
  });

  it("honors NOT, AND, OR and parentheses", () => {
    const parsed = parseHuntQuery("NOT severity=Info AND (host.name=DC01 OR host.name=WEB01)");
    expect(parsed.filter).toMatchObject({
      kind: "boolean",
      operator: "and",
      right: { kind: "boolean", operator: "or" },
    });
  });

  it("supports field existence, ranges, safe regex and template parameters", () => {
    const parsed = parseHuntQuery(
      [
        "process.command_line exists",
        "AND destination.port between 1 and 1024",
        "AND process.name matches /power(shell)?/i",
        "AND user.name=$account",
      ].join(" "),
    );

    expect(parsed.parameters).toEqual(["account"]);
    expect(explainHuntQuery(parsed)).toContain("requires process.command_line");
    expect(explainHuntQuery(parsed)).toContain("parameter $account");
  });

  it("supports stats, rare-value detection and bounded result stages", () => {
    const stats = parseHuntQuery(
      "event.category=network | stats count(), min(destination.port), max(destination.port) by destination.ip | sort count desc | limit 20",
    );
    expect(stats.pipeline.map((stage) => stage.kind)).toEqual(["stats", "sort", "limit"]);

    const rare = parseHuntQuery("destination.ip exists | rare destination.ip limit 15");
    expect(rare.pipeline).toEqual([{ kind: "rare", field: "destination.ip", limit: 15 }]);
  });

  it("returns typed source locations and suggestions for unknown fields", () => {
    try {
      parseHuntQuery("sorce.ip=192.0.2.1");
      throw new Error("expected parsing to fail");
    } catch (error) {
      expect(error).toBeInstanceOf(HuntQuerySyntaxError);
      expect(error).toMatchObject({
        code: "unknown_field",
        line: 1,
        column: 1,
      });
      expect((error as HuntQuerySyntaxError).suggestions).toContain("source.ip");
    }
  });

  // location() binary-searches a precomputed newline-offset array; line 1 / column 1 is the one
  // position almost any wrong formula still gets right, so the cases below pin the arithmetic
  // (comparison direction, lineStart derivation) at hand-derived multi-line and mid-line offsets.
  it("locates an error on the second line of a multi-line query", () => {
    try {
      // Line 2 is "| group by sorce.ip": "| group by " spans columns 1-11, the bad field starts at 12.
      parseHuntQuery("source.ip=192.0.2.1\n| group by sorce.ip");
      throw new Error("expected parsing to fail");
    } catch (error) {
      expect(error).toBeInstanceOf(HuntQuerySyntaxError);
      expect(error).toMatchObject({ code: "unknown_field", line: 2, column: 12, length: 8 });
    }
  });

  it("locates an error mid-way through the first line", () => {
    try {
      // "source.ip=192.0.2.1" is columns 1-19, " and " ends at 24, the bad field starts at 25.
      parseHuntQuery("source.ip=192.0.2.1 and sorce.ip=10.0.0.1");
      throw new Error("expected parsing to fail");
    } catch (error) {
      expect(error).toBeInstanceOf(HuntQuerySyntaxError);
      expect(error).toMatchObject({ code: "unknown_field", line: 1, column: 25, length: 8 });
    }
  });

  it("locates an error at a non-1 column on the third line", () => {
    try {
      // Line 3 is "and sorce.ip=10.0.0.1": "and " spans columns 1-4, the bad field starts at 5.
      parseHuntQuery("source.ip=192.0.2.1\nand host.name=DC01\nand sorce.ip=10.0.0.1");
      throw new Error("expected parsing to fail");
    } catch (error) {
      expect(error).toBeInstanceOf(HuntQuerySyntaxError);
      expect(error).toMatchObject({ code: "unknown_field", line: 3, column: 5, length: 8 });
    }
  });

  it("locates an error when the query's first line is empty", () => {
    try {
      // The leading newline sits at offset 0, so the token at offset 1 must be line 2, column 1.
      parseHuntQuery("\nsorce.ip=192.0.2.1");
      throw new Error("expected parsing to fail");
    } catch (error) {
      expect(error).toBeInstanceOf(HuntQuerySyntaxError);
      expect(error).toMatchObject({ code: "unknown_field", line: 2, column: 1, length: 8 });
    }
  });

  it("re-keys the newline memo across consecutive parses of different texts", () => {
    // Same error token under two different newline layouts, parsed back to back: a stale one-slot
    // memo from the first text would misplace the second text's positions.
    try {
      parseHuntQuery("host.name=a\nand sorce.ip=1");
      throw new Error("expected parsing to fail");
    } catch (error) {
      expect(error).toMatchObject({ code: "unknown_field", line: 2, column: 5 });
    }
    try {
      parseHuntQuery("host.name=a and\nsorce.ip=1");
      throw new Error("expected parsing to fail");
    } catch (error) {
      expect(error).toMatchObject({ code: "unknown_field", line: 2, column: 1 });
    }
  });

  it.each([
    "description matches /(a+)+$/",
    "description matches /(?=evil)/",
    "description matches /(evil)\\1/",
  ])("rejects unsafe regular expressions: %s", (query) => {
    expect(() => parseHuntQuery(query)).toThrowError(expect.objectContaining({ code: "unsafe_regex" }));
  });

  it("never throws an untyped error for arbitrary input", () => {
    let seed = 0x376;
    const chars = " abcdef.=!<>()|/$\"'0123456789\n";
    for (let sample = 0; sample < 500; sample++) {
      seed = (seed * 1664525 + 1013904223) >>> 0;
      const length = seed % 80;
      let text = "";
      for (let index = 0; index < length; index++) {
        seed = (seed * 1664525 + 1013904223) >>> 0;
        text += chars[seed % chars.length];
      }
      try {
        parseHuntQuery(text);
      } catch (error) {
        expect(error).toBeInstanceOf(HuntQuerySyntaxError);
      }
    }
  });
});

describe("hunt query regex safety", () => {
  // validateHuntRegex had hand-rolled heuristics for nested quantifiers and repeated wildcards.
  // They do not model alternation overlap, so `^(a|aa)+b$` — the textbook ReDoS — passed straight
  // through to run against event text. The central checker in regexSafety.ts already names this
  // exact shape; the parser now defers to it instead of keeping a second, weaker set of rules.
  it("rejects a regex that can backtrack catastrophically", () => {
    expect(() => validateHuntRegex("^(a|aa)+b$")).toThrow(HuntQuerySyntaxError);
  });

  it("rejects a pattern that is only ambiguous under a requested i flag", () => {
    expect(() => validateHuntRegex("^(a|A)+b$", "i")).toThrow(HuntQuerySyntaxError);
    expect(() => validateHuntRegex("^(a|A)+b$")).not.toThrow(); // distinct alternatives without it
  });

  it("still accepts an ordinary regex", () => {
    expect(() => validateHuntRegex("^powershell\\.exe$")).not.toThrow();
  });

  it("keeps rejecting the shapes it already refused", () => {
    expect(() => validateHuntRegex("(?=secret)")).toThrow(HuntQuerySyntaxError); // lookaround
    expect(() => validateHuntRegex("(a)\\1")).toThrow(HuntQuerySyntaxError); // backreference
    expect(() => validateHuntRegex("a", "gg")).toThrow(HuntQuerySyntaxError); // duplicate flag
    expect(() => validateHuntRegex("a", "g")).toThrow(HuntQuerySyntaxError); // disallowed flag
  });
});
