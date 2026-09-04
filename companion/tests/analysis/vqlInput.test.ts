import { describe, it, expect } from "vitest";
import {
  isContainedWhereExpression,
  normalizeWhereText,
  MAX_WHERE_LENGTH,
} from "../../src/analysis/vqlInput.js";

// The two callers inline the expression as `WHERE (${where})`, so "contained" means: nothing in it
// can close that parenthesis, start a second statement, or comment the rest of the query away (#843).
describe("isContainedWhereExpression", () => {
  it("accepts the filters analysts actually write", () => {
    for (const w of [
      "NOT OSPath =~ 'pagefile'",
      "Size > 1024 AND (Name =~ 'a' OR Name =~ 'b')",
      `Name = "it's" AND Path =~ '\\\\Windows\\\\'`,
      "lowcase(string=Name) IN ('svchost.exe', 'lsass.exe')",
      "Description =~ 'semi;colon inside a literal'",
      "Comment =~ 'a -- b' OR Comment =~ '/* not a comment */'",
      "",
    ]) {
      expect(isContainedWhereExpression(w), w).toBe(true);
    }
  });

  it("refuses a value that closes the wrapper and smuggles a statement", () => {
    expect(
      isContainedWhereExpression("1=1) LIMIT 1; SELECT * FROM execve(argv=['sh','-c','id']) WHERE (1=1"),
    ).toBe(false);
    expect(isContainedWhereExpression("x) OR (1=1")).toBe(false);
  });

  it("refuses a semicolon anywhere outside a literal, not just at the end", () => {
    expect(isContainedWhereExpression("a = 1; SELECT 1")).toBe(false);
    expect(isContainedWhereExpression("a = 1 ; b = 2")).toBe(false);
  });

  it("refuses comment markers that would hide the rest of the query", () => {
    expect(isContainedWhereExpression("a = 1 -- ) LIMIT 1")).toBe(false);
    expect(isContainedWhereExpression("a = 1 /* ) */")).toBe(false);
  });

  it("refuses unbalanced parentheses and an unterminated literal", () => {
    expect(isContainedWhereExpression("(a = 1")).toBe(false);
    expect(isContainedWhereExpression("a = 1)")).toBe(false);
    expect(isContainedWhereExpression("Name =~ 'open")).toBe(false);
    expect(isContainedWhereExpression('Name =~ "open')).toBe(false);
    expect(isContainedWhereExpression("Name =~ 'escaped\\'")).toBe(false);
  });
});

describe("normalizeWhereText", () => {
  it("collapses newlines, drops a trailing semicolon and caps the length", () => {
    expect(normalizeWhereText("a = 1\r\n  AND b = 2;;  ")).toBe("a = 1   AND b = 2");
    expect(normalizeWhereText("x".repeat(MAX_WHERE_LENGTH + 50))).toHaveLength(MAX_WHERE_LENGTH);
  });
});
