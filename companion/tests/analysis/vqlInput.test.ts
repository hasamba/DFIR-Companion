import { describe, it, expect } from "vitest";
import {
  isContainedWhereExpression,
  normalizeWhereText,
  vqlSizeProblem,
  MAX_WHERE_LENGTH,
  MAX_VQL_BYTES,
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

  // VQL's `'''…'''` is a RAW string: a backslash is a byte, so `'''a\\'''` is the one-character
  // string `a\\` followed by the CLOSED delimiter. A scanner that read that backslash as an escape
  // stayed "inside" the string, skipped the wrapper-closing `)` and the smuggled SELECT, and was
  // brought back to balanced by a later raw string — accepting the payload.
  it("refuses the raw-string desynchronization bypass", () => {
    expect(
      isContainedWhereExpression(
        `'''a\\''' = "x" OR 1=1) SELECT * FROM execve(argv=["sh","-c","id"]) WHERE ('''b'c''' = "x"`,
      ),
    ).toBe(false);
    expect(isContainedWhereExpression(`'''a\\''' = "x" OR 1=1) SELECT 1 WHERE ('''b''' = "x"`)).toBe(false);
  });

  it("accepts benign raw strings, including ones ending in a backslash or holding syntax", () => {
    for (const w of [
      String.raw`OSPath =~ '''C:\Windows\System32\'''`,
      String.raw`OSPath =~ '''C:\Users\'''`,
      String.raw`Name =~ '''\.(exe|dll)$'''`,
      `Comment = '''has (parens) and ; semicolons and -- dashes /* inside */'''`,
      `Comment = '''it's got a 'quote' and a "double" inside'''`,
      `Comment = '''''' OR Name = '''x'''`,
    ]) {
      expect(isContainedWhereExpression(w), w).toBe(true);
    }
  });

  it("treats a backtick-quoted identifier as opaque", () => {
    expect(isContainedWhereExpression("`odd)name` = 1")).toBe(true);
    expect(isContainedWhereExpression("`odd;name` = 1 AND (`a` = 2)")).toBe(true);
    expect(isContainedWhereExpression("`unterminated = 1")).toBe(false);
  });

  it("refuses an unterminated raw string", () => {
    expect(isContainedWhereExpression(`Name = '''open`)).toBe(false);
    expect(isContainedWhereExpression(`Name = '''a''`)).toBe(false);
    expect(isContainedWhereExpression(`Name = '''a\\'''`)).toBe(true);
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

// The CLI receives the program as one argv element, and the kernel's per-argument ceiling counts
// bytes, so the limit has to count what the kernel counts — a UTF-16 `length` under-reads a
// multibyte query by up to a factor of three.
describe("vqlSizeProblem", () => {
  it("accepts a large ASCII program under the byte limit", () => {
    expect(vqlSizeProblem("SELECT 1 FROM scope() -- " + "x".repeat(MAX_VQL_BYTES - 30))).toBeNull();
  });

  it("refuses a program past the byte limit", () => {
    expect(vqlSizeProblem("x".repeat(MAX_VQL_BYTES + 1))).toMatch(/vql is too long/);
  });

  it("measures UTF-8 bytes, not UTF-16 code units", () => {
    const threeBytesEach = "€".repeat(40_000); // 40,000 characters, 120,000 bytes
    expect(threeBytesEach.length).toBeLessThan(MAX_VQL_BYTES);
    expect(vqlSizeProblem(threeBytesEach)).toMatch(/vql is too long/);
    expect(vqlSizeProblem("€".repeat(30_000))).toBeNull(); // 90,000 bytes
  });
});
