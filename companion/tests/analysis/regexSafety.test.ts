import { describe, it, expect } from "vitest";
import { checkRegexSafety } from "../../src/analysis/regexSafety.js";

const reject = (src: string) => expect(checkRegexSafety(src).ok, `expected REJECT: ${src}`).toBe(false);
const accept = (src: string) => expect(checkRegexSafety(src).ok, `expected ACCEPT: ${src}`).toBe(true);

describe("checkRegexSafety — catastrophic backtracking", () => {
  it("rejects the textbook nested-quantifier shapes", () => {
    for (const src of ["(a+)+$", "(a*)*$", "(a+)*$", "(?:a+)+$", "^(\\d+\\.?)+$"]) reject(src);
  });

  it("rejects nested quantifiers however they are spelled", () => {
    // Each of these is the same danger as (a+)+ and each defeats a substring heuristic:
    // extra parens hide the quantifier, braces aren't "+" or "*", and lazy still backtracks.
    for (const src of ["((a+))+$", "(((a+)))+$", "(a{1,10})+$", "(a?){20}a{20}", "(a+?)+$"]) reject(src);
  });

  it("rejects loops over alternatives that can start with the same character", () => {
    for (const src of ["(a|a)+$", "(\\w|\\d)+X$", "([a-z]|[a-z0-9])+$", "(ab|a)+$"]) reject(src);
  });

  it("rejects adjacent repetitions competing for the same characters", () => {
    for (const src of [".*.*=.*", "\\w*\\d*$"]) reject(src);
  });

  it("rejects a pattern longer than the cap", () => {
    const r = checkRegexSafety("a".repeat(513));
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/too long/);
  });

  it("rejects invalid syntax with a reason", () => {
    const r = checkRegexSafety("(unclosed");
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/not a valid regular expression/);
  });

  it("explains why it refused", () => {
    expect(checkRegexSafety("((a+))+$").reason).toMatch(/variable-length repetition.*ReDoS/);
    expect(checkRegexSafety("(a|a)+$").reason).toMatch(/same character.*ReDoS/);
  });
});

describe("checkRegexSafety — ordinary importer patterns still pass", () => {
  it("accepts the filename patterns an analyst actually writes", () => {
    for (const src of [
      "^evtx-(.*)\\.json$",
      "^audit_.*\\.(csv|json)$",
      "\\.evtx$",
      "^Hayabusa-.+-timeline\\.csv$",
      "^(alerts|events)-\\d+\\.json$",
      "sysmon",
    ])
      accept(src);
  });

  it("accepts bounded nesting whose path count cannot explode", () => {
    // 3 repeats of a 1-3 digit run is 27 paths, not 2^n — the check is about explosion, not nesting.
    accept("^(\\d{1,3}\\.){3}\\d{1,3}$");
    accept("^([0-9a-f]{2}:){5}[0-9a-f]{2}$");
  });

  it("accepts loops over alternatives that cannot collide", () => {
    accept("(foo|bar)+$");
    accept("^([a-z]|[0-9])+$".replace("[0-9]", "[0-9]")); // disjoint classes
  });

  it("accepts adjacent loops over disjoint characters", () => {
    accept("^[a-z]*[0-9]*$");
  });
});

describe("checkRegexSafety — the rejected patterns really are dangerous", () => {
  // Shows the conservative rejections above are earning their keep: each of these compiles fine and
  // blows up on a 20-char input, while the real bound is a 1024-char filename. n stays small so the
  // cost here is milliseconds — the danger is that it doubles for every extra character.
  it("confirms the shapes a substring heuristic misses are exponential", () => {
    for (const src of ["((a+))+$", "(a|a)+$", "(a{1,10})+$"]) {
      expect(checkRegexSafety(src).ok, `${src} must be rejected`).toBe(false);
      const re = new RegExp(src);
      const time = (n: number) => {
        const t = Date.now();
        re.test("a".repeat(n) + "!");
        return Date.now() - t;
      };
      time(12); // warm up the engine
      expect(time(22), `${src} was expected to backtrack`).toBeGreaterThan(5);
    }
  });
});
