import { describe, it, expect } from "vitest";
import {
  ruleMatchesIoc,
  matchIocToExclude,
  excludeMatches,
  sanitizeExcludeRuleInput,
  normalizeSuffixPattern,
  type IocExcludeRule,
} from "../../src/analysis/iocExclude.js";
import type { IOC } from "../../src/analysis/stateTypes.js";

const rule = (over: Partial<IocExcludeRule> & Pick<IocExcludeRule, "match" | "pattern">): IocExcludeRule => ({
  id: "r1", addedAt: "2026-01-01T00:00:00Z", ...over,
});
const ioc = (type: IOC["type"], value: string): IOC => ({ id: "i", type, value, firstSeen: "2026-01-01T00:00:00Z" });

describe("normalizeSuffixPattern", () => {
  it("adds a leading dot when missing, leaves it alone otherwise", () => {
    expect(normalizeSuffixPattern("lan")).toBe(".lan");
    expect(normalizeSuffixPattern(".lan")).toBe(".lan");
    expect(normalizeSuffixPattern("  corp.local  ")).toBe(".corp.local");
  });
});

describe("ruleMatchesIoc", () => {
  it("exact rule is case-insensitive", () => {
    const r = rule({ match: "exact", pattern: "CLIENT01.LAN" });
    expect(ruleMatchesIoc(r, ioc("domain", "client01.lan"))).toBe(true);
    expect(ruleMatchesIoc(r, ioc("domain", "other.lan"))).toBe(false);
  });
  it("suffix rule matches the bare label and any subdomain, not an arbitrary substring", () => {
    const r = rule({ match: "suffix", pattern: "lan" });
    expect(ruleMatchesIoc(r, ioc("domain", "lan"))).toBe(true);
    expect(ruleMatchesIoc(r, ioc("domain", "CLIENT01.lan"))).toBe(true);
    expect(ruleMatchesIoc(r, ioc("domain", "sub.client01.lan"))).toBe(true);
    expect(ruleMatchesIoc(r, ioc("domain", "evilan.com"))).toBe(false); // not a ".lan" suffix
  });
  it("regex rule matches by pattern, case-insensitively", () => {
    const r = rule({ match: "regex", pattern: "\\.example\\.com$" });
    expect(ruleMatchesIoc(r, ioc("domain", "PROD.EXAMPLE.COM"))).toBe(true);
    expect(ruleMatchesIoc(r, ioc("domain", "evil.com"))).toBe(false);
  });
  it("honors the optional iocType restriction", () => {
    const r = rule({ match: "exact", pattern: "client01.lan", iocType: "domain" });
    expect(ruleMatchesIoc(r, ioc("domain", "client01.lan"))).toBe(true);
    expect(ruleMatchesIoc(r, ioc("other", "client01.lan"))).toBe(false);
  });
});

describe("matchIocToExclude / excludeMatches", () => {
  const rules = [
    rule({ id: "lan", match: "suffix", pattern: "lan" }),
    rule({ id: "exact", match: "exact", pattern: "badsite.com", iocType: "domain" }),
  ];
  it("returns the first matching rule (or null)", () => {
    expect(matchIocToExclude(ioc("domain", "client01.lan"), rules)?.id).toBe("lan");
    expect(matchIocToExclude(ioc("domain", "badsite.com"), rules)?.id).toBe("exact");
    expect(matchIocToExclude(ioc("domain", "fine.com"), rules)).toBeNull();
  });
  it("collects every matching IOC", () => {
    const iocs = [ioc("domain", "client01.lan"), ioc("domain", "fine.com"), ioc("domain", "badsite.com")];
    const matched = excludeMatches(iocs, rules).map((i) => i.value).sort();
    expect(matched).toEqual(["badsite.com", "client01.lan"]);
  });
  it("returns nothing when there are no rules", () => {
    expect(excludeMatches([ioc("domain", "client01.lan")], [])).toEqual([]);
  });
});

describe("sanitizeExcludeRuleInput", () => {
  it("accepts a valid rule and normalizes the mode/type/suffix pattern", () => {
    expect(sanitizeExcludeRuleInput({ match: "SUFFIX", pattern: "lan", iocType: "DOMAIN", note: " internal " }))
      .toEqual({ match: "suffix", pattern: ".lan", iocType: "domain", note: "internal" });
  });
  it("rejects an unknown match mode, empty pattern, bad regex", () => {
    expect(sanitizeExcludeRuleInput({ match: "nope", pattern: "x" })).toBeNull();
    expect(sanitizeExcludeRuleInput({ match: "exact", pattern: "  " })).toBeNull();
    expect(sanitizeExcludeRuleInput({ match: "regex", pattern: "(" })).toBeNull();
  });
  it("drops an unknown iocType rather than rejecting the rule", () => {
    expect(sanitizeExcludeRuleInput({ match: "exact", pattern: "x", iocType: "banana" }))
      .toEqual({ match: "exact", pattern: "x" });
  });
});
