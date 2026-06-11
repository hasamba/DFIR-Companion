import { describe, it, expect } from "vitest";
import {
  ipInCidr,
  isValidCidr,
  ruleMatchesIoc,
  matchIocToWhitelist,
  whitelistMatches,
  sanitizeRuleInput,
  parseWhitelistText,
  toWhitelistCsv,
  type IocWhitelistRule,
} from "../../src/analysis/iocWhitelist.js";
import type { IOC } from "../../src/analysis/stateTypes.js";

const rule = (over: Partial<IocWhitelistRule> & Pick<IocWhitelistRule, "match" | "pattern">): IocWhitelistRule => ({
  id: "r1", addedAt: "2026-01-01T00:00:00Z", ...over,
});
const ioc = (type: IOC["type"], value: string): IOC => ({ id: "i", type, value, firstSeen: "2026-01-01T00:00:00Z" });

describe("ipInCidr / isValidCidr", () => {
  it("matches IPv4 addresses inside a CIDR range", () => {
    expect(ipInCidr("10.1.2.3", "10.0.0.0/8")).toBe(true);
    expect(ipInCidr("192.168.1.50", "192.168.0.0/16")).toBe(true);
    expect(ipInCidr("172.16.5.5", "172.16.0.0/12")).toBe(true);
  });
  it("rejects addresses outside the range", () => {
    expect(ipInCidr("11.0.0.1", "10.0.0.0/8")).toBe(false);
    expect(ipInCidr("192.169.0.1", "192.168.0.0/16")).toBe(false);
  });
  it("treats a bare IP as /32 and handles /0", () => {
    expect(ipInCidr("8.8.8.8", "8.8.8.8")).toBe(true);
    expect(ipInCidr("8.8.4.4", "8.8.8.8")).toBe(false);
    expect(ipInCidr("1.2.3.4", "0.0.0.0/0")).toBe(true);
  });
  it("returns false for malformed / non-IPv4 input instead of throwing", () => {
    expect(ipInCidr("not-an-ip", "10.0.0.0/8")).toBe(false);
    expect(ipInCidr("10.0.0.1", "garbage")).toBe(false);
    expect(ipInCidr("2001:db8::1", "10.0.0.0/8")).toBe(false);
  });
  it("validates CIDR strings", () => {
    expect(isValidCidr("10.0.0.0/8")).toBe(true);
    expect(isValidCidr("10.0.0.5")).toBe(true);
    expect(isValidCidr("10.0.0.0/33")).toBe(false);
    expect(isValidCidr("999.0.0.0/8")).toBe(false);
    expect(isValidCidr("hello")).toBe(false);
  });
});

describe("ruleMatchesIoc", () => {
  it("cidr rule matches only IP values in range", () => {
    const r = rule({ match: "cidr", pattern: "10.0.0.0/8" });
    expect(ruleMatchesIoc(r, ioc("ip", "10.5.5.5"))).toBe(true);
    expect(ruleMatchesIoc(r, ioc("ip", "11.5.5.5"))).toBe(false);
  });
  it("exact rule is case-insensitive (good for hashes/domains)", () => {
    const r = rule({ match: "exact", pattern: "D41D8CD98F00B204E9800998ECF8427E" });
    expect(ruleMatchesIoc(r, ioc("hash", "d41d8cd98f00b204e9800998ecf8427e"))).toBe(true);
    expect(ruleMatchesIoc(r, ioc("hash", "deadbeef"))).toBe(false);
  });
  it("regex rule matches by pattern, case-insensitively", () => {
    const r = rule({ match: "regex", pattern: "\\.corp\\.local$" });
    expect(ruleMatchesIoc(r, ioc("domain", "DC01.CORP.LOCAL"))).toBe(true);
    expect(ruleMatchesIoc(r, ioc("domain", "evil.com"))).toBe(false);
  });
  it("honors the optional iocType restriction", () => {
    const r = rule({ match: "exact", pattern: "10.0.0.1", iocType: "ip" });
    expect(ruleMatchesIoc(r, ioc("ip", "10.0.0.1"))).toBe(true);
    // same value, different type → no match because the rule is IP-only
    expect(ruleMatchesIoc(r, ioc("other", "10.0.0.1"))).toBe(false);
  });
});

describe("matchIocToWhitelist / whitelistMatches", () => {
  const rules = [
    rule({ id: "cidr", match: "cidr", pattern: "10.0.0.0/8", iocType: "ip" }),
    rule({ id: "hash", match: "exact", pattern: "deadbeef", iocType: "hash" }),
  ];
  it("returns the first matching rule (or null)", () => {
    expect(matchIocToWhitelist(ioc("ip", "10.1.1.1"), rules)?.id).toBe("cidr");
    expect(matchIocToWhitelist(ioc("hash", "deadbeef"), rules)?.id).toBe("hash");
    expect(matchIocToWhitelist(ioc("domain", "evil.com"), rules)).toBeNull();
  });
  it("collects every matching IOC with the rule that caught it", () => {
    const iocs = [ioc("ip", "10.1.1.1"), ioc("ip", "8.8.8.8"), ioc("hash", "deadbeef")];
    const matches = whitelistMatches(iocs, rules);
    expect(matches.map((m) => m.ioc.value).sort()).toEqual(["10.1.1.1", "deadbeef"]);
  });
  it("returns nothing when there are no rules", () => {
    expect(whitelistMatches([ioc("ip", "10.1.1.1")], [])).toEqual([]);
  });
});

describe("sanitizeRuleInput", () => {
  it("accepts a valid rule and normalizes the mode/type", () => {
    expect(sanitizeRuleInput({ match: "CIDR", pattern: "10.0.0.0/8", iocType: "IP", note: " internal " }))
      .toEqual({ match: "cidr", pattern: "10.0.0.0/8", iocType: "ip", note: "internal" });
  });
  it("rejects an unknown match mode, empty pattern, bad CIDR, bad regex", () => {
    expect(sanitizeRuleInput({ match: "nope", pattern: "x" })).toBeNull();
    expect(sanitizeRuleInput({ match: "exact", pattern: "  " })).toBeNull();
    expect(sanitizeRuleInput({ match: "cidr", pattern: "10.0.0.0/99" })).toBeNull();
    expect(sanitizeRuleInput({ match: "regex", pattern: "(" })).toBeNull();
  });
  it("drops an unknown iocType rather than rejecting the rule", () => {
    expect(sanitizeRuleInput({ match: "exact", pattern: "x", iocType: "banana" }))
      .toEqual({ match: "exact", pattern: "x" });
  });
});

describe("parseWhitelistText", () => {
  it("parses a JSON array of rules", () => {
    const out = parseWhitelistText('[{"match":"cidr","pattern":"10.0.0.0/8","iocType":"ip"},{"match":"bad","pattern":"x"}]');
    expect(out).toHaveLength(1);
    expect(out[0]).toEqual({ match: "cidr", pattern: "10.0.0.0/8", iocType: "ip" });
  });
  it("parses a {rules:[…]} wrapper", () => {
    const out = parseWhitelistText('{"rules":[{"match":"exact","pattern":"deadbeef","iocType":"hash"}]}');
    expect(out).toEqual([{ match: "exact", pattern: "deadbeef", iocType: "hash" }]);
  });
  it("parses CSV with a header row and tolerant column aliases", () => {
    const csv = "mode,value,type,reason\ncidr,192.168.0.0/16,ip,internal\nexact,deadbeef,hash,known good\n";
    const out = parseWhitelistText(csv);
    expect(out).toEqual([
      { match: "cidr", pattern: "192.168.0.0/16", iocType: "ip", note: "internal" },
      { match: "exact", pattern: "deadbeef", iocType: "hash", note: "known good" },
    ]);
  });
  it("returns [] for empty / unrecognized input", () => {
    expect(parseWhitelistText("")).toEqual([]);
    expect(parseWhitelistText("just,some,headers\n")).toEqual([]); // no 'pattern' column
  });
});

describe("toWhitelistCsv", () => {
  it("round-trips through parseWhitelistText", () => {
    const rules = [
      rule({ id: "a", match: "cidr", pattern: "10.0.0.0/8", iocType: "ip", note: "internal, lab" }),
      rule({ id: "b", match: "exact", pattern: "deadbeef", iocType: "hash" }),
    ];
    const csv = toWhitelistCsv(rules);
    expect(csv.split("\n")[0]).toBe("match,pattern,type,note");
    const back = parseWhitelistText(csv);
    expect(back).toEqual([
      { match: "cidr", pattern: "10.0.0.0/8", iocType: "ip", note: "internal, lab" },
      { match: "exact", pattern: "deadbeef", iocType: "hash" },
    ]);
  });
});
